//! Solana program / address intelligence for the contract scanner (non-EVM path).

use crate::db::DbPool;
use crate::models::senseiguard::{
    OwnerPrivileges, ReputationInfo, ScanDetailsPayload, ScanTrend,
    SimulationResult,
};
use crate::models::wallet::SOLANA_MAINNET_CHAIN_ID;
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::services::ai_insight_service::AiInsightService;
use crate::services::goplus_intel_service;
use crate::services::reputation_service::ReputationService;
use crate::services::scoring_engine::ScoringEngine;
use crate::services::solana_tx_analysis::{
    static_malicious_programs, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
};
use crate::services::threat_intel_service::get_malicious_programs;
use serde_json::json;

const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const METAPLEX_METADATA_PROGRAM_ID: &str = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";

#[derive(Debug, Clone)]
pub struct SolanaProgramScanContext {
    pub program_id: String,
    pub network: String,
    pub program_label: Option<String>,
    pub is_known_system_program: bool,
    pub goplus_malicious: bool,
    pub goplus_risk_flags: Vec<String>,
    pub locally_flagged: bool,
}

pub fn solana_program_label(program_id: &str) -> Option<&'static str> {
    match program_id {
        SYSTEM_PROGRAM_ID => Some("System Program"),
        TOKEN_PROGRAM_ID => Some("SPL Token Program"),
        TOKEN_2022_PROGRAM_ID => Some("Token-2022 Program"),
        ASSOCIATED_TOKEN_PROGRAM_ID => Some("Associated Token Program"),
        METAPLEX_METADATA_PROGRAM_ID => Some("Metaplex Token Metadata"),
        _ => None,
    }
}

pub fn is_known_solana_system_program(program_id: &str) -> bool {
    solana_program_label(program_id).is_some()
}

pub async fn build_scan_context(pool: &DbPool, program_id: &str) -> SolanaProgramScanContext {
    let malicious = get_malicious_programs(pool).await;
    let locally_flagged = malicious.contains(program_id)
        || static_malicious_programs().iter().any(|p| p == program_id);

    let goplus = goplus_intel_service::enrich_addresses(
        pool,
        &[program_id.to_string()],
        "solana",
        "program",
        Some("solana"),
        1,
    )
    .await;

    SolanaProgramScanContext {
        program_id: program_id.to_string(),
        network: "Solana".to_string(),
        program_label: solana_program_label(program_id).map(str::to_string),
        is_known_system_program: is_known_solana_system_program(program_id),
        goplus_malicious: goplus.malicious_detected,
        goplus_risk_flags: goplus
            .findings
            .iter()
            .map(|s| s.to_string())
            .collect(),
        locally_flagged,
    }
}

pub fn compute_solana_trust_score(ctx: &SolanaProgramScanContext, reputation: &ReputationInfo) -> i32 {
    if ctx.goplus_malicious || ctx.locally_flagged {
        return 8;
    }
    if reputation.reported_scam == Some(true) {
        return 12;
    }
    let local = reputation.local_report_count.unwrap_or(0);
    if local >= 3 {
        return 15;
    }
    if local > 0 {
        return (45i32).saturating_sub((local as i32).saturating_mul(8));
    }
    if ctx.is_known_system_program {
        return 96;
    }
    58
}

pub fn solana_critical_risk_flags(ctx: &SolanaProgramScanContext, reputation: &ReputationInfo) -> i32 {
    let mut n = 0i32;
    if ctx.goplus_malicious || ctx.locally_flagged {
        n += 1;
    }
    if reputation.reported_scam == Some(true) {
        n += 1;
    }
    n
}

pub async fn scan_solana_program(
    pool: &DbPool,
    program_id: &str,
    for_address: Option<&str>,
    network: &str,
) -> Result<crate::models::senseiguard::ScanContractResponse, sqlx::Error> {
    let ctx = build_scan_context(pool, program_id).await;
    let reputation =
        ReputationService::get_reputation(pool, program_id, Some(SOLANA_MAINNET_CHAIN_ID as u64))
            .await;

    let trust_score = compute_solana_trust_score(&ctx, &reputation);
    let critical_risk_flags = solana_critical_risk_flags(&ctx, &reputation);

    let (scans_today, wallets_affected) =
        SenseiguardRepository::get_contract_scan_trend(pool, program_id)
            .await
            .unwrap_or((0, 0));
    let risk_trend = if scans_today > 10 && wallets_affected > 5 {
        "increasing"
    } else if scans_today > 0 {
        "stable"
    } else {
        "low_concern"
    };
    let trend = ScanTrend {
        scans_today: Some(scans_today as u32),
        wallets_affected: Some(wallets_affected as u32),
        risk_trend: Some(risk_trend.to_string()),
    };

    let user_anomaly_score = if let Some(wallet) = for_address {
        match SenseiguardRepository::count_scans_for_wallet_contract(pool, wallet, program_id).await
        {
            Ok(0) => 0.5,
            Ok(_) => 0.2,
            _ => 0.0,
        }
    } else {
        0.0
    };

    let simulation = SimulationResult {
        dangerous_functions: if ctx.goplus_malicious || ctx.locally_flagged {
            Some(vec!["malicious_program_flag".to_string()])
        } else {
            None
        },
        ..Default::default()
    };
    let owner_privileges = OwnerPrivileges::default();
    let token_control_risk = if ctx.is_known_system_program { 5 } else { 25 };
    let contract_age_risk = 30;

    let (adjusted_trust, risk_breakdown) = ScoringEngine::compute(
        &simulation,
        &owner_privileges,
        &reputation,
        user_anomaly_score,
        token_control_risk,
        contract_age_risk,
    );
    let trust_score = trust_score.min(adjusted_trust);

    let token_controlled = if ctx.is_known_system_program {
        "SOL, SPL".to_string()
    } else {
        "Unknown".to_string()
    };

    let detected_standard = ctx
        .program_label
        .clone()
        .or_else(|| Some("Solana Program".to_string()));

    let ai_summary = AiInsightService::explain_risks(
        trust_score,
        &simulation,
        &owner_privileges,
        &reputation,
        &risk_breakdown,
        &token_controlled,
    );

    let details = ScanDetailsPayload {
        simulation: Some(simulation),
        owner_privileges: Some(owner_privileges),
        reputation: Some(reputation),
        abi_source: Some("solana_intel".to_string()),
        trend: Some(trend),
        risk_breakdown: Some(risk_breakdown),
        ai_summary: Some(ai_summary.clone()),
        user_anomaly_score: Some(user_anomaly_score),
        rug_pull_probability: None,
        contract_name: ctx.program_label.clone(),
        detected_standards: detected_standard.as_ref().map(|s| vec![s.clone()]),
    };
    let mut details_json = serde_json::to_value(&details).ok();
    if let Some(ref mut v) = details_json {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("chain_family".to_string(), json!("solana"));
            obj.insert("network".to_string(), json!(network));
            obj.insert(
                "goplus_risk_flags".to_string(),
                json!(ctx.goplus_risk_flags),
            );
            obj.insert(
                "locally_flagged".to_string(),
                json!(ctx.locally_flagged),
            );
        }
    }

    let network_label = match network {
        "devnet" => "Solana Devnet",
        "mainnet" => "Solana Mainnet",
        _ => "Solana",
    };

    let row = SenseiguardRepository::create_contract_scan(
        pool,
        program_id,
        trust_score,
        critical_risk_flags,
        &token_controlled,
        1,
        details_json.as_ref(),
        for_address,
        Some(SOLANA_MAINNET_CHAIN_ID),
    )
    .await?;

    Ok(crate::models::senseiguard::ScanContractResponse {
        scan_id: row.id,
        contract_address: row.contract_address,
        trust_score: row.trust_score,
        critical_risk_flags: row.critical_risk_flags,
        token_controlled: row.token_controlled,
        owner_admin_count: row.owner_admin_count,
        scanned_at: row.scanned_at,
        chain_id: Some(SOLANA_MAINNET_CHAIN_ID as u64),
        network: Some(network_label.to_string()),
        contract_name: ctx.program_label,
        detected_standard: detected_standard,
        details: row.details,
        ai_summary: Some(ai_summary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_system_program_high_trust() {
        let ctx = SolanaProgramScanContext {
            program_id: TOKEN_PROGRAM_ID.to_string(),
            network: "mainnet".to_string(),
            program_label: Some("SPL Token Program".to_string()),
            is_known_system_program: true,
            goplus_malicious: false,
            goplus_risk_flags: vec![],
            locally_flagged: false,
        };
        let rep = ReputationInfo::default();
        assert!(compute_solana_trust_score(&ctx, &rep) >= 90);
    }

    #[test]
    fn goplus_malicious_low_trust() {
        let ctx = SolanaProgramScanContext {
            program_id: "FakeProg1111111111111111111111111111111".to_string(),
            network: "mainnet".to_string(),
            program_label: None,
            is_known_system_program: false,
            goplus_malicious: true,
            goplus_risk_flags: vec!["flag".to_string()],
            locally_flagged: false,
        };
        let rep = ReputationInfo::default();
        assert!(compute_solana_trust_score(&ctx, &rep) <= 15);
    }
}
