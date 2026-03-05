//! Smart Wallet Scanner pipeline: analyzer -> simulation -> reputation -> trend -> ai_explainer -> scoring.

use crate::db::DbPool;
use crate::models::senseiguard::{
    ContractScan, ScanDetailsPayload, ScanContractResponse, ScanTrend,
};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::services::ai_insight_service::AiInsightService;
use crate::services::analyzer_service::AnalyzerService;
use crate::services::reputation_service::ReputationService;
use crate::services::scoring_engine::ScoringEngine;
use crate::services::simulation_service::SimulationService;
use sqlx::Error;

pub struct ScanService;

impl ScanService {
    /// Run full intelligence pipeline and persist result.
    pub async fn scan_contract(
        pool: &DbPool,
        contract_address: &str,
        for_address: Option<&str>,
    ) -> Result<ScanContractResponse, Error> {
        let tokens_controlled: Vec<String> = vec!["ETH".into(), "USDC".into()];
        let token_controlled_str = tokens_controlled.join(", ");

        // 1. Analyzer: single Etherscan fetch → owner privileges, dangerous functions, and whether ABI was real
        let analysis = AnalyzerService::analyze_contract(contract_address).await;
        let owner_privileges = analysis.owner_privileges;
        let dangerous_functions = analysis.dangerous_functions;
        let abi_source = if analysis.abi_from_etherscan { "etherscan" } else { "stub" };

        // 2. Simulation
        let simulation = SimulationService::simulate_contract(
            contract_address,
            &tokens_controlled,
        ).await;
        let mut sim_with_fns = simulation.clone();
        sim_with_fns.dangerous_functions = Some(dangerous_functions);

        // 3. Reputation (uses pool for scam_reports)
        let reputation = ReputationService::get_reputation(pool, contract_address).await;

        // 4. Trend from DB
        let (scans_today, wallets_affected) = SenseiguardRepository::get_contract_scan_trend(
            pool,
            contract_address,
        ).await.unwrap_or((0, 0));
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

        // 5. User-aware anomaly (stub: higher if for_address provided and contract is risky)
        let user_anomaly_score = if for_address.is_some() { 0.78 } else { 0.0 };

        // 6. Token control scope risk (stub: 40 if controls ETH+USDC)
        let token_control_risk = if tokens_controlled.len() >= 2 { 40u8 } else { 20u8 };
        let contract_age_risk = 30u8; // stub: assume relatively new

        // 7. Scoring
        let (trust_score, risk_breakdown) = ScoringEngine::compute(
            &simulation,
            &owner_privileges,
            &reputation,
            user_anomaly_score,
            token_control_risk,
            contract_age_risk,
        );
        let rug_pull = ScoringEngine::rug_pull_probability(&owner_privileges);

        // 8. AI summary
        let ai_summary = AiInsightService::explain_risks(
            &sim_with_fns,
            &owner_privileges,
            &reputation,
            &token_controlled_str,
        );

        let critical_risk_flags = [simulation.drains_full_balance == Some(true), reputation.reported_scam == Some(true)]
            .into_iter()
            .filter(|&b| b)
            .count() as i32
            + owner_privileges.withdraw_liquidity.unwrap_or(false) as i32;

        let details = ScanDetailsPayload {
            simulation: Some(sim_with_fns),
            owner_privileges: Some(owner_privileges.clone()),
            reputation: Some(reputation),
            abi_source: Some(abi_source.to_string()),
            trend: Some(trend),
            risk_breakdown: Some(risk_breakdown),
            ai_summary: Some(ai_summary.clone()),
            user_anomaly_score: Some(user_anomaly_score),
            rug_pull_probability: Some(rug_pull),
        };
        let details_json = serde_json::to_value(&details).ok();

        let owner_admin_count = 1i32; // from analyzer in real impl

        let row = SenseiguardRepository::create_contract_scan(
            pool,
            contract_address,
            trust_score,
            critical_risk_flags,
            &token_controlled_str,
            owner_admin_count,
            details_json.as_ref(),
            for_address,
        )
        .await?;

        Ok(ScanContractResponse {
            scan_id: row.id,
            contract_address: row.contract_address,
            trust_score: row.trust_score,
            critical_risk_flags: row.critical_risk_flags,
            token_controlled: row.token_controlled,
            owner_admin_count: row.owner_admin_count,
            scanned_at: row.scanned_at,
            details: row.details,
            ai_summary: Some(ai_summary),
        })
    }

    pub async fn get_scan_details(
        pool: &DbPool,
        scan_id: uuid::Uuid,
    ) -> Result<Option<ContractScan>, Error> {
        SenseiguardRepository::get_contract_scan_by_id(pool, scan_id).await
    }
}
