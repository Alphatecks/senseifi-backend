//! Smart Wallet Scanner pipeline: analyzer -> simulation -> reputation -> trend -> ai_explainer -> scoring.

use crate::clients::etherscan;
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
        chain_id: Option<u64>,
    ) -> Result<ScanContractResponse, Error> {
        // 1. Analyzer: single Etherscan fetch → owner privileges, dangerous functions, tokens_controlled, abi_source
        let analysis = AnalyzerService::analyze_contract(contract_address, chain_id).await;
        let owner_privileges = analysis.owner_privileges;
        let dangerous_functions = analysis.dangerous_functions;
        let tokens_controlled = analysis.tokens_controlled.clone();
        let token_controlled_str = if tokens_controlled.is_empty() {
            "Unknown".to_string()
        } else {
            tokens_controlled.join(", ")
        };
        let abi_source = if analysis.abi_from_etherscan { "etherscan" } else { "stub" };

        // 2. Contract creation (for age risk and owner count)
        let creation = etherscan::fetch_contract_creation(contract_address, chain_id).await.ok().flatten();
        let contract_age_risk = creation.as_ref().map(|c| {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age_secs = now_secs.saturating_sub(c.timestamp);
            let age_days = age_secs / 86400;
            if age_days < 7 {
                80u8
            } else if age_days < 30 {
                50
            } else if age_days < 365 {
                30
            } else {
                10
            }
        }).unwrap_or(30);
        let owner_admin_count = creation.as_ref().map(|_| 1i32).unwrap_or(1);

        // 3. Simulation (Alchemy when RPC is Alchemy; else stub)
        let simulation = SimulationService::simulate_contract(
            contract_address,
            &tokens_controlled,
            &dangerous_functions,
            chain_id,
        ).await;
        let sim_with_fns = simulation;

        // 4. Reputation (uses pool for scam_reports)
        let reputation = ReputationService::get_reputation(pool, contract_address).await;

        // 5. Trend from DB
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

        // 6. User-aware anomaly: from DB (how often this wallet scanned this contract)
        let user_anomaly_score = if let Some(wallet) = for_address {
            match SenseiguardRepository::count_scans_for_wallet_contract(pool, wallet, contract_address).await {
                Ok(0) => 0.5,
                Ok(_) => 0.2,
                _ => 0.0,
            }
        } else {
            0.0
        };

        // 7. Token control scope risk: from actual tokens_controlled length
        let token_control_risk = if tokens_controlled.len() >= 2 { 40u8 } else { 20u8 };

        // 8. Scoring
        let (trust_score, risk_breakdown) = ScoringEngine::compute(
            &sim_with_fns,
            &owner_privileges,
            &reputation,
            user_anomaly_score,
            token_control_risk,
            contract_age_risk,
        );
        let rug_pull = ScoringEngine::rug_pull_probability(&owner_privileges);

        // 9. AI summary
        let ai_summary = AiInsightService::explain_risks(
            &sim_with_fns,
            &owner_privileges,
            &reputation,
            &token_controlled_str,
        );

        let critical_risk_flags = [sim_with_fns.drains_full_balance == Some(true), reputation.reported_scam == Some(true)]
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

        let effective_chain_id = chain_id.or_else(|| {
            std::env::var("ETHERSCAN_CHAIN_ID").ok().and_then(|s| s.parse::<u64>().ok())
        });
        let chain_id_db = effective_chain_id.map(|c| c as i64);

        let row = SenseiguardRepository::create_contract_scan(
            pool,
            contract_address,
            trust_score,
            critical_risk_flags,
            &token_controlled_str,
            owner_admin_count,
            details_json.as_ref(),
            for_address,
            chain_id_db,
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
            chain_id: effective_chain_id,
            network: effective_chain_id.map(Self::chain_id_to_network_name),
            details: row.details,
            ai_summary: Some(ai_summary),
        })
    }

    fn chain_id_to_network_name(chain_id: u64) -> String {
        match chain_id {
            1 => "Ethereum Mainnet".to_string(),
            56 => "BNB Smart Chain".to_string(),
            137 => "Polygon".to_string(),
            8453 => "Base".to_string(),
            42161 => "Arbitrum One".to_string(),
            10 => "Optimism".to_string(),
            5 => "Goerli".to_string(),
            11155111 => "Sepolia".to_string(),
            _ => format!("Chain {}", chain_id),
        }
    }

    pub async fn get_scan_details(
        pool: &DbPool,
        scan_id: uuid::Uuid,
    ) -> Result<Option<ContractScan>, Error> {
        SenseiguardRepository::get_contract_scan_by_id(pool, scan_id).await
    }
}
