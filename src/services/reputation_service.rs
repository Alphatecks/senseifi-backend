//! Reputation & network intelligence: GoPlus, Chainabuse, ScamSniffer, Etherscan verified, etc.

use crate::clients::external_reputation;
use crate::db::DbPool;
use crate::models::senseiguard::ReputationInfo;
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use sqlx::Row;

pub struct ReputationService;

#[derive(Debug, Clone, Default)]
pub struct ReputationGraphResult {
    pub risk_score: i32,
    pub hard_stop: bool,
    pub has_sufficient_links: bool,
    pub summary: String,
}

impl ReputationService {
    /// Aggregate reputation from external APIs and local scam reports.
    /// Sources:
    /// - Local `scam_reports` table
    /// - GoPlus token security (when reachable)
    /// - Optional URL-template feeds via env:
    ///   - CHAINABUSE_ADDRESS_URL_TEMPLATE
    ///   - SCAMSNIFFER_ADDRESS_URL_TEMPLATE
    pub async fn get_reputation(
        pool: &DbPool,
        contract_address: &str,
        chain_id: Option<u64>,
    ) -> ReputationInfo {
        let local_flags = SenseiguardRepository::count_scam_reports(pool, contract_address)
            .await
            .unwrap_or(0) as u32;
        let ext = external_reputation::fetch_combined_signals(contract_address, chain_id).await;
        let community_flags = local_flags.saturating_add(ext.community_flags);
        // Require multiple local reports before hard "reported_scam" to reduce one-off false positives.
        let reported_scam = local_flags >= 3 || ext.reported_scam;
        let verified_source = ext.verified_source.or(Some(false));

        ReputationInfo {
            reported_scam: Some(reported_scam),
            community_flags: Some(community_flags),
            verified_source,
            local_report_count: Some(local_flags),
            informational_flags: Some(ext.informational_flags),
        }
    }

    /// Lightweight graph intelligence using existing DB edges:
    /// - contract <-> scam reports
    /// - wallet/activity metadata references to destination contract
    pub async fn analyze_reputation_graph(
        pool: &DbPool,
        contract_address: Option<&str>,
        wallet_address: Option<&str>,
    ) -> ReputationGraphResult {
        let Some(contract) = contract_address else {
            return ReputationGraphResult {
                risk_score: 10,
                hard_stop: false,
                has_sufficient_links: false,
                summary: "No destination contract provided for graph analysis.".to_string(),
            };
        };

        let scam_reports = SenseiguardRepository::count_scam_reports(pool, contract)
            .await
            .unwrap_or(0);
        let trust_score = SenseiguardRepository::get_latest_trust_score(pool, contract)
            .await
            .ok()
            .flatten();

        // Approximate graph linkage count from metadata references in activity feed.
        let metadata_refs = sqlx::query(
            r#"
            SELECT COUNT(*)::bigint AS cnt
            FROM activity_feed af
            WHERE LOWER(COALESCE(af.metadata->>'to', '')) = LOWER($1)
               OR LOWER(COALESCE(af.metadata->>'spender', '')) = LOWER($1)
               OR LOWER(COALESCE(af.metadata->>'contract_address', '')) = LOWER($1)
            "#,
        )
        .bind(contract)
        .fetch_one(pool)
        .await
        .ok()
        .and_then(|row| row.try_get::<i64, _>("cnt").ok())
        .unwrap_or(0);

        // Wallet adjacency score: whether this wallet previously touched suspicious activity.
        let wallet_adjacent_risk = if let Some(wallet) = wallet_address {
            sqlx::query(
                r#"
                SELECT COUNT(*)::bigint AS cnt
                FROM activity_feed af
                JOIN wallets w ON w.id = af.wallet_id
                WHERE LOWER(w.address) = LOWER($1)
                  AND af.activity_type IN ('suspicious_approval', 'blocked_interaction')
                "#,
            )
            .bind(wallet)
            .fetch_one(pool)
            .await
            .ok()
            .and_then(|row| row.try_get::<i64, _>("cnt").ok())
            .map(|count| (count as i32 * 3).min(15))
            .unwrap_or(0)
        } else {
            0
        };

        let mut risk = 0i32;
        risk += (scam_reports as i32 * 18).min(54);
        risk += wallet_adjacent_risk;
        risk += if metadata_refs >= 20 {
            20
        } else if metadata_refs >= 5 {
            10
        } else {
            0
        };
        if let Some(ts) = trust_score {
            if ts <= 20 {
                risk += 25;
            } else if ts <= 40 {
                risk += 15;
            }
        }
        risk = risk.clamp(0, 100);

        let hard_stop = scam_reports >= 3 || risk >= 85;
        let summary = if hard_stop {
            "Reputation graph shows strong linkage to malicious clusters.".to_string()
        } else if risk >= 45 {
            "Reputation graph indicates meaningful scam-adjacent exposure.".to_string()
        } else {
            "Reputation graph does not show critical malicious adjacency.".to_string()
        };

        ReputationGraphResult {
            risk_score: risk,
            hard_stop,
            has_sufficient_links: metadata_refs >= 3 || scam_reports > 0 || trust_score.is_some(),
            summary,
        }
    }
}
