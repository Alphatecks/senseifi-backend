//! Reputation & network intelligence: GoPlus, Chainabuse, ScamSniffer, Etherscan verified, etc.

use crate::db::DbPool;
use crate::models::senseiguard::ReputationInfo;
use crate::repositories::senseiguard_repository::SenseiguardRepository;

pub struct ReputationService;

impl ReputationService {
    /// Aggregate reputation from external APIs and our scam_reports.
    /// Stub: uses only local scam_reports count; add GoPlus/Chainabuse/TokenSniffer later.
    pub async fn get_reputation(
        pool: &DbPool,
        contract_address: &str,
    ) -> ReputationInfo {
        let community_flags = SenseiguardRepository::count_scam_reports(pool, contract_address)
            .await
            .unwrap_or(0) as u32;
        ReputationInfo {
            reported_scam: Some(community_flags > 0),
            community_flags: Some(community_flags),
            verified_source: Some(false), // Etherscan verified: integrate later
        }
    }
}
