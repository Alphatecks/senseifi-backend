//! AI explanation engine: turn technical details into human-readable risk narrative.

use crate::models::senseiguard::{OwnerPrivileges, ReputationInfo, SimulationResult};

pub struct AiInsightService;

impl AiInsightService {
    /// Generate plain-language summary of risks. Stub: template from details.
    /// Real: send details to LLM with prompt "Explain the security risks for a beginner."
    pub fn explain_risks(
        simulation: &SimulationResult,
        owner_privileges: &OwnerPrivileges,
        reputation: &ReputationInfo,
        token_controlled: &str,
    ) -> String {
        let mut parts = Vec::new();
        if simulation.drains_full_balance == Some(true) {
            parts.push(format!(
                "This contract can transfer 100% of your {} if you approve it.",
                if token_controlled.is_empty() { "tokens" } else { token_controlled }
            ));
        }
        if simulation.hidden_internal_calls.unwrap_or(0) > 0 {
            parts.push("It uses hidden internal calls that can change your allowances or move funds.".to_string());
        }
        if owner_privileges.mint == Some(true) || owner_privileges.withdraw_liquidity == Some(true) {
            parts.push("The owner can mint tokens or withdraw liquidity, which can lead to a rug pull.".to_string());
        }
        if reputation.reported_scam == Some(true) {
            parts.push("This contract has been reported as a scam by the community.".to_string());
        }
        if parts.is_empty() {
            return "No major risks identified from the current analysis. Always verify contract source and approvals.".to_string();
        }
        parts.join(" ")
    }
}
