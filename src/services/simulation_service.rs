//! Pre-execution simulation: Alchemy alchemy_simulateAssetChanges when RPC is Alchemy; else stub.
//! Extracts: drains_full_balance, hidden_internal_calls, approval_scope (from ABI/dangerous_functions).

use crate::clients::{alchemy_simulate, rpc};
use crate::models::senseiguard::SimulationResult;

pub struct SimulationService;

impl SimulationService {
    /// Simulate a call to the contract. When RPC URL is Alchemy, uses alchemy_simulateAssetChanges for real data.
    /// dangerous_functions: from analyzer; used to set approval_scope (unlimited if approve/setApprovalForAll present).
    pub async fn simulate_contract(
        contract_address: &str,
        _tokens_controlled: &[String],
        dangerous_functions: &[String],
        chain_id: Option<u64>,
    ) -> SimulationResult {
        let rpc_url = match rpc::rpc_url_for_chain(chain_id) {
            Some(u) => u,
            None => {
                return Self::stub_result(dangerous_functions);
            }
        };
        match alchemy_simulate::simulate_contract_call(&rpc_url, contract_address).await {
            Ok(sim) => {
                let approval_scope = Self::approval_scope_from_dangerous(dangerous_functions);
                SimulationResult {
                    drains_full_balance: Some(sim.drains_full_balance),
                    hidden_internal_calls: Some(sim.hidden_internal_calls),
                    approval_scope: Some(approval_scope),
                    dangerous_functions: Some(dangerous_functions.to_vec()),
                }
            }
            Err(_) => Self::stub_result(dangerous_functions),
        }
    }

    fn approval_scope_from_dangerous(dangerous_functions: &[String]) -> String {
        let has_unlimited = dangerous_functions.iter().any(|s| {
            let l = s.to_lowercase();
            l.contains("setapprovalforall") || l.contains("approve")
        });
        if has_unlimited {
            "unlimited".to_string()
        } else {
            "limited".to_string()
        }
    }

    fn stub_result(dangerous_functions: &[String]) -> SimulationResult {
        let approval_scope = Self::approval_scope_from_dangerous(dangerous_functions);
        SimulationResult {
            drains_full_balance: Some(true),
            hidden_internal_calls: Some(3),
            approval_scope: Some(approval_scope),
            dangerous_functions: Some(dangerous_functions.to_vec()),
        }
    }
}
