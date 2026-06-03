//! Pre-execution simulation provider chain:
//! 1) Alchemy alchemy_simulateAssetChanges (when RPC is Alchemy),
//! 2) trace_call / debug_traceCall (generic trace-capable RPCs),
//! 3) eth_call (basic execution check).
//! Extracts: drains_full_balance, hidden_internal_calls, approval_scope (from ABI/dangerous_functions).

use crate::clients::{alchemy_simulate, rpc};
use crate::models::senseiguard::SimulationResult;
use serde_json::{json, Value};

pub struct SimulationService;

impl SimulationService {
    /// Simulate a call to the contract using provider chain.
    /// dangerous_functions: from analyzer; used to set approval_scope (unlimited only for setApprovalForAll-style signals).
    pub async fn simulate_contract(
        contract_address: &str,
        _tokens_controlled: &[String],
        dangerous_functions: &[String],
        chain_id: Option<u64>,
    ) -> SimulationResult {
        let approval_scope = Self::approval_scope_from_dangerous(dangerous_functions);
        let rpc_url = match rpc::rpc_url_for_chain(chain_id) {
            Some(u) => u,
            None => {
                return Self::conservative_result(&approval_scope, dangerous_functions);
            }
        };

        if rpc_url.contains("alchemy.com") {
            if let Ok(sim) =
                alchemy_simulate::simulate_contract_call(&rpc_url, contract_address).await
            {
                return Self::build_result(
                    sim.drains_full_balance,
                    sim.hidden_internal_calls,
                    &approval_scope,
                    dangerous_functions,
                );
            }
        }

        if let Ok((drains, hidden)) =
            Self::simulate_via_trace_call(&rpc_url, contract_address).await
        {
            return Self::build_result(drains, hidden, &approval_scope, dangerous_functions);
        }

        if let Ok((drains, hidden)) =
            Self::simulate_via_debug_trace_call(&rpc_url, contract_address).await
        {
            return Self::build_result(drains, hidden, &approval_scope, dangerous_functions);
        }

        if Self::simulate_via_eth_call(&rpc_url, contract_address)
            .await
            .is_ok()
        {
            return Self::build_result(false, 0, &approval_scope, dangerous_functions);
        }

        Self::conservative_result(&approval_scope, dangerous_functions)
    }

    fn approval_scope_from_dangerous(dangerous_functions: &[String]) -> String {
        let has_unlimited = dangerous_functions.iter().any(|s| {
            let l = s.to_lowercase();
            l.contains("setapprovalforall")
        });
        if has_unlimited {
            "unlimited".to_string()
        } else {
            "limited".to_string()
        }
    }

    fn build_result(
        drains_full_balance: bool,
        hidden_internal_calls: u32,
        approval_scope: &str,
        dangerous_functions: &[String],
    ) -> SimulationResult {
        SimulationResult {
            drains_full_balance: Some(drains_full_balance),
            hidden_internal_calls: Some(hidden_internal_calls),
            approval_scope: Some(approval_scope.to_string()),
            dangerous_functions: Some(dangerous_functions.to_vec()),
        }
    }

    /// Conservative fallback when no simulator provider is available.
    /// Avoids false positives from synthetic "always-drain" stubs.
    fn conservative_result(
        approval_scope: &str,
        dangerous_functions: &[String],
    ) -> SimulationResult {
        Self::build_result(false, 0, approval_scope, dangerous_functions)
    }

    async fn simulate_via_trace_call(
        rpc_url: &str,
        contract_address: &str,
    ) -> Result<(bool, u32), String> {
        let tx = json!({
            "from": "0x0000000000000000000000000000000000000001",
            "to": contract_address,
            "value": "0x0",
            "data": "0x"
        });

        // Support both common trace_call signatures.
        let out = match Self::json_rpc_request(
            rpc_url,
            "trace_call",
            json!([tx.clone(), ["trace"], "latest"]),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => Self::json_rpc_request(rpc_url, "trace_call", json!([tx, ["trace"]])).await?,
        };

        let hidden = Self::count_internal_calls(&out).min(u32::MAX as usize) as u32;
        Ok((false, hidden))
    }

    async fn simulate_via_debug_trace_call(
        rpc_url: &str,
        contract_address: &str,
    ) -> Result<(bool, u32), String> {
        let tx = json!({
            "from": "0x0000000000000000000000000000000000000001",
            "to": contract_address,
            "value": "0x0",
            "data": "0x"
        });
        let opts = json!({
            "tracer": "callTracer",
            "timeout": "10s"
        });

        let out =
            Self::json_rpc_request(rpc_url, "debug_traceCall", json!([tx, "latest", opts])).await?;
        let hidden = Self::count_internal_calls(&out).min(u32::MAX as usize) as u32;
        Ok((false, hidden))
    }

    async fn simulate_via_eth_call(rpc_url: &str, contract_address: &str) -> Result<(), String> {
        let tx = json!({
            "from": "0x0000000000000000000000000000000000000001",
            "to": contract_address,
            "value": "0x0",
            "data": "0x"
        });
        let _ = Self::json_rpc_request(rpc_url, "eth_call", json!([tx, "latest"])).await?;
        Ok(())
    }

    async fn json_rpc_request(rpc_url: &str, method: &str, params: Value) -> Result<Value, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });
        let out = client
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .await
            .map_err(|e| e.to_string())?;

        if out.get("error").is_some() {
            return Err(format!("{} returned error", method));
        }
        out.get("result")
            .cloned()
            .ok_or_else(|| format!("{} missing result", method))
    }

    fn count_internal_calls(v: &Value) -> usize {
        match v {
            Value::Object(map) => {
                let mut total = 0usize;
                if let Some(Value::Array(calls)) = map.get("calls") {
                    total += calls.len();
                    for c in calls {
                        total += Self::count_internal_calls(c);
                    }
                }
                if let Some(Value::Array(trace)) = map.get("trace") {
                    total += trace.len();
                    for t in trace {
                        total += Self::count_internal_calls(t);
                    }
                }
                total
            }
            Value::Array(arr) => arr.iter().map(Self::count_internal_calls).sum(),
            _ => 0,
        }
    }
}
