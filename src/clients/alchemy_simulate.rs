//! Alchemy transaction simulation: alchemy_simulateAssetChanges.
//! Use the same RPC URL as eth_getCode (ETHEREUM_RPC_URL etc.); only Alchemy URLs support this method.

use serde::Deserialize;
use serde_json::json;

/// Result of simulating a call to the contract: can it receive assets (drain risk), and how many asset changes.
pub struct SimulateResult {
    pub drains_full_balance: bool,
    pub hidden_internal_calls: u32,
}

#[derive(Debug, Deserialize)]
struct AssetChange {
    #[serde(rename = "changeType")]
    change_type: Option<String>,
    #[serde(rename = "to")]
    to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SimulateResponseResult {
    changes: Option<Vec<AssetChange>>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SimulateResponse {
    result: Option<SimulateResponseResult>,
    error: Option<serde_json::Value>,
}

/// Simulate a zero-value call to the contract. Returns whether the contract receives assets (drain risk) and number of asset changes.
/// Only works when rpc_url is an Alchemy endpoint (e.g. https://eth-mainnet.g.alchemy.com/v2/...).
pub async fn simulate_contract_call(
    rpc_url: &str,
    contract_address: &str,
) -> Result<SimulateResult, String> {
    if !rpc_url.contains("alchemy.com") {
        return Err("Not an Alchemy RPC URL".to_string());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let tx = json!({
        "from": "0x0000000000000000000000000000000000000001",
        "to": contract_address,
        "value": "0x0"
    });
    let body = json!({
        "jsonrpc": "2.0",
        "method": "alchemy_simulateAssetChanges",
        "id": 1,
        "params": [tx]
    });

    let res = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let out: SimulateResponse = res.json().await.map_err(|e| e.to_string())?;
    if out.error.is_some() {
        return Err("Alchemy simulation returned error".to_string());
    }
    let result = out.result.ok_or("No result")?;
    if result.error.is_some() {
        return Err("Simulation error".to_string());
    }
    let changes = result.changes.unwrap_or_default();
    let contract_lower = contract_address.to_lowercase();
    let drains = changes.iter().any(|c| {
        c.change_type.as_deref() == Some("TRANSFER")
            && c.to.as_ref().map(|t| t.to_lowercase()) == Some(contract_lower.clone())
    });
    let count = changes.len().min(u32::MAX as usize) as u32;
    Ok(SimulateResult {
        drains_full_balance: drains,
        hidden_internal_calls: count,
    })
}
