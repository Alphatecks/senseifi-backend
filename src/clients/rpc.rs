//! JSON-RPC client: bytecode via eth_getCode. Supports multiple chains via env (ETHEREUM_RPC_URL, BSC_RPC_URL, etc.).

use serde::Deserialize;
use serde_json::json;

/// RPC URL for a chain. request_chain_id None or 1 => ETHEREUM_RPC_URL; 56 => BSC_RPC_URL; 137 => POLYGON_RPC_URL; etc.
pub fn rpc_url_for_chain(request_chain_id: Option<u64>) -> Option<String> {
    let cid = request_chain_id.unwrap_or(1);
    let url = match cid {
        1 => std::env::var("ETHEREUM_RPC_URL").ok(),
        56 => std::env::var("BSC_RPC_URL").ok(),
        137 => std::env::var("POLYGON_RPC_URL").ok(),
        8453 => std::env::var("BASE_RPC_URL").ok(),
        42161 => std::env::var("ARBITRUM_RPC_URL").ok(),
        _ => std::env::var("ETHEREUM_RPC_URL").ok(),
    };
    let url = url.filter(|s| !s.is_empty());
    if url.is_none() && cid != 1 {
        std::env::var("ETHEREUM_RPC_URL").ok().filter(|s| !s.is_empty())
    } else {
        url
    }
}

/// Returns runtime bytecode (hex with 0x prefix) as bytes. Strips 0x and decodes.
/// request_chain_id: if Some, use that chain's RPC (BSC_RPC_URL for 56, etc.); else use ETHEREUM_RPC_URL.
pub async fn fetch_bytecode(address: &str, request_chain_id: Option<u64>) -> Result<Vec<u8>, String> {
    let url = rpc_url_for_chain(request_chain_id).ok_or_else(|| "No RPC URL set for this chain (set ETHEREUM_RPC_URL, or BSC_RPC_URL for chain 56, etc.)".to_string())?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getCode",
        "params": [address, "latest"]
    });
    let res = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let out: RpcResponse = res.json().await.map_err(|e| e.to_string())?;
    let hex_str = out.result.strip_prefix("0x").unwrap_or(&out.result);
    if hex_str.is_empty() || hex_str == "0x" {
        return Ok(Vec::new());
    }
    hex::decode(hex_str).map_err(|e| e.to_string())
}

/// Native balance in wei (hex with 0x). request_chain_id: chain for RPC (1 = Ethereum, etc.).
pub async fn fetch_balance_wei(
    address: &str,
    request_chain_id: Option<u64>,
) -> Result<String, String> {
    let url = rpc_url_for_chain(request_chain_id)
        .ok_or_else(|| "No RPC URL set for this chain".to_string())?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [address, "latest"]
    });
    let res = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let out: RpcResponse = res.json().await.map_err(|e| e.to_string())?;
    Ok(out.result)
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: String,
}
