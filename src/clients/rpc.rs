//! JSON-RPC client: bytecode via eth_getCode, balance via eth_getBalance.
//! Per-chain URLs from env; see README / DEPLOYMENT.md. No silent L1 fallback for L2 chain IDs.

use serde::Deserialize;
use serde_json::{json, Value};

/// RPC URL for a chain. Set the env var for each chain you use; optional `RPC_URL_{chain_id}` for others.
/// Does **not** fall back to Ethereum mainnet RPC for L2/other chains (avoids wrong-chain zero balances).
pub fn rpc_url_for_chain(request_chain_id: Option<u64>) -> Option<String> {
    let cid = request_chain_id.unwrap_or(1);
    let from_env = |key: &str| std::env::var(key).ok().filter(|s| !s.is_empty());

    let url = match cid {
        1 => from_env("ETHEREUM_RPC_URL"),
        56 => from_env("BSC_RPC_URL"),
        137 => from_env("POLYGON_RPC_URL"),
        8453 => from_env("BASE_RPC_URL"),
        42161 => from_env("ARBITRUM_RPC_URL"),
        10 => from_env("OPTIMISM_RPC_URL"),
        324 => from_env("ZKSYNC_ERA_RPC_URL").or_else(|| from_env("ZKSYNC_RPC_URL")),
        59144 => from_env("LINEA_RPC_URL"),
        534352 => from_env("SCROLL_RPC_URL"),
        43114 => from_env("AVALANCHE_RPC_URL"),
        250 => from_env("FANTOM_RPC_URL"),
        _ => None,
    };

    if url.is_some() {
        return url;
    }

    // Long-tail: RPC_URL_10, RPC_URL_8453, etc.
    from_env(&format!("RPC_URL_{}", cid))
}

#[derive(Debug, Deserialize)]
struct JsonRpcErrorObj {
    code: Option<i64>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    result: Option<Value>,
    error: Option<JsonRpcErrorObj>,
}

fn parse_jsonrpc_string_result(body: &str) -> Result<String, String> {
    let env: JsonRpcEnvelope = serde_json::from_str(body).map_err(|e| e.to_string())?;
    if let Some(err) = env.error {
        let code = err.code.unwrap_or(0);
        let msg = err.message.unwrap_or_else(|| "unknown".to_string());
        tracing::warn!(code, %msg, "JSON-RPC error response");
        return Err(format!("RPC error {}: {}", code, msg));
    }
    let Some(result) = env.result else {
        return Err("JSON-RPC missing result".to_string());
    };
    match result {
        Value::String(s) => Ok(s),
        Value::Null => Ok("0x0".to_string()),
        _ => Err("JSON-RPC result is not a string".to_string()),
    }
}

/// Returns runtime bytecode (hex with 0x prefix) as bytes.
pub async fn fetch_bytecode(address: &str, request_chain_id: Option<u64>) -> Result<Vec<u8>, String> {
    let url = rpc_url_for_chain(request_chain_id).ok_or_else(|| {
        let cid = request_chain_id.unwrap_or(1);
        rpc_missing_msg(cid)
    })?;
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
    let text = res.text().await.map_err(|e| e.to_string())?;
    let hex_str = parse_jsonrpc_string_result(&text)?;
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
    if hex_str.is_empty() || hex_str == "0x" {
        return Ok(Vec::new());
    }
    hex::decode(hex_str).map_err(|e| e.to_string())
}

/// Native balance in wei (hex with 0x).
pub async fn fetch_balance_wei(
    address: &str,
    request_chain_id: Option<u64>,
) -> Result<String, String> {
    let cid = request_chain_id.unwrap_or(1);
    let url = rpc_url_for_chain(request_chain_id).ok_or_else(|| rpc_missing_msg(cid))?;
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
    let text = res.text().await.map_err(|e| e.to_string())?;
    parse_jsonrpc_string_result(&text)
}

fn rpc_missing_msg(chain_id: u64) -> String {
    format!(
        "No RPC URL for chain_id {}. Set the matching env (e.g. OPTIMISM_RPC_URL for 10, BASE_RPC_URL for 8453) or RPC_URL_{}.",
        chain_id, chain_id
    )
}

/// Convert `eth_getBalance` hex wei to native token units as f64 (18 decimals). Uses `u128`; overflow → 0.0.
pub fn wei_hex_to_eth_f64(hex_wei: &str) -> f64 {
    let s = hex_wei.strip_prefix("0x").unwrap_or(hex_wei);
    if s.is_empty() {
        return 0.0;
    }
    let wei = u128::from_str_radix(s, 16).unwrap_or(0);
    wei as f64 / 1e18
}
