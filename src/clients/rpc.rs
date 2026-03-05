//! Ethereum JSON-RPC client: bytecode via eth_getCode.
//! Set ETHEREUM_RPC_URL (e.g. https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY or Infura/QuickNode).

use serde::Deserialize;
use serde_json::json;

fn rpc_url() -> Option<String> {
    std::env::var("ETHEREUM_RPC_URL").ok().filter(|s| !s.is_empty())
}

/// Returns runtime bytecode (hex with 0x prefix) as bytes. Strips 0x and decodes.
pub async fn fetch_bytecode(address: &str) -> Result<Vec<u8>, String> {
    let url = rpc_url().ok_or_else(|| "ETHEREUM_RPC_URL not set".to_string())?;
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

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: String,
}
