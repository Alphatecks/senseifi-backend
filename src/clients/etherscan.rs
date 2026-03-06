//! Etherscan API client: ABI and contract source/verification.
//! Uses Etherscan API V2 (https://api.etherscan.io/v2/api) with chainid. Set ETHERSCAN_API_KEY; optional ETHERSCAN_BASE_URL, ETHERSCAN_CHAIN_ID (default 1 = Ethereum).

use serde::Deserialize;

const ETHERSCAN_V2_BASE: &str = "https://api.etherscan.io/v2/api";

fn base_url() -> String {
    let url = std::env::var("ETHERSCAN_BASE_URL").unwrap_or_else(|_| ETHERSCAN_V2_BASE.to_string());
    // If env is set to legacy V1 URL, use V2 so we don't get deprecation errors
    if url.trim_end_matches('/').ends_with("/api") && !url.contains("/v2") {
        tracing::info!("ETHERSCAN_BASE_URL looks like V1 ({}); using V2 endpoint", url);
        return ETHERSCAN_V2_BASE.to_string();
    }
    url
}

fn chain_id() -> String {
    std::env::var("ETHERSCAN_CHAIN_ID").unwrap_or_else(|_| "1".to_string())
}

fn api_key() -> Option<String> {
    std::env::var("ETHERSCAN_API_KEY").ok().filter(|s| !s.is_empty())
}

#[derive(Debug, Deserialize)]
pub struct EtherscanAbiResponse {
    pub status: String,
    pub message: String,
    #[serde(default)]
    pub result: String,
}

/// Lenient wrapper so we can deserialize even when Etherscan returns
/// result as array or single object, or ABI/SourceCode in different shapes.
#[derive(Debug, Deserialize)]
pub struct EtherscanSourceResponse {
    pub status: String,
    pub message: String,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
}

fn first_result_item(result: Option<&serde_json::Value>) -> Option<&serde_json::Value> {
    let r = result?;
    if let Some(arr) = r.as_array() {
        return arr.first();
    }
    if r.is_object() {
        return Some(r);
    }
    None
}

fn string_from_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn source_code_non_empty(v: &serde_json::Value) -> bool {
    let s = string_from_value(v);
    !s.is_empty() && s != "{{}" && !s.eq_ignore_ascii_case("Contract source code not verified")
}

/// Returns (abi_json_string, verified). Uses getabi if API key set; else tries getsourcecode for ABI.
/// request_chain_id: if Some, use for this request; else use ETHERSCAN_CHAIN_ID env or 1.
pub async fn fetch_abi_and_verified(address: &str, request_chain_id: Option<u64>) -> Result<(String, bool), String> {
    let key = api_key();
    let url = base_url();
    if key.is_some() {
        tracing::info!("ETHERSCAN_API_KEY is set; will call Etherscan API");
    } else {
        tracing::warn!("ETHERSCAN_API_KEY is missing or empty; Etherscan calls will not use your key (rate limits / no activity on your key)");
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    // Prefer getabi (returns ABI only). V2 requires chainid.
    let cid = request_chain_id
        .map(|n| n.to_string())
        .unwrap_or_else(chain_id);
    if key.is_some() {
        tracing::info!("Etherscan getabi request for contract {} (chainid={})", address, cid);
        let mut params = vec![
            ("chainid", cid.as_str()),
            ("module", "contract"),
            ("action", "getabi"),
            ("address", address),
        ];
        if let Some(k) = &key {
            params.push(("apikey", k.as_str()));
        }
        let res = client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Etherscan getabi request failed: {}", e);
                e.to_string()
            })?;
        let _status = res.status();
        let body: EtherscanAbiResponse = res.json().await.map_err(|e| e.to_string())?;
        if body.status == "1" && body.result.trim_start().starts_with('[') {
            tracing::info!("Etherscan getabi success: ABI received for {}", address);
            return Ok((body.result, true)); // getabi only returns for verified
        }
        if body.message == "NOTOK" && body.result.contains("Contract source code not verified") {
            tracing::info!("Etherscan: contract {} not verified; using empty ABI (stub data)", address);
            return Ok((String::new(), false));
        }
        // Log why getabi didn't succeed so we can debug NOTOK / wrong chain / rate limit
        let result_preview = body.result.chars().take(200).collect::<String>();
        tracing::warn!("Etherscan getabi did not return ABI for {}: status={} message={} result_preview={:?}", address, body.status, body.message, result_preview);
    }

    // Fallback: getsourcecode (returns ABI + source; verified = SourceCode non-empty). V2 requires chainid.
    let cid2 = request_chain_id
        .map(|n| n.to_string())
        .unwrap_or_else(chain_id);
    tracing::info!("Etherscan getsourcecode request for contract {} (chainid={})", address, cid2);
    let mut params = vec![
        ("chainid", cid2.as_str()),
        ("module", "contract"),
        ("action", "getsourcecode"),
        ("address", address),
    ];
    if let Some(k) = &key {
        params.push(("apikey", k.as_str()));
    }
    let res = client
        .get(&url)
        .query(&params)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Etherscan getsourcecode request failed: {}", e);
            e.to_string()
        })?;
    let body: EtherscanSourceResponse = res.json().await.map_err(|e| {
        tracing::error!("Etherscan getsourcecode decode error: {} (response may have unexpected shape)", e);
        e.to_string()
    })?;
    if body.status != "1" {
        let reason = body.result.as_ref().and_then(|r| {
            r.as_str()
                .map(String::from)
                .or_else(|| r.get("message").and_then(|m| m.as_str()).map(String::from))
                .or_else(|| Some(r.to_string()))
        }).unwrap_or_else(|| body.message.clone());
        tracing::warn!("Etherscan getsourcecode NOTOK for {}: {} (check ETHERSCAN_BASE_URL if this is a non-Ethereum contract)", address, reason);
        return Err(reason);
    }
    let item = first_result_item(body.result.as_ref());
    let abi = item
        .and_then(|i| i.get("ABI"))
        .map(string_from_value)
        .unwrap_or_default();
    let verified = item
        .and_then(|i| i.get("SourceCode"))
        .map(source_code_non_empty)
        .unwrap_or(false);
    Ok((abi, verified))
}

/// Contract creation info from getcontractcreation (block, timestamp, creator).
#[derive(Debug, Clone)]
pub struct ContractCreationInfo {
    pub block_number: u64,
    pub timestamp: u64,
    pub contract_creator: String,
}

#[derive(Debug, Deserialize)]
struct EtherscanContractCreationResponse {
    status: String,
    message: String,
    #[serde(default)]
    result: Option<serde_json::Value>,
}

/// Fetch contract creation block, timestamp, and creator. Uses getcontractcreation (V2 with chainid).
pub async fn fetch_contract_creation(
    address: &str,
    request_chain_id: Option<u64>,
) -> Result<Option<ContractCreationInfo>, String> {
    let cid = request_chain_id
        .map(|n| n.to_string())
        .unwrap_or_else(chain_id);
    let url = base_url();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let params = [
        ("chainid", cid.as_str()),
        ("module", "contract"),
        ("action", "getcontractcreation"),
        ("contractaddresses", address),
    ];
    let mut request = client.get(&url).query(&params);
    if let Some(k) = api_key() {
        request = request.query(&[("apikey", k.as_str())]);
    }
    let res = request.send().await.map_err(|e| e.to_string())?;
    let body: EtherscanContractCreationResponse = res.json().await.map_err(|e| e.to_string())?;
    if body.status != "1" {
        return Ok(None);
    }
    let result = match &body.result {
        Some(serde_json::Value::Array(arr)) => arr.first(),
        _ => None,
    };
    let item = match result {
        Some(serde_json::Value::Object(m)) => m,
        _ => return Ok(None),
    };
    let block_number = item
        .get("blockNumber")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let timestamp = item
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let contract_creator = item
        .get("contractCreator")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if contract_creator.is_empty() && timestamp == 0 {
        return Ok(None);
    }
    Ok(Some(ContractCreationInfo {
        block_number,
        timestamp,
        contract_creator,
    }))
}
