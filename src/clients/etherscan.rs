//! Etherscan API client: ABI and contract source/verification.
//! Set ETHERSCAN_API_KEY and optionally ETHERSCAN_BASE_URL (default: https://api.etherscan.io/api).

use serde::Deserialize;

fn base_url() -> String {
    std::env::var("ETHERSCAN_BASE_URL").unwrap_or_else(|_| "https://api.etherscan.io/api".to_string())
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

#[derive(Debug, Deserialize)]
pub struct SourceCodeItem {
    #[serde(rename = "ABI")]
    pub abi: Option<String>,
    #[serde(rename = "ContractName")]
    pub contract_name: Option<String>,
    #[serde(rename = "SourceCode")]
    pub source_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EtherscanSourceResponse {
    pub status: String,
    pub message: String,
    pub result: Option<Vec<SourceCodeItem>>,
}

/// Returns (abi_json_string, verified). Uses getabi if API key set; else tries getsourcecode for ABI.
pub async fn fetch_abi_and_verified(address: &str) -> Result<(String, bool), String> {
    let key = api_key();
    let url = base_url();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    // Prefer getabi (returns ABI only)
    if key.is_some() {
        let mut params = vec![
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
            .map_err(|e| e.to_string())?;
        let _status = res.status();
        let body: EtherscanAbiResponse = res.json().await.map_err(|e| e.to_string())?;
        if body.status == "1" && body.result.trim_start().starts_with('[') {
            return Ok((body.result, true)); // getabi only returns for verified
        }
        if body.message == "NOTOK" && body.result.contains("Contract source code not verified") {
            return Ok((String::new(), false));
        }
    }

    // Fallback: getsourcecode (returns ABI + source; verified = SourceCode non-empty)
    let mut params = vec![
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
        .map_err(|e| e.to_string())?;
    let body: EtherscanSourceResponse = res.json().await.map_err(|e| e.to_string())?;
    if body.status != "1" {
        return Err(body.message);
    }
    let verified = body
        .result
        .as_ref()
        .and_then(|r| r.first())
        .map(|i| {
            i.source_code
                .as_ref()
                .map(|s| !s.is_empty() && s != "{{}")
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let abi = body
        .result
        .as_ref()
        .and_then(|r| r.first())
        .and_then(|i| i.abi.as_ref())
        .cloned()
        .unwrap_or_default();
    Ok((abi, verified))
}
