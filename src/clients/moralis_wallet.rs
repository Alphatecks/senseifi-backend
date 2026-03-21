//! Moralis Web3 Data API: wallet ERC-20 token balances (aggregated per chain).

use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;

const DEFAULT_BASE: &str = "https://deep-index.moralis.io";

/// Map EVM `chain_id` to Moralis `chain` query parameter.
pub fn moralis_chain_slug(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("eth"),
        11155111 => Some("sepolia"),
        56 => Some("bsc"),
        137 => Some("polygon"),
        8453 => Some("base"),
        42161 => Some("arbitrum"),
        10 => Some("optimism"),
        324 => Some("zksync"),
        59144 => Some("linea"),
        534352 => Some("scroll"),
        43114 => Some("avalanche"),
        250 => Some("fantom"),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoralisErc20Item {
    #[serde(default)]
    pub token_address: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub decimals: Option<u8>,
    /// Integer string (wei-like units for the token).
    #[serde(default)]
    pub balance: Option<String>,
    #[serde(default)]
    pub balance_formatted: Option<String>,
    #[serde(default)]
    pub usd_value: Option<f64>,
    #[serde(default)]
    pub possible_spam: Option<bool>,
}

/// Normalized row for DB upsert.
#[derive(Debug, Clone)]
pub struct IndexedTokenBalance {
    pub contract_address: String,
    pub symbol: String,
    pub name: String,
    pub balance_display: String,
    pub usd_value: f64,
}

fn moralis_api_key() -> Option<String> {
    std::env::var("MORALIS_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn moralis_base_url() -> String {
    std::env::var("MORALIS_API_BASE_URL")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE.to_string())
}

fn parse_moralis_token_list(body: &str) -> Result<Vec<MoralisErc20Item>, String> {
    if let Ok(v) = serde_json::from_str::<Vec<MoralisErc20Item>>(body) {
        return Ok(v);
    }
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(default)]
        result: Vec<MoralisErc20Item>,
    }
    if let Ok(env) = serde_json::from_str::<Envelope>(body) {
        return Ok(env.result);
    }
    #[derive(Deserialize)]
    struct DataWrap {
        #[serde(default)]
        data: Vec<MoralisErc20Item>,
    }
    serde_json::from_str::<DataWrap>(body)
        .map(|w| w.data)
        .map_err(|e| format!("Moralis JSON parse error: {e}"))
}

fn clamp_utf8(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

fn format_balance_from_raw(raw: &str, decimals: u8) -> String {
    let raw = raw.trim();
    if raw.is_empty() || raw == "0" {
        return "0".to_string();
    }
    let n = match BigUint::from_str_radix(raw, 10) {
        Ok(v) => v,
        Err(_) => return raw.to_string(),
    };
    let pow = BigUint::from(10u32).pow(decimals as u32);
    let int_part = &n / &pow;
    let frac = &n % &pow;
    if decimals == 0 {
        return int_part.to_string();
    }
    let mut frac_s = frac.to_string();
    while frac_s.len() < decimals as usize {
        frac_s.insert(0, '0');
    }
    // Trim trailing zeros for display
    while frac_s.ends_with('0') {
        frac_s.pop();
    }
    if frac_s.is_empty() {
        int_part.to_string()
    } else {
        format!("{int_part}.{frac_s}")
    }
}

/// Fetch non-zero token balances for `address` on `chain_id`. Returns error string on HTTP/parse failures.
pub async fn fetch_wallet_tokens(
    wallet_address: &str,
    chain_id: u64,
) -> Result<Vec<IndexedTokenBalance>, String> {
    let key = moralis_api_key().ok_or_else(|| "MORALIS_API_KEY is not set".to_string())?;
    let slug = moralis_chain_slug(chain_id).ok_or_else(|| {
        format!("chain_id {chain_id} is not mapped for Moralis token sync")
    })?;
    let base = moralis_base_url();
    let addr = wallet_address.trim();
    let url = format!(
        "{base}/api/v2.2/wallets/{addr}/tokens?chain={slug}&exclude_spam=true&exclude_unverified_contracts=false"
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let res = client
        .get(&url)
        .header("X-API-Key", key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = res.status();
    let body = res.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("Moralis HTTP {status}: {}", body.chars().take(200).collect::<String>()));
    }

    let items = parse_moralis_token_list(&body)?;

    let mut out = Vec::new();
    for it in items {
        if it.possible_spam == Some(true) {
            continue;
        }
        let Some(contract) = it
            .token_address
            .as_ref()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| s.starts_with("0x") && s.len() == 42)
        else {
            continue;
        };
        let raw_bal = it.balance.as_deref().unwrap_or("0").trim();
        if raw_bal == "0" || raw_bal.is_empty() {
            continue;
        }
        let decimals = it.decimals.unwrap_or(18).min(36);
        let balance_display = if let Some(ref f) = it.balance_formatted {
            let t = f.trim();
            if !t.is_empty() && t != "0" {
                t.to_string()
            } else {
                format_balance_from_raw(raw_bal, decimals)
            }
        } else {
            format_balance_from_raw(raw_bal, decimals)
        };
        if balance_display == "0" || balance_display == "0.0" {
            continue;
        }
        let symbol = clamp_utf8(
            it.symbol
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("???"),
            20,
        );
        let name = clamp_utf8(
            it.name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&symbol),
            100,
        );
        let usd_value = it.usd_value.unwrap_or(0.0).max(0.0);
        out.push(IndexedTokenBalance {
            contract_address: contract,
            symbol,
            name,
            balance_display,
            usd_value,
        });
    }
    Ok(out)
}

pub fn has_moralis_config() -> bool {
    moralis_api_key().is_some()
}
