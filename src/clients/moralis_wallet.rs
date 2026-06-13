//! Moralis Web3 Data API: wallet ERC-20 token balances (aggregated per chain).
//!
//! Moralis `GET /api/v2.2/wallets/{address}/tokens` returns **snake_case** JSON and accepts `chain`
//! as a documented enum string or **hex** (e.g. `0x38` for BSC). zkSync (324), Scroll (534352), and
//! Fantom (250) are not in the wallet token balances chain list — we skip them (native FTM still
//! comes from RPC in `multi_chain_native_aggregate`).

use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;

const DEFAULT_BASE: &str = "https://deep-index.moralis.io";

/// Moralis-supported chains for wallet token balances (hex matches their enum).
/// See: https://docs.moralis.com/data-api/evm/wallet/token-balances
pub fn moralis_chain_param(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("0x1"),
        11155111 => Some("0xaa36a7"),
        56 => Some("0x38"),
        137 => Some("0x89"),
        43114 => Some("0xa86a"),
        42161 => Some("0xa4b1"),
        8453 => Some("0x2105"),
        10 => Some("0xa"),
        59144 => Some("0xe708"),
        _ => None,
    }
}

/// Backwards-compatible name for callers that checked slug mapping.
#[inline]
pub fn moralis_chain_slug(chain_id: u64) -> Option<&'static str> {
    moralis_chain_param(chain_id)
}

#[derive(Debug, Deserialize)]
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
    /// When true, this row is the chain gas token — excluded; native USD comes from RPC in `multi_chain_native_aggregate`.
    #[serde(default)]
    pub native_token: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct MoralisTokenPage {
    #[serde(default)]
    result: Vec<MoralisErc20Item>,
    #[serde(default)]
    cursor: Option<String>,
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

fn parse_moralis_page(body: &str) -> Result<MoralisTokenPage, String> {
    if let Ok(page) = serde_json::from_str::<MoralisTokenPage>(body) {
        return Ok(page);
    }
    if let Ok(v) = serde_json::from_str::<Vec<MoralisErc20Item>>(body) {
        return Ok(MoralisTokenPage {
            result: v,
            cursor: None,
        });
    }
    #[derive(Deserialize)]
    struct DataWrap {
        #[serde(default)]
        data: Vec<MoralisErc20Item>,
    }
    serde_json::from_str::<DataWrap>(body)
        .map(|w| MoralisTokenPage {
            result: w.data,
            cursor: None,
        })
        .map_err(|e| format!("Moralis JSON parse error: {e}"))
}

fn moralis_exclude_spam() -> bool {
    std::env::var("MORALIS_EXCLUDE_SPAM")
        .ok()
        .map(|s| matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
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
    let chain = moralis_chain_param(chain_id).ok_or_else(|| {
        format!(
            "chain_id {chain_id} is not supported by Moralis wallet token API (e.g. zkSync 324 and Scroll 534352)"
        )
    })?;
    let base = moralis_base_url();
    let addr = wallet_address.trim();
    let exclude_spam = moralis_exclude_spam();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;

    let mut items: Vec<MoralisErc20Item> = Vec::new();
    let mut cursor: Option<String> = None;
    const MAX_PAGES: u32 = 50;
    let mut pages: u32 = 0;
    loop {
        pages += 1;
        if pages > MAX_PAGES {
            break;
        }
        let mut req = client
            .get(format!("{base}/api/v2.2/wallets/{addr}/tokens"))
            .header("X-API-Key", &key)
            .header("Accept", "application/json")
            .query(&[
                ("chain", chain),
                ("exclude_unverified_contracts", "false"),
                ("exclude_native", "true"),
                ("limit", "100"),
            ])
            .query(&[("exclude_spam", if exclude_spam { "true" } else { "false" })]);
        if let Some(ref c) = cursor {
            if !c.is_empty() {
                req = req.query(&[("cursor", c.as_str())]);
            }
        }
        let res = req.send().await.map_err(|e| e.to_string())?;
        let status = res.status();
        let body = res.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!(
                "chain_id {chain_id} (chain={chain}): Moralis HTTP {status}: {}",
                body.chars().take(200).collect::<String>()
            ));
        }
        let page = parse_moralis_page(&body)?;
        items.extend(page.result);
        let next = page.cursor.filter(|s| !s.is_empty());
        if next.is_none() {
            break;
        }
        cursor = next;
    }

    let mut out = Vec::new();
    for it in items {
        if it.native_token == Some(true) {
            continue;
        }
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

#[cfg(test)]
mod tests {
    use super::moralis_chain_param;

    #[test]
    fn fantom_not_in_wallet_token_balances_api() {
        assert!(moralis_chain_param(250).is_none());
    }

    #[test]
    fn zksync_and_scroll_not_supported() {
        assert!(moralis_chain_param(324).is_none());
        assert!(moralis_chain_param(534352).is_none());
    }

    #[test]
    fn linea_and_avalanche_supported() {
        assert_eq!(moralis_chain_param(59144), Some("0xe708"));
        assert_eq!(moralis_chain_param(43114), Some("0xa86a"));
    }
}
