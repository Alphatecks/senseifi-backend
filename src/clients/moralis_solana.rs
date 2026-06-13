//! Moralis Solana API: native SOL balance and SPL token holdings.
//!
//! `GET /account/{network}/{address}/balance` and `GET /account/{network}/{address}/tokens`

use serde::Deserialize;

const DEFAULT_BASE: &str = "https://solana-gateway.moralis.io";

/// Normalized native SOL balance for DB upsert.
#[derive(Debug, Clone)]
pub struct SolanaNativeBalance {
    pub balance_display: String,
    pub usd_value: f64,
}

/// Normalized SPL token row for DB upsert (mint stored as contract_address).
#[derive(Debug, Clone)]
pub struct SolanaSplBalance {
    pub mint: String,
    pub symbol: String,
    pub name: String,
    pub balance_display: String,
    pub usd_value: f64,
}

#[derive(Debug, Deserialize)]
struct MoralisSolBalanceResponse {
    #[serde(default)]
    lamports: Option<String>,
    #[serde(default)]
    solana: Option<String>,
    #[serde(default, rename = "usdValue")]
    usd_value: Option<f64>,
    #[serde(default, rename = "usd_value")]
    usd_value_snake: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct MoralisSplTokenItem {
    #[serde(default)]
    mint: Option<String>,
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default, rename = "amountRaw")]
    amount_raw: Option<String>,
    #[serde(default)]
    decimals: Option<u8>,
    #[serde(default, rename = "possibleSpam")]
    possible_spam: Option<bool>,
    #[serde(default, rename = "usdValue")]
    usd_value: Option<f64>,
    #[serde(default, rename = "usd_value")]
    usd_value_snake: Option<f64>,
}

fn moralis_api_key() -> Option<String> {
    std::env::var("MORALIS_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn moralis_solana_base_url() -> String {
    std::env::var("MORALIS_SOLANA_API_BASE_URL")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE.to_string())
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

fn is_valid_solana_mint(mint: &str) -> bool {
    let m = mint.trim();
    (32..=44).contains(&m.len())
        && m.chars().all(|c| {
            matches!(
                c,
                '1'..='9'
                    | 'A'..='H'
                    | 'J'..='N'
                    | 'P'..='Z'
                    | 'a'..='k'
                    | 'm'..='z'
            )
        })
}

fn parse_sol_balance(body: &str) -> Result<SolanaNativeBalance, String> {
    let raw: MoralisSolBalanceResponse =
        serde_json::from_str(body).map_err(|e| format!("Moralis Solana balance JSON: {e}"))?;
    let balance_display = raw
        .solana
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            raw.lamports.as_deref().and_then(|l| {
                let lamports: f64 = l.trim().parse().ok()?;
                Some(format!("{}", lamports / 1_000_000_000.0))
            })
        })
        .unwrap_or_else(|| "0".to_string());
    let usd_value = raw
        .usd_value
        .or(raw.usd_value_snake)
        .unwrap_or(0.0)
        .max(0.0);
    Ok(SolanaNativeBalance {
        balance_display,
        usd_value,
    })
}

fn parse_spl_tokens(body: &str) -> Result<Vec<SolanaSplBalance>, String> {
    let items: Vec<MoralisSplTokenItem> = if let Ok(v) = serde_json::from_str::<Vec<MoralisSplTokenItem>>(body)
    {
        v
    } else {
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default)]
            result: Vec<MoralisSplTokenItem>,
        }
        serde_json::from_str::<Wrap>(body)
            .map(|w| w.result)
            .map_err(|e| format!("Moralis Solana tokens JSON: {e}"))?
    };

    let mut out = Vec::new();
    for it in items {
        if it.possible_spam == Some(true) {
            continue;
        }
        let Some(mint) = it
            .mint
            .as_deref()
            .map(str::trim)
            .filter(|s| is_valid_solana_mint(s))
        else {
            continue;
        };
        let balance_display = it
            .amount
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "0")
            .map(str::to_string)
            .or_else(|| {
                it.amount_raw.as_deref().and_then(|raw| {
                    let raw = raw.trim();
                    if raw.is_empty() || raw == "0" {
                        return None;
                    }
                    let decimals = it.decimals.unwrap_or(0).min(18);
                    let n: f64 = raw.parse().ok()?;
                    let denom = 10f64.powi(decimals as i32);
                    Some(format!("{}", n / denom))
                })
            });
        let Some(balance_display) = balance_display else {
            continue;
        };
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
        let usd_value = it
            .usd_value
            .or(it.usd_value_snake)
            .unwrap_or(0.0)
            .max(0.0);
        out.push(SolanaSplBalance {
            mint: mint.to_string(),
            symbol,
            name,
            balance_display,
            usd_value,
        });
    }
    Ok(out)
}

/// Fetch native SOL balance for a wallet on `mainnet` or `devnet`.
pub async fn fetch_native_balance(
    wallet_address: &str,
    network: &str,
) -> Result<SolanaNativeBalance, String> {
    let key = moralis_api_key().ok_or_else(|| "MORALIS_API_KEY is not set".to_string())?;
    let base = moralis_solana_base_url();
    let addr = wallet_address.trim();
    let net = network.trim();
    if net != "mainnet" && net != "devnet" {
        return Err(format!("unsupported Solana network: {net}"));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{base}/account/{net}/{addr}/balance");
    let res = client
        .get(&url)
        .header("X-API-Key", &key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    let body = res.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "Moralis Solana balance HTTP {status}: {}",
            body.chars().take(200).collect::<String>()
        ));
    }
    parse_sol_balance(&body)
}

/// Fetch SPL token balances for a wallet on `mainnet` or `devnet`.
pub async fn fetch_spl_tokens(
    wallet_address: &str,
    network: &str,
) -> Result<Vec<SolanaSplBalance>, String> {
    let key = moralis_api_key().ok_or_else(|| "MORALIS_API_KEY is not set".to_string())?;
    let base = moralis_solana_base_url();
    let addr = wallet_address.trim();
    let net = network.trim();
    if net != "mainnet" && net != "devnet" {
        return Err(format!("unsupported Solana network: {net}"));
    }
    let exclude_spam = moralis_exclude_spam();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{base}/account/{net}/{addr}/tokens");
    let res = client
        .get(&url)
        .header("X-API-Key", &key)
        .header("Accept", "application/json")
        .query(&[("excludeSpam", if exclude_spam { "true" } else { "false" })])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    let body = res.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "Moralis Solana tokens HTTP {status}: {}",
            body.chars().take(200).collect::<String>()
        ));
    }
    parse_spl_tokens(&body)
}

pub fn has_moralis_config() -> bool {
    moralis_api_key().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sol_balance_json() {
        let body = r#"{"lamports":"1500000000","solana":"1.5","usdValue":225.5}"#;
        let b = parse_sol_balance(body).expect("parse");
        assert_eq!(b.balance_display, "1.5");
        assert!((b.usd_value - 225.5).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_spl_tokens_json() {
        let body = r#"[
            {
                "mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "symbol":"USDC",
                "name":"USD Coin",
                "amount":"12.5",
                "decimals":6,
                "possibleSpam":false,
                "usdValue":12.5
            }
        ]"#;
        let tokens = parse_spl_tokens(body).expect("parse");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].symbol, "USDC");
        assert_eq!(tokens[0].mint, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    }

    #[test]
    fn parse_spl_skips_spam() {
        let body = r#"[{"mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","symbol":"SCAM","name":"Scam","amount":"1","possibleSpam":true}]"#;
        let tokens = parse_spl_tokens(body).expect("parse");
        assert!(tokens.is_empty());
    }
}
