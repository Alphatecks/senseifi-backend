//! USD spot for native gas tokens: CoinGecko (optional Pro), CoinCap, then Binance public ticker.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NativeUsdQuote {
    pub usd_per_unit: f64,
    /// "coingecko" | "coingecko_pro" | "coincap" | "binance"
    pub source: &'static str,
}

#[derive(Debug, Deserialize)]
struct CoinGeckoUsdWrap {
    usd: f64,
}

#[derive(Debug, Deserialize)]
struct CoinCapData {
    #[serde(rename = "priceUsd")]
    price_usd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoinCapResponse {
    data: Option<CoinCapData>,
}

/// CoinGecko `simple/price` `ids` parameter for the native currency of `chain_id`.
pub fn coingecko_id_for_chain(chain_id: i64) -> &'static str {
    match chain_id {
        56 => "binancecoin",
        137 => "matic-network",
        43114 => "avalanche-2",
        250 => "fantom",
        1 | 10 | 42161 | 8453 | 5 | 11155111 | 17000 | 324 | 59144 | 534352 => "ethereum",
        _ => "ethereum",
    }
}

/// CoinCap `/v2/assets/{id}` id segment (lowercase slug).
fn coincap_id_for_chain(chain_id: i64) -> &'static str {
    match chain_id {
        56 => "binance-coin",
        137 => "matic-network",
        43114 => "avalanche",
        250 => "fantom",
        1 | 10 | 42161 | 8453 | 5 | 11155111 | 17000 | 324 | 59144 | 534352 => "ethereum",
        _ => "ethereum",
    }
}

fn http_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("senseifi-backend/1.0")
        .build()
        .ok()
}

async fn fetch_coingecko(chain_id: i64) -> Option<NativeUsdQuote> {
    let id = coingecko_id_for_chain(chain_id);
    let pro_key = std::env::var("COINGECKO_API_KEY").ok().filter(|s| !s.is_empty());
    let use_pro = pro_key.is_some();
    let (url, source): (String, &'static str) = if use_pro {
        (
            format!(
                "https://pro-api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
                id
            ),
            "coingecko_pro",
        )
    } else {
        (
            format!(
                "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
                id
            ),
            "coingecko",
        )
    };

    let client = http_client()?;
    let mut req = client.get(&url);
    if let Some(ref k) = pro_key {
        req = req.header("x-cg-pro-api-key", k);
    }
    let res = req.send().await.ok()?;
    if !res.status().is_success() {
        tracing::warn!(status = %res.status(), chain_id, "CoinGecko price HTTP non-success");
        return None;
    }
    let map: HashMap<String, CoinGeckoUsdWrap> = res.json().await.ok()?;
    let usd = map.get(id)?.usd;
    Some(NativeUsdQuote {
        usd_per_unit: usd,
        source,
    })
}

/// Binance spot USDT pair (public, no key). USDT ≈ USD for portfolio display.
fn binance_symbol_for_chain(chain_id: i64) -> &'static str {
    match chain_id {
        56 => "BNBUSDT",
        137 => "MATICUSDT",
        43114 => "AVAXUSDT",
        250 => "FTMUSDT",
        _ => "ETHUSDT",
    }
}

#[derive(Debug, Deserialize)]
struct BinanceTickerPrice {
    price: String,
}

async fn fetch_binance_usdt(chain_id: i64) -> Option<NativeUsdQuote> {
    let symbol = binance_symbol_for_chain(chain_id);
    let url = format!(
        "https://api.binance.com/api/v3/ticker/price?symbol={}",
        symbol
    );
    let client = http_client()?;
    let res = client.get(url).send().await.ok()?;
    if !res.status().is_success() {
        tracing::warn!(
            status = %res.status(),
            chain_id,
            %symbol,
            "Binance price HTTP non-success"
        );
        return None;
    }
    let body: BinanceTickerPrice = res.json().await.ok()?;
    let usd: f64 = body.price.parse().ok()?;
    if !usd.is_finite() || usd <= 0.0 {
        return None;
    }
    Some(NativeUsdQuote {
        usd_per_unit: usd,
        source: "binance",
    })
}

async fn fetch_coincap(chain_id: i64) -> Option<NativeUsdQuote> {
    let slug = coincap_id_for_chain(chain_id);
    let url = format!("https://api.coincap.io/v2/assets/{}", slug);
    let client = http_client()?;
    let res = client.get(url).send().await.ok()?;
    if !res.status().is_success() {
        tracing::warn!(status = %res.status(), chain_id, %slug, "CoinCap price HTTP non-success");
        return None;
    }
    let body: CoinCapResponse = res.json().await.ok()?;
    let price_str = body.data?.price_usd?;
    let usd: f64 = price_str.parse().ok()?;
    Some(NativeUsdQuote {
        usd_per_unit: usd,
        source: "coincap",
    })
}

/// Best-effort USD per native unit: CoinGecko (Pro if set), CoinCap, Binance USDT ticker.
pub async fn fetch_native_usd_detailed(chain_id: i64) -> Option<NativeUsdQuote> {
    if let Some(q) = fetch_coingecko(chain_id).await {
        return Some(q);
    }
    tracing::warn!(chain_id, "CoinGecko native USD failed; trying CoinCap");
    if let Some(q) = fetch_coincap(chain_id).await {
        return Some(q);
    }
    tracing::warn!(chain_id, "CoinCap failed; trying Binance USDT");
    if let Some(q) = fetch_binance_usdt(chain_id).await {
        return Some(q);
    }
    tracing::warn!(chain_id, "Native USD pricing failed (CoinGecko, CoinCap, Binance)");
    None
}

/// Spot USD for one unit of the chain native token. None if all sources fail.
#[allow(dead_code)]
pub async fn fetch_native_usd_per_unit(chain_id: i64) -> Option<f64> {
    fetch_native_usd_detailed(chain_id)
        .await
        .map(|q| q.usd_per_unit)
}
