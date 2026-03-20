//! USD spot for native gas tokens: CoinGecko (optional Pro), CoinCap, Binance, Coinbase.
//! In-memory cache by asset id (same as CoinGecko id) avoids rate limits when scanning many chains.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct NativeUsdQuote {
    pub usd_per_unit: f64,
    /// "coingecko" | "coingecko_pro" | "coincap" | "binance" | "coinbase"
    pub source: &'static str,
}

const PRICE_CACHE_TTL: Duration = Duration::from_secs(120);

type PriceCacheMap = HashMap<String, (NativeUsdQuote, Instant)>;

fn price_cache() -> &'static Mutex<PriceCacheMap> {
    static CACHE: OnceLock<Mutex<PriceCacheMap>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key_for_chain(chain_id: i64) -> String {
    coingecko_id_for_chain(chain_id).to_string()
}

fn cached_quote(chain_id: i64) -> Option<NativeUsdQuote> {
    let key = cache_key_for_chain(chain_id);
    let mut g = price_cache().lock().ok()?;
    let (q, at) = g.get(&key)?;
    if at.elapsed() < PRICE_CACHE_TTL {
        return Some(q.clone());
    }
    g.remove(&key);
    None
}

fn store_cached_quote(chain_id: i64, q: &NativeUsdQuote) {
    let key = cache_key_for_chain(chain_id);
    if let Ok(mut g) = price_cache().lock() {
        g.insert(key, (q.clone(), Instant::now()));
    }
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

/// Coinbase public spot (no key). Pair must exist on Coinbase (e.g. BNB-USD).
fn coinbase_spot_pair(chain_id: i64) -> &'static str {
    match chain_id {
        56 => "BNB-USD",
        137 => "MATIC-USD",
        43114 => "AVAX-USD",
        250 => "FTM-USD",
        _ => "ETH-USD",
    }
}

#[derive(Debug, Deserialize)]
struct CoinbaseSpotAmt {
    amount: String,
}

#[derive(Debug, Deserialize)]
struct CoinbaseSpotResp {
    data: CoinbaseSpotAmt,
}

async fn fetch_coinbase_spot(chain_id: i64) -> Option<NativeUsdQuote> {
    let pair = coinbase_spot_pair(chain_id);
    let url = format!("https://api.coinbase.com/v2/prices/{}/spot", pair);
    let client = http_client()?;
    let res = client.get(&url).send().await.ok()?;
    if !res.status().is_success() {
        tracing::warn!(
            status = %res.status(),
            chain_id,
            %pair,
            "Coinbase spot HTTP non-success"
        );
        return None;
    }
    let body: CoinbaseSpotResp = res.json().await.ok()?;
    let usd: f64 = body.data.amount.parse().ok()?;
    if !usd.is_finite() || usd <= 0.0 {
        return None;
    }
    Some(NativeUsdQuote {
        usd_per_unit: usd,
        source: "coinbase",
    })
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

/// Best-effort USD per native unit. Cached 120s per asset (CoinGecko id) to reduce rate limits.
pub async fn fetch_native_usd_detailed(chain_id: i64) -> Option<NativeUsdQuote> {
    if let Some(q) = cached_quote(chain_id) {
        return Some(q);
    }

    let q = if let Some(q) = fetch_coingecko(chain_id).await {
        q
    } else {
        tracing::warn!(chain_id, "CoinGecko native USD failed; trying CoinCap");
        if let Some(q) = fetch_coincap(chain_id).await {
            q
        } else {
            tracing::warn!(chain_id, "CoinCap failed; trying Binance USDT");
            if let Some(q) = fetch_binance_usdt(chain_id).await {
                q
            } else {
                tracing::warn!(chain_id, "Binance failed; trying Coinbase spot");
                if let Some(q) = fetch_coinbase_spot(chain_id).await {
                    q
                } else {
                    tracing::warn!(
                        chain_id,
                        "Native USD pricing failed (CoinGecko, CoinCap, Binance, Coinbase)"
                    );
                    return None;
                }
            }
        }
    };

    store_cached_quote(chain_id, &q);
    Some(q)
}

/// Spot USD for one unit of the chain native token. None if all sources fail.
#[allow(dead_code)]
pub async fn fetch_native_usd_per_unit(chain_id: i64) -> Option<f64> {
    fetch_native_usd_detailed(chain_id)
        .await
        .map(|q| q.usd_per_unit)
}
