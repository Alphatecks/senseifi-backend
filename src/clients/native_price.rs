//! USD price for a chain's native gas token (CoinGecko public API). Used for dashboard totals.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct CoinGeckoUsdWrap {
    usd: f64,
}

/// CoinGecko `simple/price` `ids` parameter for the native currency of `chain_id`.
pub fn coingecko_id_for_chain(chain_id: i64) -> &'static str {
    match chain_id {
        56 => "binancecoin",
        137 => "matic-network",
        43114 => "avalanche-2",
        250 => "fantom",
        // Ethereum and ETH-native L2s / testnets we treat as ETH spot
        1 | 10 | 42161 | 8453 | 5 | 11155111 | 17000 => "ethereum",
        _ => "ethereum",
    }
}

/// Spot USD for one unit of the chain native token (e.g. 1 ETH on mainnet). None if request fails.
pub async fn fetch_native_usd_per_unit(chain_id: i64) -> Option<f64> {
    let id = coingecko_id_for_chain(chain_id);
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
        id
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("senseifi-backend/1.0")
        .build()
        .ok()?;
    let map: HashMap<String, CoinGeckoUsdWrap> = client.get(url).send().await.ok()?.json().await.ok()?;
    map.get(id).map(|w| w.usd)
}
