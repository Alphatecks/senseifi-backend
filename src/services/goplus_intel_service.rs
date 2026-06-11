//! Helpers merging GoPlus address security into analyze flows and cache.

use crate::clients::goplus;
use crate::db::DbPool;
use crate::services::external_intel_cache_service;
use serde_json::json;

const GOPLUS_ADDRESS_RISK: i32 = 95;

pub struct GoPlusAddressEnrichment {
    pub risk_boost: i32,
    pub findings: Vec<String>,
    pub malicious_detected: bool,
}

pub async fn enrich_addresses(
    pool: &DbPool,
    addresses: &[String],
    chain_id: &str,
    entity_type: &str,
    chain_family: Option<&str>,
    limit: usize,
) -> GoPlusAddressEnrichment {
    let mut out = GoPlusAddressEnrichment {
        risk_boost: 0,
        findings: Vec::new(),
        malicious_detected: false,
    };

    if !goplus::is_enabled() || addresses.is_empty() {
        return out;
    }

    let mut join = tokio::task::JoinSet::new();
    for addr in addresses.iter().take(limit).cloned() {
        let chain = chain_id.to_string();
        join.spawn(async move {
            let result = goplus::check_address_security(&addr, &chain).await;
            (addr, result)
        });
    }

    while let Some(task) = join.join_next().await {
        let Ok((addr, Some(result))) = task else {
            continue;
        };
        if !result.is_malicious {
            continue;
        }

        out.malicious_detected = true;
        out.risk_boost = out.risk_boost.max(GOPLUS_ADDRESS_RISK);
        out.findings.push(format!(
            "[critical] GoPlus: malicious {} {}",
            entity_type,
            truncate_addr(&addr)
        ));

        let _ = external_intel_cache_service::upsert_positive_hit(
            pool,
            entity_type,
            &addr,
            chain_family,
            "goplus",
            GOPLUS_ADDRESS_RISK,
            json!({
                "source_api": "address_security",
                "chain_id": chain_id,
                "risk_flags": result.risk_flags,
            }),
        )
        .await;
    }

    out
}

fn truncate_addr(addr: &str) -> String {
    if addr.len() <= 12 {
        return addr.to_string();
    }
    format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
}

pub fn evm_chain_id_string(chain_id: Option<i64>) -> String {
    chain_id.unwrap_or(1).to_string()
}
