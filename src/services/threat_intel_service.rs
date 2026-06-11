//! Dynamic multi-chain threat intelligence aggregated from runtime signals.
//!
//! Env vars (`SENSEIGUARD_MALICIOUS_*`) are optional emergency overrides only — the
//! primary feed is built from scam reports, activity feed, threat events, and blocks.

use crate::db::DbPool;
use crate::models::wallet::is_valid_solana_address;
use crate::services::domain_intel_service;
use crate::services::external_intel_cache_service;
use crate::services::solana_tx_analysis::{parse_env_malicious_programs, static_malicious_programs};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

const MIN_DOMAIN_RISK: i32 = 70;
const MIN_PROGRAM_RISK: i32 = 65;
const MAX_FEED_ITEMS: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct ThreatIntelSources {
    pub from_scam_reports: usize,
    pub from_activity_feed: usize,
    pub from_threat_events: usize,
    pub from_user_blocks: usize,
    pub from_env_override: usize,
    pub from_domain_intel: usize,
    pub from_goplus_cache: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MultichainThreatFeed {
    pub malicious_contracts: Vec<String>,
    pub malicious_programs: Vec<String>,
    pub malicious_domains: Vec<String>,
    pub malicious_domains_by_family: HashMap<String, Vec<String>>,
    pub trusted_domains: Vec<String>,
    pub sources: ThreatIntelSources,
    pub updated_at: DateTime<Utc>,
}

fn parse_env_domains(var: &str) -> Vec<String> {
    std::env::var(var)
        .ok()
        .map(|s| {
            s.split(',')
                .map(|d| d.trim().to_lowercase())
                .filter(|d| !d.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_domain(input: &str) -> Option<String> {
    domain_intel_service::normalize_domain_host(input)
}

fn is_evm_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x")
}

fn chain_family_from_metadata(meta: &Value) -> Option<String> {
    meta.get("chain_family")
        .or_else(|| meta.get("chainFamily"))
        .or_else(|| meta.get("context").and_then(|c| c.get("chain_family")))
        .or_else(|| meta.get("context").and_then(|c| c.get("chainFamily")))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s == "evm" || s == "solana")
}

fn domain_is_high_risk(event_type: Option<&str>, risk_score: i32) -> bool {
    matches!(event_type, Some("domain_risk_detected" | "tx_blocked" | "tx_warned"))
        || risk_score >= MIN_DOMAIN_RISK
}

pub async fn get_multichain_threat_feed(pool: &DbPool) -> Result<MultichainThreatFeed, String> {
    let domain_feed = domain_intel_service::get_domain_threat_feed(pool).await?;

    let malicious_contracts = sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT contract_address
        FROM scam_reports
        WHERE contract_address ~* '^0x[0-9a-f]{40}$'
        ORDER BY contract_address
        LIMIT $1
        "#,
    )
    .bind(MAX_FEED_ITEMS as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let scam_programs = sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT contract_address
        FROM scam_reports
        WHERE contract_address !~* '^0x[0-9a-f]{40}$'
          AND length(contract_address) >= 32
        ORDER BY contract_address
        LIMIT $1
        "#,
    )
    .bind(MAX_FEED_ITEMS as i64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let event_programs = sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT source_contract
        FROM threat_events
        WHERE source_contract IS NOT NULL
          AND source_contract !~* '^0x[0-9a-f]{40}$'
          AND length(source_contract) >= 32
          AND risk_score >= $1
        ORDER BY source_contract
        LIMIT $2
        "#,
    )
    .bind(MIN_PROGRAM_RISK)
    .bind(MAX_FEED_ITEMS as i64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let blocked_programs = sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT contract_address
        FROM user_blocked_contracts
        WHERE contract_address !~* '^0x[0-9a-f]{40}$'
          AND length(contract_address) >= 32
        ORDER BY contract_address
        LIMIT $1
        "#,
    )
    .bind(MAX_FEED_ITEMS as i64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let activity_program_rows = sqlx::query_as::<_, (String,)>(
        r#"
        SELECT DISTINCT elem
        FROM activity_feed,
        LATERAL jsonb_array_elements_text(
            CASE
                WHEN jsonb_typeof(metadata->'program_ids') = 'array'
                THEN metadata->'program_ids'
                ELSE '[]'::jsonb
            END
        ) AS elem
        WHERE elem <> ''
          AND (
            metadata->>'event_type' = 'tx_blocked'
            OR COALESCE((metadata->>'risk_score')::int, 0) >= $1
          )
        LIMIT $2
        "#,
    )
    .bind(MIN_DOMAIN_RISK)
    .bind(MAX_FEED_ITEMS as i64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let activity_domain_rows = sqlx::query_as::<_, (Option<String>, Value)>(
        r#"
        SELECT metadata->>'domain' AS domain, metadata
        FROM activity_feed
        WHERE metadata IS NOT NULL
          AND metadata ? 'domain'
        ORDER BY created_at DESC
        LIMIT 5000
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let threat_domain_rows = sqlx::query_as::<_, (String, Value, i32)>(
        r#"
        SELECT domain, metadata, risk_score
        FROM threat_events
        WHERE domain IS NOT NULL
          AND trim(domain) <> ''
          AND risk_score >= $1
        ORDER BY event_time DESC
        LIMIT 2000
        "#,
    )
    .bind(MIN_PROGRAM_RISK)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let env_programs = parse_env_malicious_programs();
    let env_domains_evm = parse_env_domains("SENSEIGUARD_MALICIOUS_DOMAINS");
    let env_domains_solana = parse_env_domains("SENSEIGUARD_MALICIOUS_DOMAINS_SOLANA");

    let mut program_set: HashSet<String> = HashSet::new();
    let mut from_scam_reports = 0usize;
    for p in scam_programs {
        if is_valid_solana_address(&p) || (!is_evm_address(&p) && p.len() >= 32) {
            if program_set.insert(p.clone()) {
                from_scam_reports += 1;
            }
        }
    }

    let mut from_threat_events = 0usize;
    for p in event_programs {
        if program_set.insert(p.clone()) {
            from_threat_events += 1;
        }
    }

    let mut from_user_blocks = 0usize;
    for p in blocked_programs {
        if program_set.insert(p.clone()) {
            from_user_blocks += 1;
        }
    }

    let mut from_activity_programs = 0usize;
    for (p,) in activity_program_rows {
        if (is_valid_solana_address(&p) || (!is_evm_address(&p) && p.len() >= 32))
            && program_set.insert(p.clone())
        {
            from_activity_programs += 1;
        }
    }

    for p in static_malicious_programs() {
        program_set.insert(p);
    }

    let mut from_env_override = 0usize;
    for p in env_programs {
        if program_set.insert(p.clone()) {
            from_env_override += 1;
        }
    }

    let mut evm_domains: HashSet<String> = HashSet::new();
    let mut solana_domains: HashSet<String> = HashSet::new();
    let mut all_domains: HashSet<String> = domain_feed.malicious_domains.iter().cloned().collect();
    let mut from_activity_domains = 0usize;

    for d in &domain_feed.malicious_domains {
        evm_domains.insert(d.clone());
        solana_domains.insert(d.clone());
    }

    for (domain, metadata) in activity_domain_rows {
        let Some(raw) = domain else { continue };
        let Some(norm) = normalize_domain(&raw) else {
            continue;
        };
        let event_type = metadata
            .get("event_type")
            .and_then(|v| v.as_str());
        let risk_score = metadata
            .get("risk_score")
            .or_else(|| metadata.get("riskScore"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        if !domain_is_high_risk(event_type, risk_score) {
            continue;
        }
        if all_domains.insert(norm.clone()) {
            from_activity_domains += 1;
        }
        match chain_family_from_metadata(&metadata).as_deref() {
            Some("solana") => {
                solana_domains.insert(norm);
            }
            Some("evm") => {
                evm_domains.insert(norm);
            }
            _ => {
                evm_domains.insert(norm.clone());
                solana_domains.insert(norm);
            }
        }
    }

    for (domain, metadata, risk_score) in threat_domain_rows {
        let Some(norm) = normalize_domain(&domain) else {
            continue;
        };
        if risk_score < MIN_PROGRAM_RISK {
            continue;
        }
        all_domains.insert(norm.clone());
        match chain_family_from_metadata(&metadata).as_deref() {
            Some("solana") => {
                solana_domains.insert(norm);
            }
            Some("evm") => {
                evm_domains.insert(norm);
            }
            _ => {
                evm_domains.insert(norm.clone());
                solana_domains.insert(norm);
            }
        }
    }

    for d in env_domains_evm {
        if let Some(norm) = normalize_domain(&d) {
            evm_domains.insert(norm.clone());
            all_domains.insert(norm);
        }
    }
    for d in env_domains_solana {
        if let Some(norm) = normalize_domain(&d) {
            solana_domains.insert(norm.clone());
            all_domains.insert(norm);
        }
    }

    let mut from_goplus_cache = 0usize;

    if let Ok(goplus_domains) = external_intel_cache_service::list_active_malicious_domains(pool, None).await {
        for d in goplus_domains {
            if all_domains.insert(d.clone()) {
                from_goplus_cache += 1;
            }
            evm_domains.insert(d.clone());
            solana_domains.insert(d);
        }
    }
    if let Ok(goplus_evm_domains) =
        external_intel_cache_service::list_active_malicious_domains(pool, Some("evm")).await
    {
        for d in goplus_evm_domains {
            evm_domains.insert(d);
        }
    }
    if let Ok(goplus_sol_domains) =
        external_intel_cache_service::list_active_malicious_domains(pool, Some("solana")).await
    {
        for d in goplus_sol_domains {
            solana_domains.insert(d);
        }
    }

    if let Ok(goplus_programs) =
        external_intel_cache_service::list_active_malicious_addresses(pool, "program").await
    {
        for addr in goplus_programs {
            if (is_valid_solana_address(&addr) || (!is_evm_address(&addr) && addr.len() >= 32))
                && program_set.insert(addr)
            {
                from_goplus_cache += 1;
            }
        }
    }

    let mut malicious_programs: Vec<String> = program_set.into_iter().collect();
    malicious_programs.sort();

    let goplus_contract_cache =
        external_intel_cache_service::list_active_malicious_addresses(pool, "contract")
            .await
            .unwrap_or_default();
    let mut contract_set: HashSet<String> = malicious_contracts.into_iter().collect();
    for addr in goplus_contract_cache {
        if addr.starts_with("0x") && contract_set.insert(addr) {
            from_goplus_cache += 1;
        }
    }
    let mut malicious_contracts: Vec<String> = contract_set.into_iter().collect();
    malicious_contracts.sort();

    let mut malicious_domains: Vec<String> = all_domains.into_iter().collect();
    malicious_domains.sort();

    let mut evm_list: Vec<String> = evm_domains.into_iter().collect();
    evm_list.sort();
    let mut solana_list: Vec<String> = solana_domains.into_iter().collect();
    solana_list.sort();

    let mut malicious_domains_by_family = HashMap::new();
    malicious_domains_by_family.insert("evm".to_string(), evm_list);
    malicious_domains_by_family.insert("solana".to_string(), solana_list);

    Ok(MultichainThreatFeed {
        malicious_contracts,
        malicious_programs,
        malicious_domains,
        malicious_domains_by_family,
        trusted_domains: domain_feed.trusted_domains,
        sources: ThreatIntelSources {
            from_scam_reports,
            from_activity_feed: from_activity_domains + from_activity_programs,
            from_threat_events,
            from_user_blocks,
            from_env_override,
            from_domain_intel: domain_feed.sources.from_activity_feed,
            from_goplus_cache,
        },
        updated_at: Utc::now(),
    })
}

pub async fn get_malicious_programs(pool: &DbPool) -> HashSet<String> {
    get_multichain_threat_feed(pool)
        .await
        .map(|f| f.malicious_programs.into_iter().collect())
        .unwrap_or_default()
}

/// Persist high-risk Solana observations so the threat feed learns automatically.
pub async fn record_solana_analysis_signals(
    pool: &DbPool,
    wallet_address: &str,
    domain: Option<&str>,
    risk_score: i32,
    program_ids: &[String],
    flagged_programs: &[String],
    malicious_program_detected: bool,
    method: &str,
) {
    if risk_score < MIN_PROGRAM_RISK && !malicious_program_detected {
        return;
    }

    let Some(wallet) = crate::repositories::wallet_repository::WalletRepository::get_wallet_by_address(
        pool,
        wallet_address,
    )
    .await
    .ok()
    .flatten()
    else {
        return;
    };

    let event_type = if risk_score >= 80 || malicious_program_detected {
        "tx_blocked"
    } else {
        "tx_warned"
    };

    let metadata = json!({
        "event_type": event_type,
        "chain_family": "solana",
        "method": method,
        "risk_score": risk_score,
        "program_ids": program_ids,
        "flagged_programs": flagged_programs,
        "domain": domain,
        "malicious_program_detected": malicious_program_detected,
        "source": "solana_tx_analyze",
    });

    let _ = crate::services::senseiguard_service::SenseiguardService::ingest_activity(
        pool,
        wallet_address,
        crate::models::senseiguard::IngestActivityRequest {
            activity_type: "extension_event".to_string(),
            title: "Solana transaction risk signal".to_string(),
            description: Some(format!("Auto-learned from analyze ({})", method)),
            metadata: Some(metadata.clone()),
        },
    )
    .await;

    for program_id in flagged_programs {
        if !is_valid_solana_address(program_id) {
            continue;
        }
        let confidence = if malicious_program_detected {
            90
        } else if risk_score >= 80 {
            85
        } else {
            70
        };
        let _ = crate::services::threat_correlation_service::ThreatCorrelationService::ingest_signal(
            pool,
            crate::services::threat_correlation_service::ThreatSignalInput {
                wallet_id: wallet.id,
                threat_id: None,
                event_type: "solana_tx_analyze".to_string(),
                signal_category: "transaction".to_string(),
                threat_type: Some("drainer".to_string()),
                surface: Some("tx_intent".to_string()),
                risk_score,
                confidence_score: confidence,
                source_contract: Some(program_id.clone()),
                domain: domain.map(|s| s.to_string()),
                metadata: metadata.clone(),
                event_time: None,
                kill_chain_stage: Some(crate::models::senseiguard::kill_chain::EXECUTE.to_string()),
            },
        )
        .await;
    }

    if let Some(d) = domain.filter(|s| !s.trim().is_empty()) {
        if risk_score >= MIN_DOMAIN_RISK {
            let _ = crate::services::threat_correlation_service::ThreatCorrelationService::ingest_signal(
                pool,
                crate::services::threat_correlation_service::ThreatSignalInput {
                    wallet_id: wallet.id,
                    threat_id: None,
                    event_type: "domain_risk_detected".to_string(),
                    signal_category: "domain".to_string(),
                    threat_type: Some("frontend_phishing".to_string()),
                    surface: Some("off_chain".to_string()),
                    risk_score,
                    confidence_score: 72,
                    source_contract: None,
                    domain: Some(d.to_string()),
                    metadata: json!({
                        "chain_family": "solana",
                        "source": "solana_tx_analyze",
                    }),
                    event_time: None,
                    kill_chain_stage: Some(crate::models::senseiguard::kill_chain::LURE.to_string()),
                },
            )
            .await;
        }
    }
}
