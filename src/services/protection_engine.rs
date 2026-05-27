//! Protection engine: toggles gate real behavior. Evaluates transactions, approvals,
//! dApp connections, and wallet activity (monitor cycle). Emergency lock and custom rules enforced here.

use crate::db::DbPool;
use crate::models::senseiguard::{
    kill_chain, AnalyzeTxResponse, DappConnectionCheckResponse, SignalGroupSummary,
    ThreatCorrelationSummary, UserProtectionSettings, WebsiteScanSummary,
};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::domain_intel_service;
use crate::services::threat_correlation_service::{ThreatCorrelationService, ThreatSignalInput};
use crate::services::threat_scoring_v2::{ThreatScoringV2, ThreatSignal, SCORING_MODEL_V2};
use crate::services::website_scan_service;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::cmp::Reverse;
use strsim::levenshtein;

// --- Production risk bands (aligned with PHISHING_DETECTION_ROADMAP) ---
// Score >= 80 → Block; 50–79 → Dangerous (high warning); 30–49 → Warning (medium); < 30 → Safe.
const BLOCK_THRESHOLD: i32 = 80;
const HIGH_WARNING_THRESHOLD: i32 = 50;
const MEDIUM_WARNING_THRESHOLD: i32 = 30;

/// Signal weights for additive risk (doc: domain typosquat +25, homograph +25, unlimited approval +35, etc.)
const WEIGHT_DOMAIN_TYPOSQUAT: i32 = 25;
const WEIGHT_DOMAIN_HOMOGRAPH: i32 = 25;
const WEIGHT_UNLIMITED_APPROVAL: i32 = 35;
const WEIGHT_DELEGATECALL_PATTERN: i32 = 20;
const WEIGHT_UNKNOWN_DESTINATION: i32 = 25;

/// Band for API response: Safe | Warning | Dangerous | Block (from risk_score).
pub fn score_to_band(score: i32) -> &'static str {
    match score {
        _ if score >= BLOCK_THRESHOLD => "Block",
        _ if score >= HIGH_WARNING_THRESHOLD => "Dangerous",
        _ if score >= MEDIUM_WARNING_THRESHOLD => "Warning",
        _ => "Safe",
    }
}

/// Result of evaluating a transaction (pre-sign). Aligned with doc: band, threat_types, explanation, risk_breakdown.
pub struct TxEvalResult {
    pub risk_score: i32,
    pub warning: Option<String>,
    pub recommended_action: String,
    pub blocked: bool,
    pub band: String,
    pub threat_types: Vec<String>,
    pub explanation: Option<String>,
    pub risk_breakdown: Option<serde_json::Value>,
    pub correlation: Option<ThreatCorrelationSummary>,
    pub scoring_model: Option<String>,
    pub kill_chain_stage: Option<String>,
    pub signal_groups: Option<Vec<SignalGroupSummary>>,
    pub should_persist_threat: bool,
}

/// Result of evaluating an approval event.
pub struct ApprovalEvalResult {
    pub risk_score: i32,
    pub should_alert: bool,
    pub warning: Option<String>,
}

/// Result of evaluating a dApp connection.
pub struct DappEvalResult {
    pub risk_score: i32,
    pub phishing_risk: bool,
    pub safety: String,
    pub website_scan: Option<WebsiteScanSummary>,
    pub correlation: Option<ThreatCorrelationSummary>,
}

/// When high_risk_tx_warnings is OFF we skip analysis. When ON we run threat analysis and apply rules + emergency lock.
pub async fn evaluate_transaction(
    pool: &DbPool,
    wallet_address: &str,
    to: Option<&str>,
    value: Option<&str>,
    data: Option<&str>,
) -> Result<TxEvalResult, String> {
    let settings = SenseiguardRepository::get_protection_settings(pool, wallet_address)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or(default_settings());

    if settings.emergency_lock {
        let whitelist: Vec<String> = settings
            .whitelisted_addresses
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let to_normalized = to.map(|s| s.to_lowercase()).unwrap_or_default();
        let allowed = whitelist.iter().any(|a| a.to_lowercase() == to_normalized);
        if !allowed && !to_normalized.is_empty() {
            let msg = "Emergency lock is on. Only whitelisted addresses are allowed.";
            return Ok(TxEvalResult {
                risk_score: 100,
                warning: Some(msg.to_string()),
                recommended_action: "Reject transaction".to_string(),
                blocked: true,
                band: "Block".to_string(),
                threat_types: vec![
                    crate::models::senseiguard::threat_types::POLICY_ENFORCEMENT.to_string()
                ],
                explanation: Some(msg.to_string()),
                risk_breakdown: Some(
                    serde_json::json!({ "approval_risk": 0, "simulation_drain": 0 }),
                ),
                correlation: None,
                scoring_model: None,
                kill_chain_stage: None,
                signal_groups: None,
                should_persist_threat: true,
            });
        }
    }

    if !settings.high_risk_tx_warnings {
        return Ok(TxEvalResult {
            risk_score: 0,
            warning: None,
            recommended_action: "Proceed".to_string(),
            blocked: false,
            band: "Safe".to_string(),
            threat_types: vec![],
            explanation: None,
            risk_breakdown: None,
            correlation: None,
            scoring_model: None,
            kill_chain_stage: None,
            signal_groups: None,
            should_persist_threat: false,
        });
    }

    let blocked =
        SenseiguardRepository::is_contract_blocked(pool, wallet_address, to.unwrap_or(""))
            .await
            .unwrap_or(false);
    if blocked {
        let msg = "Contract is blocked by your protection settings.";
        return Ok(TxEvalResult {
            risk_score: 100,
            warning: Some(msg.to_string()),
            recommended_action: "Reject transaction".to_string(),
            blocked: true,
            band: "Block".to_string(),
            threat_types: vec![
                crate::models::senseiguard::threat_types::PHISHING_INDICATOR.to_string()
            ],
            explanation: Some(msg.to_string()),
            risk_breakdown: Some(serde_json::json!({ "approval_risk": 0, "simulation_drain": 0 })),
            correlation: None,
            scoring_model: None,
            kill_chain_stage: None,
            signal_groups: None,
            should_persist_threat: true,
        });
    }

    let (risk_score, warning, recommended_action, mut threat_types, risk_breakdown) =
        threat_analyze_tx_sync(to, value, data);
    let rules_block = apply_security_rules_tx(pool, wallet_address, to, value, data).await;
    let blocked = rules_block.unwrap_or(false)
        || (settings.auto_block_high_risk && risk_score >= BLOCK_THRESHOLD);
    let recommended_action = if blocked {
        "Reject transaction".to_string()
    } else {
        recommended_action
    };
    let warning = warning.or_else(|| {
        if blocked {
            Some("Blocked by rule or auto-block high risk.".to_string())
        } else {
            None
        }
    });
    if blocked && risk_score >= 70 && threat_types.is_empty() {
        threat_types
            .push(crate::models::senseiguard::threat_types::MALICIOUS_TRANSACTION.to_string());
    }
    let band = score_to_band(risk_score).to_string();
    let explanation = warning.clone();
    let should_persist = !threat_types.is_empty() || risk_score >= 60;

    Ok(TxEvalResult {
        risk_score,
        warning,
        recommended_action,
        blocked,
        band,
        threat_types,
        explanation,
        risk_breakdown: Some(risk_breakdown),
        correlation: None,
        scoring_model: None,
        kill_chain_stage: None,
        signal_groups: None,
        should_persist_threat: should_persist,
    })
}

/// Map calldata heuristics to v2 Execute-stage signals.
pub fn collect_tx_signals(to: Option<&str>, value: Option<&str>, data: Option<&str>) -> Vec<ThreatSignal> {
    use crate::models::senseiguard::threat_types;
    let mut signals = Vec::new();
    let data = data.unwrap_or("");
    let to_addr = to.unwrap_or("").to_lowercase();
    let campaign = if to_addr.is_empty() {
        ThreatScoringV2::campaign_key_generic("unknown_destination")
    } else {
        ThreatScoringV2::campaign_key_contract(&to_addr)
    };

    if to_addr.is_empty() || to_addr == "0x0000000000000000000000000000000000000000" {
        signals.push(ThreatSignal::new(
            kill_chain::EXECUTE,
            "transaction",
            Some(threat_types::MALICIOUS_TRANSACTION),
            WEIGHT_UNKNOWN_DESTINATION,
            62,
            &campaign,
        ));
    }

    if data.starts_with("0x") && data.len() >= 10 {
        let sig = &data[2..10].to_lowercase();
        if sig == "095ea7b3" || sig == "a22cb465" {
            signals.push(ThreatSignal::new(
                kill_chain::EXECUTE,
                "approval",
                Some(threat_types::UNLIMITED_APPROVAL),
                WEIGHT_UNLIMITED_APPROVAL,
                68,
                &campaign,
            ));
        }
        if sig == "3659cfe6" {
            signals.push(ThreatSignal::new(
                kill_chain::EXECUTE,
                "transaction",
                Some(threat_types::MALICIOUS_TRANSACTION),
                WEIGHT_DELEGATECALL_PATTERN,
                65,
                &campaign,
            ));
        }
    }

    if let Some(v) = value {
        if let Some(hex) = v.strip_prefix("0x") {
            if let Ok(value_wei) = u128::from_str_radix(hex, 16) {
                if value_wei > 0 {
                    signals.push(ThreatSignal::new(
                        kill_chain::EXECUTE,
                        "value_exposure",
                        None,
                        10,
                        45,
                        &campaign,
                    ));
                }
            }
        }
    }

    signals
}

async fn collect_temporal_signals(
    pool: &DbPool,
    wallet_id: uuid::Uuid,
    domain: Option<&str>,
) -> Vec<ThreatSignal> {
    let mut signals = Vec::new();
    if let Some(domain) = domain.filter(|d| !d.trim().is_empty()) {
        if let Ok(Some(first_seen)) =
            SenseiguardRepository::first_threat_event_time_for_domain(pool, wallet_id, domain).await
        {
            let age = Utc::now().signed_duration_since(first_seen);
            if age < Duration::days(7) {
                signals.push(ThreatSignal::new(
                    kill_chain::LURE,
                    "temporal",
                    Some(crate::models::senseiguard::threat_types::FRONTEND_PHISHING),
                    12,
                    58,
                    &ThreatScoringV2::campaign_key_domain(domain),
                ).with_metadata(json!({ "domain_first_seen_days": age.num_days() })));
            }
        }
    }
    signals
}

async fn collect_dapp_signals_v2(
    pool: &DbPool,
    wallet_address: &str,
    domain: &str,
) -> Result<Vec<ThreatSignal>, String> {
    let eval = evaluate_dapp_connection(pool, wallet_address, domain, None).await?;
    let threat_type = if eval.phishing_risk {
        Some(crate::models::senseiguard::threat_types::FRONTEND_PHISHING)
    } else {
        Some(crate::models::senseiguard::threat_types::PHISHING_INDICATOR)
    };
    if eval.risk_score <= 0 {
        return Ok(vec![]);
    }
    Ok(vec![ThreatSignal::new(
        kill_chain::LURE,
        "domain",
        threat_type,
        eval.risk_score,
        if eval.phishing_risk { 72 } else { 58 },
        &ThreatScoringV2::campaign_key_domain(domain),
    )])
}

async fn evaluate_transaction_v2(
    pool: &DbPool,
    wallet_address: &str,
    to: Option<&str>,
    value: Option<&str>,
    data: Option<&str>,
    sign_method: Option<&str>,
    sign_params: Option<&Vec<Value>>,
    domain: Option<&str>,
) -> Result<TxEvalResult, String> {
    let settings = SenseiguardRepository::get_protection_settings(pool, wallet_address)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or(default_settings());

    let base = evaluate_transaction(pool, wallet_address, to, value, data).await?;
    if base.threat_types.first().map(String::as_str)
        == Some(crate::models::senseiguard::threat_types::POLICY_ENFORCEMENT)
    {
        return Ok(base);
    }
    if !settings.high_risk_tx_warnings {
        return Ok(base);
    }

    let mut signals = collect_tx_signals(to, value, data);
    signals.extend(ThreatScoringV2::collect_signature_signals(sign_method, sign_params));

    if let Some(domain) = domain.filter(|d| !d.trim().is_empty()) {
        signals.extend(collect_dapp_signals_v2(pool, wallet_address, domain).await?);
    }

    if let Ok(Some(wallet)) = WalletRepository::get_wallet_by_address(pool, wallet_address).await {
        signals.extend(collect_temporal_signals(pool, wallet.id, domain).await);
    }

    let mut verdict = ThreatScoringV2::evaluate_signals(&signals);
    let rules_block = apply_security_rules_tx(pool, wallet_address, to, value, data).await;
    let blocked = base.blocked
        || rules_block.unwrap_or(false)
        || (settings.auto_block_high_risk && verdict.risk_score >= BLOCK_THRESHOLD);

    if blocked && verdict.band != "Block" {
        verdict.band = "Block".to_string();
        verdict.recommended_action = "Reject transaction".to_string();
    }

    let warning = verdict.explanation.clone().or(base.warning);
    Ok(TxEvalResult {
        risk_score: verdict.risk_score,
        warning,
        recommended_action: if blocked {
            "Reject transaction".to_string()
        } else {
            verdict.recommended_action
        },
        blocked,
        band: verdict.band,
        threat_types: verdict.threat_types,
        explanation: verdict.explanation,
        risk_breakdown: Some(verdict.risk_breakdown),
        correlation: None,
        scoring_model: Some(SCORING_MODEL_V2.to_string()),
        kill_chain_stage: verdict.kill_chain_stage,
        signal_groups: Some(verdict.signal_groups),
        should_persist_threat: verdict.should_persist_threat,
    })
}

/// Returns (score, warning, recommended_action, threat_types, risk_breakdown). Uses additive signal weights.
fn threat_analyze_tx_sync(
    to: Option<&str>,
    value: Option<&str>,
    data: Option<&str>,
) -> (i32, Option<String>, String, Vec<String>, serde_json::Value) {
    let mut score = 0i32;
    let mut approval_risk = 0i32;
    let mut delegatecall_risk = 0i32;
    let mut destination_risk = 0i32;
    let mut value_exposure_risk = 0i32;
    let mut warning = None;
    let mut threat_types: Vec<String> = Vec::new();
    let data = data.unwrap_or("");
    let to = to.unwrap_or("").to_lowercase();
    if to.is_empty() || to == "0x0000000000000000000000000000000000000000" {
        score += WEIGHT_UNKNOWN_DESTINATION;
        destination_risk = WEIGHT_UNKNOWN_DESTINATION;
        warning = Some("Unknown destination contract detected.".to_string());
        threat_types
            .push(crate::models::senseiguard::threat_types::MALICIOUS_TRANSACTION.to_string());
    }
    if data.starts_with("0x") && data.len() >= 10 {
        let sig = &data[2..10].to_lowercase();
        if sig == "095ea7b3" || sig == "a22cb465" {
            score += WEIGHT_UNLIMITED_APPROVAL;
            approval_risk = WEIGHT_UNLIMITED_APPROVAL;
            warning = Some("Unlimited or high-value approval detected.".to_string());
            threat_types
                .push(crate::models::senseiguard::threat_types::UNLIMITED_APPROVAL.to_string());
        }
        if data.len() > 138 && (sig == "095ea7b3" || sig == "a22cb465") {
            let amount_hex = data.get(74..138).unwrap_or("");
            if amount_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" {
                if score < WEIGHT_UNLIMITED_APPROVAL {
                    score += WEIGHT_UNLIMITED_APPROVAL;
                    approval_risk = WEIGHT_UNLIMITED_APPROVAL;
                    warning = Some("Unlimited approval detected.".to_string());
                    threat_types.push(
                        crate::models::senseiguard::threat_types::UNLIMITED_APPROVAL.to_string(),
                    );
                }
            }
        }
        if sig == "3659cfe6" {
            score += WEIGHT_DELEGATECALL_PATTERN;
            delegatecall_risk = WEIGHT_DELEGATECALL_PATTERN;
            if warning.is_none() {
                warning =
                    Some("Upgradeable proxy/admin transaction signature detected.".to_string());
            }
            threat_types
                .push(crate::models::senseiguard::threat_types::MALICIOUS_TRANSACTION.to_string());
        }
    }
    if let Some(v) = value {
        if let Some(hex) = v.strip_prefix("0x") {
            if let Ok(value_wei) = u128::from_str_radix(hex, 16) {
                if value_wei > 0 {
                    value_exposure_risk = 10;
                    score += value_exposure_risk;
                }
            }
        }
    }
    score = score.min(100);
    let recommended_action = if score >= BLOCK_THRESHOLD {
        "Reject transaction".to_string()
    } else if score >= HIGH_WARNING_THRESHOLD {
        "Review before signing".to_string()
    } else if score >= MEDIUM_WARNING_THRESHOLD {
        "Review before signing".to_string()
    } else {
        "Proceed".to_string()
    };
    let risk_breakdown = serde_json::json!({
        "approval_risk": approval_risk,
        "delegatecall_risk": delegatecall_risk,
        "destination_risk": destination_risk,
        "value_exposure_risk": value_exposure_risk,
        "simulation_drain": 0
    });
    (
        score,
        warning,
        recommended_action,
        threat_types,
        risk_breakdown,
    )
}

async fn apply_security_rules_tx(
    pool: &DbPool,
    wallet_address: &str,
    _to: Option<&str>,
    value: Option<&str>,
    data: Option<&str>,
) -> Option<bool> {
    let rules = SenseiguardRepository::list_security_rules(pool, wallet_address)
        .await
        .ok()?;
    for r in rules {
        if !r.enabled {
            continue;
        }
        match r.rule_type.as_str() {
            "block_unlimited_approval" => {
                let data = data.unwrap_or("");
                if data.starts_with("0x") && data.len() >= 138 {
                    let sig = &data[2..10].to_lowercase();
                    if sig == "095ea7b3" || sig == "a22cb465" {
                        let amount_hex = data.get(74..138).unwrap_or("");
                        if amount_hex
                            == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        {
                            return Some(true);
                        }
                    }
                }
            }
            "block_tx_above_usd" => {
                let max_usd = r
                    .condition_json
                    .get("max_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if max_usd > 0.0 {
                    let value_wei = value
                        .and_then(|s| s.strip_prefix("0x"))
                        .and_then(|s| u128::from_str_radix(s, 16).ok())
                        .unwrap_or(0);
                    if value_wei > 0 {
                        let eth_value = value_wei as f64 / 1e18;
                        if eth_value * 2000.0 > max_usd {
                            return Some(true);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// When new_approval_alerts is ON we evaluate and optionally store alert; when OFF no alert.
pub async fn evaluate_approval(
    pool: &DbPool,
    wallet_address: &str,
    _token_address: Option<&str>,
    spender_address: &str,
    amount_raw: Option<&str>,
) -> Result<ApprovalEvalResult, String> {
    let settings = SenseiguardRepository::get_protection_settings(pool, wallet_address)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or(default_settings());

    if settings.emergency_lock {
        return Ok(ApprovalEvalResult {
            risk_score: 100,
            should_alert: true,
            warning: Some("Emergency lock is on. Approvals are blocked.".to_string()),
        });
    }

    let is_unlimited = amount_raw
        .map(|s| s.to_lowercase().contains("ffffffff"))
        .unwrap_or(false);
    let risk_score =
        if SenseiguardRepository::is_contract_blocked(pool, wallet_address, spender_address)
            .await
            .unwrap_or(false)
        {
            100
        } else if is_unlimited {
            85
        } else {
            40
        };

    let should_alert = settings.new_approval_alerts && risk_score >= 50;
    let warning = if risk_score >= 70 {
        Some(format!(
            "Risky approval to {} (unlimited or blocked contract).",
            &spender_address[..8.min(spender_address.len())]
        ))
    } else {
        None
    };

    Ok(ApprovalEvalResult {
        risk_score,
        should_alert,
        warning,
    })
}

// --- Domain phishing: Levenshtein + homograph (Phase 1.1) ---

/// Known brand names (lowercase) and their single canonical domain. If domain is similar to brand but not canonical, flag.
const BRAND_CANONICAL: &[(&str, &str)] = &[
    ("uniswap", "uniswap.org"),
    ("metamask", "metamask.io"),
    ("opensea", "opensea.io"),
    ("pancakeswap", "pancakeswap.finance"),
    ("etherscan", "etherscan.io"),
    ("phantom", "phantom.app"),
    ("rabby", "rabby.io"),
    ("coinbase", "coinbase.com"),
    ("trustwallet", "trustwallet.com"),
];

/// Max Levenshtein distance to consider domain "similar" to a brand (typosquat).
const LEVENSHTEIN_THRESHOLD: usize = 2;

/// Returns true if the domain label is suspiciously similar to a known brand but not the canonical domain.
fn domain_similarity_phishing(domain_lower: &str) -> bool {
    let host = domain_lower
        .split('/')
        .next()
        .unwrap_or(domain_lower)
        .split(':')
        .next()
        .unwrap_or(domain_lower);
    let labels: Vec<&str> = host.split('.').collect();
    for (brand, canonical) in BRAND_CANONICAL {
        let canonical_lower = canonical.to_lowercase();
        for label in &labels {
            if label.is_empty() {
                continue;
            }
            let d = levenshtein(label, brand);
            if d <= LEVENSHTEIN_THRESHOLD && d < label.len() {
                let is_canonical = host == canonical_lower
                    || host == format!("www.{}", canonical_lower)
                    || host.ends_with(&format!(".{}", canonical_lower));
                if !is_canonical {
                    return true;
                }
            }
        }
    }
    false
}

/// Returns true if domain contains non-ASCII (e.g. homograph: Cyrillic 'а' instead of Latin 'a').
fn is_homograph_domain(domain: &str) -> bool {
    domain.chars().any(|c| c as u32 > 127)
}

/// Rank finding text by prefixed severity (higher = more severe).
/// Expected format: "[critical] ...", "[high] ...", "[medium] ...", "[low] ...".
fn finding_severity_rank(finding: &str) -> i32 {
    let lower = finding.trim().to_ascii_lowercase();
    if lower.starts_with("[critical]") {
        4
    } else if lower.starts_with("[high]") {
        3
    } else if lower.starts_with("[medium]") {
        2
    } else if lower.starts_with("[low]") {
        1
    } else {
        0
    }
}

/// When new_dapp_connection_alerts is ON we check domain; when OFF skip.
pub async fn evaluate_dapp_connection(
    pool: &DbPool,
    wallet_address: &str,
    target: &str,
    max_pages: Option<u8>,
) -> Result<DappEvalResult, String> {
    let _settings = SenseiguardRepository::get_protection_settings(pool, wallet_address)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or(default_settings());

    let domain_lower = target.to_lowercase();
    let legacy_typo = domain_lower.contains("unlswap")
        || domain_lower.contains("unisvvap")
        || (domain_lower.contains("metamask") && domain_lower != "metamask.io");
    let similarity_phishing = domain_similarity_phishing(&domain_lower);
    let homograph = is_homograph_domain(target);

    let mut risk_score = 0i32;
    if legacy_typo || similarity_phishing {
        risk_score += WEIGHT_DOMAIN_TYPOSQUAT;
    }
    if homograph {
        risk_score += WEIGHT_DOMAIN_HOMOGRAPH;
    }
    let intel = domain_intel_service::assess_domain(pool, target).await;
    risk_score += intel.risk_boost;

    let mut website_scan_summary: Option<WebsiteScanSummary> = None;
    if let Ok(scan) = website_scan_service::scan_website(target, max_pages).await {
        risk_score = (risk_score + scan.risk_score).min(100);
        let mut findings = scan
            .issues
            .iter()
            .take(8)
            .map(|i| format!("[{}] {}", i.severity, i.message))
            .collect::<Vec<_>>();
        if intel.is_malicious {
            findings.insert(
                0,
                "[critical] Domain matched malicious threat-intelligence feed.".to_string(),
            );
        } else if intel.is_trusted {
            findings.insert(
                0,
                "[low] Domain matched trusted protocol allowlist.".to_string(),
            );
        } else if let Some(reason) = intel.reason.clone() {
            findings.insert(0, format!("[low] {}", reason));
        }
        // Ensure UI "top finding" (first item) is always highest severity.
        findings.sort_by_key(|f| Reverse(finding_severity_rank(f)));
        website_scan_summary = Some(WebsiteScanSummary {
            target: scan.target,
            normalized_url: scan.normalized_url,
            domain: intel.domain,
            safety: scan.safety,
            risk_score: scan.risk_score,
            crawled_pages: scan.crawled_pages,
            issue_count: scan.issues.len(),
            findings,
        });
    } else if intel.is_malicious || intel.is_trusted {
        let finding = if intel.is_malicious {
            "[critical] Domain matched malicious threat-intelligence feed.".to_string()
        } else {
            "[low] Domain matched trusted protocol allowlist.".to_string()
        };
        website_scan_summary = Some(WebsiteScanSummary {
            target: target.to_string(),
            normalized_url: format!("https://{}", intel.domain),
            domain: intel.domain.clone(),
            safety: score_to_band(risk_score.clamp(0, 100)).to_string(),
            risk_score: risk_score.clamp(0, 100),
            crawled_pages: 0,
            issue_count: 1,
            findings: vec![finding],
        });
    }
    risk_score = risk_score.clamp(0, 100);
    let phishing_risk = risk_score >= MEDIUM_WARNING_THRESHOLD;
    let safety = score_to_band(risk_score).to_string();

    Ok(DappEvalResult {
        risk_score,
        phishing_risk,
        safety,
        website_scan: website_scan_summary,
        correlation: None,
    })
}

/// Run one monitor cycle for a wallet (update last_scan_at; in future: check approvals, tokens, contracts).
pub async fn run_monitor_cycle(pool: &DbPool, wallet_address: &str) -> Result<(), String> {
    let row = SenseiguardRepository::get_protection_auto_scan(pool, wallet_address)
        .await
        .map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(());
    };
    if !row.auto_scan_enabled {
        return Ok(());
    }
    SenseiguardRepository::update_auto_scan_last_scan_at(pool, wallet_address)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn default_settings() -> UserProtectionSettings {
    use chrono::Utc;
    UserProtectionSettings {
        wallet_address: String::new(),
        auto_security_scan: true,
        high_risk_tx_warnings: true,
        new_approval_alerts: true,
        new_dapp_connection_alerts: true,
        auto_block_high_risk: false,
        emergency_lock: false,
        whitelisted_addresses: Some(serde_json::json!([])),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn build_analyze_tx_response(skipped: bool, result: Option<TxEvalResult>) -> AnalyzeTxResponse {
    if skipped {
        return AnalyzeTxResponse {
            skipped: true,
            risk_score: None,
            band: None,
            threat_types: None,
            explanation: None,
            recommendation: None,
            risk_breakdown: None,
            warning: None,
            recommended_action: None,
            reason: Some("High-risk transaction warnings are disabled.".to_string()),
            elite_assessment: None,
            correlation: None,
            scoring_model: None,
            kill_chain_stage: None,
            signal_groups: None,
        };
    }
    let Some(r) = result else {
        return AnalyzeTxResponse {
            skipped: false,
            risk_score: Some(0),
            band: Some("Safe".to_string()),
            threat_types: Some(vec![]),
            explanation: None,
            recommendation: Some("Proceed".to_string()),
            risk_breakdown: None,
            warning: None,
            recommended_action: Some("Proceed".to_string()),
            reason: None,
            elite_assessment: None,
            correlation: None,
            scoring_model: None,
            kill_chain_stage: None,
            signal_groups: None,
        };
    };
    let recommendation = r.recommended_action.clone();
    AnalyzeTxResponse {
        skipped: false,
        risk_score: Some(r.risk_score),
        band: Some(r.band),
        threat_types: Some(r.threat_types),
        explanation: r.explanation,
        recommendation: Some(recommendation.clone()),
        risk_breakdown: r.risk_breakdown,
        warning: r.warning,
        recommended_action: Some(recommendation),
        reason: None,
        elite_assessment: None,
        correlation: r.correlation,
        scoring_model: r.scoring_model,
        kill_chain_stage: r.kill_chain_stage,
        signal_groups: r.signal_groups,
    }
}

pub fn build_dapp_check_response(
    skipped: bool,
    result: Option<DappEvalResult>,
) -> DappConnectionCheckResponse {
    if skipped {
        return DappConnectionCheckResponse {
            skipped: true,
            risk_score: None,
            phishing_risk: None,
            safety: None,
            website_scan: None,
            reason: Some("New dApp connection alerts are disabled.".to_string()),
            correlation: None,
        };
    }
    let Some(r) = result else {
        return DappConnectionCheckResponse {
            skipped: false,
            risk_score: Some(0),
            phishing_risk: Some(false),
            safety: Some("Safe".to_string()),
            website_scan: None,
            reason: None,
            correlation: None,
        };
    };
    DappConnectionCheckResponse {
        skipped: false,
        risk_score: Some(r.risk_score),
        phishing_risk: Some(r.phishing_risk),
        safety: Some(r.safety),
        website_scan: r.website_scan,
        reason: None,
        correlation: r.correlation,
    }
}

pub fn build_dapp_check_skipped_with_reason(reason: &str) -> DappConnectionCheckResponse {
    DappConnectionCheckResponse {
        skipped: true,
        risk_score: None,
        phishing_risk: None,
        safety: None,
        website_scan: None,
        reason: Some(reason.to_string()),
        correlation: None,
    }
}

/// Full analyze-tx flow: settings check, evaluate, persist threat/alert when needed, return response.
/// Used by both POST /api/protection/transaction/analyze and POST /api/dashboard/{address}/analyze-tx.
pub async fn analyze_tx_and_respond(
    pool: &DbPool,
    wallet_address: &str,
    to: Option<&str>,
    value: Option<&str>,
    data: Option<&str>,
    sign_method: Option<&str>,
    sign_params: Option<&Vec<Value>>,
    domain: Option<&str>,
) -> Result<AnalyzeTxResponse, String> {
    let settings = match SenseiguardRepository::get_protection_settings(pool, wallet_address).await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(build_analyze_tx_response(true, None));
        }
        Err(e) => return Err(e.to_string()),
    };
    if !settings.high_risk_tx_warnings {
        return Ok(build_analyze_tx_response(true, None));
    }

    let mut r = if ThreatScoringV2::enabled() {
        evaluate_transaction_v2(
            pool,
            wallet_address,
            to,
            value,
            data,
            sign_method,
            sign_params,
            domain,
        )
        .await?
    } else {
        evaluate_transaction(pool, wallet_address, to, value, data).await?
    };

    let threat_type = r.threat_types.first().map(String::as_str);
    let is_policy_enforcement = matches!(
        threat_type,
        Some(crate::models::senseiguard::threat_types::POLICY_ENFORCEMENT)
    );

    if !is_policy_enforcement && r.risk_score > 0 {
        if let Ok(Some(wallet)) =
            WalletRepository::get_wallet_by_address(pool, wallet_address).await
        {
            let confidence_guess = if r.risk_score >= 85 {
                88
            } else if r.risk_score >= 70 {
                76
            } else if r.risk_score >= 50 {
                68
            } else {
                55
            };
            let signal_category = if r
                .threat_types
                .iter()
                .any(|t| t == crate::models::senseiguard::threat_types::UNLIMITED_APPROVAL)
            {
                "approval"
            } else if r
                .threat_types
                .iter()
                .any(|t| t == crate::models::senseiguard::threat_types::SIGNATURE_PHISHING)
            {
                "signature"
            } else {
                "transaction"
            };
            let kill_stage = r.kill_chain_stage.clone().or_else(|| {
                if sign_method.is_some() {
                    Some(kill_chain::HOOK.to_string())
                } else {
                    Some(kill_chain::EXECUTE.to_string())
                }
            });
            if let Ok(Some(correlation)) = ThreatCorrelationService::ingest_signal(
                pool,
                ThreatSignalInput {
                    wallet_id: wallet.id,
                    threat_id: None,
                    event_type: "tx_intent_analysis".to_string(),
                    signal_category: signal_category.to_string(),
                    threat_type: r.threat_types.first().cloned(),
                    surface: Some("tx_intent".to_string()),
                    risk_score: r.risk_score,
                    confidence_score: confidence_guess,
                    source_contract: to.map(|s| s.to_string()),
                    domain: domain.map(|s| s.to_string()),
                    metadata: json!({
                        "band": r.band.clone(),
                        "recommended_action": r.recommended_action.clone(),
                        "threat_types": r.threat_types.clone(),
                        "risk_breakdown": r.risk_breakdown.clone(),
                        "scoring_model": r.scoring_model.clone(),
                    }),
                    event_time: None,
                    kill_chain_stage: kill_stage,
                },
            )
            .await
            {
                if ThreatScoringV2::enabled() {
                    r.risk_score = r.risk_score.max(correlation.risk_score);
                    r.band = score_to_band(r.risk_score).to_string();
                    if correlation.confidence_score >= 80 {
                        r.should_persist_threat = true;
                    }
                    if settings.auto_block_high_risk && r.risk_score >= BLOCK_THRESHOLD {
                        r.blocked = true;
                        r.recommended_action = "Reject transaction".to_string();
                    }
                }
                r.correlation = Some(correlation);
            }
        }
    }

    let should_persist = if is_policy_enforcement {
        false
    } else if ThreatScoringV2::enabled() {
        r.should_persist_threat
    } else {
        (r.risk_score >= 60 || !r.threat_types.is_empty()) && r.risk_score > 0
    };

    if should_persist {
        if let Ok(Some(wallet)) =
            WalletRepository::get_wallet_by_address(pool, wallet_address).await
        {
            let severity = match r.band.as_str() {
                "Block" | "Dangerous" => "high",
                "Warning" => "medium",
                _ => "low",
            };
            let title = r
                .explanation
                .as_deref()
                .unwrap_or("Pre-sign transaction risk detected");
            let campaign_uuid = r
                .correlation
                .as_ref()
                .and_then(|c| uuid::Uuid::parse_str(&c.campaign_id).ok());
            if ThreatScoringV2::enabled() {
                let _ = SenseiguardRepository::upsert_open_threat_for_campaign(
                    pool,
                    wallet.id,
                    severity,
                    title,
                    to,
                    threat_type,
                    Some("tx_intent"),
                    r.explanation.as_deref(),
                    r.kill_chain_stage.as_deref(),
                    campaign_uuid,
                )
                .await;
            } else {
                let _ = SenseiguardRepository::create_threat_with_surface(
                    pool,
                    wallet.id,
                    severity,
                    title,
                    to,
                    threat_type,
                    Some("tx_intent"),
                    r.explanation.as_deref(),
                )
                .await;
            }
            if r.risk_score >= 85 {
                let _ = SenseiguardRepository::create_alert(
                    pool,
                    wallet.id,
                    None,
                    severity,
                    title,
                    r.explanation.as_deref(),
                )
                .await;
            }
        }
    }

    Ok(build_analyze_tx_response(false, Some(r)))
}

#[cfg(test)]
mod threat_model_v2_tests {
    use super::*;
    use crate::models::senseiguard::threat_types;
    use crate::services::threat_scoring_v2::ThreatScoringV2;

    const APPROVE_DATA: &str =
        "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn v1_and_v2_both_flag_unlimited_approval_calldata() {
        let (v1_score, _, _, v1_types, _) =
            threat_analyze_tx_sync(Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"), None, Some(APPROVE_DATA));
        assert!(v1_score >= MEDIUM_WARNING_THRESHOLD);
        assert!(v1_types.iter().any(|t| t == threat_types::UNLIMITED_APPROVAL));

        let signals = collect_tx_signals(
            Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            None,
            Some(APPROVE_DATA),
        );
        let v2 = ThreatScoringV2::evaluate_signals(&signals);
        assert!(v2
            .threat_types
            .iter()
            .any(|t| t == threat_types::UNLIMITED_APPROVAL));
    }

    #[test]
    fn v2_standalone_approval_warn_only_no_persist() {
        let signals = collect_tx_signals(
            Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            None,
            Some(APPROVE_DATA),
        );
        let v2 = ThreatScoringV2::evaluate_signals(&signals);
        assert_eq!(v2.band, "Warning");
        assert!(!v2.should_persist_threat);
    }

    #[test]
    fn v2_signature_hook_adds_persist_when_confident() {
        let mut signals = collect_tx_signals(
            Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            None,
            Some(APPROVE_DATA),
        );
        signals.extend(ThreatScoringV2::collect_signature_signals(
            Some("eth_signTypedData_v4"),
            Some(&vec![serde_json::json!({"types": {"Permit": []}})]),
        ));
        let v2 = ThreatScoringV2::evaluate_signals(&signals);
        assert!(v2.should_persist_threat);
        assert!(v2.stages_present.contains(&kill_chain::HOOK.to_string()));
    }

    #[test]
    fn build_analyze_tx_response_includes_v2_fields() {
        let result = TxEvalResult {
            risk_score: 45,
            warning: None,
            recommended_action: "Review before signing".to_string(),
            blocked: false,
            band: "Warning".to_string(),
            threat_types: vec![threat_types::UNLIMITED_APPROVAL.to_string()],
            explanation: Some("test".to_string()),
            risk_breakdown: Some(json!({})),
            correlation: None,
            scoring_model: Some(SCORING_MODEL_V2.to_string()),
            kill_chain_stage: Some(kill_chain::EXECUTE.to_string()),
            signal_groups: Some(vec![]),
            should_persist_threat: false,
        };
        let resp = build_analyze_tx_response(false, Some(result));
        assert_eq!(resp.scoring_model.as_deref(), Some(SCORING_MODEL_V2));
        assert_eq!(resp.kill_chain_stage.as_deref(), Some(kill_chain::EXECUTE));
    }
}
