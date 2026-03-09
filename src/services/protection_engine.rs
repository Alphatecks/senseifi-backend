//! Protection engine: toggles gate real behavior. Evaluates transactions, approvals,
//! dApp connections, and wallet activity (monitor cycle). Emergency lock and custom rules enforced here.

use crate::db::DbPool;
use strsim::levenshtein;
use crate::models::senseiguard::{
    AnalyzeTxResponse, DappConnectionCheckResponse, UserProtectionSettings,
};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::repositories::wallet_repository::WalletRepository;

// --- Production risk bands (aligned with PHISHING_DETECTION_ROADMAP) ---
// Score >= 80 → Block; 50–79 → Dangerous (high warning); 30–49 → Warning (medium); < 30 → Safe.
const BLOCK_THRESHOLD: i32 = 80;
const HIGH_WARNING_THRESHOLD: i32 = 50;
const MEDIUM_WARNING_THRESHOLD: i32 = 30;

/// Signal weights for additive risk (doc: domain typosquat +25, homograph +25, unlimited approval +35, etc.)
const WEIGHT_DOMAIN_TYPOSQUAT: i32 = 25;
const WEIGHT_DOMAIN_HOMOGRAPH: i32 = 25;
const WEIGHT_UNLIMITED_APPROVAL: i32 = 35;

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
                threat_types: vec![],
                explanation: Some(msg.to_string()),
                risk_breakdown: Some(serde_json::json!({ "approval_risk": 0, "simulation_drain": 0 })),
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
        });
    }

    let blocked = SenseiguardRepository::is_contract_blocked(pool, wallet_address, to.unwrap_or(""))
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
            threat_types: vec![crate::models::senseiguard::threat_types::PHISHING_INDICATOR.to_string()],
            explanation: Some(msg.to_string()),
            risk_breakdown: Some(serde_json::json!({ "approval_risk": 0, "simulation_drain": 0 })),
        });
    }

    let (risk_score, warning, recommended_action, mut threat_types, risk_breakdown) =
        threat_analyze_tx_sync(to, value, data);
    let rules_block = apply_security_rules_tx(pool, wallet_address, to, value, data).await;
    let blocked = rules_block.unwrap_or(false) || (settings.auto_block_high_risk && risk_score >= BLOCK_THRESHOLD);
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
        threat_types.push(crate::models::senseiguard::threat_types::MALICIOUS_TRANSACTION.to_string());
    }
    let band = score_to_band(risk_score).to_string();
    let explanation = warning.clone();

    Ok(TxEvalResult {
        risk_score,
        warning,
        recommended_action,
        blocked,
        band,
        threat_types,
        explanation,
        risk_breakdown: Some(risk_breakdown),
    })
}

/// Returns (score, warning, recommended_action, threat_types, risk_breakdown). Uses additive signal weights.
fn threat_analyze_tx_sync(
    _to: Option<&str>,
    _value: Option<&str>,
    data: Option<&str>,
) -> (i32, Option<String>, String, Vec<String>, serde_json::Value) {
    let mut score = 0i32;
    let mut approval_risk = 0i32;
    let mut warning = None;
    let mut threat_types: Vec<String> = Vec::new();
    let data = data.unwrap_or("");
    if data.starts_with("0x") && data.len() >= 10 {
        let sig = &data[2..10].to_lowercase();
        if sig == "095ea7b3" || sig == "a22cb465" {
            score += WEIGHT_UNLIMITED_APPROVAL;
            approval_risk = WEIGHT_UNLIMITED_APPROVAL;
            warning = Some("Unlimited or high-value approval detected.".to_string());
            threat_types.push(crate::models::senseiguard::threat_types::UNLIMITED_APPROVAL.to_string());
        }
        if data.len() > 138 && (sig == "095ea7b3" || sig == "a22cb465") {
            let amount_hex = data.get(74..138).unwrap_or("");
            if amount_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" {
                if score < WEIGHT_UNLIMITED_APPROVAL {
                    score += WEIGHT_UNLIMITED_APPROVAL;
                    approval_risk = WEIGHT_UNLIMITED_APPROVAL;
                    warning = Some("Unlimited approval detected.".to_string());
                    threat_types.push(crate::models::senseiguard::threat_types::UNLIMITED_APPROVAL.to_string());
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
        "simulation_drain": 0
    });
    (score, warning, recommended_action, threat_types, risk_breakdown)
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
                        if amount_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" {
                            return Some(true);
                        }
                    }
                }
            }
            "block_tx_above_usd" => {
                let max_usd = r.condition_json.get("max_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
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
    let risk_score = if SenseiguardRepository::is_contract_blocked(pool, wallet_address, spender_address)
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

/// When new_dapp_connection_alerts is ON we check domain; when OFF skip.
pub async fn evaluate_dapp_connection(
    pool: &DbPool,
    wallet_address: &str,
    domain: &str,
) -> Result<DappEvalResult, String> {
    let _settings = SenseiguardRepository::get_protection_settings(pool, wallet_address)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or(default_settings());

    let domain_lower = domain.to_lowercase();
    let legacy_typo = domain_lower.contains("unlswap")
        || domain_lower.contains("unisvvap")
        || (domain_lower.contains("metamask") && domain_lower != "metamask.io");
    let similarity_phishing = domain_similarity_phishing(&domain_lower);
    let homograph = is_homograph_domain(domain);

    let mut risk_score = 0i32;
    if legacy_typo || similarity_phishing {
        risk_score += WEIGHT_DOMAIN_TYPOSQUAT;
    }
    if homograph {
        risk_score += WEIGHT_DOMAIN_HOMOGRAPH;
    }
    risk_score = risk_score.min(100);
    let phishing_risk = risk_score >= MEDIUM_WARNING_THRESHOLD;

    Ok(DappEvalResult {
        risk_score,
        phishing_risk,
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
    }
}

pub fn build_dapp_check_response(skipped: bool, result: Option<DappEvalResult>) -> DappConnectionCheckResponse {
    if skipped {
        return DappConnectionCheckResponse {
            skipped: true,
            risk_score: None,
            phishing_risk: None,
            reason: Some("New dApp connection alerts are disabled.".to_string()),
        };
    }
    let Some(r) = result else {
        return DappConnectionCheckResponse {
            skipped: false,
            risk_score: Some(0),
            phishing_risk: Some(false),
            reason: None,
        };
    };
    DappConnectionCheckResponse {
        skipped: false,
        risk_score: Some(r.risk_score),
        phishing_risk: Some(r.phishing_risk),
        reason: None,
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
) -> Result<AnalyzeTxResponse, String> {
    let settings = match SenseiguardRepository::get_protection_settings(pool, wallet_address).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(build_analyze_tx_response(true, None));
        }
        Err(e) => return Err(e.to_string()),
    };
    if !settings.high_risk_tx_warnings {
        return Ok(build_analyze_tx_response(true, None));
    }
    let r = evaluate_transaction(pool, wallet_address, to, value, data).await?;
    if (r.risk_score >= 60 || !r.threat_types.is_empty()) && r.risk_score > 0 {
        if let Ok(Some(wallet)) = WalletRepository::get_wallet_by_address(pool, wallet_address).await {
            let severity = match r.band.as_str() {
                "Block" | "Dangerous" => "high",
                "Warning" => "medium",
                _ => "low",
            };
            let title = r
                .explanation
                .as_deref()
                .unwrap_or("Pre-sign transaction risk detected");
            let threat_type = r.threat_types.first().map(String::as_str);
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
