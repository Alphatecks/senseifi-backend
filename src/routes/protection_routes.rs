// Protection Control: 5 toggle switches (GET/PUT settings) + functionality endpoints.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

use crate::clients::{moralis_wallet, rpc};
use crate::db::DbPool;
use crate::models::senseiguard::{
    kill_chain, BlockContractRequest, CreateSecurityRuleRequest, DappConnectionCheckRequest,
    EmergencyLockRequest, IngestActivityRequest, ReportScamRequest, SimulateTxRequest,
    SimulateTxResponse, UpdateProtectionSettingsRequest, UpdateSecurityRuleRequest,
    UserRiskProfile, WatchlistContractRequest,
};
use crate::models::wallet::{
    is_valid_scan_contract_address, is_valid_security_contract_address,
    is_valid_security_wallet_address, is_valid_solana_address, is_valid_wallet_address,
    normalize_solana_network, parse_chain_family, resolve_scan_chain_family, ChainFamily,
};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::domain_intel_service;
use crate::services::elite_intelligence_service::{
    EliteAssessmentRequest, EliteIntelligenceService,
};
use crate::services::goplus_intel_service;
use crate::services::protection_engine::{
    analyze_solana_tx_and_respond, analyze_tx_and_respond, evaluate_approval, evaluate_dapp_connection,
    run_monitor_cycle, score_to_band, DappEvalResult,
};
use crate::services::solana_tx_analysis::{analyze_solana_request, is_solana_sign_method};
use crate::services::threat_intel_service::{
    get_malicious_programs, get_multichain_threat_feed, record_solana_analysis_signals,
};
use crate::services::scan_service::ScanService;
use crate::services::threat_correlation_service::{ThreatCorrelationService, ThreatSignalInput};
use crate::services::xp_usage_service::{
    self, parse_insufficient_xp_error, XpUsageAction, XpUsageError,
};
use axum::extract::Path;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct WalletQuery {
    wallet_address: String,
}

#[derive(Debug, Deserialize)]
struct ScanHistoryQuery {
    wallet_address: String,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct EmergencyFreezeRequest {
    wallet_address: String,
    freeze: bool,
}

#[derive(Debug, Deserialize)]
struct RevokeApprovalRequest {
    wallet_address: String,
    contract_address: String,
    #[serde(default)]
    chain_id: Option<i64>,
}

fn analyze_tx_route_error(e: String) -> (StatusCode, Json<Value>) {
    if let Some((xp_balance, xp_cost)) = parse_insufficient_xp_error(&e) {
        (
            StatusCode::PAYMENT_REQUIRED,
            Json(xp_usage_service::insufficient_xp_json(
                xp_balance,
                xp_cost,
                XpUsageAction::TxAnalysis.as_str(),
            )),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e })),
        )
    }
}

fn xp_usage_route_error(err: XpUsageError) -> (StatusCode, Json<Value>) {
    match err {
        XpUsageError::InsufficientXp {
            xp_balance,
            xp_cost,
            action_type,
        } => (
            StatusCode::PAYMENT_REQUIRED,
            Json(xp_usage_service::insufficient_xp_json(
                xp_balance,
                xp_cost,
                &action_type,
            )),
        ),
        XpUsageError::Database(e) => {
            eprintln!("xp usage error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Database error" })),
            )
        }
    }
}

fn bad_address() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": "Invalid address format for chain family"
        })),
    )
}

fn bad_wallet_address(family: ChainFamily) -> (StatusCode, Json<serde_json::Value>) {
    let hint = match family {
        ChainFamily::Evm => "Expected 0x + 40 hex characters",
        ChainFamily::Solana => "Expected base58 Solana pubkey (32–44 characters)",
    };
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": format!("Invalid wallet_address format. {}", hint)
        })),
    )
}

fn site_safety_label(band: &str) -> String {
    band.to_ascii_lowercase()
}

fn risk_level_10(score: i32) -> f64 {
    ((score as f64) / 10.0 * 10.0).round() / 10.0
}

fn build_dapp_extension_response(
    skipped: bool,
    result: Option<DappEvalResult>,
    reason: Option<&str>,
) -> Value {
    if skipped {
        return json!({
            "skipped": true,
            "reason": reason,
            "correlation": null,
        });
    }

    let r = result.unwrap_or(DappEvalResult {
        risk_score: 0,
        phishing_risk: false,
        safety: "Safe".to_string(),
        website_scan: None,
        correlation: None,
    });

    let band = r.safety.clone();
    let site_safety = site_safety_label(&band);
    let findings = r
        .website_scan
        .as_ref()
        .map(|s| s.findings.clone())
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| {
            vec!["[low] No significant domain risks detected".to_string()]
        });

    let website_scan = r.website_scan.as_ref().map(|ws| {
        json!({
            "target": ws.target,
            "normalized_url": ws.normalized_url,
            "domain": ws.domain,
            "safety": site_safety_label(&ws.safety),
            "summary": format!(
                "Scanned {} page(s); {} issue(s) found",
                ws.crawled_pages, ws.issue_count
            ),
            "findings": ws.findings,
            "risk_score": ws.risk_score,
            "crawled_pages": ws.crawled_pages,
            "issue_count": ws.issue_count,
        })
    });

    json!({
        "skipped": false,
        "risk_score": r.risk_score,
        "risk_level_10": risk_level_10(r.risk_score),
        "band": band,
        "site_safety": site_safety,
        "site_safe": band == "Safe",
        "findings": findings,
        "phishing_risk": r.phishing_risk,
        "safety": r.safety,
        "website_scan": website_scan,
        "correlation": r.correlation,
    })
}

fn normalize_dapp_domain(target: &str) -> Option<String> {
    let raw = target.trim().to_lowercase();
    if raw.is_empty() {
        return None;
    }
    let with_scheme = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw
    } else {
        format!("https://{}", raw)
    };
    Url::parse(&with_scheme)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}

fn derive_dapp_name(domain: &str) -> String {
    let host = domain
        .trim()
        .trim_start_matches("www.")
        .trim_start_matches("app.");
    let root = host.split('.').next().unwrap_or("dapp");
    let mut chars = root.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => "Dapp".to_string(),
    }
}

fn normalize_contract_input(input: &str) -> String {
    let s = input.trim();
    if s.is_empty() {
        return String::new();
    }
    if is_valid_solana_address(s) {
        return s.to_string();
    }
    if let Some(addr) = extract_solana_from_scan_url(s) {
        return addr;
    }
    if s.len() >= 42 && s.starts_with("0x") && s[2..42].chars().all(|c| c.is_ascii_hexdigit()) {
        return s[..42].to_string();
    }
    if let Some(start) = s.find("0x") {
        let rest = &s[start..];
        let addr: String = rest
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == 'x')
            .collect();
        if addr.len() == 42 && addr.starts_with("0x") {
            return addr;
        }
    }
    s.to_string()
}

fn extract_solana_from_scan_url(s: &str) -> Option<String> {
    let lower = s.to_lowercase();
    for marker in ["/account/", "/token/", "/address/"] {
        if let Some(idx) = lower.find(marker) {
            let rest = &s[idx + marker.len()..];
            let candidate: String = rest
                .chars()
                .take_while(|c| {
                    c.is_ascii_alphanumeric() && *c != '0' && *c != 'O' && *c != 'I' && *c != 'l'
                })
                .collect();
            if is_valid_solana_address(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn protection_routes() -> Router<DbPool> {
    Router::new()
        .route("/settings", get(get_settings).put(update_settings))
        .route(
            "/extension/scan-smart-contract",
            post(extension_scan_smart_contract),
        )
        .route(
            "/extension/analyze-transaction-screen",
            post(extension_analyze_transaction_screen),
        )
        .route("/extension/risk-panel", post(extension_risk_panel))
        .route(
            "/extension/scam-token-detected",
            post(extension_scam_token_detected),
        )
        .route("/extension/screen-action", post(extension_screen_action))
        .route("/transaction/analyze", post(transaction_analyze))
        .route("/threat-feed", get(get_threat_feed))
        .route("/domain-threat-feed", get(domain_threat_feed))
        .route("/dapp/connection-check", post(dapp_connection_check))
        .route("/monitor/run", post(monitor_run))
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/{rule_id}", put(update_rule).delete(delete_rule))
        .route("/emergency-lock", post(emergency_lock))
        .route("/emergency-freeze", post(emergency_freeze))
        .route("/approvals/ingest", post(approvals_ingest))
        .route("/security-alerts", get(security_alerts))
        .route("/address-safety", get(address_safety))
        .route("/simulate-tx", post(simulate_tx))
        .route("/block-malicious", post(block_malicious))
        .route(
            "/block-contract",
            post(block_contract).delete(unblock_contract),
        )
        .route("/blocked", get(list_blocked))
        .route(
            "/watchlist",
            post(add_watchlist)
                .delete(remove_from_watchlist)
                .get(list_watchlist),
        )
        .route("/report", post(report_scam))
        .route("/revoke-approval", post(revoke_approval))
        .route("/scan-history", get(scan_history))
}

pub fn telemetry_routes() -> Router<DbPool> {
    Router::new().route("/events", post(ingest_telemetry_events))
}

#[derive(Debug, Deserialize)]
struct ExtensionAnalyzeRequest {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Vec<Value>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    wallet_address: Option<String>,
    #[serde(default)]
    chain_id: Option<i64>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    chain_family: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    meta: Option<Value>,
    #[serde(default)]
    risk_profile: Option<String>,
    #[serde(default)]
    liquidity_drop_1h_pct: Option<f64>,
    #[serde(default)]
    dev_wallet_sell_pct_supply: Option<f64>,
    #[serde(default)]
    token_mint_burst_count: Option<i64>,
    #[serde(default)]
    abnormal_volume_zscore: Option<f64>,
    #[serde(default)]
    recently_upgraded_hours_ago: Option<i64>,
    #[serde(default)]
    recently_exploited_days_ago: Option<i64>,
    #[serde(default)]
    interaction_count_with_contract: Option<i64>,
    #[serde(default)]
    wallet_balance_usd: Option<f64>,
    #[serde(default)]
    tx_value_usd: Option<f64>,
    // Back-compat fields (legacy mobile/web callers).
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExtensionScanSmartContractRequest {
    wallet_address: String,
    contract_link: String,
    #[serde(default)]
    chain_id: Option<u64>,
    #[serde(default)]
    chain_family: Option<String>,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExtensionAnalyzeTxScreenRequest {
    wallet_address: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Vec<Value>>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    chain_id: Option<i64>,
    #[serde(default)]
    chain_family: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExtensionRiskPanelRequest {
    wallet_address: String,
    #[serde(default)]
    contract_address: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExtensionScamTokenDetectedRequest {
    wallet_address: String,
    #[serde(default)]
    token_symbol: Option<String>,
    #[serde(default)]
    token_address: Option<String>,
    #[serde(default)]
    contract_address: Option<String>,
    #[serde(default)]
    chain_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ExtensionScreenActionRequest {
    wallet_address: String,
    action: String,
    #[serde(default)]
    token_symbol: Option<String>,
    #[serde(default)]
    token_address: Option<String>,
    #[serde(default)]
    contract_address: Option<String>,
    #[serde(default)]
    chain_id: Option<i64>,
    #[serde(default)]
    chain_family: Option<String>,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelemetryBatchRequest {
    events: Vec<TelemetryEvent>,
}

#[derive(Debug, Deserialize)]
struct TelemetryEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default, rename = "riskScore")]
    risk_score: Option<i32>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    findings: Option<Vec<String>>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    context: Option<Value>,
    #[serde(default, rename = "chainFamily")]
    chain_family: Option<String>,
    at: String,
}

fn extension_error(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "success": false,
            "message": message,
        })),
    )
}

fn extract_tx_fields(
    req: &ExtensionAnalyzeRequest,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut to = req.to.clone();
    let mut value = req.value.clone();
    let mut data = req.data.clone();

    if let Some(first) = req.params.as_ref().and_then(|v| v.first()) {
        if first.is_object() {
            if to.is_none() {
                to = first
                    .get("to")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if value.is_none() {
                value = first
                    .get("value")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if data.is_none() {
                data = first
                    .get("data")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
    }

    (to, value, data)
}

fn findings_from_analyze(
    score: i32,
    warning: Option<&str>,
    threat_types: Option<&Vec<String>>,
    domain: Option<&str>,
) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    if let Some(w) = warning {
        findings.push(w.to_string());
    }
    if let Some(tt) = threat_types {
        for t in tt {
            let text = match t.as_str() {
                "unlimited_approval" => "Unlimited approval pattern detected",
                "phishing_indicator" => "Phishing indicator detected",
                "malicious_transaction" => "Malicious transaction pattern detected",
                "frontend_phishing" => "Frontend phishing signal detected",
                _ => t.as_str(),
            };
            if !findings.iter().any(|f| f == text) {
                findings.push(text.to_string());
            }
        }
    }
    if score >= 80 && findings.is_empty() {
        findings.push("High-risk transaction pattern detected".to_string());
    }
    if let Some(d) = domain {
        if !d.trim().is_empty() && score >= 30 {
            findings.push(format!("Risk context includes domain {}", d));
        }
    }
    findings
}

fn parse_user_profile(raw: Option<&str>) -> UserRiskProfile {
    match raw.unwrap_or("standard").to_lowercase().as_str() {
        "beginner" => UserRiskProfile::Beginner,
        "pro" => UserRiskProfile::Pro,
        _ => UserRiskProfile::Standard,
    }
}

async fn compute_contract_reputation_risk(
    pool: &DbPool,
    contract_address: &str,
) -> (i32, Option<i32>, i64, i64) {
    let trust_score = SenseiguardRepository::get_latest_trust_score(pool, contract_address)
        .await
        .ok()
        .flatten();
    let scam_reports = SenseiguardRepository::count_scam_reports(pool, contract_address)
        .await
        .unwrap_or(0);
    let wallets_affected = SenseiguardRepository::get_contract_scan_trend(pool, contract_address)
        .await
        .map(|(_, wallets)| wallets)
        .unwrap_or(0);

    let trust_risk = match trust_score {
        Some(s) if s <= 20 => 35,
        Some(s) if s <= 35 => 28,
        Some(s) if s <= 50 => 20,
        Some(s) if s <= 70 => 10,
        _ => 0,
    };
    // Require multiple independent reports before strong reputation penalty.
    let report_risk = if scam_reports >= 3 {
        ((scam_reports as i32 - 2) * 8).min(24)
    } else {
        0
    };
    let total = (trust_risk + report_risk).min(35);
    (total, trust_score, scam_reports, wallets_affected)
}

async fn get_settings(
    State(pool): State<DbPool>,
    Query(q): Query<WalletQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::get_protection_settings(&pool, &q.wallet_address).await {
        Ok(Some(s)) => Ok(Json(json!({
            "success": true,
            "data": {
                "wallet_address": s.wallet_address,
                "auto_security_scan": s.auto_security_scan,
                "high_risk_tx_warnings": s.high_risk_tx_warnings,
                "new_approval_alerts": s.new_approval_alerts,
                "new_dapp_connection_alerts": s.new_dapp_connection_alerts,
                "auto_block_high_risk": s.auto_block_high_risk,
                "emergency_lock": s.emergency_lock,
                "whitelisted_addresses": s.whitelisted_addresses,
                "updated_at": s.updated_at
            }
        }))),
        Ok(None) => Ok(Json(json!({
            "success": true,
            "data": {
                "wallet_address": q.wallet_address,
                "auto_security_scan": true,
                "high_risk_tx_warnings": true,
                "new_approval_alerts": true,
                "new_dapp_connection_alerts": true,
                "auto_block_high_risk": false,
                "emergency_lock": false,
                "whitelisted_addresses": [],
                "updated_at": null
            }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn update_settings(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<UpdateProtectionSettingsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(bad_address());
    }
    let existing = SenseiguardRepository::get_protection_settings(&pool, &req.wallet_address)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": e.to_string() })),
            )
        })?;
    let (auto, high_risk, approval, dapp, auto_block) = match &existing {
        Some(s) => (
            req.auto_security_scan.unwrap_or(s.auto_security_scan),
            req.high_risk_tx_warnings.unwrap_or(s.high_risk_tx_warnings),
            req.new_approval_alerts.unwrap_or(s.new_approval_alerts),
            req.new_dapp_connection_alerts
                .unwrap_or(s.new_dapp_connection_alerts),
            req.auto_block_high_risk.unwrap_or(s.auto_block_high_risk),
        ),
        None => (
            req.auto_security_scan.unwrap_or(true),
            req.high_risk_tx_warnings.unwrap_or(true),
            req.new_approval_alerts.unwrap_or(true),
            req.new_dapp_connection_alerts.unwrap_or(true),
            req.auto_block_high_risk.unwrap_or(false),
        ),
    };
    let emergency_lock = req
        .emergency_lock
        .or_else(|| existing.as_ref().map(|s| s.emergency_lock));
    let whitelisted_addresses = req
        .whitelisted_addresses
        .as_ref()
        .map(|v| serde_json::to_value(v).unwrap_or(serde_json::json!([])))
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|s| s.whitelisted_addresses.clone())
        });
    match SenseiguardRepository::upsert_protection_settings_full(
        &pool,
        &req.wallet_address,
        auto,
        high_risk,
        approval,
        dapp,
        auto_block,
        emergency_lock,
        whitelisted_addresses,
    )
    .await
    {
        Ok(s) => {
            let _ = SenseiguardRepository::upsert_protection_auto_scan(
                &pool,
                &req.wallet_address,
                s.auto_security_scan,
                60,
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "data": {
                    "wallet_address": s.wallet_address,
                    "auto_security_scan": s.auto_security_scan,
                    "high_risk_tx_warnings": s.high_risk_tx_warnings,
                    "new_approval_alerts": s.new_approval_alerts,
                    "new_dapp_connection_alerts": s.new_dapp_connection_alerts,
                    "auto_block_high_risk": s.auto_block_high_risk,
                    "emergency_lock": s.emergency_lock,
                    "whitelisted_addresses": s.whitelisted_addresses,
                    "updated_at": s.updated_at
                }
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn extension_scan_smart_contract(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<ExtensionScanSmartContractRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let contract_address = normalize_contract_input(&req.contract_link);
    if !is_valid_scan_contract_address(&contract_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid contract link/address",
        ));
    }
    let chain_family =
        resolve_scan_chain_family(req.chain_family.as_deref(), &contract_address);
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format",
        ));
    }

    if let Err(e) = xp_usage_service::charge_wallet_usage(
        &pool,
        &req.wallet_address,
        XpUsageAction::ContractScan,
        Some(json!({
            "contract_address": contract_address,
            "chain_family": chain_family.as_str(),
            "source": "extension_scan_smart_contract"
        })),
    )
    .await
    {
        return Err(xp_usage_route_error(e));
    }

    let scan = ScanService::scan_contract(
        &pool,
        &contract_address,
        Some(req.wallet_address.as_str()),
        req.chain_id,
        chain_family,
        normalize_solana_network(req.network.as_deref()).as_deref(),
    )
    .await
    .map_err(|e| extension_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if let Err(e) = ScanService::record_wallet_scan_history(
        &pool,
        &req.wallet_address,
        &scan,
        chain_family,
    )
    .await
    {
        eprintln!("wallet scan history: {}", e);
    }

    let (contract_reputation_risk, trust_score, scam_reports, wallets_affected) =
        compute_contract_reputation_risk(&pool, &contract_address).await;

    let scan_risk = (100 - scan.trust_score).clamp(0, 100);
    let final_risk = (scan_risk + contract_reputation_risk).clamp(0, 100);
    let risk_level_10 = ((final_risk as f64) / 10.0 * 10.0).round() / 10.0;
    let malicious = final_risk >= 75 || scam_reports >= 3 || scan.critical_risk_flags > 0;

    Ok(Json(json!({
        "screen": if malicious { "malicious_contract_detected" } else { "sensei_risk_panel" },
        "title": if malicious { "Malicious Contract Detected" } else { "Scan Smart Contract" },
        "contract_address": contract_address,
        "contract_name": scan.contract_name,
        "network": scan.network,
        "risk_score": final_risk,
        "contract_risk_score": final_risk,
        "transaction_risk_score": Value::Null,
        "final_decision_score": final_risk,
        "decision_context": "contract_baseline_only",
        "risk_level_10": risk_level_10,
        "reported_incidents": scam_reports,
        "wallets_drained_estimate": wallets_affected,
        "critical_warning": malicious,
        "findings": {
            "trust_score": trust_score.unwrap_or(scan.trust_score),
            "critical_risk_flags": scan.critical_risk_flags,
            "token_controlled": scan.token_controlled,
            "owner_admin_count": scan.owner_admin_count,
            "details": scan.details
        },
        "actions": if malicious {
            vec!["see_more_results", "proceed_at_your_own_risk"]
        } else {
            vec!["view_risk_panel", "done"]
        }
    })))
}

async fn extension_analyze_transaction_screen(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<ExtensionAnalyzeTxScreenRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format",
        ));
    }

    let chain_family = if req.chain_family.is_some() {
        parse_chain_family(req.chain_family.as_deref())
    } else if is_valid_solana_address(&req.wallet_address) {
        ChainFamily::Solana
    } else {
        ChainFamily::Evm
    };

    let result = if chain_family == ChainFamily::Solana {
        let method = req.method.as_deref().ok_or_else(|| {
            extension_error(
                StatusCode::BAD_REQUEST,
                "method is required for Solana transaction analysis",
            )
        })?;
        analyze_solana_tx_and_respond(
            &pool,
            &req.wallet_address,
            method,
            req.params.as_deref(),
            None,
        )
        .await
        .map_err(analyze_tx_route_error)?
    } else {
        analyze_tx_and_respond(
            &pool,
            &req.wallet_address,
            req.to.as_deref(),
            req.value.as_deref(),
            req.data.as_deref(),
            req.method.as_deref(),
            req.params.as_ref(),
            None,
        )
        .await
        .map_err(analyze_tx_route_error)?
    };

    let transaction_risk_score = result.risk_score.unwrap_or(0).clamp(0, 100);
    let policy_enforcement_active = result
        .threat_types
        .as_ref()
        .map(|types| {
            types
                .iter()
                .any(|t| t == crate::models::senseiguard::threat_types::POLICY_ENFORCEMENT)
        })
        .unwrap_or(false);
    let contract_risk_score = if let Some(to) = req.to.as_deref() {
        if is_valid_security_contract_address(to) {
            let (contract_reputation_risk, trust_score, _reports, _wallets) =
                compute_contract_reputation_risk(&pool, to).await;
            let trust_based = trust_score.map(|t| (100 - t).clamp(0, 100)).unwrap_or(0);
            Some((trust_based + contract_reputation_risk).clamp(0, 100))
        } else {
            None
        }
    } else {
        None
    };
    // If settings policy (e.g. emergency lock) blocked the tx, do not present that as
    // intrinsic contract maliciousness on this analysis screen.
    let effective_tx_risk_score = if policy_enforcement_active {
        0
    } else {
        transaction_risk_score
    };
    let final_decision_score = contract_risk_score
        .map(|c| c.max(effective_tx_risk_score))
        .unwrap_or(effective_tx_risk_score);
    let risk_level = if final_decision_score >= 80 {
        "Critical"
    } else if final_decision_score >= 50 {
        "High"
    } else if final_decision_score >= 30 {
        "Medium"
    } else {
        "Safe"
    };

    let tx_details = if policy_enforcement_active {
        "Wallet protection policy is enforcing a block (for example emergency lock). Contract risk is shown separately."
    } else if req.method.as_deref() == Some("eth_signTypedData_v4")
        || req.method.as_deref() == Some("eth_signTypedData")
    {
        "Typed-data signature request detected."
    } else if req.method.as_deref() == Some("eth_sign")
        || req.method.as_deref() == Some("personal_sign")
    {
        "Raw signature request detected."
    } else if result
        .threat_types
        .as_ref()
        .map(|v| v.iter().any(|t| t == "unlimited_approval"))
        .unwrap_or(false)
    {
        "This transaction grants unlimited access to your assets."
    } else {
        "Transaction analyzed for approvals, destination, and malicious patterns."
    };

    Ok(Json(json!({
        "screen": "sensei_analysis_engine",
        "title": "Sensei Analysis Engine",
        "risk_score": final_decision_score,
        "contract_risk_score": contract_risk_score,
        "transaction_risk_score": transaction_risk_score,
        "final_decision_score": final_decision_score,
        "decision_context": "transaction_intent_with_contract_context",
        "policy_enforcement_active": policy_enforcement_active,
        "risk_level": risk_level,
        "recommendation": result.recommended_action.unwrap_or_else(|| "Review before signing".to_string()),
        "transaction_details": tx_details,
        "threat_types": result.threat_types.unwrap_or_default(),
        "findings": result.explanation,
        "risk_breakdown": result.risk_breakdown,
        "chain_id": req.chain_id,
        "has_backend": true,
        "actions": {
            "cancel_transaction": true,
            "proceed_anyway": final_decision_score < 90
        }
    })))
}

async fn extension_risk_panel(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<ExtensionRiskPanelRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format",
        ));
    }

    let mut site_reputation = "Unknown".to_string();
    if let Some(domain) = req.domain.as_deref() {
        if !domain.trim().is_empty() {
            if let Ok(r) =
                evaluate_dapp_connection(&pool, &req.wallet_address, domain, Some(2)).await
            {
                site_reputation = r.safety;
            }
        }
    }

    let mut contract_risk = "Unknown".to_string();
    let mut user_reports: i64 = 0;
    if let Some(addr) = req.contract_address.as_deref() {
        let address = normalize_contract_input(addr);
        if is_valid_security_contract_address(&address) {
            let (risk, _trust, reports, _wallets) =
                compute_contract_reputation_risk(&pool, &address).await;
            user_reports = reports;
            contract_risk = if risk >= 35 {
                "High".to_string()
            } else if risk >= 15 {
                "Medium".to_string()
            } else {
                "Low".to_string()
            };
        }
    }

    Ok(Json(json!({
        "screen": "sensei_risk_panel",
        "title": "Sensei Risk Panel",
        "status": "live",
        "findings": {
            "site_reputation": site_reputation,
            "contract_risk": contract_risk,
            "user_reports": if user_reports > 0 { user_reports.to_string() } else { "None".to_string() }
        },
        "actions": ["done"]
    })))
}

async fn extension_scam_token_detected(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<ExtensionScamTokenDetectedRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format",
        ));
    }
    let contract_address = req
        .contract_address
        .clone()
        .or(req.token_address.clone())
        .map(|s| normalize_contract_input(&s));

    let mut risk_score = 85;
    let mut user_reports = 0i64;
    if let Some(addr) = contract_address.as_deref() {
        if is_valid_security_contract_address(addr) {
            let (risk, _trust, reports, _wallets) =
                compute_contract_reputation_risk(&pool, addr).await;
            risk_score = (60 + risk).clamp(0, 100);
            user_reports = reports;
        }
    }

    let token = if let Some(sym) = req
        .token_symbol
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        sym
    } else if let (Some(token_addr), Some(chain_id)) = (req.token_address.as_ref(), req.chain_id) {
        let token_addr_l = token_addr.to_lowercase();
        match rpc::fetch_erc20_symbol(&token_addr_l, Some(chain_id)).await {
            Ok(sym) if !sym.trim().is_empty() => sym,
            _ => match moralis_wallet::fetch_wallet_tokens(&req.wallet_address, chain_id).await {
                Ok(tokens) => tokens
                    .into_iter()
                    .find(|t| t.contract_address.eq_ignore_ascii_case(&token_addr_l))
                    .map(|t| t.symbol)
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "Unknown Token".to_string()),
                Err(_) => "Unknown Token".to_string(),
            },
        }
    } else {
        "Unknown Token".to_string()
    };
    Ok(Json(json!({
        "screen": "scam_token_detected",
        "title": "Scam Token Detected",
        "token": token,
        "risk_level": format!("{}/10", ((risk_score as f64) / 10.0).round()),
        "critical_warning": true,
        "reported_incidents": user_reports,
        "actions": {
            "hide_token": true,
            "analyze_contract": contract_address.is_some(),
            "report_scam": contract_address.is_some(),
            "proceed_at_your_own_risk": true
        }
    })))
}

async fn extension_screen_action(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<ExtensionScreenActionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let chain_family = parse_chain_family(req.chain_family.as_deref());
    if !is_valid_wallet_address(&req.wallet_address, chain_family) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format",
        ));
    }
    let action = req.action.trim().to_lowercase();
    match action.as_str() {
        "hide_token" => {
            let metadata = json!({
                "token_symbol": req.token_symbol,
                "token_address": req.token_address,
                "action": "hide_token"
            });
            let _ = crate::services::senseiguard_service::SenseiguardService::ingest_activity(
                &pool,
                &req.wallet_address,
                IngestActivityRequest {
                    activity_type: "blocked_interaction".to_string(),
                    title: "Token hidden from extension panel".to_string(),
                    description: Some(
                        "User hid a suspicious token from the extension view.".to_string(),
                    ),
                    metadata: Some(metadata),
                },
            )
            .await;
            Ok(Json(json!({ "success": true, "action": action })))
        }
        "report_scam" => {
            let Some(contract) = req.contract_address.as_deref() else {
                return Err(extension_error(
                    StatusCode::BAD_REQUEST,
                    "contract_address is required for report_scam",
                ));
            };
            let address = normalize_contract_input(contract);
            if !is_valid_security_contract_address(&address) {
                return Err(extension_error(
                    StatusCode::BAD_REQUEST,
                    "Invalid contract_address",
                ));
            }
            let row = SenseiguardRepository::create_scam_report(
                &pool,
                &address,
                Some(&req.wallet_address),
            )
            .await
            .map_err(|e| extension_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
            Ok(Json(json!({
                "success": true,
                "action": action,
                "report_id": row.id,
                "contract_address": row.contract_address
            })))
        }
        "analyze_contract" => {
            let Some(contract) = req.contract_address.as_deref() else {
                return Err(extension_error(
                    StatusCode::BAD_REQUEST,
                    "contract_address is required for analyze_contract",
                ));
            };
            let address = normalize_contract_input(contract);
            let chain_family =
                resolve_scan_chain_family(req.chain_family.as_deref(), &address);
            if !is_valid_scan_contract_address(&address) {
                return Err(extension_error(
                    StatusCode::BAD_REQUEST,
                    "Invalid contract_address",
                ));
            }
            if !is_valid_security_wallet_address(&req.wallet_address) {
                return Err(extension_error(
                    StatusCode::BAD_REQUEST,
                    "Invalid wallet_address format",
                ));
            }
            if let Err(e) = xp_usage_service::charge_wallet_usage(
                &pool,
                &req.wallet_address,
                XpUsageAction::ContractScan,
                Some(json!({
                    "contract_address": address,
                    "chain_family": chain_family.as_str(),
                    "source": "extension_analyze_contract"
                })),
            )
            .await
            {
                return Err(xp_usage_route_error(e));
            }
            let scan = ScanService::scan_contract(
                &pool,
                &address,
                Some(req.wallet_address.as_str()),
                req.chain_id.map(|v| v as u64),
                chain_family,
                normalize_solana_network(req.network.as_deref()).as_deref(),
            )
            .await
            .map_err(|e| extension_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
            if let Err(e) = ScanService::record_wallet_scan_history(
                &pool,
                &req.wallet_address,
                &scan,
                chain_family,
            )
            .await
            {
                eprintln!("wallet scan history: {}", e);
            }
            Ok(Json(json!({
                "success": true,
                "action": action,
                "scan_id": scan.scan_id,
                "trust_score": scan.trust_score,
                "critical_risk_flags": scan.critical_risk_flags
            })))
        }
        "proceed_anyway" | "cancel_transaction" | "done" | "go_back" => Ok(Json(json!({
            "success": true,
            "action": action
        }))),
        _ => Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Unsupported action",
        )),
    }
}

async fn analyze_solana_transaction(
    pool: &DbPool,
    req: &ExtensionAnalyzeRequest,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let method = req
        .method
        .as_deref()
        .ok_or_else(|| extension_error(StatusCode::BAD_REQUEST, "method is required for Solana analysis"))?;

    if !is_solana_sign_method(method) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Unsupported method for Solana transaction analysis",
        ));
    }

    if method != "connect" && method != "wallet_standard_connect" && req.params.is_none() {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "params is required when method is provided",
        ));
    }

    let wallet_address = req
        .wallet_address
        .clone()
        .ok_or_else(|| extension_error(StatusCode::BAD_REQUEST, "wallet_address is required"))?;

    if !is_valid_solana_address(&wallet_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format for Solana",
        ));
    }

    let domain_target = req
        .domain
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| req.url.clone().filter(|s| !s.trim().is_empty()));

    let mut domain_risk_score = 0i32;
    let mut site_safety: Option<String> = None;
    let mut website_scan_payload: Option<Value> = None;

    if let Some(ref target) = domain_target {
        if let Ok(dapp_eval) =
            evaluate_dapp_connection(pool, &wallet_address, target, None).await
        {
            domain_risk_score = dapp_eval.risk_score;
            site_safety = Some(site_safety_label(&dapp_eval.safety));
            website_scan_payload = dapp_eval
                .website_scan
                .as_ref()
                .and_then(|s| serde_json::to_value(s).ok());
        }
    }

    let malicious_programs = get_malicious_programs(pool).await;

    let solana = analyze_solana_request(
        method,
        req.params.as_deref(),
        &malicious_programs,
        domain_risk_score,
    );

    let goplus_programs = goplus_intel_service::enrich_addresses(
        pool,
        &solana.program_ids,
        "solana",
        "program",
        Some("solana"),
        8,
    )
    .await;

    let mut score = solana.risk_score;
    let mut findings = solana.findings.clone();
    let mut malicious_program_detected = solana.malicious_program_detected;
    if goplus_programs.malicious_detected {
        score = score.max(goplus_programs.risk_boost);
        malicious_program_detected = true;
        for f in goplus_programs.findings {
            if !findings.contains(&f) {
                findings.push(f);
            }
        }
    }

    let band = score_to_band(score).to_string();
    let malicious = malicious_program_detected || score >= 80;

    let domain_for_signals = req
        .domain
        .as_deref()
        .or(req.url.as_deref())
        .and_then(normalize_dapp_domain);

    record_solana_analysis_signals(
        pool,
        &wallet_address,
        domain_for_signals.as_deref(),
        score,
        &solana.program_ids,
        &solana.flagged_programs,
        malicious_program_detected,
        method,
    )
    .await;

    Ok(Json(json!({
        "risk_score": score,
        "riskScore": score,
        "risk_level_10": risk_level_10(score),
        "band": band,
        "findings": findings,
        "breakdown": solana.breakdown,
        "recommendation": solana.recommendation,
        "malicious_contract_detected": malicious,
        "malicious_program_detected": malicious_program_detected,
        "reported_incidents": 0,
        "wallets_drained_estimate": 0,
        "threat_types": solana.threat_types,
        "site_safety": site_safety,
        "site_safe": site_safety.as_deref().map(|s| s == "safe"),
        "website_scan": website_scan_payload,
        "correlation": null,
        "chain_family": "solana",
        "network": req.network,
        "url": req.url,
        "domain": req.domain,
        "program_ids": solana.program_ids,
    })))
}

async fn transaction_analyze(
    State(pool): State<DbPool>,
    axum::Json(raw): axum::Json<Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let req: ExtensionAnalyzeRequest = serde_json::from_value(raw).map_err(|_| {
        extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid request body for transaction analysis",
        )
    })?;

    if req
        .source
        .as_deref()
        .is_some_and(|s| s != "senseiguard_extension")
    {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid source. Expected senseiguard_extension",
        ));
    }

    let chain_family = parse_chain_family(req.chain_family.as_deref());
    if chain_family == ChainFamily::Solana {
        return analyze_solana_transaction(&pool, &req).await;
    }

    if let Some(method) = req.method.as_deref() {
        let allowed = [
            "eth_sendTransaction",
            "eth_sign",
            "eth_signTypedData",
            "eth_signTypedData_v3",
            "eth_signTypedData_v4",
        ];
        if !allowed.contains(&method) {
            return Err(extension_error(
                StatusCode::BAD_REQUEST,
                "Unsupported method for transaction analysis",
            ));
        }
        if req.params.is_none() {
            return Err(extension_error(
                StatusCode::BAD_REQUEST,
                "params is required when method is provided",
            ));
        }
    }

    let wallet_address = req
        .wallet_address
        .clone()
        .ok_or_else(|| extension_error(StatusCode::BAD_REQUEST, "wallet_address is required"))?;

    if !is_valid_security_wallet_address(&wallet_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format",
        ));
    }

    let (to, value, data) = extract_tx_fields(&req);

    let domain_owned = req
        .domain
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| req.url.as_deref().and_then(normalize_dapp_domain));

    match analyze_tx_and_respond(
        &pool,
        &wallet_address,
        to.as_deref(),
        value.as_deref(),
        data.as_deref(),
        req.method.as_deref(),
        req.params.as_ref(),
        domain_owned.as_deref(),
    )
    .await
    {
        Ok(out) => {
            let base_score = out.risk_score.unwrap_or(0).clamp(0, 100);
            let approval_risk = out
                .risk_breakdown
                .as_ref()
                .and_then(|v| v.get("approval_risk"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as i32;

            // Add contract/project maliciousness signals for extension worker path.
            let mut contract_reputation_risk = 0i32;
            let mut trust_score: Option<i32> = None;
            let mut scam_reports: i64 = 0;
            let mut wallets_drained_estimate: i64 = 0;
            let mut goplus_evm_findings: Vec<String> = Vec::new();
            if let Some(ref to_addr) = to {
                if is_valid_security_contract_address(to_addr) {
                    let (rep_risk, trust, reports, wallets_affected) =
                        compute_contract_reputation_risk(&pool, to_addr).await;
                    contract_reputation_risk = rep_risk;
                    trust_score = trust;
                    scam_reports = reports;
                    wallets_drained_estimate = wallets_affected;

                    let goplus_addr = goplus_intel_service::enrich_addresses(
                        &pool,
                        std::slice::from_ref(to_addr),
                        &goplus_intel_service::evm_chain_id_string(req.chain_id),
                        "contract",
                        Some("evm"),
                        1,
                    )
                    .await;
                    if goplus_addr.malicious_detected {
                        contract_reputation_risk =
                            contract_reputation_risk.max(goplus_addr.risk_boost);
                    }
                    goplus_evm_findings = goplus_addr.findings;
                }
            }

            let mut behavioral_risk = 0i32;
            let mut website_scan_payload: Option<Value> = None;
            let mut site_safety: Option<String> = None;
            if let Some(domain) = req.domain.as_deref() {
                if !domain.trim().is_empty() {
                    if let Ok(dapp_eval) =
                        evaluate_dapp_connection(&pool, &wallet_address, domain, None).await
                    {
                        behavioral_risk = dapp_eval.risk_score.clamp(0, 50);
                        site_safety = Some(dapp_eval.safety.clone());
                        website_scan_payload = dapp_eval
                            .website_scan
                            .as_ref()
                            .and_then(|s| serde_json::to_value(s).ok());
                    }
                }
            } else if let Some(url) = req.url.as_deref() {
                if !url.trim().is_empty() {
                    if let Ok(dapp_eval) =
                        evaluate_dapp_connection(&pool, &wallet_address, url, None).await
                    {
                        behavioral_risk = dapp_eval.risk_score.clamp(0, 50);
                        site_safety = Some(dapp_eval.safety.clone());
                        website_scan_payload = dapp_eval
                            .website_scan
                            .as_ref()
                            .and_then(|s| serde_json::to_value(s).ok());
                    }
                }
            }

            let elite = EliteIntelligenceService::assess_transaction(
                &pool,
                EliteAssessmentRequest {
                    wallet_address: wallet_address.clone(),
                    method: req.method.clone(),
                    to: to.clone(),
                    value: value.clone(),
                    data: data.clone(),
                    params: req.params.clone(),
                    base_protocol_risk: base_score,
                    tx_engine_risk: base_score,
                    contract_reputation_risk,
                    behavioral_risk,
                    liquidity_drop_1h_pct: req.liquidity_drop_1h_pct,
                    dev_wallet_sell_pct_supply: req.dev_wallet_sell_pct_supply,
                    token_mint_burst_count: req.token_mint_burst_count,
                    abnormal_volume_zscore: req.abnormal_volume_zscore,
                    recently_upgraded_hours_ago: req.recently_upgraded_hours_ago,
                    recently_exploited_days_ago: req.recently_exploited_days_ago,
                    interaction_count_with_contract: req.interaction_count_with_contract,
                    wallet_balance_usd: req.wallet_balance_usd,
                    tx_value_usd: req.tx_value_usd,
                    profile: parse_user_profile(req.risk_profile.as_deref()),
                },
            )
            .await;

            let score = elite.risk_score;
            let final_band = match elite.risk_tier.as_str() {
                "block" => "Block".to_string(),
                "warn" => "Warning".to_string(),
                _ => "Safe".to_string(),
            };
            let final_recommendation = elite.recommended_action.clone();
            let mut findings = findings_from_analyze(
                base_score,
                out.warning.as_deref().or(out.explanation.as_deref()),
                out.threat_types.as_ref(),
                req.domain.as_deref(),
            );
            if contract_reputation_risk > 0 {
                if scam_reports > 0 {
                    findings.push(format!(
                        "Destination contract has {} community scam report(s)",
                        scam_reports
                    ));
                }
                if let Some(t) = trust_score {
                    findings.push(format!("Destination contract trust score is low ({})", t));
                }
                findings.push("Destination contract linked to malicious-risk signals".to_string());
            }
            for f in goplus_evm_findings {
                if !findings.iter().any(|x| x == &f) {
                    findings.push(f);
                }
            }
            if behavioral_risk >= 30 {
                findings.push("Project/domain phishing risk signal detected".to_string());
            }
            for reason in &elite.reasons {
                if !findings.iter().any(|f| f == &reason.message) {
                    findings.push(reason.message.clone());
                }
            }

            Ok(Json(json!({
                "risk_score": score,
                "riskScore": score,
                "findings": findings,
                "breakdown": {
                    "approval_risk": approval_risk,
                    "contract_reputation_risk": contract_reputation_risk,
                    "behavioral_risk": behavioral_risk,
                    "elite_components": elite.component_scores
                },
                "band": final_band,
                "recommendation": final_recommendation,
                "risk_tier": elite.risk_tier,
                "confidence_score": elite.confidence_score,
                "confidence_summary": elite.confidence_summary,
                "hard_stop_codes": elite.hard_stop_codes,
                "profile": elite.profile,
                "shadow_mode": elite.shadow_mode,
                "elite_reasons": elite.reasons,
                "elite_assessment": elite,
                "chain_id": req.chain_id,
                "url": req.url,
                "domain": req.domain,
                "site_safety": site_safety,
                "site_safe": site_safety.as_deref().map(|s| s == "Safe"),
                "website_scan": website_scan_payload,
                "malicious_contract_detected": contract_reputation_risk > 0 || score >= 80,
                "risk_level_10": ((score as f64) / 10.0 * 10.0).round() / 10.0,
                "reported_incidents": scam_reports,
                "wallets_drained_estimate": wallets_drained_estimate
            })))
        }
        Err(e) => Err(analyze_tx_route_error(e)),
    }
}

async fn dapp_connection_check(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<DappConnectionCheckRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let chain_family = parse_chain_family(req.chain_family.as_deref());

    if let Some(ref wallet) = req.wallet_address {
        let trimmed = wallet.trim();
        if !trimmed.is_empty() && !is_valid_wallet_address(trimmed, chain_family) {
            return Err(bad_wallet_address(chain_family));
        }
    }

    let wallet_for_scan = req
        .wallet_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let target = req
        .url
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or(req.domain.as_deref().filter(|s| !s.trim().is_empty()))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": "domain or url is required" })),
            )
        })?;

    let mut run_side_effects = false;
    if let Some(wallet_address) = wallet_for_scan {
        match SenseiguardRepository::get_protection_settings(&pool, wallet_address).await {
            Ok(Some(settings)) if settings.new_dapp_connection_alerts => {
                run_side_effects = true;
                if let Err(e) = xp_usage_service::charge_wallet_usage(
                    &pool,
                    wallet_address,
                    XpUsageAction::DappCheck,
                    Some(json!({ "target": target, "chain_family": chain_family.as_str() })),
                )
                .await
                {
                    return Err(xp_usage_route_error(e));
                }
            }
            Ok(Some(_)) => {}
            Ok(None) if chain_family == ChainFamily::Evm => {
                let out = build_dapp_extension_response(
                    true,
                    None,
                    Some("Protection settings not found for wallet. Save settings first."),
                );
                return Ok(Json(out));
            }
            Ok(None) => {}
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e.to_string() })),
                ));
            }
        }
    }

    let scan_wallet = wallet_for_scan.unwrap_or("11111111111111111111111111111111");

    match evaluate_dapp_connection(&pool, scan_wallet, target, req.max_pages).await {
        Ok(mut r) => {
            if run_side_effects {
                if let Some(wallet_address) = wallet_for_scan {
                    if r.risk_score > 0 {
                        if let Ok(Some(wallet)) =
                            WalletRepository::get_wallet_by_address(&pool, wallet_address).await
                        {
                            let domain = normalize_dapp_domain(target);
                            let confidence = if r.risk_score >= 75 {
                                84
                            } else if r.risk_score >= 50 {
                                74
                            } else {
                                62
                            };
                            if let Ok(correlation) = ThreatCorrelationService::ingest_signal(
                                &pool,
                                ThreatSignalInput {
                                    wallet_id: wallet.id,
                                    threat_id: None,
                                    event_type: "dapp_connection_check".to_string(),
                                    signal_category: "domain".to_string(),
                                    threat_type: Some(if r.phishing_risk {
                                        "frontend_phishing".to_string()
                                    } else {
                                        "phishing_indicator".to_string()
                                    }),
                                    surface: Some("off_chain".to_string()),
                                    risk_score: r.risk_score,
                                    confidence_score: confidence,
                                    source_contract: None,
                                    domain: domain.clone(),
                                    metadata: json!({
                                        "target": target,
                                        "safety": r.safety.clone(),
                                        "phishing_risk": r.phishing_risk,
                                        "website_scan": r.website_scan.clone(),
                                        "chain_family": chain_family.as_str()
                                    }),
                                    event_time: None,
                                    kill_chain_stage: Some(kill_chain::LURE.to_string()),
                                },
                            )
                            .await
                            {
                                r.correlation = correlation;
                            }
                        }
                    }
                    if let Some(domain) = normalize_dapp_domain(target) {
                        let dapp_name = derive_dapp_name(&domain);
                        let description = r
                            .website_scan
                            .as_ref()
                            .map(|scan| {
                                format!(
                                    "Connection checked via SenseiGuard (safety: {}).",
                                    scan.safety
                                )
                            })
                            .unwrap_or_else(|| "Connection checked via SenseiGuard.".to_string());
                        let _ = SenseiguardRepository::upsert_dapp_connection(
                            &pool,
                            wallet_address,
                            &domain,
                            &dapp_name,
                            Some(&description),
                            None,
                        )
                        .await;
                    }
                }
            }
            Ok(Json(build_dapp_extension_response(false, Some(r), None)))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct MonitorRunRequest {
    wallet_address: String,
}

#[derive(Debug, Deserialize)]
struct IngestApprovalRequest {
    wallet_address: String,
    #[serde(default)]
    token_address: Option<String>,
    spender_address: String,
    #[serde(default)]
    amount_raw: Option<String>,
}

async fn monitor_run(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<MonitorRunRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(bad_address());
    }
    match run_monitor_cycle(&pool, &req.wallet_address).await {
        Ok(()) => Ok(Json(
            json!({ "success": true, "message": "Monitor cycle completed" }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn approvals_ingest(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<IngestApprovalRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) || !is_valid_security_contract_address(&req.spender_address) {
        return Err(bad_address());
    }
    if let Some(ref t) = req.token_address {
        if !is_valid_security_contract_address(t) {
            return Err(bad_address());
        }
    }
    match evaluate_approval(
        &pool,
        &req.wallet_address,
        req.token_address.as_deref(),
        &req.spender_address,
        req.amount_raw.as_deref(),
    )
    .await
    {
        Ok(r) => {
            let mut correlation: Option<crate::models::senseiguard::ThreatCorrelationSummary> =
                None;
            if r.risk_score > 0 {
                if let Ok(Some(wallet)) =
                    WalletRepository::get_wallet_by_address(&pool, &req.wallet_address).await
                {
                    let confidence = if r.risk_score >= 85 {
                        86
                    } else if r.risk_score >= 65 {
                        74
                    } else {
                        60
                    };
                    if let Ok(result) = ThreatCorrelationService::ingest_signal(
                        &pool,
                        ThreatSignalInput {
                            wallet_id: wallet.id,
                            threat_id: None,
                            event_type: "approval_ingest".to_string(),
                            signal_category: "approval".to_string(),
                            threat_type: Some(if r.risk_score >= 70 {
                                "unlimited_approval".to_string()
                            } else {
                                "malicious_transaction".to_string()
                            }),
                            surface: Some("wallet_state".to_string()),
                            risk_score: r.risk_score,
                            confidence_score: confidence,
                            source_contract: Some(req.spender_address.clone()),
                            domain: None,
                            metadata: json!({
                                "token_address": req.token_address.clone(),
                                "spender_address": req.spender_address.clone(),
                                "amount_raw": req.amount_raw.clone(),
                                "should_alert": r.should_alert
                            }),
                            event_time: None,
                            kill_chain_stage: Some(kill_chain::EXECUTE.to_string()),
                        },
                    )
                    .await
                    {
                        correlation = result;
                    }
                }
            }
            if r.should_alert {
                let _ = SenseiguardRepository::create_approval_alert(
                    &pool,
                    &req.wallet_address,
                    req.token_address.as_deref(),
                    &req.spender_address,
                    req.amount_raw.as_deref(),
                    r.risk_score,
                )
                .await;
            }
            Ok(Json(json!({
                "success": true,
                "risk_score": r.risk_score,
                "should_alert": r.should_alert,
                "warning": r.warning,
                "correlation": correlation
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct SecurityAlertsQuery {
    wallet_address: String,
    #[serde(default)]
    limit: Option<u32>,
}

async fn security_alerts(
    State(pool): State<DbPool>,
    Query(q): Query<SecurityAlertsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    let limit = q.limit.unwrap_or(20).min(100) as i64;

    let approval_alerts =
        match SenseiguardRepository::list_approval_alerts(&pool, &q.wallet_address, limit).await {
            Ok(list) => list
                .into_iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "type": "high_risk_approval",
                        "title": "High-Risk Approval Detected",
                        "contract": a.spender_address,
                        "contract_truncated": truncate_address(&a.spender_address),
                        "token_address": a.token_address,
                        "risk_score": a.risk_score,
                        "created_at": a.created_at,
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e.to_string() })),
                ));
            }
        };

    let mut general: Vec<serde_json::Value> = Vec::new();
    if let Ok(Some(wallet)) =
        WalletRepository::get_wallet_by_address(&pool, &q.wallet_address).await
    {
        if let Ok(alerts) = SenseiguardRepository::list_alerts(&pool, wallet.id, limit).await {
            for a in alerts {
                general.push(json!({
                    "id": a.id,
                    "type": "alert",
                    "title": a.title,
                    "severity": a.severity,
                    "body": a.body,
                    "created_at": a.created_at,
                }));
            }
        }
    }

    let mut data: Vec<serde_json::Value> = approval_alerts;
    data.extend(general);
    data.sort_by(|a, b| {
        let t_a = a.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        let t_b = b.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        t_b.cmp(t_a)
    });
    let data: Vec<serde_json::Value> = data.into_iter().take(limit as usize).collect();

    Ok(Json(json!({ "success": true, "data": data })))
}

async fn scan_history(
    State(pool): State<DbPool>,
    Query(q): Query<ScanHistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    let wallet = crate::models::wallet::normalize_wallet_address_for_lookup(&q.wallet_address);
    let limit = q.limit.unwrap_or(20).min(100) as i64;
    match SenseiguardRepository::list_wallet_scan_history(&pool, &wallet, limit).await {
        Ok(rows) => {
            let data: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "wallet_address": r.wallet_address,
                        "scan_type": r.scan_type,
                        "risk_score": r.risk_score,
                        "issues_found": r.issues_found,
                        "details": r.details,
                        "scanned_at": r.scanned_at
                    })
                })
                .collect();
            Ok(Json(json!({ "success": true, "data": data })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn get_threat_feed(
    State(pool): State<DbPool>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let feed = get_multichain_threat_feed(&pool).await.map_err(|_| {
        extension_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build threat feed",
        )
    })?;

    Ok(Json(json!({
        "malicious_contracts": feed.malicious_contracts,
        "malicious_domains": feed.malicious_domains,
        "malicious_programs": feed.malicious_programs,
        "malicious_domains_by_family": feed.malicious_domains_by_family,
        "trusted_domains": feed.trusted_domains,
        "sources": feed.sources,
        "updated_at": feed.updated_at,
    })))
}

async fn domain_threat_feed(
    State(pool): State<DbPool>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let feed = domain_intel_service::get_domain_threat_feed(&pool)
        .await
        .map_err(|e| extension_error(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::to_value(feed).unwrap_or(json!({
        "malicious_domains": [],
        "trusted_domains": [],
    }))))
}

async fn ingest_telemetry_events(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<TelemetryBatchRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if req.events.is_empty() {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "events must contain at least one item",
        ));
    }

    let allowed = [
        "tx_evaluated",
        "tx_blocked",
        "tx_warned",
        "domain_risk_detected",
        "user_decision",
        "sync_heartbeat",
    ];

    for ev in &req.events {
        if !allowed.contains(&ev.event_type.as_str()) {
            return Err(extension_error(
                StatusCode::BAD_REQUEST,
                "events contains unsupported type",
            ));
        }
        if chrono::DateTime::parse_from_rfc3339(&ev.at).is_err() {
            return Err(extension_error(
                StatusCode::BAD_REQUEST,
                "events.at must be RFC3339 date-time",
            ));
        }
        if let Some(s) = ev.risk_score {
            if !(0..=100).contains(&s) {
                return Err(extension_error(
                    StatusCode::BAD_REQUEST,
                    "events.riskScore must be between 0 and 100",
                ));
            }
        }
    }

    let mut accepted: i64 = 0;
    for ev in req.events {
        accepted += 1;
        let chain_family = ev
            .chain_family
            .as_deref()
            .or_else(|| {
                ev.context
                    .as_ref()
                    .and_then(|ctx| ctx.get("chain_family").or_else(|| ctx.get("chainFamily")))
                    .and_then(|v| v.as_str())
            })
            .map(|s| parse_chain_family(Some(s)))
            .unwrap_or(ChainFamily::Evm);

        let wallet_from_context = ev
            .context
            .as_ref()
            .and_then(|ctx| ctx.get("wallet_address"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(wallet_address) = wallet_from_context {
            if is_valid_wallet_address(&wallet_address, chain_family) {
                let program_ids = ev
                    .context
                    .as_ref()
                    .and_then(|ctx| ctx.get("program_ids"))
                    .cloned()
                    .or_else(|| {
                        ev.context.as_ref().and_then(|ctx| {
                            ctx.get("programIds").cloned()
                        })
                    });
                let metadata = json!({
                    "event_type": ev.event_type,
                    "risk_score": ev.risk_score,
                    "domain": ev.domain,
                    "method": ev.method,
                    "findings": ev.findings,
                    "decision": ev.decision,
                    "context": ev.context,
                    "chain_family": chain_family.as_str(),
                    "program_ids": program_ids,
                    "at": ev.at,
                });
                let _ = crate::services::senseiguard_service::SenseiguardService::ingest_activity(
                    &pool,
                    &wallet_address,
                    IngestActivityRequest {
                        activity_type: "extension_event".to_string(),
                        title: "Extension telemetry event".to_string(),
                        description: Some(format!(
                            "Telemetry batch ingest ({})",
                            chain_family.as_str()
                        )),
                        metadata: Some(metadata),
                    },
                )
                .await;
            }
        }
    }

    Ok(Json(json!({
        "success": true,
        "accepted": accepted,
        "message": "Telemetry events accepted"
    })))
}

#[derive(Debug, Deserialize)]
struct AddressSafetyQuery {
    wallet_address: String,
}

fn truncate_address(addr: &str) -> String {
    if addr.len() <= 14 {
        return addr.to_string();
    }
    format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
}

fn risk_level_from_score(score: i32) -> &'static str {
    if score >= 70 {
        "Low Risk"
    } else if score >= 40 {
        "Medium Risk"
    } else {
        "High Risk"
    }
}

async fn address_safety(
    State(pool): State<DbPool>,
    Query(q): Query<AddressSafetyQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }

    let addresses =
        match SenseiguardRepository::list_relevant_addresses_for_wallet(&pool, &q.wallet_address)
            .await
        {
            Ok(a) => a,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e.to_string() })),
                ));
            }
        };

    let mut results: Vec<serde_json::Value> = Vec::new();
    for addr in addresses {
        let trust = SenseiguardRepository::get_latest_trust_score(&pool, &addr)
            .await
            .ok()
            .flatten()
            .unwrap_or(50);
        let scam_count: i64 = SenseiguardRepository::count_scam_reports(&pool, &addr)
            .await
            .unwrap_or(0);
        let safety_score = (trust - (scam_count * 15) as i32).clamp(0, 100);
        results.push(json!({
            "address": addr,
            "address_truncated": truncate_address(&addr),
            "safety_score": safety_score,
            "risk_level": risk_level_from_score(safety_score),
        }));
    }
    results.sort_by(|a, b| {
        b.get("safety_score")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .cmp(&a.get("safety_score").and_then(|v| v.as_i64()).unwrap_or(0))
    });

    Ok(Json(json!({ "success": true, "data": results })))
}

async fn list_rules(
    State(pool): State<DbPool>,
    Query(q): Query<WalletQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::list_security_rules(&pool, &q.wallet_address).await {
        Ok(list) => Ok(Json(json!({ "success": true, "data": list }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn create_rule(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<CreateSecurityRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(bad_address());
    }
    let condition = req.condition_json.unwrap_or(serde_json::json!({}));
    let action = req.action.as_deref().unwrap_or("block");
    match SenseiguardRepository::create_security_rule(
        &pool,
        &req.wallet_address,
        &req.rule_type,
        &condition,
        action,
    )
    .await
    {
        Ok(rule) => Ok(Json(json!({ "success": true, "data": rule }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn update_rule(
    State(pool): State<DbPool>,
    Path(rule_id): Path<Uuid>,
    Query(q): Query<WalletQuery>,
    axum::Json(req): axum::Json<UpdateSecurityRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::update_security_rule(
        &pool,
        rule_id,
        &q.wallet_address,
        req.enabled,
        req.condition_json.as_ref(),
        req.action.as_deref(),
    )
    .await
    {
        Ok(Some(rule)) => Ok(Json(json!({ "success": true, "data": rule }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Rule not found" })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn delete_rule(
    State(pool): State<DbPool>,
    Path(rule_id): Path<Uuid>,
    Query(q): Query<WalletQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::delete_security_rule(&pool, rule_id, &q.wallet_address).await {
        Ok(n) => Ok(Json(json!({ "success": true, "removed": n }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn emergency_lock(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<EmergencyLockRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(bad_address());
    }
    if let Some(ref addrs) = req.whitelisted_addresses {
        for a in addrs {
            if !is_valid_security_wallet_address(a) {
                return Err(bad_address());
            }
        }
    }
    let existing = SenseiguardRepository::get_protection_settings(&pool, &req.wallet_address)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": e.to_string() })),
            )
        })?;
    let (auto, high_risk, approval, dapp, auto_block) = match &existing {
        Some(s) => (
            s.auto_security_scan,
            s.high_risk_tx_warnings,
            s.new_approval_alerts,
            s.new_dapp_connection_alerts,
            s.auto_block_high_risk,
        ),
        None => (true, true, true, true, false),
    };
    let whitelist = req
        .whitelisted_addresses
        .map(|v| serde_json::to_value(v).unwrap_or(serde_json::json!([])))
        .unwrap_or_else(|| {
            existing
                .as_ref()
                .and_then(|s| s.whitelisted_addresses.clone())
                .unwrap_or(serde_json::json!([]))
        });
    match SenseiguardRepository::upsert_protection_settings_full(
        &pool,
        &req.wallet_address,
        auto,
        high_risk,
        approval,
        dapp,
        auto_block,
        Some(req.lock),
        Some(whitelist),
    )
    .await
    {
        Ok(s) => Ok(Json(json!({
            "success": true,
            "data": {
                "wallet_address": s.wallet_address,
                "emergency_lock": s.emergency_lock,
                "whitelisted_addresses": s.whitelisted_addresses
            }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn emergency_freeze(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<EmergencyFreezeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(bad_address());
    }
    let existing = SenseiguardRepository::get_protection_settings(&pool, &req.wallet_address)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": e.to_string() })),
            )
        })?;
    let (auto, high_risk, approval, dapp, _) = match &existing {
        Some(s) => (
            s.auto_security_scan,
            s.high_risk_tx_warnings,
            s.new_approval_alerts,
            s.new_dapp_connection_alerts,
            s.auto_block_high_risk,
        ),
        None => (true, true, true, true, false),
    };
    let auto_block = req.freeze
        || existing
            .as_ref()
            .map(|s| s.auto_block_high_risk)
            .unwrap_or(false);
    let whitelist = existing
        .as_ref()
        .and_then(|s| s.whitelisted_addresses.clone())
        .unwrap_or(serde_json::json!([]));
    match SenseiguardRepository::upsert_protection_settings_full(
        &pool,
        &req.wallet_address,
        auto,
        high_risk,
        approval,
        dapp,
        auto_block,
        Some(req.freeze),
        Some(whitelist),
    )
    .await
    {
        Ok(s) => Ok(Json(json!({
            "success": true,
            "data": {
                "wallet_address": s.wallet_address,
                "freeze": s.emergency_lock,
                "emergency_lock": s.emergency_lock,
                "auto_block_high_risk": auto_block
            }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn simulate_tx(
    axum::Json(req): axum::Json<SimulateTxRequest>,
) -> Result<Json<SimulateTxResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) {
        return Err(bad_address());
    }
    let out = SimulateTxResponse {
        risk_level: "medium".to_string(),
        expected_token_loss: Some("100% of approved token".to_string()),
        hidden_internal_calls: 2,
        dangerous_functions: vec!["setApprovalForAll".to_string(), "delegatecall".to_string()],
        should_warn: true,
    };
    Ok(Json(out))
}

async fn block_malicious(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<BlockContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) || !is_valid_security_contract_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::block_contract(&pool, &req.wallet_address, &req.contract_address)
        .await
    {
        Ok(record) => Ok(Json(json!({
            "success": true,
            "data": { "id": record.id, "wallet_address": record.wallet_address, "contract_address": record.contract_address }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn block_contract(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<BlockContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) || !is_valid_security_contract_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::block_contract(&pool, &req.wallet_address, &req.contract_address)
        .await
    {
        Ok(record) => Ok(Json(json!({
            "success": true,
            "data": { "id": record.id, "wallet_address": record.wallet_address, "contract_address": record.contract_address }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn unblock_contract(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<BlockContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) || !is_valid_security_contract_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::unblock_contract(&pool, &req.wallet_address, &req.contract_address)
        .await
    {
        Ok(n) => Ok(Json(json!({ "success": true, "removed": n }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn list_blocked(
    State(pool): State<DbPool>,
    Query(q): Query<WalletQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::list_blocked_contracts(&pool, &q.wallet_address).await {
        Ok(list) => Ok(Json(json!({ "success": true, "data": list }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn add_watchlist(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<WatchlistContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) || !is_valid_security_contract_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::add_to_watchlist(&pool, &req.wallet_address, &req.contract_address)
        .await
    {
        Ok(record) => Ok(Json(json!({
            "success": true,
            "data": { "id": record.id, "wallet_address": record.wallet_address, "contract_address": record.contract_address }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn remove_from_watchlist(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<WatchlistContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) || !is_valid_security_contract_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::remove_from_watchlist(
        &pool,
        &req.wallet_address,
        &req.contract_address,
    )
    .await
    {
        Ok(n) => Ok(Json(json!({ "success": true, "removed": n }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn list_watchlist(
    State(pool): State<DbPool>,
    Query(q): Query<WalletQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::list_watchlist(&pool, &q.wallet_address).await {
        Ok(list) => Ok(Json(json!({ "success": true, "data": list }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn report_scam(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<ReportScamRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_contract_address(&req.contract_address) {
        return Err(bad_address());
    }
    if let Some(ref w) = req.reporter_wallet_address {
        if !is_valid_security_wallet_address(w) {
            return Err(bad_address());
        }
    }
    match SenseiguardRepository::create_scam_report(
        &pool,
        &req.contract_address,
        req.reporter_wallet_address.as_deref(),
    )
    .await
    {
        Ok(record) => Ok(Json(json!({
            "success": true,
            "data": { "id": record.id, "contract_address": record.contract_address }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

async fn revoke_approval(
    axum::Json(req): axum::Json<RevokeApprovalRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_security_wallet_address(&req.wallet_address) || !is_valid_security_contract_address(&req.contract_address) {
        return Err(bad_address());
    }
    let chain_id = req.chain_id.unwrap_or(1);
    let revoke_url = format!(
        "https://revoke.cash/address/{}?chainId={}",
        req.wallet_address, chain_id
    );
    Ok(Json(json!({
        "success": true,
        "message": "Revoke this approval on-chain using your wallet.",
        "revoke_url": revoke_url,
        "wallet_address": req.wallet_address,
        "contract_address": req.contract_address,
        "chain_id": chain_id
    })))
}
