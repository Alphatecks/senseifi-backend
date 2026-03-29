// Protection Control: 5 toggle switches (GET/PUT settings) + functionality endpoints.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::models::senseiguard::{
    BlockContractRequest, CreateSecurityRuleRequest, DappConnectionCheckRequest,
    EmergencyLockRequest, IngestActivityRequest, ReportScamRequest, SimulateTxRequest,
    SimulateTxResponse, UpdateProtectionSettingsRequest, UpdateSecurityRuleRequest,
    WatchlistContractRequest,
};
use crate::models::wallet::is_valid_eth_address;
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::protection_engine::{
    analyze_tx_and_respond, build_dapp_check_response, evaluate_approval, evaluate_dapp_connection,
    run_monitor_cycle,
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

fn bad_address() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": "Invalid address format (0x + 40 hex)"
        })),
    )
}

pub fn protection_routes() -> Router<DbPool> {
    Router::new()
        .route("/settings", get(get_settings).put(update_settings))
        .route("/transaction/analyze", post(transaction_analyze))
        .route("/threat-feed", get(get_threat_feed))
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
        .route("/block-contract", post(block_contract).delete(unblock_contract))
        .route("/blocked", get(list_blocked))
        .route("/watchlist", post(add_watchlist).delete(remove_from_watchlist).get(list_watchlist))
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
    // Back-compat fields (legacy mobile/web callers).
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    data: Option<String>,
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

fn extract_tx_fields(req: &ExtensionAnalyzeRequest) -> (Option<String>, Option<String>, Option<String>) {
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
    let report_risk = (scam_reports as i32 * 12).min(40);
    let total = (trust_risk + report_risk).min(45);
    (total, trust_score, scam_reports, wallets_affected)
}

async fn get_settings(
    State(pool): State<DbPool>,
    Query(q): Query<WalletQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_eth_address(&q.wallet_address) {
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
    if !is_valid_eth_address(&req.wallet_address) {
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
            req.new_dapp_connection_alerts.unwrap_or(s.new_dapp_connection_alerts),
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
    let emergency_lock = req.emergency_lock.or_else(|| existing.as_ref().map(|s| s.emergency_lock));
    let whitelisted_addresses = req
        .whitelisted_addresses
        .as_ref()
        .map(|v| serde_json::to_value(v).unwrap_or(serde_json::json!([])))
        .or_else(|| existing.as_ref().and_then(|s| s.whitelisted_addresses.clone()));
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

    if req.source.as_deref().is_some_and(|s| s != "senseiguard_extension") {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid source. Expected senseiguard_extension",
        ));
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

    let wallet_address = req.wallet_address.clone().ok_or_else(|| {
        extension_error(
            StatusCode::BAD_REQUEST,
            "wallet_address is required",
        )
    })?;

    if !is_valid_eth_address(&wallet_address) {
        return Err(extension_error(
            StatusCode::BAD_REQUEST,
            "Invalid wallet_address format",
        ));
    }

    let (to, value, data) = extract_tx_fields(&req);

    match analyze_tx_and_respond(
        &pool,
        &wallet_address,
        to.as_deref(),
        value.as_deref(),
        data.as_deref(),
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
            if let Some(ref to_addr) = to {
                if is_valid_eth_address(to_addr) {
                    let (rep_risk, trust, reports, wallets_affected) =
                        compute_contract_reputation_risk(&pool, to_addr).await;
                    contract_reputation_risk = rep_risk;
                    trust_score = trust;
                    scam_reports = reports;
                    wallets_drained_estimate = wallets_affected;
                }
            }

            let mut behavioral_risk = 0i32;
            if let Some(domain) = req.domain.as_deref() {
                if !domain.trim().is_empty() {
                    if let Ok(dapp_eval) = evaluate_dapp_connection(&pool, &wallet_address, domain).await {
                        behavioral_risk = dapp_eval.risk_score.clamp(0, 50);
                    }
                }
            }

            let score = (base_score + contract_reputation_risk + behavioral_risk).clamp(0, 100);
            let final_band = crate::services::protection_engine::score_to_band(score).to_string();
            let final_recommendation = if score >= 80 {
                "Reject transaction".to_string()
            } else if score >= 30 {
                "Review before signing".to_string()
            } else {
                "Proceed".to_string()
            };
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
            if behavioral_risk >= 30 {
                findings.push("Project/domain phishing risk signal detected".to_string());
            }

            Ok(Json(json!({
                "risk_score": score,
                "riskScore": score,
                "findings": findings,
                "breakdown": {
                    "approval_risk": approval_risk,
                    "contract_reputation_risk": contract_reputation_risk,
                    "behavioral_risk": behavioral_risk
                },
                "band": final_band,
                "recommendation": final_recommendation,
                "chain_id": req.chain_id,
                "url": req.url,
                "domain": req.domain,
                "malicious_contract_detected": contract_reputation_risk > 0 || score >= 80,
                "risk_level_10": ((score as f64) / 10.0 * 10.0).round() / 10.0,
                "reported_incidents": scam_reports,
                "wallets_drained_estimate": wallets_drained_estimate
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "message": e,
            })),
        )),
    }
}

async fn dapp_connection_check(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<DappConnectionCheckRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_eth_address(&req.wallet_address) {
        return Err(bad_address());
    }
    let settings = match SenseiguardRepository::get_protection_settings(&pool, &req.wallet_address).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            let out = build_dapp_check_response(true, None);
            return Ok(Json(serde_json::to_value(&out).unwrap_or(json!({ "skipped": true }))));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": e.to_string() })),
            ));
        }
    };
    if !settings.new_dapp_connection_alerts {
        let out = build_dapp_check_response(true, None);
        return Ok(Json(serde_json::to_value(&out).unwrap_or(json!({ "skipped": true }))));
    }
    match evaluate_dapp_connection(&pool, &req.wallet_address, &req.domain).await {
        Ok(r) => {
            let out = build_dapp_check_response(false, Some(r));
            Ok(Json(serde_json::to_value(&out).unwrap_or(json!({}))))
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
    if !is_valid_eth_address(&req.wallet_address) {
        return Err(bad_address());
    }
    match run_monitor_cycle(&pool, &req.wallet_address).await {
        Ok(()) => Ok(Json(json!({ "success": true, "message": "Monitor cycle completed" }))),
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
    if !is_valid_eth_address(&req.wallet_address) || !is_valid_eth_address(&req.spender_address) {
        return Err(bad_address());
    }
    if let Some(ref t) = req.token_address {
        if !is_valid_eth_address(t) {
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
                "warning": r.warning
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
    if !is_valid_eth_address(&q.wallet_address) {
        return Err(bad_address());
    }
    let limit = q.limit.unwrap_or(20).min(100) as i64;

    let approval_alerts = match SenseiguardRepository::list_approval_alerts(&pool, &q.wallet_address, limit).await {
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
    if let Ok(Some(wallet)) = WalletRepository::get_wallet_by_address(&pool, &q.wallet_address).await {
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
    if !is_valid_eth_address(&q.wallet_address) {
        return Err(bad_address());
    }
    let limit = q.limit.unwrap_or(20).min(100) as i64;
    match SenseiguardRepository::list_wallet_scan_history(&pool, &q.wallet_address, limit).await {
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
    let malicious_contracts = sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT contract_address
        FROM scam_reports
        WHERE contract_address ~* '^0x[0-9a-f]{40}$'
        ORDER BY contract_address
        LIMIT 500
        "#,
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| extension_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to build threat feed"))?;

    let domains_raw = sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT metadata->>'domain' AS domain
        FROM activity_feed
        WHERE metadata IS NOT NULL
          AND metadata ? 'domain'
        ORDER BY created_at DESC
        LIMIT 1000
        "#,
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| extension_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to build threat feed"))?;

    let mut malicious_domains: Vec<String> = Vec::new();
    for d in domains_raw.into_iter().flatten() {
        let d = d.trim().to_lowercase();
        if d.is_empty() || malicious_domains.iter().any(|x| x == &d) {
            continue;
        }
        malicious_domains.push(d);
        if malicious_domains.len() >= 500 {
            break;
        }
    }

    Ok(Json(json!({
        "malicious_contracts": malicious_contracts,
        "malicious_domains": malicious_domains,
        "updated_at": Utc::now(),
    })))
}

async fn ingest_telemetry_events(
    State(pool): State<DbPool>,
    axum::Json(req): axum::Json<TelemetryBatchRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if req.events.is_empty() {
        return Err(extension_error(StatusCode::BAD_REQUEST, "events must contain at least one item"));
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
            return Err(extension_error(StatusCode::BAD_REQUEST, "events contains unsupported type"));
        }
        if chrono::DateTime::parse_from_rfc3339(&ev.at).is_err() {
            return Err(extension_error(StatusCode::BAD_REQUEST, "events.at must be RFC3339 date-time"));
        }
        if let Some(s) = ev.risk_score {
            if !(0..=100).contains(&s) {
                return Err(extension_error(StatusCode::BAD_REQUEST, "events.riskScore must be between 0 and 100"));
            }
        }
    }

    let mut accepted: i64 = 0;
    for ev in req.events {
        accepted += 1;
        let wallet_from_context = ev
            .context
            .as_ref()
            .and_then(|ctx| ctx.get("wallet_address"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(wallet_address) = wallet_from_context {
            if is_valid_eth_address(&wallet_address) {
                let metadata = json!({
                    "event_type": ev.event_type,
                    "risk_score": ev.risk_score,
                    "domain": ev.domain,
                    "method": ev.method,
                    "findings": ev.findings,
                    "decision": ev.decision,
                    "context": ev.context,
                    "at": ev.at,
                });
                let _ = crate::services::senseiguard_service::SenseiguardService::ingest_activity(
                    &pool,
                    &wallet_address,
                    IngestActivityRequest {
                        activity_type: "extension_event".to_string(),
                        title: "Extension telemetry event".to_string(),
                        description: Some("Telemetry batch ingest".to_string()),
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
    format!("{}...{}", &addr[..6], &addr[addr.len()-4..])
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
    if !is_valid_eth_address(&q.wallet_address) {
        return Err(bad_address());
    }

    let addresses = match SenseiguardRepository::list_relevant_addresses_for_wallet(&pool, &q.wallet_address).await {
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
        let trust = SenseiguardRepository::get_latest_trust_score(&pool, &addr).await.ok().flatten().unwrap_or(50);
        let scam_count: i64 = SenseiguardRepository::count_scam_reports(&pool, &addr).await.unwrap_or(0);
        let safety_score = (trust - (scam_count * 15) as i32).clamp(0, 100);
        results.push(json!({
            "address": addr,
            "address_truncated": truncate_address(&addr),
            "safety_score": safety_score,
            "risk_level": risk_level_from_score(safety_score),
        }));
    }
    results.sort_by(|a, b| b.get("safety_score").and_then(|v| v.as_i64()).unwrap_or(0).cmp(&a.get("safety_score").and_then(|v| v.as_i64()).unwrap_or(0)));

    Ok(Json(json!({ "success": true, "data": results })))
}

async fn list_rules(
    State(pool): State<DbPool>,
    Query(q): Query<WalletQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_eth_address(&q.wallet_address) {
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
    if !is_valid_eth_address(&req.wallet_address) {
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
    if !is_valid_eth_address(&q.wallet_address) {
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
    if !is_valid_eth_address(&q.wallet_address) {
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
    if !is_valid_eth_address(&req.wallet_address) {
        return Err(bad_address());
    }
    if let Some(ref addrs) = req.whitelisted_addresses {
        for a in addrs {
            if !is_valid_eth_address(a) {
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
        .unwrap_or_else(|| existing.as_ref().and_then(|s| s.whitelisted_addresses.clone()).unwrap_or(serde_json::json!([])));
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
    if !is_valid_eth_address(&req.wallet_address) {
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
    let auto_block = req.freeze || existing.as_ref().map(|s| s.auto_block_high_risk).unwrap_or(false);
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
    if !is_valid_eth_address(&req.wallet_address) {
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
    if !is_valid_eth_address(&req.wallet_address) || !is_valid_eth_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::block_contract(&pool, &req.wallet_address, &req.contract_address).await {
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
    if !is_valid_eth_address(&req.wallet_address) || !is_valid_eth_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::block_contract(&pool, &req.wallet_address, &req.contract_address).await {
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
    if !is_valid_eth_address(&req.wallet_address) || !is_valid_eth_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::unblock_contract(&pool, &req.wallet_address, &req.contract_address).await {
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
    if !is_valid_eth_address(&q.wallet_address) {
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
    if !is_valid_eth_address(&req.wallet_address) || !is_valid_eth_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::add_to_watchlist(&pool, &req.wallet_address, &req.contract_address).await {
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
    if !is_valid_eth_address(&req.wallet_address) || !is_valid_eth_address(&req.contract_address) {
        return Err(bad_address());
    }
    match SenseiguardRepository::remove_from_watchlist(&pool, &req.wallet_address, &req.contract_address).await {
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
    if !is_valid_eth_address(&q.wallet_address) {
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
    if !is_valid_eth_address(&req.contract_address) {
        return Err(bad_address());
    }
    if let Some(ref w) = req.reporter_wallet_address {
        if !is_valid_eth_address(w) {
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
    if !is_valid_eth_address(&req.wallet_address) || !is_valid_eth_address(&req.contract_address) {
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
