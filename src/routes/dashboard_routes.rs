use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::models::senseiguard::IngestActivityRequest;
use crate::models::wallet::is_valid_eth_address;
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::dashboard_user_service;
use crate::services::senseiguard_service::SenseiguardService;

#[derive(Debug, serde::Deserialize)]
struct RecentActivityQuery {
    #[serde(default = "default_per_wallet")]
    per_wallet: i64,
}
fn default_per_wallet() -> i64 {
    20
}

#[derive(Debug, serde::Deserialize)]
struct LiveActivityFeedQuery {
    /// Scope to this user's wallets when set.
    user_id: Option<String>,
    #[serde(default = "default_page")]
    page: u32,
    #[serde(default = "default_per_page_10")]
    per_page: u32,
}
fn default_page() -> u32 {
    1
}
fn default_per_page_10() -> u32 {
    10
}

#[derive(Debug, serde::Deserialize)]
struct OverviewQuery {
    /// Current user id (e.g. from auth or dashboard_user from connect). Scopes to that user's wallets.
    user_id: Option<String>,
    /// When user_id is missing, use this wallet's user_id so a connected wallet still shows in overview.
    wallet_address: Option<String>,
    #[serde(default = "default_timeline_limit")]
    timeline_limit: i64,
}
fn default_timeline_limit() -> i64 {
    20
}

/// One entry in the threat intelligence catalog (for the "Threat Intelligence" modal).
#[derive(Debug, serde::Serialize)]
struct ThreatIntelligenceItem {
    title: String,
    description: String,
    severity: String,
}

pub fn dashboard_routes() -> Router<DbPool> {
    Router::new()
        .route("/overview", get(dashboard_overview))
        .route("/activity/recent", get(recent_activity_all_wallets))
        .route("/activity/feed", get(live_activity_feed))
        .route("/threat-intelligence", get(threat_intelligence_catalog))
        .route("/{address}/metrics", get(dashboard_metrics))
        .route("/{address}/summary", get(dashboard_summary))
        .route("/{address}/security-status", get(security_status))
        .route("/{address}/scan", post(run_full_scan).get(get_latest_scan_report))
        .route("/{address}/threats", get(list_threats))
        .route("/{address}/scans", get(list_scans))
        .route("/{address}/alerts", get(list_alerts))
        .route("/{address}/activity", get(list_activity).post(ingest_activity))
        .route("/{address}/approvals", get(list_approvals))
        .route("/{address}/transaction-monitoring", get(list_transaction_monitoring))
        .route("/{address}/assets", get(list_assets))
}

fn bad_address() -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": "Invalid wallet address format"
        })),
    )
}

async fn dashboard_overview(
    State(pool): State<DbPool>,
    Query(q): Query<OverviewQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let limit = q.timeline_limit.clamp(1, 100);
    // Prefer user_id. When missing, resolve from wallet_address so "connected wallet" still shows 1 active.
    let user_id = q
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let user_id = match user_id {
        Some(id) => id,
        None => {
            let addr = q.wallet_address.as_deref().map(str::trim).filter(|s| !s.is_empty());
            match addr.filter(|a| is_valid_eth_address(a)) {
                Some(address) => {
                    match WalletRepository::get_wallet_by_address(&pool, address).await {
                        Ok(Some(w)) => {
                            if let Some(uid) = w.user_id.filter(|s| !s.is_empty()) {
                                uid
                            } else {
                                // Wallet connected but user_id null (e.g. legacy). Assign dashboard user.
                                match dashboard_user_service::get_or_create_for_wallet(
                                    &pool,
                                    address,
                                )
                                .await
                                {
                                    Ok(du) => du.user_id,
                                    Err(_) => String::new(),
                                }
                            }
                        }
                        Ok(None) => String::new(),
                        Err(_) => String::new(),
                    }
                }
                None => String::new(),
            }
        }
    };
    // When we resolved user_id from wallet_address, persist it on the wallet so it stays linked.
    if !user_id.is_empty() {
        if let Some(addr) = q.wallet_address.as_deref().filter(|a| is_valid_eth_address(a)) {
            let _ = WalletRepository::update_wallet_user_id(&pool, addr, &user_id).await;
        }
    }
    // Fallback: when both user_id and wallet_address are missing, use the most recently connected active wallet so "1 connected" shows.
    // Set OVERVIEW_SINGLE_WALLET_FALLBACK=false to disable (e.g. multi-tenant).
    let single_wallet_fallback = std::env::var("OVERVIEW_SINGLE_WALLET_FALLBACK")
        .map(|s| s != "false")
        .unwrap_or(true);
    let user_id = if user_id.is_empty() && single_wallet_fallback {
        match WalletRepository::get_all_active_wallets(&pool).await {
            Ok(wallets) if !wallets.is_empty() => {
                // Use most recently connected wallet (already ordered by connected_at DESC).
                let w = &wallets[0];
                tracing::info!(
                    "dashboard_overview: no user_id/wallet_address; active_wallets={}, using fallback for {}",
                    wallets.len(),
                    &w.address
                );
                if let Some(uid) = w.user_id.as_ref().filter(|s| !s.is_empty()) {
                    uid.clone()
                } else {
                    match dashboard_user_service::get_or_create_for_wallet(&pool, &w.address).await
                    {
                        Ok(du) => {
                            let _ =
                                WalletRepository::update_wallet_user_id(&pool, &w.address, &du.user_id)
                                    .await;
                            du.user_id
                        }
                        Err(e) => {
                            tracing::warn!("dashboard_overview: get_or_create_for_wallet failed for {}: {}", w.address, e);
                            String::new()
                        }
                    }
                }
            }
            Ok(_wallets) => {
                tracing::info!("dashboard_overview: no user_id/wallet_address; active_wallets=0, overview will show 0");
                user_id
            }
            Err(e) => {
                tracing::warn!("dashboard_overview: get_all_active_wallets failed: {}", e);
                user_id
            }
        }
    } else {
        user_id
    };
    if user_id.is_empty() {
        tracing::debug!("dashboard_overview: no user_id or wallet_address; overview will show 0 active wallets");
    }
    match SenseiguardService::get_dashboard_overview(&pool, &user_id, limit).await {
        Ok(overview) => Ok(Json(json!({
            "success": true,
            "data": overview
        }))),
        Err(e) => {
            eprintln!("dashboard_overview: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to load dashboard overview" })),
            ))
        }
    }
}

/// Threat intelligence catalog for the "View threat" / Threat Intelligence modal.
/// Returns known threat types with title, description, and severity (no wallet required).
async fn threat_intelligence_catalog() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let catalog: Vec<ThreatIntelligenceItem> = vec![
        ThreatIntelligenceItem {
            title: "Phishing DApp".to_string(),
            description: "Fake Uniswap interface prompting wallet connect".to_string(),
            severity: "High".to_string(),
        },
        ThreatIntelligenceItem {
            title: "Crypto Scam Website".to_string(),
            description: "Imitation of a popular exchange to steal credentials".to_string(),
            severity: "Critical".to_string(),
        },
        ThreatIntelligenceItem {
            title: "Malicious Transaction".to_string(),
            description: "Transaction that drains funds or grants unlimited approvals".to_string(),
            severity: "High".to_string(),
        },
        ThreatIntelligenceItem {
            title: "Risky Token".to_string(),
            description: "Token with hidden mint, blacklist, or drainer logic".to_string(),
            severity: "Medium".to_string(),
        },
        ThreatIntelligenceItem {
            title: "Unlimited Approval".to_string(),
            description: "Token approval that allows unlimited spend without user consent".to_string(),
            severity: "High".to_string(),
        },
        ThreatIntelligenceItem {
            title: "Signature Phishing".to_string(),
            description: "Request for a signature that could authorize asset transfer or permissions".to_string(),
            severity: "Critical".to_string(),
        },
    ];
    Ok(Json(json!({
        "success": true,
        "data": catalog
    })))
}

async fn dashboard_metrics(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    match SenseiguardService::get_dashboard_metrics(&pool, &address).await {
        Ok(metrics) => Ok(Json(json!({
            "success": true,
            "data": metrics
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("dashboard_metrics: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to load metrics" })),
            ))
        }
    }
}

async fn dashboard_summary(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    match SenseiguardService::dashboard_summary(&pool, &address).await {
        Ok(summary) => Ok(Json(json!({
            "success": true,
            "data": summary
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("dashboard_summary error: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to load dashboard" })),
            ))
        }
    }
}

async fn security_status(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    match SenseiguardService::get_security_status(&pool, &address).await {
        Ok(status) => Ok(Json(json!({
            "success": true,
            "data": status
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("security_status: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to get security status" })),
            ))
        }
    }
}

async fn run_full_scan(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    match SenseiguardService::run_full_scan(&pool, &address).await {
        Ok(report) => Ok(Json(json!({
            "success": true,
            "data": {
                "scan_id": report.scan_id,
                "wallet_id": report.wallet_id,
                "score": report.score,
                "status": report.status,
                "scanned_at": report.scanned_at,
                "observations": report.observations
            }
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("run_full_scan: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to run scan" })),
            ))
        }
    }
}

async fn get_latest_scan_report(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    match SenseiguardService::get_latest_scan_report(&pool, &address).await {
        Ok(Some(report)) => Ok(Json(json!({
            "success": true,
            "data": {
                "scan_id": report.scan_id,
                "wallet_id": report.wallet_id,
                "score": report.score,
                "status": report.status,
                "scanned_at": report.scanned_at,
                "observations": report.observations
            }
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "No scan found for this wallet. Run a full scan first." })),
        )),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("get_latest_scan_report: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to get scan report" })),
            ))
        }
    }
}

#[derive(serde::Deserialize)]
struct LimitQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 {
    20
}

#[derive(Debug, serde::Deserialize)]
struct ApprovalsQuery {
    #[serde(default)]
    period: Option<String>,
    #[serde(default = "default_approvals_limit")]
    limit: i64,
}
fn default_approvals_limit() -> i64 {
    50
}

#[derive(Debug, serde::Deserialize)]
struct TransactionMonitoringQuery {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default = "default_tm_per_page")]
    per_page: Option<u32>,
}
fn default_tm_per_page() -> Option<u32> {
    Some(10)
}

async fn list_threats(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    let limit = q.limit.clamp(1, 100);
    match SenseiguardService::list_threats(&pool, &address, limit).await {
        Ok(list) => Ok(Json(json!({
            "success": true,
            "data": list
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("list_threats: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to list threats" })),
            ))
        }
    }
}

async fn list_scans(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    let limit = q.limit.clamp(1, 100);
    match SenseiguardService::list_scans(&pool, &address, limit).await {
        Ok(list) => Ok(Json(json!({
            "success": true,
            "data": list
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("list_scans: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to list scans" })),
            ))
        }
    }
}

async fn list_alerts(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    let limit = q.limit.clamp(1, 100);
    match SenseiguardService::list_alerts(&pool, &address, limit).await {
        Ok(list) => Ok(Json(json!({
            "success": true,
            "data": list
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("list_alerts: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to list alerts" })),
            ))
        }
    }
}

async fn recent_activity_all_wallets(
    State(pool): State<DbPool>,
    Query(q): Query<RecentActivityQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let per_wallet = q.per_wallet.clamp(1, 50);
    match SenseiguardService::recent_activity_all_wallets(&pool, per_wallet).await {
        Ok(list) => Ok(Json(json!({
            "success": true,
            "data": list.iter().map(|(addr, acts)| json!({ "address": addr, "activities": acts })).collect::<Vec<_>>()
        }))),
        Err(e) => {
            eprintln!("recent_activity_all_wallets: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to load recent activity" })),
            ))
        }
    }
}

async fn live_activity_feed(
    State(pool): State<DbPool>,
    Query(q): Query<LiveActivityFeedQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let page = q.page.max(1);
    let per_page = q.per_page.clamp(1, 50);
    let user_id = q.user_id.as_deref().filter(|s| !s.trim().is_empty());
    match SenseiguardService::get_live_activity_feed(&pool, user_id, page, per_page).await {
        Ok((items, total)) => Ok(Json(json!({
            "success": true,
            "data": items,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total
            }
        }))),
        Err(e) => {
            eprintln!("live_activity_feed: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to load activity feed" })),
            ))
        }
    }
}

async fn list_approvals(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
    Query(q): Query<ApprovalsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    let limit = q.limit.clamp(1, 100);
    let period = q.period.as_deref();
    match SenseiguardService::list_approvals(&pool, &address, period, limit).await {
        Ok(list) => Ok(Json(json!({
            "success": true,
            "data": list
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("list_approvals: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to list approvals" })),
            ))
        }
    }
}

async fn list_transaction_monitoring(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
    Query(q): Query<TransactionMonitoringQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 50);
    match SenseiguardService::list_transaction_monitoring(&pool, &address, page, per_page).await {
        Ok((data, total)) => Ok(Json(json!({
            "success": true,
            "data": data,
            "pagination": { "page": page, "per_page": per_page, "total": total }
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("list_transaction_monitoring: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to list transaction monitoring" })),
            ))
        }
    }
}

async fn list_activity(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    let limit = q.limit.clamp(1, 100);
    match SenseiguardService::list_activity(&pool, &address, limit).await {
        Ok(list) => Ok(Json(json!({
            "success": true,
            "data": list
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("list_activity: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to list activity" })),
            ))
        }
    }
}

async fn ingest_activity(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
    headers: HeaderMap,
    Json(body): Json<IngestActivityRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    if let Ok(secret) = std::env::var("INGEST_SECRET") {
        let token = headers
            .get("x-ingest-token")
            .and_then(|v: &http::HeaderValue| v.to_str().ok())
            .unwrap_or("");
        if token != secret {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "success": false, "error": "Invalid or missing x-ingest-token" })),
            ));
        }
    }
    if body.activity_type.is_empty() || body.title.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "activity_type and title are required"
            })),
        ));
    }
    match SenseiguardService::ingest_activity(&pool, &address, body).await {
        Ok(activity) => Ok(Json(json!({
            "success": true,
            "data": activity
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("ingest_activity: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to ingest activity" })),
            ))
        }
    }
}

async fn list_assets(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_address());
    }
    match SenseiguardService::list_assets(&pool, &address).await {
        Ok(list) => Ok(Json(json!({
            "success": true,
            "data": list
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("list_assets: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to list assets" })),
            ))
        }
    }
}
