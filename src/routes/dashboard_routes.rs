use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::models::wallet::is_valid_eth_address;
use crate::services::senseiguard_service::SenseiguardService;

pub fn dashboard_routes() -> Router<DbPool> {
    Router::new()
        .route("/{address}/summary", get(dashboard_summary))
        .route("/{address}/security-status", get(security_status))
        .route("/{address}/scan", post(run_full_scan).get(get_latest_scan_report))
        .route("/{address}/threats", get(list_threats))
        .route("/{address}/scans", get(list_scans))
        .route("/{address}/alerts", get(list_alerts))
        .route("/{address}/activity", get(list_activity))
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
