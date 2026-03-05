use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::json;
use uuid::Uuid;

use crate::db::DbPool;
use crate::models::senseiguard::{ScanContractRequest, ScanContractResponse};
use crate::models::wallet::is_valid_eth_address;
use crate::services::scan_service::ScanService;

/// If input looks like a URL, try to extract 0x address; else return trimmed string for validation.
fn normalize_contract_input(input: &str) -> String {
    let s = input.trim();
    if s.is_empty() {
        return String::new();
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

pub fn scan_routes() -> Router<DbPool> {
    Router::new()
        .route("/", post(scan_contract))
        .route("/:scan_id", get(get_scan_details))
}

async fn scan_contract(
    State(pool): State<DbPool>,
    axum::Json(request): axum::Json<ScanContractRequest>,
) -> Result<Json<ScanContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let address = normalize_contract_input(&request.contract_address);
    if !is_valid_eth_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid contract address or link. Use 0x + 40 hex chars or an Etherscan-style URL."
            })),
        ));
    }
    let for_address = request
        .for_address
        .as_ref()
        .map(|s| normalize_contract_input(s))
        .filter(|s| is_valid_eth_address(s));
    let for_ref = for_address.as_deref();
    match ScanService::scan_contract(&pool, &address, for_ref).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": e.to_string()
            })),
        )),
    }
}

async fn get_scan_details(
    State(pool): State<DbPool>,
    Path(scan_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let id = scan_id
        .parse::<Uuid>()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": "Invalid scan ID" })),
            )
        })?;
    match ScanService::get_scan_details(&pool, id).await {
        Ok(Some(scan)) => Ok(Json(json!({
            "success": true,
            "data": scan
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Scan not found" })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}
