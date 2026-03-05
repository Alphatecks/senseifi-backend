use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, delete},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Error;

use crate::db::DbPool;
use crate::models::wallet::{
    ConnectWalletRequest, ALLOWED_WALLET_TYPES, CHAIN_ID_MAX, CHAIN_ID_MIN, is_valid_eth_address,
};
use crate::services::wallet_service::WalletService;

#[derive(Debug, Deserialize)]
struct ListWalletsQuery {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default = "default_per_page")]
    per_page: Option<u32>,
}
fn default_per_page() -> Option<u32> {
    Some(6)
}

pub fn wallet_routes() -> Router<DbPool> {
    Router::new()
        .route("/", get(list_connected_wallets))
        .route("/connect", post(connect_wallet))
        .route("/{address}/status", get(get_wallet_status))
        .route("/{address}", get(get_wallet))
        .route("/{address}", delete(disconnect_wallet))
}

async fn connect_wallet(
    State(pool): State<DbPool>,
    Json(request): Json<ConnectWalletRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&request.address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid wallet address format"
            })),
        ));
    }
    if request.chain_id < CHAIN_ID_MIN || request.chain_id > CHAIN_ID_MAX {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid chain_id"
            })),
        ));
    }
    let wt = request.wallet_type.to_lowercase();
    if !ALLOWED_WALLET_TYPES.contains(&wt.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid wallet_type; allowed: metamask, coinbase"
            })),
        ));
    }
    let mut req = request;
    req.wallet_type = wt;
    match WalletService::connect_wallet(&pool, req).await {
        Ok(wallet) => Ok(Json(json!({
            "success": true,
            "data": wallet
        }))),
        Err(Error::RowNotFound) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid wallet address format"
            })),
        )),
        Err(e) => {
            eprintln!("Error connecting wallet: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Failed to connect wallet"
                })),
            ))
        }
    }
}

fn bad_request_address() -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": "Invalid wallet address format"
        })),
    )
}

async fn list_connected_wallets(
    State(pool): State<DbPool>,
    Query(q): Query<ListWalletsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(6).clamp(1, 50);
    match WalletService::list_connected_wallets(&pool, page, per_page).await {
        Ok((data, total)) => Ok(Json(json!({
            "success": true,
            "data": data,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total
            }
        }))),
        Err(e) => {
            eprintln!("list_connected_wallets: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Failed to list connected wallets"
                })),
            ))
        }
    }
}

async fn get_wallet_status(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_request_address());
    }
    match WalletService::get_wallet_status(&pool, &address).await {
        Ok(status) => Ok(Json(json!({
            "success": true,
            "data": status
        }))),
        Err(Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Wallet not found"
            })),
        )),
        Err(e) => {
            eprintln!("Error getting wallet status: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Failed to get wallet status"
                })),
            ))
        }
    }
}

async fn get_wallet(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_request_address());
    }
    match WalletService::get_wallet(&pool, &address).await {
        Ok(wallet) => Ok(Json(json!({
            "success": true,
            "data": wallet
        }))),
        Err(Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Wallet not found"
            })),
        )),
        Err(e) => {
            eprintln!("Error getting wallet: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Failed to get wallet"
                })),
            ))
        }
    }
}

async fn disconnect_wallet(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_request_address());
    }
    match WalletService::disconnect_wallet(&pool, &address).await {
        Ok(_) => Ok(Json(json!({
            "success": true,
            "message": "Wallet disconnected successfully"
        }))),
        Err(Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Wallet not found"
            })),
        )),
        Err(e) => {
            eprintln!("Error disconnecting wallet: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Failed to disconnect wallet"
                })),
            ))
        }
    }
}
