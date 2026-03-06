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

use crate::clients::rpc;
use crate::db::DbPool;
use crate::models::wallet::{
    ConnectWalletRequest, ALLOWED_WALLET_TYPES, CHAIN_ID_MAX, CHAIN_ID_MIN, is_valid_eth_address,
};
use crate::repositories::dashboard_user_repository::DashboardUserRepository;
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::dashboard_user_service;
use crate::services::senseiguard_service::SenseiguardService;
use crate::services::wallet_service::WalletService;

#[derive(Debug, Deserialize)]
struct ListWalletsQuery {
    /// Active account address: only this wallet is returned (the one used for security checks).
    for_address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BalanceQuery {
    #[serde(default)]
    chain_id: Option<i64>,
}

pub fn wallet_routes() -> Router<DbPool> {
    Router::new()
        .route("/", get(list_connected_wallets))
        .route("/connect", post(connect_wallet))
        .route("/{address}/balance", get(get_wallet_balance))
        .route("/{address}/dashboard-user", get(get_dashboard_user))
        .route("/{address}/modal", get(get_connected_wallet_modal))
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
    req.wallet_type = wt.clone();

    // If frontend doesn't send user_id, create/get dashboard user (random user_id, display_name, user_number).
    let dashboard_user = if req.user_id.is_none() || req.user_id.as_deref().map(|s| s.trim().is_empty()).unwrap_or(true) {
        match dashboard_user_service::get_or_create_for_wallet(&pool, &req.address).await {
            Ok(du) => {
                req.user_id = Some(du.user_id.clone());
                Some(du)
            }
            Err(e) => {
                eprintln!("get_or_create_for_wallet: {}", e);
                None
            }
        }
    } else {
        None
    };

    match WalletService::connect_wallet(&pool, req).await {
        Ok(wallet) => {
            // Ensure wallet row has user_id so overview "active wallets" count includes this wallet.
            if let Some(ref du) = dashboard_user {
                let _ = WalletRepository::update_wallet_user_id(&pool, &wallet.address, &du.user_id).await;
            }
            let mut body = json!({
                "success": true,
                "data": wallet
            });
            if let Some(du) = dashboard_user {
                body["dashboard_user"] = serde_json::json!({
                    "user_id": du.user_id,
                    "display_name": du.display_name,
                    "user_number": du.user_number,
                    "user_label": du.user_label()
                });
            }
            Ok(Json(body))
        }
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

async fn get_wallet_balance(
    Path(address): Path<String>,
    Query(q): Query<BalanceQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_request_address());
    }
    let chain_id = q.chain_id.unwrap_or(1);
    if chain_id < CHAIN_ID_MIN || chain_id > CHAIN_ID_MAX {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid chain_id" })),
        ));
    }
    let chain_id_u = chain_id as u64;
    match rpc::fetch_balance_wei(&address, Some(chain_id_u)).await {
        Ok(hex_wei) => {
            let balance_eth = parse_wei_hex(&hex_wei).map(|w| w as f64 / 1e18).unwrap_or(0.0);
            Ok(Json(json!({
                "success": true,
                "data": {
                    "balance_wei": hex_wei,
                    "balance_eth": balance_eth,
                    "chain_id": chain_id
                }
            })))
        }
        Err(e) => {
            eprintln!("fetch_balance_wei: {}", e);
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "success": false,
                    "error": "Could not fetch balance (RPC not configured or unavailable)"
                })),
            ))
        }
    }
}

/// Parse hex wei to u64 (for ETH display). Large balances may exceed u64; then we return 0.0 ETH.
fn parse_wei_hex(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

async fn get_connected_wallet_modal(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_request_address());
    }
    const ACTIVITY_LIMIT: i64 = 20;
    match SenseiguardService::get_connected_wallet_modal(&pool, &address, ACTIVITY_LIMIT).await {
        Ok(modal) => Ok(Json(json!({
            "success": true,
            "data": modal
        }))),
        Err(sqlx::Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Wallet not found"
            })),
        )),
        Err(e) => {
            eprintln!("get_connected_wallet_modal: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Failed to load wallet modal"
                })),
            ))
        }
    }
}

async fn get_dashboard_user(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err(bad_request_address());
    }
    match DashboardUserRepository::get_by_wallet(&pool, &address).await {
        Ok(Some(du)) => Ok(Json(json!({
            "success": true,
            "data": {
                "user_id": du.user_id,
                "display_name": du.display_name,
                "user_number": du.user_number,
                "user_label": du.user_label()
            }
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "No dashboard user for this wallet. Connect the wallet first."
            })),
        )),
        Err(e) => {
            eprintln!("get_dashboard_user: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Failed to load dashboard user"
                })),
            ))
        }
    }
}

async fn list_connected_wallets(
    State(pool): State<DbPool>,
    Query(q): Query<ListWalletsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let address = match &q.for_address {
        Some(a) if !a.is_empty() => a.as_str(),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": "for_address is required (active account address used for security checks)"
                })),
            ));
        }
    };
    if !is_valid_eth_address(address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid wallet address format"
            })),
        ));
    }
    match WalletService::list_connected_wallets_for_account(&pool, address).await {
        Ok((data, total)) => Ok(Json(json!({
            "success": true,
            "data": data,
            "pagination": { "page": 1, "per_page": total.max(1), "total": total }
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
