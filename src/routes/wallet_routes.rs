use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde_json::{json, Value};
use sqlx::Error;

use crate::db::DbPool;
use crate::models::wallet::ConnectWalletRequest;
use crate::services::wallet_service::WalletService;

pub fn wallet_routes() -> Router<DbPool> {
    Router::new()
        .route("/connect", post(connect_wallet))
        .route("/{address}/status", get(get_wallet_status))
        .route("/{address}", get(get_wallet).delete(disconnect_wallet))
}

async fn connect_wallet(
    State(pool): State<DbPool>,
    Json(request): Json<ConnectWalletRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match WalletService::connect_wallet(&pool, request).await {
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
            eprintln!("Error connecting wallet: {:?}", e);
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

async fn get_wallet_status(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
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
