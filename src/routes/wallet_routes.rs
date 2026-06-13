use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Error;

use crate::clients::{etherscan, rpc};
use crate::db::DbPool;
use crate::models::wallet::{
    is_valid_eth_address, is_valid_wallet_address, parse_chain_family, ConnectWalletRequest,
    ChainFamily, ALLOWED_EVM_WALLET_TYPES, ALLOWED_SOLANA_WALLET_TYPES, CHAIN_ID_MAX, CHAIN_ID_MIN,
    normalize_evm_wallet_type,
    SOLANA_MAINNET_CHAIN_ID,
};
use crate::repositories::dashboard_user_repository::DashboardUserRepository;
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::dashboard_user_service;
use crate::services::senseiguard_service::SenseiguardService;
use crate::services::waitlist_service;
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

#[derive(Debug, Deserialize)]
struct WalletAgeQuery {
    /// EVM chain_id (Etherscan API V2). Default 1 (Ethereum).
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
        .route("/{address}/age", get(get_wallet_age))
        .route("/{address}", get(get_wallet))
        .route("/{address}", delete(disconnect_wallet))
}

async fn connect_wallet(
    State(pool): State<DbPool>,
    Json(request): Json<ConnectWalletRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let chain_family = parse_chain_family(request.chain_family.as_deref());

    if !is_valid_wallet_address(&request.address, chain_family) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "message": "Invalid wallet address format",
                "error": "Invalid wallet address format"
            })),
        ));
    }

    let wt_raw = request.wallet_type.to_lowercase();
    let wt = match chain_family {
        ChainFamily::Evm => match normalize_evm_wallet_type(&wt_raw) {
            Some(canonical) => canonical.to_string(),
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "message": format!(
                            "Invalid wallet_type; allowed for {}: {}",
                            chain_family.as_str(),
                            ALLOWED_EVM_WALLET_TYPES.join(", ")
                        ),
                        "error": "Invalid wallet_type"
                    })),
                ));
            }
        },
        ChainFamily::Solana => {
            if !ALLOWED_SOLANA_WALLET_TYPES.contains(&wt_raw.as_str()) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "message": format!(
                            "Invalid wallet_type; allowed for {}: {}",
                            chain_family.as_str(),
                            ALLOWED_SOLANA_WALLET_TYPES.join(", ")
                        ),
                        "error": "Invalid wallet_type"
                    })),
                ));
            }
            wt_raw
        }
    };

    let effective_chain_id = match chain_family {
        ChainFamily::Evm => {
            if request.chain_id < CHAIN_ID_MIN || request.chain_id > CHAIN_ID_MAX {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "message": "Invalid chain_id",
                        "error": "Invalid chain_id"
                    })),
                ));
            }
            request.chain_id
        }
        ChainFamily::Solana => {
            if request.chain_id == 0 {
                SOLANA_MAINNET_CHAIN_ID
            } else if request.chain_id < CHAIN_ID_MIN || request.chain_id > CHAIN_ID_MAX {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "message": "Invalid chain_id",
                        "error": "Invalid chain_id"
                    })),
                ));
            } else {
                request.chain_id
            }
        }
    };

    let mut req = request;
    req.wallet_type = wt.clone();
    req.chain_id = effective_chain_id;

    // If frontend doesn't send user_id, create/get dashboard user (random user_id, display_name, user_number).
    let dashboard_user = if req.user_id.is_none()
        || req
            .user_id
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
    {
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

    let xp_user_id = req
        .user_id
        .clone()
        .or_else(|| dashboard_user.as_ref().map(|du| du.user_id.clone()));

    match WalletService::connect_wallet(&pool, req).await {
        Ok(wallet) => {
            // Ensure wallet row has user_id so overview "active wallets" count includes this wallet.
            if let Some(ref du) = dashboard_user {
                let _ =
                    WalletRepository::update_wallet_user_id(&pool, &wallet.address, &du.user_id)
                        .await;
            }
            if let Some(user_id) = xp_user_id.as_deref() {
                if let Err(e) =
                    waitlist_service::ensure_welcome_xp_claim(&pool, user_id, &wallet.address)
                        .await
                {
                    eprintln!("ensure_welcome_xp_claim on connect: {}", e);
                }
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
                "message": "Invalid wallet address format",
                "error": "Invalid wallet address format"
            })),
        )),
        Err(e) => {
            eprintln!("Error connecting wallet: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "message": "Failed to connect wallet",
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
            let balance_eth = rpc::wei_hex_to_eth_f64(&hex_wei);
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

/// First on-chain activity timestamp for an address (Etherscan V2 indexer). Not wallet DB state.
async fn get_wallet_age(
    State(_pool): State<DbPool>,
    Path(address): Path<String>,
    Query(q): Query<WalletAgeQuery>,
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
    let cid = chain_id as u64;
    let bytecode = rpc::fetch_bytecode(&address, Some(cid))
        .await
        .unwrap_or_default();
    let is_contract = !bytecode.is_empty();

    match etherscan::fetch_wallet_first_activity(&address, cid, is_contract).await {
        Ok(Some(act)) => {
            let now = chrono::Utc::now().timestamp();
            let age_seconds = now.saturating_sub(act.unix_ts as i64).max(0);
            let first_at = chrono::DateTime::<chrono::Utc>::from_timestamp(act.unix_ts as i64, 0)
                .map(|t| t.to_rfc3339());
            Ok(Json(json!({
                "success": true,
                "data": {
                    "address": address,
                    "chain_id": chain_id,
                    "is_contract": is_contract,
                    "first_activity_unix": act.unix_ts,
                    "first_activity_at": first_at,
                    "age_seconds": age_seconds,
                    "age_days": (age_seconds as f64 / 86400.0 * 100.0).round() / 100.0,
                    "first_tx_hash": act.tx_hash,
                    "first_block": act.block_number,
                    "source": act.source,
                    "methodology": "Oldest normal tx, else oldest internal tx, else contract creation (contracts only). Requires Etherscan V2 support for chain_id; set ETHERSCAN_API_KEY."
                }
            })))
        }
        Ok(None) => Ok(Json(json!({
            "success": true,
            "data": {
                "address": address,
                "chain_id": chain_id,
                "is_contract": is_contract,
                "first_activity_unix": Value::Null,
                "first_activity_at": Value::Null,
                "age_seconds": Value::Null,
                "age_days": Value::Null,
                "first_tx_hash": Value::Null,
                "first_block": Value::Null,
                "source": "none",
                "methodology": "No indexed normal/internal txs and no deployment record for this chain (or address never used here)."
            }
        }))),
        Err(e) => {
            tracing::warn!("get_wallet_age: {}", e);
            Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "success": false,
                    "error": e,
                    "hint": "Set ETHERSCAN_API_KEY and ensure the chain is supported by Etherscan API V2."
                })),
            ))
        }
    }
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
