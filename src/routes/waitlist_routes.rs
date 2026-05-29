use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::models::waitlist::{xp_breakdown_json, xp_claim_json};
use crate::models::wallet::is_valid_eth_address;
use crate::services::waitlist_service::{self, WaitlistXpError};
use crate::services::xp_usage_service::{self, XpUsageError};

#[derive(Debug, Deserialize)]
struct PreviewQuery {
    email: String,
}

#[derive(Debug, Deserialize)]
struct StatusQuery {
    wallet_address: Option<String>,
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsageQuery {
    wallet_address: Option<String>,
    user_id: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ClaimRequest {
    email: String,
    wallet_address: String,
}

pub fn waitlist_routes() -> Router<DbPool> {
    Router::new()
        .route("/preview", get(preview_xp))
        .route("/claim", post(claim_xp))
        .route("/status", get(get_xp_status))
        .route("/usage", get(get_xp_usage))
}

fn xp_error_status(err: &WaitlistXpError) -> StatusCode {
    match err {
        WaitlistXpError::InvalidEmail | WaitlistXpError::InvalidWalletAddress => {
            StatusCode::BAD_REQUEST
        }
        WaitlistXpError::WalletNotConnected | WaitlistXpError::EmailNotOnWaitlist => {
            StatusCode::NOT_FOUND
        }
        WaitlistXpError::EmailAlreadyClaimed { .. } => StatusCode::CONFLICT,
        WaitlistXpError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn xp_error_body(err: &WaitlistXpError) -> Value {
    let mut body = json!({
        "success": false,
        "error": err.message(),
    });
    match err {
        WaitlistXpError::EmailAlreadyClaimed {
            claimed_by_user_id,
        } => {
            body["claimed_by_user_id"] = json!(claimed_by_user_id);
        }
        WaitlistXpError::Database(e) => {
            eprintln!("waitlist xp error: {}", e);
        }
        _ => {}
    }
    body
}

async fn preview_xp(
    State(pool): State<DbPool>,
    Query(q): Query<PreviewQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match waitlist_service::preview_xp_by_email(&pool, &q.email).await {
        Ok(breakdown) => Ok(Json(json!({
            "success": true,
            "data": xp_breakdown_json(&breakdown),
        }))),
        Err(e) => Err((xp_error_status(&e), Json(xp_error_body(&e)))),
    }
}

async fn claim_xp(
    State(pool): State<DbPool>,
    Json(body): Json<ClaimRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match waitlist_service::claim_xp(&pool, &body.email, &body.wallet_address).await {
        Ok(result) => {
            let message = if result.already_claimed {
                if result.email_mismatch {
                    "This wallet already claimed waitlist XP with a different email"
                } else {
                    "Waitlist XP was already claimed for this wallet"
                }
            } else {
                "Waitlist XP claimed successfully"
            };
            Ok(Json(json!({
                "success": true,
                "message": message,
                "already_claimed": result.already_claimed,
                "email_mismatch": result.email_mismatch,
                "data": xp_claim_json(&result.claim),
            })))
        }
        Err(e) => Err((xp_error_status(&e), Json(xp_error_body(&e)))),
    }
}

async fn get_xp_status(
    State(pool): State<DbPool>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let wallet_address = q
        .wallet_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let user_id = q
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let result = match (wallet_address, user_id) {
        (Some(addr), _) => {
            if !is_valid_eth_address(addr) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": "Invalid wallet address format"
                    })),
                ));
            }
            waitlist_service::get_claim_for_wallet(&pool, addr).await
        }
        (None, Some(uid)) => waitlist_service::get_claim_for_user_id(&pool, uid).await,
        (None, None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": "wallet_address or user_id is required"
                })),
            ));
        }
    };

    match result {
        Ok(Some(claim)) => Ok(Json(json!({
            "success": true,
            "claimed": true,
            "data": xp_claim_json(&claim),
        }))),
        Ok(None) => Ok(Json(json!({
            "success": true,
            "claimed": false,
            "data": null,
        }))),
        Err(e) => Err((xp_error_status(&e), Json(xp_error_body(&e)))),
    }
}

async fn get_xp_usage(
    State(pool): State<DbPool>,
    Query(q): Query<UsageQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let wallet_address = q
        .wallet_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let user_id = q
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(addr) = wallet_address {
        if !is_valid_eth_address(addr) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": "Invalid wallet address format"
                })),
            ));
        }
    }

    match xp_usage_service::list_usage_for_account(
        &pool,
        wallet_address,
        user_id,
        q.limit,
    )
    .await
    {
        Ok(payload) => {
            if payload
                .get("error")
                .and_then(|v| v.as_str())
                .is_some()
            {
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(payload),
                ))
            } else {
                Ok(Json(payload))
            }
        }
        Err(XpUsageError::Database(e)) => {
            eprintln!("waitlist usage error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Database error" })),
            ))
        }
        Err(XpUsageError::InsufficientXp { .. }) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": "Unexpected usage lookup error" })),
        )),
    }
}
