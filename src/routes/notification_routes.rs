use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use sqlx::Error;

use crate::db::DbPool;
use crate::models::notification::{
    notification_list_json, MarkAllNotificationsReadRequest, MarkNotificationReadRequest,
    WalletNotificationQuery,
};
use crate::models::wallet::is_valid_dashboard_wallet_address;
use crate::services::notification_service::NotificationService;

pub fn notification_routes() -> Router<DbPool> {
    Router::new()
        .route("/", get(list_notifications))
        .route("/read", post(mark_notification_read))
        .route("/read-all", post(mark_all_notifications_read))
}

async fn list_notifications(
    State(pool): State<DbPool>,
    Query(q): Query<WalletNotificationQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_dashboard_wallet_address(&q.wallet_address) {
        return Err(bad_address());
    }

    match NotificationService::list_for_wallet(&pool, &q.wallet_address, q.limit.unwrap_or(50))
        .await
    {
        Ok(response) => Ok(Json(notification_list_json(
            response.unread_count,
            &response.notifications,
        ))),
        Err(Error::RowNotFound) => Err(bad_address()),
        Err(e) => {
            eprintln!("list_notifications: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to load notifications" })),
            ))
        }
    }
}

async fn mark_notification_read(
    State(pool): State<DbPool>,
    axum::Json(body): axum::Json<MarkNotificationReadRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_dashboard_wallet_address(&body.wallet_address) {
        return Err(bad_address());
    }

    match NotificationService::mark_read(
        &pool,
        &body.wallet_address,
        &body.source_type,
        body.source_id,
    )
    .await
    {
        Ok(true) => Ok(Json(json!({ "success": true, "read": true }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Notification not found" })),
        )),
        Err(Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("mark_notification_read: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to mark notification read" })),
            ))
        }
    }
}

async fn mark_all_notifications_read(
    State(pool): State<DbPool>,
    axum::Json(body): axum::Json<MarkAllNotificationsReadRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_dashboard_wallet_address(&body.wallet_address) {
        return Err(bad_address());
    }

    match NotificationService::mark_all_read(&pool, &body.wallet_address).await {
        Ok(updated) => Ok(Json(json!({
            "success": true,
            "updated": updated
        }))),
        Err(Error::RowNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Wallet not found" })),
        )),
        Err(e) => {
            eprintln!("mark_all_notifications_read: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Failed to mark notifications read" })),
            ))
        }
    }
}

fn bad_address() -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": "Invalid wallet address format (EVM or Solana)"
        })),
    )
}
