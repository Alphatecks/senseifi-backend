use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::models::subscription::{CreateCheckoutSessionRequest, CreatePortalSessionRequest};
use crate::services::onchain_payment_webhook_service::OnchainPaymentWebhookService;
use crate::services::subscription_service::SubscriptionService;

#[derive(Debug, Deserialize)]
struct SubscriptionStatusQuery {
    user_id: String,
}

pub fn subscription_routes() -> Router<DbPool> {
    Router::new()
        .route("/plans", get(list_plans))
        .route("/status", get(subscription_status))
        .route("/checkout", post(create_checkout_session))
        .route("/portal", post(create_portal_session))
        .route("/webhook", post(stripe_webhook))
}

async fn list_plans() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match SubscriptionService::list_plans() {
        Ok(plans) => Ok(Json(json!({ "success": true, "data": plans }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn subscription_status(
    State(pool): State<DbPool>,
    Query(q): Query<SubscriptionStatusQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user_id = q.user_id.trim();
    if user_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "user_id is required" })),
        ));
    }

    match SubscriptionService::get_subscription_status(&pool, user_id).await {
        Ok(Some(status)) => Ok(Json(json!({ "success": true, "data": status }))),
        Ok(None) => Ok(Json(json!({
            "success": true,
            "data": {
                "user_id": user_id,
                "plan": "free",
                "billing_cycle": "monthly",
                "status": "inactive"
            }
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn create_checkout_session(
    State(pool): State<DbPool>,
    Json(req): Json<CreateCheckoutSessionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !stripe_checkout_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "Stripe checkout is disabled. Use onchain wallet subscription flow."
            })),
        ));
    }
    let user_id = req.user_id.trim();
    if user_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "user_id is required" })),
        ));
    }

    match SubscriptionService::create_checkout_session(
        &pool,
        user_id,
        &req.plan,
        req.billing_cycle.as_deref(),
        req.success_url.as_deref(),
        req.cancel_url.as_deref(),
    )
    .await
    {
        Ok(url) => Ok(Json(json!({
            "success": true,
            "data": { "checkout_url": url }
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn create_portal_session(
    State(pool): State<DbPool>,
    Json(req): Json<CreatePortalSessionRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !stripe_checkout_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "Stripe portal is disabled for onchain subscription mode."
            })),
        ));
    }
    let user_id = req.user_id.trim();
    if user_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "user_id is required" })),
        ));
    }

    match SubscriptionService::create_billing_portal_session(
        &pool,
        user_id,
        req.return_url.as_deref(),
    )
    .await
    {
        Ok(url) => Ok(Json(json!({
            "success": true,
            "data": { "portal_url": url }
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn stripe_webhook(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !stripe_webhook_enabled() {
        return Ok(Json(json!({
            "success": true,
            "ignored": true,
            "reason": "stripe webhook disabled"
        })));
    }
    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if signature.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Missing stripe-signature header" })),
        ));
    }

    match SubscriptionService::process_webhook(&pool, signature, &body).await {
        Ok(()) => Ok(Json(json!({ "success": true }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

fn stripe_checkout_enabled() -> bool {
    std::env::var("PAYMENTS_ALLOW_STRIPE_CHECKOUT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(!OnchainPaymentWebhookService::is_onchain_enabled())
}

fn stripe_webhook_enabled() -> bool {
    std::env::var("PAYMENTS_ALLOW_STRIPE_WEBHOOK")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}
