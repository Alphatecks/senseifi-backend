use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use rust_decimal::Decimal;
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::models::onchain_payment::{
    CreateSubscriptionCycleRequest, OnchainSubscribeRequest, OnchainWebhookRequest,
    TriggerDueChargeJobRequest, UpsertOnchainPaymentProfileRequest,
};
use crate::repositories::onchain_payment_repository::{
    CreateSubscriptionCycleInput, OnchainPaymentRepository,
};
use crate::repositories::subscription_repository::SubscriptionRepository;
use crate::services::onchain_payment_webhook_service::OnchainPaymentWebhookService;
use crate::services::onchain_subscribe_service::OnchainSubscribeService;
use crate::services::plan_catalog::OnchainPriceTable;

pub fn payment_routes() -> Router<DbPool> {
    Router::new()
        .route("/plans", get(list_onchain_plans))
        .route("/onchain-subscribe", post(onchain_subscribe))
        .route("/profile", post(upsert_payment_profile))
        .route("/cycles", post(create_subscription_cycle))
        .route("/jobs/trigger-due", post(trigger_due_charge_job))
        .route("/jobs/expire-grace", post(trigger_grace_expiry_job))
        .route("/webhooks/base-indexer", post(base_indexer_webhook))
        .route("/webhooks/payment-contract", post(payment_contract_webhook))
}

/// Lists Pro / Pro+ / Premium SKUs with monthly and annual USD prices (no Stripe). Requires onchain billing enabled.
async fn list_onchain_plans() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !OnchainPaymentWebhookService::is_onchain_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "Onchain payments are disabled" })),
        ));
    }
    let table = OnchainPriceTable::from_env_or_default();
    Ok(Json(json!({
        "success": true,
        "data": table.list_descriptors()
    })))
}

/// Creates or updates `user_subscriptions` for the chosen plan, then upserts the onchain payment profile.
/// `subscription_id_bytes32` is `keccak256` of the UTF-8 hyphenated UUID (for `upsertBilling` on the payment contract).
async fn onchain_subscribe(
    State(pool): State<DbPool>,
    Json(req): Json<OnchainSubscribeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match OnchainSubscribeService::subscribe(&pool, req).await {
        Ok(data) => Ok(Json(json!({ "success": true, "data": data }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn upsert_payment_profile(
    State(pool): State<DbPool>,
    Json(req): Json<UpsertOnchainPaymentProfileRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !OnchainPaymentWebhookService::is_onchain_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "Onchain payments are disabled" })),
        ));
    }
    let chain_id = req.chain_id.unwrap_or(8453);
    let max_charge_usdc = req.max_charge_usdc.and_then(Decimal::from_f64_retain);
    match OnchainPaymentWebhookService::upsert_payment_profile(
        &pool,
        req.user_id.trim(),
        req.payer_address.trim(),
        chain_id,
        req.token_contract.trim(),
        req.payment_contract.trim(),
        max_charge_usdc,
    )
    .await
    {
        Ok(()) => Ok(Json(json!({ "success": true }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn create_subscription_cycle(
    State(pool): State<DbPool>,
    Json(req): Json<CreateSubscriptionCycleRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !OnchainPaymentWebhookService::is_onchain_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "Onchain payments are disabled" })),
        ));
    }
    let sub = SubscriptionRepository::get_by_user_id(&pool, req.user_id.trim())
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "success": false, "error": "No subscription found for user_id" })),
            )
        })?;
    let amount_due_usdc = Decimal::from_f64_retain(req.amount_due_usdc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid amount_due_usdc" })),
        )
    })?;
    let cycle = OnchainPaymentRepository::create_subscription_cycle(
        &pool,
        CreateSubscriptionCycleInput {
            user_id: req.user_id.trim(),
            subscription_id: sub.id,
            plan: req.plan.trim(),
            billing_cycle: req.billing_cycle.trim(),
            amount_due_usdc,
            due_at: req.due_at,
            grace_expires_at: req.grace_expires_at,
        },
    )
    .await
    .map_err(internal_error)?;
    Ok(Json(json!({ "success": true, "data": cycle })))
}

async fn trigger_due_charge_job(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(req): Json<TriggerDueChargeJobRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_job_token(&headers)?;
    if !OnchainPaymentWebhookService::is_onchain_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "Onchain payments are disabled" })),
        ));
    }
    let limit = req.limit.clamp(1, 500);
    match OnchainPaymentWebhookService::trigger_due_charge_job(&pool, limit).await {
        Ok(attempt_ids) => Ok(Json(json!({
            "success": true,
            "data": { "submitted_attempt_ids": attempt_ids, "shadow_mode": OnchainPaymentWebhookService::is_shadow_mode() }
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn trigger_grace_expiry_job(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(req): Json<TriggerDueChargeJobRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    verify_internal_job_token(&headers)?;
    if !OnchainPaymentWebhookService::is_onchain_enabled() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "Onchain payments are disabled" })),
        ));
    }
    let limit = req.limit.clamp(1, 500);
    match OnchainPaymentWebhookService::handle_grace_expiry_job(&pool, limit).await {
        Ok(cancelled_count) => Ok(Json(
            json!({ "success": true, "data": { "cancelled_cycles": cancelled_count } }),
        )),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn base_indexer_webhook(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(req): Json<OnchainWebhookRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !OnchainPaymentWebhookService::is_onchain_enabled() {
        return Ok(Json(
            json!({ "success": true, "ignored": true, "reason": "onchain disabled" }),
        ));
    }
    OnchainPaymentWebhookService::verify_webhook_token(
        "ONCHAIN_BASE_INDEXER_WEBHOOK_TOKEN",
        headers.get("x-webhook-token").and_then(|v| v.to_str().ok()),
    )
    .map_err(bad_request_error)?;

    match OnchainPaymentWebhookService::process_contract_event(&pool, "base-indexer", &req).await {
        Ok(()) => Ok(Json(json!({ "success": true }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

async fn payment_contract_webhook(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Json(req): Json<OnchainWebhookRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !OnchainPaymentWebhookService::is_onchain_enabled() {
        return Ok(Json(
            json!({ "success": true, "ignored": true, "reason": "onchain disabled" }),
        ));
    }
    OnchainPaymentWebhookService::verify_webhook_token(
        "ONCHAIN_PAYMENT_CONTRACT_WEBHOOK_TOKEN",
        headers.get("x-webhook-token").and_then(|v| v.to_str().ok()),
    )
    .map_err(bad_request_error)?;

    match OnchainPaymentWebhookService::process_contract_event(&pool, "payment-contract", &req)
        .await
    {
        Ok(()) => Ok(Json(json!({ "success": true }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

fn verify_internal_job_token(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let expected = std::env::var("ONCHAIN_INTERNAL_JOB_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "ONCHAIN_INTERNAL_JOB_TOKEN must be configured" })),
            )
        })?;
    let provided = headers
        .get("x-internal-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if provided != expected {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Unauthorized" })),
        ));
    }
    Ok(())
}

fn internal_error(e: sqlx::Error) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "success": false, "error": format!("{e}") })),
    )
}

fn bad_request_error(e: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "success": false, "error": e })),
    )
}
