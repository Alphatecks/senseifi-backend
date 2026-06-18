use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::models::onchain_payment::{
    CreateSubscriptionCycleRequest, OnchainSubscribeRequest, OnchainWebhookRequest,
    TriggerDueChargeJobRequest, UpsertOnchainPaymentProfileRequest,
};
use crate::repositories::onchain_payment_repository::{
    BillingHistoryRow, CreateSubscriptionCycleInput, OnchainPaymentRepository,
};
use crate::repositories::subscription_repository::SubscriptionRepository;
use crate::services::onchain_payment_webhook_service::OnchainPaymentWebhookService;
use crate::services::onchain_subscribe_service::OnchainSubscribeService;
use crate::services::plan_catalog::OnchainPriceTable;

pub fn payment_routes() -> Router<DbPool> {
    Router::new()
        .route("/plans", get(list_onchain_plans))
        .route("/billing-context", get(get_billing_context))
        .route("/billing-history", get(list_billing_history))
        .route("/onchain-subscribe", post(onchain_subscribe))
        .route("/profile", post(upsert_payment_profile))
        .route("/cycles", post(create_subscription_cycle))
        .route("/jobs/trigger-due", post(trigger_due_charge_job))
        .route("/jobs/expire-grace", post(trigger_grace_expiry_job))
        .route("/webhooks/base-indexer", post(base_indexer_webhook))
        .route("/webhooks/payment-contract", post(payment_contract_webhook))
}

#[derive(Debug, serde::Deserialize)]
struct BillingContextQuery {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    wallet_address: Option<String>,
}

/// Which connected wallet to use for onchain USDC billing (EVM on Base / Base Sepolia).
async fn get_billing_context(
    State(pool): State<DbPool>,
    Query(q): Query<BillingContextQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user_id = q.user_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let wallet_address = q
        .wallet_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if user_id.is_none() && wallet_address.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "user_id or wallet_address is required"
            })),
        ));
    }
    match OnchainSubscribeService::billing_context(&pool, user_id, wallet_address).await {
        Ok(data) => Ok(Json(json!({ "success": true, "data": data }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": e })),
        )),
    }
}

#[derive(Debug, serde::Deserialize)]
struct BillingHistoryQuery {
    user_id: String,
    #[serde(default = "default_page")]
    page: u32,
    #[serde(default = "default_per_page")]
    per_page: u32,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    status: Option<String>,
}
fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    10
}

#[derive(Debug, serde::Serialize)]
struct BillingHistoryItem {
    id: String,
    plan_name: String,
    amount: String,
    currency: String,
    purchase_date: String,
    end_date: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_url: Option<String>,
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

/// Table API for billing history page.
async fn list_billing_history(
    State(pool): State<DbPool>,
    Query(q): Query<BillingHistoryQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user_id = q.user_id.trim();
    if user_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "user_id is required" })),
        ));
    }
    let page = q.page.max(1);
    let per_page = q.per_page.clamp(1, 100);

    let (rows, total) = OnchainPaymentRepository::list_billing_history(
        &pool,
        user_id,
        page,
        per_page,
        q.search.as_deref(),
        q.status.as_deref(),
    )
    .await
    .map_err(internal_error)?;

    let data: Vec<BillingHistoryItem> = rows.into_iter().map(map_billing_row).collect();
    Ok(Json(json!({
        "success": true,
        "data": data,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": ((total.max(0) as u32) + per_page - 1) / per_page
        }
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
    let chain_id = req.chain_id.unwrap_or_else(crate::models::wallet::onchain_billing_chain_id);
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

fn map_billing_row(row: BillingHistoryRow) -> BillingHistoryItem {
    BillingHistoryItem {
        id: row.cycle_id.to_string(),
        plan_name: plan_label(&row.plan),
        amount: format!("${} USDC", row.amount_due_usdc.round_dp(2)),
        currency: "USDC".to_string(),
        purchase_date: format_yyyy_mm_dd(row.purchase_date),
        end_date: format_yyyy_mm_dd(row.end_date),
        status: billing_status_label(&row.status),
        action_url: build_receipt_url(row.chain_id, row.onchain_tx_hash.as_deref()),
    }
}

fn plan_label(plan: &str) -> String {
    let p = plan.trim().to_ascii_lowercase();
    if p.is_empty() {
        return "Plan".to_string();
    }
    format!("{} + plan", capitalize(&p))
}

fn capitalize(s: &str) -> String {
    let mut out = s.to_string();
    if let Some(first) = out.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    out
}

fn billing_status_label(status: &str) -> String {
    match status.to_ascii_lowercase().as_str() {
        "confirmed" | "paid" => "Completed".to_string(),
        "failed" | "cancelled" => "Failed".to_string(),
        "pending_confirmation" | "submitted" | "created" | "charging" | "scheduled" => {
            "Pending".to_string()
        }
        "grace" => "Grace".to_string(),
        other => capitalize(other),
    }
}

fn format_yyyy_mm_dd(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d").to_string()
}

fn build_receipt_url(chain_id: i32, tx_hash: Option<&str>) -> Option<String> {
    let tx = tx_hash?.trim();
    if tx.is_empty() {
        return None;
    }
    let base = match chain_id {
        1 => "https://etherscan.io/tx/",
        8453 => "https://basescan.org/tx/",
        84532 => "https://sepolia.basescan.org/tx/",
        56 => "https://bscscan.com/tx/",
        137 => "https://polygonscan.com/tx/",
        42161 => "https://arbiscan.io/tx/",
        10 => "https://optimistic.etherscan.io/tx/",
        _ => "https://basescan.org/tx/",
    };
    Some(format!("{base}{tx}"))
}
