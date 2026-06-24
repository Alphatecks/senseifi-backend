use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct OnchainPaymentProfile {
    pub id: Uuid,
    pub user_id: String,
    pub payer_address: String,
    pub chain_id: i32,
    pub token_contract: String,
    pub payment_contract: String,
    pub allowance_status: String,
    #[serde(with = "rust_decimal::serde::str_option")]
    pub max_charge_usdc: Option<Decimal>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct SubscriptionChargeAttempt {
    pub id: Uuid,
    pub user_id: String,
    pub subscription_id: Uuid,
    pub chain_id: i32,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    #[serde(with = "rust_decimal::serde::str")]
    pub amount_usdc: Decimal,
    pub status: String,
    pub onchain_tx_hash: Option<String>,
    pub onchain_nonce: Option<i64>,
    pub failure_code: Option<String>,
    pub failure_reason: Option<String>,
    pub idempotency_key: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct OnchainEventLog {
    pub id: Uuid,
    pub provider: String,
    pub event_id: String,
    pub event_type: String,
    pub chain_id: i32,
    pub tx_hash: Option<String>,
    pub payload: Value,
    pub received_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
    pub processing_status: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct SubscriptionCycle {
    pub id: Uuid,
    pub user_id: String,
    pub subscription_id: Uuid,
    pub plan: String,
    pub billing_cycle: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub amount_due_usdc: Decimal,
    pub due_at: DateTime<Utc>,
    pub charge_attempt_id: Option<Uuid>,
    pub status: String,
    pub grace_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct OnchainSubscribeRequest {
    pub user_id: String,
    pub plan: String,
    #[serde(default)]
    pub billing_cycle: Option<String>,
    pub payer_address: String,
    #[serde(default)]
    pub chain_id: Option<i32>,
    #[serde(default)]
    pub token_contract: Option<String>,
    #[serde(default)]
    pub payment_contract: Option<String>,
    #[serde(default)]
    pub max_charge_usdc: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct OnchainSubscribeResponse {
    pub subscription_id: Uuid,
    pub subscription_id_bytes32: String,
    pub plan: String,
    pub billing_cycle: String,
    pub chain_id: i32,
    pub token_contract: String,
    pub payment_contract: String,
    /// Human-readable USDC amount for one billing period (same units as wallet display).
    pub amount_usdc_per_period: f64,
    pub max_charge_usdc: f64,
    /// USDC token amount in base units (6 decimals), e.g. `"30000000"` for 30 USDC — use for `approve` / `upsertBilling` value.
    pub amount_usdc_per_period_base_units: String,
    pub max_charge_usdc_base_units: String,
    pub currency: String,
}

#[derive(Debug, Deserialize)]
pub struct UpsertOnchainPaymentProfileRequest {
    pub user_id: String,
    pub payer_address: String,
    #[serde(default)]
    pub chain_id: Option<i32>,
    pub token_contract: String,
    pub payment_contract: String,
    #[serde(default)]
    pub max_charge_usdc: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionCycleRequest {
    pub user_id: String,
    pub plan: String,
    pub billing_cycle: String,
    pub amount_due_usdc: f64,
    pub due_at: DateTime<Utc>,
    #[serde(default)]
    pub grace_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct TriggerDueChargeJobRequest {
    #[serde(default = "default_due_job_limit")]
    pub limit: i64,
}

const fn default_due_job_limit() -> i64 {
    100
}

#[derive(Debug, Deserialize)]
pub struct OnchainWebhookRequest {
    pub event_id: String,
    pub event_type: String,
    #[serde(default)]
    pub chain_id: Option<i32>,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub subscription_id: Option<Uuid>,
    #[serde(default)]
    pub charge_attempt_id: Option<Uuid>,
    #[serde(default)]
    pub period_start: Option<DateTime<Utc>>,
    #[serde(default)]
    pub period_end: Option<DateTime<Utc>>,
    #[serde(default)]
    pub amount_usdc: Option<f64>,
    #[serde(default)]
    pub failure_code: Option<String>,
    #[serde(default)]
    pub failure_reason: Option<String>,
    #[serde(default)]
    pub allowance_status: Option<String>,
    /// SenseiFiBilling `BillingUpserted` payer (indexed topic).
    #[serde(default)]
    pub payer_address: Option<String>,
    /// SenseiFiBilling `BillingUpserted` data word — USDC base units (6 decimals), **not** an active flag.
    #[serde(default)]
    pub charged_usdc_raw: Option<u64>,
    #[serde(default)]
    pub payload: Option<Value>,
}
