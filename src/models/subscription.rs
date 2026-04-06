use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct UserSubscription {
    pub id: Uuid,
    pub user_id: String,
    pub plan: String,
    pub billing_cycle: String,
    pub status: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub stripe_price_id: Option<String>,
    pub checkout_session_id: Option<String>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanDescriptor {
    pub key: String,
    pub label: String,
    pub billing_cycle: String,
    pub stripe_price_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateCheckoutSessionRequest {
    pub user_id: String,
    pub plan: String,
    #[serde(default)]
    pub billing_cycle: Option<String>,
    #[serde(default)]
    pub success_url: Option<String>,
    #[serde(default)]
    pub cancel_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePortalSessionRequest {
    pub user_id: String,
    #[serde(default)]
    pub return_url: Option<String>,
}
