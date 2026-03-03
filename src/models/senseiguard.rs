use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecurityScan {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub score: i32,
    pub status: String,
    pub scanned_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Threat {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub severity: String,
    pub title: String,
    pub source_contract: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Alert {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub threat_id: Option<Uuid>,
    pub severity: String,
    pub title: String,
    pub body: Option<String>,
    pub read_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ActivityFeedItem {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub activity_type: String,
    pub title: String,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WalletAsset {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub symbol: String,
    pub name: String,
    pub balance: String,
    pub usd_value: f64,
    pub change_percent: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SecurityStatusResponse {
    pub score: i32,
    pub status: String,
    pub message: String,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct DashboardSummaryResponse {
    pub security_status: SecurityStatusResponse,
    pub threats_this_month: i64,
    pub threats_trend_percent: f64,
    pub scans_this_month: i64,
    pub scans_trend_percent: f64,
    pub total_asset_usd: String,
    pub total_asset_trend_percent: f64,
    pub unread_alerts: i64,
    pub high_risk_alerts: i64,
    pub alerts_trend_percent: f64,
    pub issues_this_month: i32,
}

#[derive(Debug, Deserialize)]
pub struct RunScanResponse {
    pub score: i32,
    pub status: String,
    pub scanned_at: DateTime<Utc>,
}
