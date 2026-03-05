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
    #[serde(default)]
    pub observations: Option<serde_json::Value>,
}

/// Single item in a scan report (what was observed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanObservation {
    pub observation_type: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Response for run full scan: scan metadata + list of observations.
#[derive(Debug, Serialize)]
pub struct FullScanReportResponse {
    pub scan_id: Uuid,
    pub wallet_id: Uuid,
    pub score: i32,
    pub status: String,
    pub scanned_at: DateTime<Utc>,
    pub observations: Vec<ScanObservation>,
}

/// Surface where the threat was detected (see SENSEIGUARD_ARCHITECTURE.md).
pub const SURFACE_WALLET_STATE: &str = "wallet_state";
pub const SURFACE_TX_INTENT: &str = "tx_intent";
pub const SURFACE_CONTRACT: &str = "contract";
pub const SURFACE_OFF_CHAIN: &str = "off_chain";

/// Threat types we detect and store for dashboard metrics.
pub mod threat_types {
    pub const MALICIOUS_TRANSACTION: &str = "malicious_transaction";
    pub const PHISHING_INDICATOR: &str = "phishing_indicator";
    pub const RISKY_TOKEN: &str = "risky_token";
    pub const UNLIMITED_APPROVAL: &str = "unlimited_approval";
    pub const SIGNATURE_PHISHING: &str = "signature_phishing";
    pub const DRAINER_PATTERN: &str = "drainer_pattern";
    pub const BEHAVIORAL_ANOMALY: &str = "behavioral_anomaly";
    pub const FRONTEND_PHISHING: &str = "frontend_phishing";
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
    #[serde(default)]
    pub threat_type: Option<String>,
    #[serde(default)]
    pub surface: Option<String>,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub risk_breakdown: Option<serde_json::Value>,
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

/// Request body for ingesting a live activity (e.g. from chain indexer or security worker).
#[derive(Debug, Deserialize)]
pub struct IngestActivityRequest {
    pub activity_type: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Activity types that match the Live Activity UI.
pub mod activity_types {
    pub const OUTGOING_TX: &str = "outgoing_tx";
    pub const SUSPICIOUS_APPROVAL: &str = "suspicious_approval";
    pub const BLOCKED_INTERACTION: &str = "blocked_interaction";
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

/// One metric card: value (count) + trend % (this month vs previous month).
#[derive(Debug, Clone, Serialize)]
pub struct MetricCard {
    pub value: i64,
    pub change_percent: f64,
}

/// Active threat level card: "Low" | "Medium" | "High" from security_score + trend %.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatLevelCard {
    pub value: String,
    pub change_percent: f64,
}

/// Response for GET /api/dashboard/{address}/metrics (four cards on frontend).
#[derive(Debug, Clone, Serialize)]
pub struct DashboardMetricsResponse {
    pub malicious_transaction: MetricCard,
    pub phishing_indicators: MetricCard,
    pub risky_tokens: MetricCard,
    pub active_threat_level: ThreatLevelCard,
}

#[derive(Debug, Deserialize)]
pub struct RunScanResponse {
    pub score: i32,
    pub status: String,
    pub scanned_at: DateTime<Utc>,
}
