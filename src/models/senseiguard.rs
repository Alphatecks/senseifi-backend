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

/// Activity feed item with wallet address for dashboard overview (all wallets).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ActivityFeedItemWithAddress {
    pub id: Uuid,
    pub wallet_id: Uuid,
    #[serde(rename = "wallet_address")]
    pub wallet_address: String,
    pub activity_type: String,
    pub title: String,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// One row for the Live activity feed API (Time, Wallet, Type, Asset & Amount, Counterparty/dApp, Risk, Status).
#[derive(Debug, Clone, Serialize)]
pub struct LiveActivityFeedItem {
    pub id: Uuid,
    #[serde(rename = "time")]
    pub created_at: DateTime<Utc>,
    pub wallet: String,
    pub wallet_address: String,
    #[serde(rename = "type")]
    pub type_display: String,
    pub asset: Option<String>,
    pub amount: Option<String>,
    pub counterparty: Option<String>,
    pub risk_level: Option<String>,
    pub status: Option<String>,
    pub title: String,
    pub description: Option<String>,
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

/// One row for Approval & Permission UI: contract, type (unlimited/limited), risk, date.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WalletApproval {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub contract_address: String,
    pub approval_type: String,
    pub risk_level: String,
    pub detected_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// One row for Transaction monitoring UI: title (e.g. "Swap ETH → USDC") + risk level.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MonitoredTransaction {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub title: String,
    pub risk_level: String,
    pub detected_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SecurityStatusResponse {
    pub score: i32,
    pub status: String,
    pub message: String,
    pub last_scan_at: Option<DateTime<Utc>>,
    /// Doc: security-score level (safe | moderate | dangerous).
    pub level: String,
    /// Doc: per-component breakdown when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_breakdown: Option<serde_json::Value>,
    /// Doc: last_updated (same as last_scan_at or wallet_monitoring update).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<DateTime<Utc>>,
}

/// Response for GET /api/wallets/{address}/modal — real data for connected-wallet modal (Details, Balance, Security, Activity).
#[derive(Debug, Serialize)]
pub struct ConnectedWalletModalResponse {
    pub details: ConnectedWalletModalDetails,
    pub balance: ConnectedWalletModalBalance,
    pub security: ConnectedWalletModalSecurity,
    pub activity: Vec<ActivityFeedItem>,
}

#[derive(Debug, Serialize)]
pub struct ConnectedWalletModalDetails {
    pub provider: String,
    pub wallet_address: String,
    pub network: String,
    pub connected_at: DateTime<Utc>,
    pub wallet_type: String,
    pub connected_via: String,
    pub security_status: String,
}

#[derive(Debug, Serialize)]
pub struct ConnectedWalletModalBalance {
    pub total_usd: f64,
    /// Sum of `wallet_assets.usd_value` only (before adding native USD).
    pub wallet_assets_usd: f64,
    pub native_balance_eth: f64,
    pub native_usd: f64,
    pub native_balance_wei: String,
    /// "coingecko" | "coingecko_pro" | "coincap" when price succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_price_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_pricing_error: Option<String>,
    pub assets: Vec<WalletAsset>,
}

#[derive(Debug, Serialize)]
pub struct ConnectedWalletModalSecurity {
    /// 2FA not tracked in backend; null when unknown.
    pub two_fa: Option<String>,
    pub active_approvals: i64,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub last_scan_ago: Option<String>,
    /// "Low" | "Medium" | "High" from security score.
    pub threat_level: String,
    /// 0-100 from transaction_monitoring high_risk/total.
    pub risk_exposure_percent: f64,
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
    /// Sum of `wallet_assets.usd_value` (ERC-20 rows etc.); native is separate fields below.
    pub wallet_assets_usd: f64,
    pub native_balance_eth: f64,
    pub native_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_price_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_pricing_error: Option<String>,
    pub unread_alerts: i64,
    pub high_risk_alerts: i64,
    pub alerts_trend_percent: f64,
    pub issues_this_month: i32,
}

/// Response for GET /dashboard/overview — real data only (no simulations or hardcoded values).
#[derive(Debug, Serialize)]
pub struct DashboardOverviewResponse {
    pub wallet_status: WalletStatusOverview,
    pub active_alerts: ActiveAlertsOverview,
    pub activity_timeline: Vec<ActivityFeedItemWithAddress>,
    pub recent_activity: RecentActivityOverview,
    pub connected_risk: ConnectedRiskOverview,
}

#[derive(Debug, Serialize)]
pub struct WalletStatusOverview {
    pub active_wallet_count: i64,
    /// "safe" | "moderate" | "attention" from worst wallet score.
    pub status: String,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ActiveAlertsOverview {
    pub total: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Debug, Serialize)]
pub struct RecentActivityOverview {
    /// Activity feed events in last 24h (all wallets).
    pub transactions_24h: i64,
    /// From activity_feed where activity_type suggests contract interaction. No external API; 0 if not tracked.
    pub contract_calls_24h: i64,
    pub suspicious_events_24h: i64,
}

#[derive(Debug, Serialize)]
pub struct ConnectedRiskOverview {
    pub total_risk_items: i64,
    pub high_risk_connections: i64,
    /// dApp connections not stored in DB; 0 until ingest or external API.
    pub active_dapps: i64,
}

/// One wallet row for Activity Monitor "Connected wallet" tab.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityMonitorWalletResponse {
    pub address: String,
    pub wallet_type_display: String,
    pub chain_id: i64,
    pub chain_name: String,
    pub status: String,
    pub security_level: String,
    pub last_activity: String,
}

/// One dApp row for Activity Monitor "Connected dApps" tab.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityMonitorDappResponse {
    pub dapp_name: String,
    pub description: String,
    pub tokens: String,
    pub status: String,
    pub connected_wallet_address: String,
    pub last_activity: String,
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

/// Response for GET /api/dashboard/security-overview — real data for security dashboard cards.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityOverviewResponse {
    pub overall_risk: OverallRiskCard,
    pub active_threats: ActiveThreatsCard,
    pub scam_pattern_insights: ScamPatternInsightsCard,
    pub scam_patterns: ScamPatternsCard,
    pub reported_threats: ReportedThreatsCard,
    pub live_scam_signals: Vec<LiveScamSignalItem>,
    /// AI Threat Explanation card: description text, display risk level, and whether summary is available.
    pub ai_threat_explanation: AiThreatExplanationCard,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiThreatExplanationCard {
    /// Contextual summary + reasons (generated from threat signals; not static).
    pub description: String,
    /// Display label for current risk, e.g. "Elevated", "Safe".
    pub risk_level: String,
    /// Whether a detailed summary can be shown (e.g. View Summary button).
    pub view_summary_available: bool,
    /// Bullet-point reasons derived from risk signals (for UI or LLM later).
    pub reasons: Vec<String>,
    /// Raw signal IDs that contributed (e.g. "active_threats", "multiple_scam_patterns").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverallRiskCard {
    /// 0–100; higher = worse.
    pub risk_score: i32,
    /// Safe | Warning | Dangerous | Block (from production bands).
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveThreatsCard {
    pub networks_affected: i64,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScamPatternInsightsCard {
    pub period: String,
    /// Daily counts for chart: day (YYYY-MM-DD), count.
    pub daily: Vec<ScamFrequencyDay>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScamFrequencyDay {
    pub day: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScamPatternsCard {
    /// "Low" | "Medium" | "High" from detected_count.
    pub status: String,
    pub detected_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportedThreatsCard {
    /// Community scam reports (verified count).
    pub verified: i64,
    /// Threats detected (last 30 days for user).
    pub detected: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveScamSignalItem {
    /// Short address (e.g. 0xA34...92F) or wallet address.
    pub address: String,
    pub threat_type: String,
    pub detected_at: String,
    pub risk_level: String,
}

/// One row for GET /api/dashboard/community-reported-threats (table: Threat Type, Description, Network, Risk Level, Reports, Status, Last Seen).
#[derive(Debug, Clone, Serialize)]
pub struct CommunityReportedThreatItem {
    pub threat_type: String,
    pub title: String,
    pub description: String,
    pub network: String,
    pub risk_level: String,
    pub reports: i64,
    pub status: String,
    pub last_seen: String,
}

/// Response for GET /api/dashboard/{address}/metrics (four cards on frontend).
#[derive(Debug, Clone, Serialize)]
pub struct DashboardMetricsResponse {
    pub malicious_transaction: MetricCard,
    pub phishing_indicators: MetricCard,
    pub risky_tokens: MetricCard,
    pub active_threat_level: ThreatLevelCard,
}

// ---- Smart Wallet Scanner: detail blocks (stored in contract_scans.details JSONB) ----

/// Simulation result: what will happen if user interacts (drains, hidden calls, approvals).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drains_full_balance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden_internal_calls: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dangerous_functions: Option<Vec<String>>,
}

/// Owner/admin privilege analysis: mint, pause, upgrade, withdraw liquidity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OwnerPrivileges {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgradeable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdraw_liquidity: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blacklist: Option<bool>,
}

/// External reputation: GoPlus, Chainabuse, verified source, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_scam: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community_flags: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_source: Option<bool>,
}

/// Trend: scans today, wallets affected, risk_trend badge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanTrend {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scans_today: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallets_affected: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_trend: Option<String>, // "increasing" | "stable" | "low_concern"
}

/// Explainable trust score: contribution per factor (percent of total risk).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskBreakdown {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_privileges: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_control_scope: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_age: Option<u8>,
}

/// Full details payload for one contract scan (stored in details JSONB).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanDetailsPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation: Option<SimulationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_privileges: Option<OwnerPrivileges>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<ReputationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trend: Option<ScanTrend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_breakdown: Option<RiskBreakdown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_anomaly_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rug_pull_probability: Option<String>, // "Low" | "Medium" | "High"
    /// "etherscan" when ABI was fetched from chain explorer; "stub" when contract unverified or fetch failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi_source: Option<String>,
    /// Contract name from Etherscan (verified contracts via getsourcecode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_name: Option<String>,
    /// Detected standards from ABI: e.g. ["ERC-20"], ["ERC-721"], ["ERC-20", "ERC-1155"].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_standards: Option<Vec<String>>,
}

/// Smart Wallet Scanner: one scan result (trust score, risk flags, tokens, owner count).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ContractScan {
    pub id: Uuid,
    pub contract_address: String,
    pub trust_score: i32,
    pub critical_risk_flags: i32,
    pub token_controlled: String,
    pub owner_admin_count: i32,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    pub scanned_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub scanned_for_address: Option<String>,
    /// Chain ID used for this scan (1=ETH, 56=BSC, etc.). Null for scans created before migration.
    #[serde(default)]
    pub chain_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ScanContractRequest {
    pub contract_address: String,
    /// Optional: wallet address for user-aware risk (behavioral anomaly) and trend.
    #[serde(default)]
    pub for_address: Option<String>,
    /// Optional: chain ID for the contract (1=Ethereum, 56=BSC, 137=Polygon, 8453=Base, 42161=Arbitrum). If omitted, uses ETHERSCAN_CHAIN_ID env or 1.
    #[serde(default)]
    pub chain_id: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ScanContractResponse {
    pub scan_id: Uuid,
    pub contract_address: String,
    pub trust_score: i32,
    pub critical_risk_flags: i32,
    pub token_controlled: String,
    pub owner_admin_count: i32,
    pub scanned_at: DateTime<Utc>,
    /// Chain ID used for this scan (1=ETH, 56=BSC, 137=Polygon, etc.). So the UI shows the correct network, not a default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Network name derived from chain_id (e.g. "BNB Smart Chain", "Ethereum Mainnet").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Contract name from Etherscan (verified contracts). Real when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_name: Option<String>,
    /// Detected standard(s) from ABI, e.g. "ERC-20", "ERC-721", "ERC-1155" or "ERC-20 (Custom)".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_standard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_summary: Option<String>,
}

// ---- Contract scanner: scam pattern, activity, liquidity, community (for UI) ----

/// Scam pattern checklist + similarity to known scam patterns (0–100).
#[derive(Debug, Serialize)]
pub struct ScamPatternResponse {
    pub honeypot: bool,
    pub approval_drain: bool,
    pub delayed_rug: bool,
    pub fee_escalation: bool,
    /// 0–100; higher = more similar to known scam patterns.
    pub similarity_score_percent: u8,
}

/// Contract on-chain activity metrics (wire to indexer/RPC for real data).
#[derive(Debug, Serialize)]
pub struct ContractActivityResponse {
    pub avg_tx_per_day: Option<u64>,
    pub largest_tx_usd: Option<String>,
    pub abnormal_activity: bool,
}

/// Liquidity metrics (wire to DEX/subgraph for real data).
#[derive(Debug, Serialize)]
pub struct ContractLiquidityResponse {
    pub initial_lp_usd: Option<String>,
    pub current_lp_usd: Option<String>,
    pub sudden_pulls: Option<u32>,
}

/// Community / report signals for a contract.
#[derive(Debug, Serialize)]
pub struct CommunitySignalsResponse {
    pub report_count: i64,
    pub confirmed_exploits: i64,
    pub users_flagged_count: i64,
}

// ---- Protection: block, watchlist, report ----

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserBlockedContract {
    pub id: Uuid,
    pub wallet_address: String,
    pub contract_address: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserContractWatchlist {
    pub id: Uuid,
    pub wallet_address: String,
    pub contract_address: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScamReport {
    pub id: Uuid,
    pub contract_address: String,
    pub reporter_wallet_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct BlockContractRequest {
    pub wallet_address: String,
    pub contract_address: String,
}

#[derive(Debug, Deserialize)]
pub struct WatchlistContractRequest {
    pub wallet_address: String,
    pub contract_address: String,
}

#[derive(Debug, Deserialize)]
pub struct ReportScamRequest {
    pub contract_address: String,
    #[serde(default)]
    pub reporter_wallet_address: Option<String>,
}

/// Protection Control UI: toggle state for the 5 switches (stored per wallet).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserProtectionSettings {
    pub wallet_address: String,
    pub auto_security_scan: bool,
    pub high_risk_tx_warnings: bool,
    pub new_approval_alerts: bool,
    pub new_dapp_connection_alerts: bool,
    pub auto_block_high_risk: bool,
    #[serde(default)]
    pub emergency_lock: bool,
    #[serde(default)]
    pub whitelisted_addresses: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProtectionSettingsRequest {
    pub wallet_address: String,
    #[serde(default)]
    pub auto_security_scan: Option<bool>,
    #[serde(default)]
    pub high_risk_tx_warnings: Option<bool>,
    #[serde(default)]
    pub new_approval_alerts: Option<bool>,
    #[serde(default)]
    pub new_dapp_connection_alerts: Option<bool>,
    #[serde(default)]
    pub auto_block_high_risk: Option<bool>,
    #[serde(default)]
    pub emergency_lock: Option<bool>,
    #[serde(default)]
    pub whitelisted_addresses: Option<Vec<String>>,
}

/// Pre-sign transaction simulation request (from, to, data, value, chain_id).
#[derive(Debug, Deserialize)]
pub struct SimulateTxRequest {
    pub wallet_address: String,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub chain_id: Option<i64>,
}

/// Pre-sign simulation result: risk level, expected loss, dangerous patterns.
#[derive(Debug, Serialize)]
pub struct SimulateTxResponse {
    pub risk_level: String,
    pub expected_token_loss: Option<String>,
    pub hidden_internal_calls: u32,
    pub dangerous_functions: Vec<String>,
    pub should_warn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ContractFingerprint {
    pub id: Uuid,
    pub contract_address: String,
    pub bytecode_hash: String,
    pub abi_pattern_hash: Option<String>,
    pub family: Option<String>,
    pub known_attack_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RunScanResponse {
    pub score: i32,
    pub status: String,
    pub scanned_at: DateTime<Utc>,
}

// ---- Protection engine: transaction analyze, dApp check, rules, auto-scan ----

/// Request for POST /api/transaction/analyze (pre-sign threat analysis).
#[derive(Debug, Deserialize)]
pub struct AnalyzeTxRequest {
    pub wallet_address: String,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub chain_id: Option<i64>,
}

/// Response: risk score, band, threat_types, explanation, recommendation; or skipped if toggle off. Doc-aligned.
#[derive(Debug, Serialize)]
pub struct AnalyzeTxResponse {
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_breakdown: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request for POST /api/dapp/connection-check.
#[derive(Debug, Deserialize)]
pub struct DappConnectionCheckRequest {
    pub wallet_address: String,
    pub domain: String,
}

/// Response: risk score and phishing flag; or skipped if toggle off.
#[derive(Debug, Serialize)]
pub struct DappConnectionCheckResponse {
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phishing_risk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One row in protection_auto_scan (which addresses have Auto Security Scan on).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProtectionAutoScan {
    pub wallet_address: String,
    pub auto_scan_enabled: bool,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub scan_interval_seconds: i32,
    pub updated_at: DateTime<Utc>,
}

/// One approval alert (when New Approval Alerts is on).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WalletApprovalAlert {
    pub id: Uuid,
    pub wallet_address: String,
    pub token_address: Option<String>,
    pub spender_address: String,
    pub amount_raw: Option<String>,
    pub risk_score: i32,
    pub created_at: DateTime<Utc>,
}

/// One custom security rule (block tx >$5k, block contract <24h, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WalletSecurityRule {
    pub id: Uuid,
    pub wallet_address: String,
    pub rule_type: String,
    pub condition_json: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSecurityRuleRequest {
    pub wallet_address: String,
    pub rule_type: String,
    #[serde(default)]
    pub condition_json: Option<serde_json::Value>,
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecurityRuleRequest {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub condition_json: Option<serde_json::Value>,
    #[serde(default)]
    pub action: Option<String>,
}

/// Emergency lock: set/clear firewall mode and whitelist.
#[derive(Debug, Deserialize)]
pub struct EmergencyLockRequest {
    pub wallet_address: String,
    pub lock: bool,
    #[serde(default)]
    pub whitelisted_addresses: Option<Vec<String>>,
}
