use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct NotificationAction {
    pub label: String,
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationItem {
    pub id: String,
    pub source_type: String,
    pub source_id: Uuid,
    pub category: String,
    pub icon: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub read: bool,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<NotificationAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationListResponse {
    pub unread_count: i64,
    pub notifications: Vec<NotificationItem>,
}

pub fn notification_list_json(unread_count: i64, notifications: &[NotificationItem]) -> Value {
    json!({
        "success": true,
        "unread_count": unread_count,
        "data": notifications,
    })
}

pub fn composite_notification_id(source_type: &str, source_id: Uuid) -> String {
    format!("{source_type}:{source_id}")
}

#[derive(Debug, Deserialize)]
pub struct WalletNotificationQuery {
    pub wallet_address: String,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct MarkNotificationReadRequest {
    pub wallet_address: String,
    pub source_type: String,
    pub source_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct MarkAllNotificationsReadRequest {
    pub wallet_address: String,
}
