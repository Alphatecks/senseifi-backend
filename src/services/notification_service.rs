//! Unified notification center: alerts, activity, approvals, threats, broadcasts.

use sqlx::Error;
use uuid::Uuid;

use crate::db::DbPool;
use crate::models::notification::{
    composite_notification_id, NotificationAction, NotificationItem, NotificationListResponse,
};
use crate::models::senseiguard::{ActivityFeedItem, Alert};
use crate::models::wallet::{canonical_eth_address, is_valid_eth_address};
use crate::repositories::notification_repository::NotificationRepository;
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::repositories::wallet_repository::WalletRepository;

pub struct NotificationService;

const SOURCE_ALERT: &str = "alert";
const SOURCE_APPROVAL: &str = "approval_alert";
const SOURCE_ACTIVITY: &str = "activity";
const SOURCE_THREAT: &str = "threat";
const SOURCE_BROADCAST: &str = "broadcast";

impl NotificationService {
    pub async fn list_for_wallet(
        pool: &DbPool,
        wallet_address: &str,
        limit: i64,
    ) -> Result<NotificationListResponse, Error> {
        if !is_valid_eth_address(wallet_address) {
            return Err(Error::RowNotFound);
        }
        let wallet_address = canonical_eth_address(wallet_address);
        let limit = limit.clamp(1, 100);
        let read_set = NotificationRepository::list_read_source_ids(pool, &wallet_address).await?;

        let mut items: Vec<NotificationItem> = Vec::new();

        if let Ok(broadcasts) = NotificationRepository::list_active_broadcasts(pool, limit).await {
            for b in broadcasts {
                let read = read_set.contains(&(SOURCE_BROADCAST.to_string(), b.id));
                items.push(NotificationItem {
                    id: composite_notification_id(SOURCE_BROADCAST, b.id),
                    source_type: SOURCE_BROADCAST.to_string(),
                    source_id: b.id,
                    category: b.category.clone(),
                    icon: b.icon_type.clone(),
                    title: b.title,
                    description: b.body,
                    read,
                    created_at: b.created_at,
                    action: notification_action(
                        b.action_label.as_deref(),
                        b.action_type.as_deref(),
                        b.action_url.as_deref(),
                    ),
                });
            }
        }

        if let Ok(Some(wallet)) =
            WalletRepository::get_wallet_by_address(pool, &wallet_address).await
        {
            if let Ok(alerts) = SenseiguardRepository::list_alerts(pool, wallet.id, limit).await {
                for alert in alerts {
                    items.push(map_alert(&alert, &read_set));
                }
            }

            if let Ok(activities) =
                SenseiguardRepository::list_activity(pool, wallet.id, limit).await
            {
                for activity in activities {
                    items.push(map_activity(&activity, &read_set));
                }
            }

            if let Ok(threats) =
                SenseiguardRepository::list_active_threats(pool, wallet.id, limit).await
            {
                for threat in threats {
                    let read = read_set.contains(&(SOURCE_THREAT.to_string(), threat.id));
                    items.push(NotificationItem {
                        id: composite_notification_id(SOURCE_THREAT, threat.id),
                        source_type: SOURCE_THREAT.to_string(),
                        source_id: threat.id,
                        category: threat_category(&threat.threat_type, &threat.title),
                        icon: "warning".to_string(),
                        title: threat.title.clone(),
                        description: threat.explanation.clone().or_else(|| {
                            threat.source_contract.as_ref().map(|c| {
                                format!("Related contract: {c}. Review before continuing.")
                            })
                        }),
                        read,
                        created_at: threat.detected_at,
                        action: Some(NotificationAction {
                            label: "View Details".to_string(),
                            action_type: "view_threat".to_string(),
                            url: None,
                        }),
                    });
                }
            }
        }

        if let Ok(approval_alerts) =
            SenseiguardRepository::list_approval_alerts(pool, &wallet_address, limit).await
        {
            for alert in approval_alerts {
                let read = read_set.contains(&(SOURCE_APPROVAL.to_string(), alert.id));
                items.push(NotificationItem {
                    id: composite_notification_id(SOURCE_APPROVAL, alert.id),
                    source_type: SOURCE_APPROVAL.to_string(),
                    source_id: alert.id,
                    category: "transaction".to_string(),
                    icon: "security".to_string(),
                    title: "Suspicious Transaction Detected".to_string(),
                    description: Some(format!(
                        "A risky approval to {} was flagged (risk score {}). Review before signing.",
                        truncate_address(&alert.spender_address),
                        alert.risk_score
                    )),
                    read,
                    created_at: alert.created_at,
                    action: Some(NotificationAction {
                        label: "Review Transaction".to_string(),
                        action_type: "review_transaction".to_string(),
                        url: Some(format!(
                            "/dashboard/{}/approvals",
                            wallet_address.to_lowercase()
                        )),
                    }),
                });
            }
        }

        items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        items.truncate(limit as usize);

        let unread_count = items.iter().filter(|n| !n.read).count() as i64;

        Ok(NotificationListResponse {
            unread_count,
            notifications: items,
        })
    }

    pub async fn mark_read(
        pool: &DbPool,
        wallet_address: &str,
        source_type: &str,
        source_id: Uuid,
    ) -> Result<bool, Error> {
        if !is_valid_eth_address(wallet_address) {
            return Err(Error::RowNotFound);
        }
        let wallet_address = canonical_eth_address(wallet_address);

        if source_type == SOURCE_ALERT {
            if let Ok(Some(wallet)) =
                WalletRepository::get_wallet_by_address(pool, &wallet_address).await
            {
                return Ok(
                    SenseiguardRepository::mark_alert_read(pool, wallet.id, source_id)
                        .await?
                        .is_some(),
                );
            }
            return Ok(false);
        }

        Ok(
            NotificationRepository::mark_source_read(pool, &wallet_address, source_type, source_id)
                .await?,
        )
    }

    pub async fn mark_all_read(pool: &DbPool, wallet_address: &str) -> Result<i64, Error> {
        if !is_valid_eth_address(wallet_address) {
            return Err(Error::RowNotFound);
        }
        let wallet_address = canonical_eth_address(wallet_address);
        let list = Self::list_for_wallet(pool, &wallet_address, 100).await?;
        let mut updated = SenseiguardRepository::mark_all_alerts_read(
            pool,
            WalletRepository::get_wallet_by_address(pool, &wallet_address)
                .await?
                .ok_or(Error::RowNotFound)?
                .id,
        )
        .await?;

        let unread: Vec<(String, Uuid)> = list
            .notifications
            .into_iter()
            .filter(|n| !n.read && n.source_type != SOURCE_ALERT)
            .map(|n| (n.source_type, n.source_id))
            .collect();

        updated +=
            NotificationRepository::mark_sources_read(pool, &wallet_address, &unread).await?;
        Ok(updated)
    }
}

fn map_alert(
    alert: &Alert,
    read_set: &std::collections::HashSet<(String, Uuid)>,
) -> NotificationItem {
    let read = alert.read_at.is_some() || read_set.contains(&(SOURCE_ALERT.to_string(), alert.id));
    NotificationItem {
        id: composite_notification_id(SOURCE_ALERT, alert.id),
        source_type: SOURCE_ALERT.to_string(),
        source_id: alert.id,
        category: alert_category(&alert.severity),
        icon: "security".to_string(),
        title: alert.title.clone(),
        description: alert.body.clone(),
        read,
        created_at: alert.created_at,
        action: Some(NotificationAction {
            label: "View Alert".to_string(),
            action_type: "view_alert".to_string(),
            url: None,
        }),
    }
}

fn map_activity(
    activity: &ActivityFeedItem,
    read_set: &std::collections::HashSet<(String, Uuid)>,
) -> NotificationItem {
    let read = read_set.contains(&(SOURCE_ACTIVITY.to_string(), activity.id));
    let (category, icon, action) = activity_mapping(&activity.activity_type);

    NotificationItem {
        id: composite_notification_id(SOURCE_ACTIVITY, activity.id),
        source_type: SOURCE_ACTIVITY.to_string(),
        source_id: activity.id,
        category: category.to_string(),
        icon: icon.to_string(),
        title: activity.title.clone(),
        description: activity.description.clone(),
        read,
        created_at: activity.created_at,
        action,
    }
}

fn activity_mapping(
    activity_type: &str,
) -> (&'static str, &'static str, Option<NotificationAction>) {
    match activity_type {
        "suspicious_approval" | "blocked_interaction" => (
            "transaction",
            "security",
            Some(NotificationAction {
                label: "Review Transaction".to_string(),
                action_type: "review_transaction".to_string(),
                url: None,
            }),
        ),
        "outgoing_tx" => ("transaction", "security", None),
        _ => ("security", "security", None),
    }
}

fn alert_category(severity: &str) -> String {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => "security".to_string(),
        "medium" | "warning" => "account".to_string(),
        _ => "security".to_string(),
    }
}

fn threat_category(threat_type: &Option<String>, title: &str) -> String {
    let t = threat_type.as_deref().unwrap_or("").to_ascii_lowercase();
    let title_l = title.to_ascii_lowercase();
    if t.contains("token") || title_l.contains("token") {
        "token_risk".to_string()
    } else {
        "security".to_string()
    }
}

fn notification_action(
    label: Option<&str>,
    action_type: Option<&str>,
    url: Option<&str>,
) -> Option<NotificationAction> {
    let label = label.filter(|s| !s.trim().is_empty())?;
    Some(NotificationAction {
        label: label.to_string(),
        action_type: action_type.unwrap_or("open_url").to_string(),
        url: url.filter(|s| !s.trim().is_empty()).map(str::to_string),
    })
}

fn truncate_address(addr: &str) -> String {
    if addr.len() >= 10 {
        format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}
