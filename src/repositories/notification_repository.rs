use chrono::{DateTime, Utc};
use sqlx::{Error, FromRow};
use std::collections::HashSet;
use uuid::Uuid;

use crate::db::DbPool;

pub struct NotificationRepository;

#[derive(Debug, Clone, FromRow)]
pub struct BroadcastNotificationRow {
    pub id: Uuid,
    pub title: String,
    pub body: Option<String>,
    pub category: String,
    pub icon_type: String,
    pub action_label: Option<String>,
    pub action_url: Option<String>,
    pub action_type: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl NotificationRepository {
    pub async fn list_active_broadcasts(
        pool: &DbPool,
        limit: i64,
    ) -> Result<Vec<BroadcastNotificationRow>, Error> {
        sqlx::query_as(
            r#"
            SELECT id, title, body, category, icon_type, action_label, action_url, action_type, created_at
            FROM broadcast_notifications
            WHERE active = true
              AND starts_at <= NOW()
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn list_read_source_ids(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<HashSet<(String, Uuid)>, Error> {
        let rows: Vec<(String, Uuid)> = sqlx::query_as(
            r#"
            SELECT source_type, source_id
            FROM notification_read_receipts
            WHERE LOWER(wallet_address) = LOWER($1)
            "#,
        )
        .bind(wallet_address)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    pub async fn mark_source_read(
        pool: &DbPool,
        wallet_address: &str,
        source_type: &str,
        source_id: Uuid,
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO notification_read_receipts (wallet_address, source_type, source_id, read_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (wallet_address, source_type, source_id) DO NOTHING
            "#,
        )
        .bind(wallet_address)
        .bind(source_type)
        .bind(source_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn mark_sources_read(
        pool: &DbPool,
        wallet_address: &str,
        items: &[(String, Uuid)],
    ) -> Result<i64, Error> {
        let mut inserted = 0i64;
        for (source_type, source_id) in items {
            if Self::mark_source_read(pool, wallet_address, source_type, *source_id).await? {
                inserted += 1;
            }
        }
        Ok(inserted)
    }
}
