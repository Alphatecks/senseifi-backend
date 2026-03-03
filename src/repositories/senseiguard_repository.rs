use crate::db::DbPool;
use crate::models::senseiguard::{
    ActivityFeedItem, Alert, SecurityScan, Threat, WalletAsset,
};
use chrono::{DateTime, Utc};
use sqlx::Error;
use uuid::Uuid;

pub struct SenseiguardRepository;

impl SenseiguardRepository {
    pub async fn get_latest_scan(pool: &DbPool, wallet_id: Uuid) -> Result<Option<SecurityScan>, Error> {
        sqlx::query_as(
            "SELECT * FROM security_scans WHERE wallet_id = $1 ORDER BY scanned_at DESC LIMIT 1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn create_scan(pool: &DbPool, wallet_id: Uuid, score: i32) -> Result<SecurityScan, Error> {
        let status = match score {
            0..=39 => "weak",
            40..=69 => "moderate",
            _ => "strong",
        };
        let row = sqlx::query_as(
            r#"
            INSERT INTO security_scans (wallet_id, score, status, scanned_at)
            VALUES ($1, $2, $3, NOW())
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(score)
        .bind(status)
        .fetch_one(pool)
        .await?;

        sqlx::query(
            r#"
            UPDATE wallet_monitoring
            SET security_score = $1, last_scan_at = NOW(), updated_at = NOW()
            WHERE wallet_id = $2
            "#,
        )
        .bind(score)
        .bind(wallet_id)
        .execute(pool)
        .await?;

        Ok(row)
    }

    pub async fn count_threats_this_month(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let start: DateTime<Utc> = Utc::now() - chrono::Duration::days(30);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM threats WHERE wallet_id = $1 AND detected_at >= $2",
        )
        .bind(wallet_id)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn list_threats(
        pool: &DbPool,
        wallet_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Threat>, Error> {
        sqlx::query_as(
            "SELECT * FROM threats WHERE wallet_id = $1 ORDER BY detected_at DESC LIMIT $2",
        )
        .bind(wallet_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn count_scans_this_month(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let start: DateTime<Utc> = Utc::now() - chrono::Duration::days(30);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM security_scans WHERE wallet_id = $1 AND scanned_at >= $2",
        )
        .bind(wallet_id)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn list_scans(
        pool: &DbPool,
        wallet_id: Uuid,
        limit: i64,
    ) -> Result<Vec<SecurityScan>, Error> {
        sqlx::query_as(
            "SELECT * FROM security_scans WHERE wallet_id = $1 ORDER BY scanned_at DESC LIMIT $2",
        )
        .bind(wallet_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn unread_alerts_count(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND read_at IS NULL",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn high_risk_alerts_count(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND severity = 'high' AND read_at IS NULL",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn list_alerts(
        pool: &DbPool,
        wallet_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Alert>, Error> {
        sqlx::query_as(
            "SELECT * FROM alerts WHERE wallet_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(wallet_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn list_activity(
        pool: &DbPool,
        wallet_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ActivityFeedItem>, Error> {
        sqlx::query_as(
            "SELECT * FROM activity_feed WHERE wallet_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(wallet_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn get_wallet_issues_this_month(pool: &DbPool, wallet_id: Uuid) -> Result<i32, Error> {
        let row = sqlx::query_as(
            "SELECT COALESCE(issues_this_month, 0) FROM wallet_monitoring WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r: (i32,)| r.0).unwrap_or(0))
    }

    pub async fn list_assets(pool: &DbPool, wallet_id: Uuid) -> Result<Vec<WalletAsset>, Error> {
        sqlx::query_as("SELECT * FROM wallet_assets WHERE wallet_id = $1 ORDER BY usd_value DESC")
            .bind(wallet_id)
            .fetch_all(pool)
            .await
    }

    pub async fn total_asset_usd(pool: &DbPool, wallet_id: Uuid) -> Result<f64, Error> {
        let row: (Option<f64>,) = sqlx::query_as(
            "SELECT COALESCE(SUM(usd_value), 0) FROM wallet_assets WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0.unwrap_or(0.0))
    }

    pub async fn upsert_asset(
        pool: &DbPool,
        wallet_id: Uuid,
        symbol: &str,
        name: &str,
        balance: &str,
        usd_value: f64,
        change_percent: f64,
    ) -> Result<WalletAsset, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO wallet_assets (wallet_id, symbol, name, balance, usd_value, change_percent, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (wallet_id, symbol)
            DO UPDATE SET balance = EXCLUDED.balance, usd_value = EXCLUDED.usd_value,
                           change_percent = EXCLUDED.change_percent, updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(symbol)
        .bind(name)
        .bind(balance)
        .bind(usd_value)
        .bind(change_percent)
        .fetch_one(pool)
        .await
    }

    pub async fn create_threat(
        pool: &DbPool,
        wallet_id: Uuid,
        severity: &str,
        title: &str,
        source_contract: Option<&str>,
    ) -> Result<Threat, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO threats (wallet_id, severity, title, source_contract, detected_at)
            VALUES ($1, $2, $3, $4, NOW())
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(severity)
        .bind(title)
        .bind(source_contract)
        .fetch_one(pool)
        .await
    }

    pub async fn create_alert(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_id: Option<Uuid>,
        severity: &str,
        title: &str,
        body: Option<&str>,
    ) -> Result<Alert, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO alerts (wallet_id, threat_id, severity, title, body)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(threat_id)
        .bind(severity)
        .bind(title)
        .bind(body)
        .fetch_one(pool)
        .await
    }

    pub async fn create_activity(
        pool: &DbPool,
        wallet_id: Uuid,
        activity_type: &str,
        title: &str,
        description: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> Result<ActivityFeedItem, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO activity_feed (wallet_id, activity_type, title, description, metadata)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(activity_type)
        .bind(title)
        .bind(description)
        .bind(metadata)
        .fetch_one(pool)
        .await
    }
}
