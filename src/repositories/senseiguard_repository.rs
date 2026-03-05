use crate::db::DbPool;
use crate::models::senseiguard::{
    ActivityFeedItem, Alert, ContractFingerprint, ContractScan, MonitoredTransaction, ScamReport,
    SecurityScan, Threat, UserBlockedContract, UserContractWatchlist, WalletApproval, WalletAsset,
};
use chrono::{Datelike, DateTime, NaiveDate, Utc};
use sqlx::Error;
use uuid::Uuid;

fn month_start_utc(dt: DateTime<Utc>) -> DateTime<Utc> {
    NaiveDate::from_ymd_opt(dt.year(), dt.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| DateTime::from_naive_utc_and_offset(t, Utc))
        .unwrap_or_else(|| dt)
}

pub struct SenseiguardRepository;

impl SenseiguardRepository {
    pub async fn get_latest_scan(pool: &DbPool, wallet_id: Uuid) -> Result<Option<SecurityScan>, Error> {
        sqlx::query_as(
            "SELECT id, wallet_id, score, status, scanned_at, created_at, COALESCE(observations, '[]'::jsonb) as observations FROM security_scans WHERE wallet_id = $1 ORDER BY scanned_at DESC LIMIT 1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn create_scan(
        pool: &DbPool,
        wallet_id: Uuid,
        score: i32,
        observations: &serde_json::Value,
    ) -> Result<SecurityScan, Error> {
        let status = match score {
            0..=39 => "weak",
            40..=69 => "moderate",
            _ => "strong",
        };
        let row = sqlx::query_as(
            r#"
            INSERT INTO security_scans (wallet_id, score, status, scanned_at, observations)
            VALUES ($1, $2, $3, NOW(), $4)
            RETURNING id, wallet_id, score, status, scanned_at, created_at, observations
            "#,
        )
        .bind(wallet_id)
        .bind(score)
        .bind(status)
        .bind(observations)
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

    /// Count threats by type in calendar month (start of month to now).
    pub async fn count_threats_by_type_this_month(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_type: &str,
    ) -> Result<i64, Error> {
        let start = month_start_utc(Utc::now());
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM threats WHERE wallet_id = $1 AND threat_type = $2 AND detected_at >= $3",
        )
        .bind(wallet_id)
        .bind(threat_type)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Count threats by type in previous calendar month.
    pub async fn count_threats_by_type_previous_month(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_type: &str,
    ) -> Result<i64, Error> {
        let now = Utc::now();
        let this_start = month_start_utc(now);
        let (prev_year, prev_month) = if now.month() == 1 {
            (now.year() - 1, 12u32)
        } else {
            (now.year(), now.month() - 1)
        };
        let prev_start = NaiveDate::from_ymd_opt(prev_year as i32, prev_month, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|t| DateTime::from_naive_utc_and_offset(t, Utc))
            .unwrap_or(this_start);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM threats WHERE wallet_id = $1 AND threat_type = $2 AND detected_at >= $3 AND detected_at < $4",
        )
        .bind(wallet_id)
        .bind(threat_type)
        .bind(prev_start)
        .bind(this_start)
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

    pub async fn list_approvals(
        pool: &DbPool,
        wallet_id: Uuid,
        since: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<WalletApproval>, Error> {
        let rows = if let Some(s) = since {
            sqlx::query_as(
                "SELECT * FROM wallet_approvals WHERE wallet_id = $1 AND detected_at >= $2 ORDER BY detected_at DESC LIMIT $3",
            )
            .bind(wallet_id)
            .bind(s)
            .bind(limit)
            .fetch_all(pool)
        } else {
            sqlx::query_as(
                "SELECT * FROM wallet_approvals WHERE wallet_id = $1 ORDER BY detected_at DESC LIMIT $2",
            )
            .bind(wallet_id)
            .bind(limit)
            .fetch_all(pool)
        }
        .await?;
        Ok(rows)
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
        sqlx::query_as(
            "SELECT id, wallet_id, symbol, name, balance, usd_value::float8, change_percent::float8, created_at, updated_at FROM wallet_assets WHERE wallet_id = $1 ORDER BY usd_value DESC",
        )
        .bind(wallet_id)
        .fetch_all(pool)
        .await
    }

    pub async fn list_transaction_monitoring_paginated(
        pool: &DbPool,
        wallet_id: Uuid,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<MonitoredTransaction>, i64), Error> {
        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM transaction_monitoring WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        let offset = (page.saturating_sub(1) as i64) * (per_page as i64);
        let limit = per_page as i64;
        let rows = sqlx::query_as::<_, MonitoredTransaction>(
            "SELECT * FROM transaction_monitoring WHERE wallet_id = $1 ORDER BY detected_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(wallet_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        Ok((rows, total.0))
    }

    pub async fn total_asset_usd(pool: &DbPool, wallet_id: Uuid) -> Result<f64, Error> {
        let row = sqlx::query_as(
            "SELECT COALESCE(SUM(usd_value), 0)::float8 FROM wallet_assets WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r: (f64,)| r.0).unwrap_or(0.0))
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
        Self::create_threat_with_surface(pool, wallet_id, severity, title, source_contract, None, None, None).await
    }

    /// Create a threat with surface and explanation (transaction lie detector pipeline).
    pub async fn create_threat_with_surface(
        pool: &DbPool,
        wallet_id: Uuid,
        severity: &str,
        title: &str,
        source_contract: Option<&str>,
        threat_type: Option<&str>,
        surface: Option<&str>,
        explanation: Option<&str>,
    ) -> Result<Threat, Error> {
        let risk_breakdown: Option<serde_json::Value> = None;
        sqlx::query_as(
            r#"
            INSERT INTO threats (wallet_id, severity, title, source_contract, threat_type, surface, explanation, risk_breakdown, detected_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(severity)
        .bind(title)
        .bind(source_contract)
        .bind(threat_type)
        .bind(surface)
        .bind(explanation)
        .bind(risk_breakdown)
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

    pub async fn create_contract_scan(
        pool: &DbPool,
        contract_address: &str,
        trust_score: i32,
        critical_risk_flags: i32,
        token_controlled: &str,
        owner_admin_count: i32,
        details: Option<&serde_json::Value>,
        scanned_for_address: Option<&str>,
    ) -> Result<ContractScan, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO contract_scans (contract_address, trust_score, critical_risk_flags, token_controlled, owner_admin_count, details, scanned_at, scanned_for_address)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
            RETURNING *
            "#,
        )
        .bind(contract_address)
        .bind(trust_score)
        .bind(critical_risk_flags)
        .bind(token_controlled)
        .bind(owner_admin_count)
        .bind(details)
        .bind(scanned_for_address)
        .fetch_one(pool)
        .await
    }

    pub async fn get_contract_scan_by_id(
        pool: &DbPool,
        scan_id: Uuid,
    ) -> Result<Option<ContractScan>, Error> {
        sqlx::query_as("SELECT id, contract_address, trust_score, critical_risk_flags, token_controlled, owner_admin_count, details, scanned_at, created_at, scanned_for_address FROM contract_scans WHERE id = $1")
            .bind(scan_id)
            .fetch_optional(pool)
            .await
    }

    /// Trend for a contract: scans in last 24h, distinct wallets, risk_trend hint.
    pub async fn get_contract_scan_trend(
        pool: &DbPool,
        contract_address: &str,
    ) -> Result<(i64, i64), Error> {
        let scans_today: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM contract_scans WHERE contract_address = $1 AND scanned_at > NOW() - INTERVAL '24 hours'",
        )
        .bind(contract_address)
        .fetch_one(pool)
        .await?;
        let wallets_affected: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT scanned_for_address)::bigint FROM contract_scans WHERE contract_address = $1 AND scanned_at > NOW() - INTERVAL '7 days' AND scanned_for_address IS NOT NULL",
        )
        .bind(contract_address)
        .fetch_one(pool)
        .await?;
        Ok((scans_today.0, wallets_affected.0))
    }

    // ---- Contract fingerprints ----
    pub async fn get_fingerprint_by_contract(
        pool: &DbPool,
        contract_address: &str,
    ) -> Result<Option<ContractFingerprint>, Error> {
        sqlx::query_as("SELECT * FROM contract_fingerprints WHERE contract_address = $1")
            .bind(contract_address)
            .fetch_optional(pool)
            .await
    }

    pub async fn upsert_contract_fingerprint(
        pool: &DbPool,
        contract_address: &str,
        bytecode_hash: &str,
        abi_pattern_hash: Option<&str>,
        family: Option<&str>,
        known_attack_type: Option<&str>,
    ) -> Result<ContractFingerprint, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO contract_fingerprints (contract_address, bytecode_hash, abi_pattern_hash, family, known_attack_type, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (contract_address) DO UPDATE SET
                bytecode_hash = EXCLUDED.bytecode_hash,
                abi_pattern_hash = EXCLUDED.abi_pattern_hash,
                family = EXCLUDED.family,
                known_attack_type = EXCLUDED.known_attack_type,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(contract_address)
        .bind(bytecode_hash)
        .bind(abi_pattern_hash)
        .bind(family)
        .bind(known_attack_type)
        .fetch_one(pool)
        .await
    }

    // ---- Protection: block ----
    pub async fn block_contract(
        pool: &DbPool,
        wallet_address: &str,
        contract_address: &str,
    ) -> Result<UserBlockedContract, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO user_blocked_contracts (wallet_address, contract_address)
            VALUES ($1, $2)
            ON CONFLICT (wallet_address, contract_address) DO UPDATE SET wallet_address = user_blocked_contracts.wallet_address
            RETURNING *
            "#,
        )
        .bind(wallet_address)
        .bind(contract_address)
        .fetch_one(pool)
        .await
    }

    pub async fn unblock_contract(
        pool: &DbPool,
        wallet_address: &str,
        contract_address: &str,
    ) -> Result<u64, Error> {
        let r = sqlx::query("DELETE FROM user_blocked_contracts WHERE wallet_address = $1 AND contract_address = $2")
            .bind(wallet_address)
            .bind(contract_address)
            .execute(pool)
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn is_contract_blocked(
        pool: &DbPool,
        wallet_address: &str,
        contract_address: &str,
    ) -> Result<bool, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_blocked_contracts WHERE wallet_address = $1 AND contract_address = $2",
        )
        .bind(wallet_address)
        .bind(contract_address)
        .fetch_one(pool)
        .await?;
        Ok(row.0 > 0)
    }

    pub async fn list_blocked_contracts(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<Vec<UserBlockedContract>, Error> {
        sqlx::query_as("SELECT * FROM user_blocked_contracts WHERE wallet_address = $1 ORDER BY created_at DESC")
            .bind(wallet_address)
            .fetch_all(pool)
            .await
    }

    // ---- Protection: watchlist ----
    pub async fn add_to_watchlist(
        pool: &DbPool,
        wallet_address: &str,
        contract_address: &str,
    ) -> Result<UserContractWatchlist, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO user_contract_watchlist (wallet_address, contract_address)
            VALUES ($1, $2)
            ON CONFLICT (wallet_address, contract_address) DO UPDATE SET wallet_address = user_contract_watchlist.wallet_address
            RETURNING *
            "#,
        )
        .bind(wallet_address)
        .bind(contract_address)
        .fetch_one(pool)
        .await
    }

    pub async fn remove_from_watchlist(
        pool: &DbPool,
        wallet_address: &str,
        contract_address: &str,
    ) -> Result<u64, Error> {
        let r = sqlx::query("DELETE FROM user_contract_watchlist WHERE wallet_address = $1 AND contract_address = $2")
            .bind(wallet_address)
            .bind(contract_address)
            .execute(pool)
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn list_watchlist(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<Vec<UserContractWatchlist>, Error> {
        sqlx::query_as("SELECT * FROM user_contract_watchlist WHERE wallet_address = $1 ORDER BY created_at DESC")
            .bind(wallet_address)
            .fetch_all(pool)
            .await
    }

    // ---- Protection: scam report ----
    pub async fn create_scam_report(
        pool: &DbPool,
        contract_address: &str,
        reporter_wallet_address: Option<&str>,
    ) -> Result<ScamReport, Error> {
        sqlx::query_as(
            "INSERT INTO scam_reports (contract_address, reporter_wallet_address) VALUES ($1, $2) RETURNING *",
        )
        .bind(contract_address)
        .bind(reporter_wallet_address)
        .fetch_one(pool)
        .await
    }

    pub async fn count_scam_reports(pool: &DbPool, contract_address: &str) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM scam_reports WHERE contract_address = $1",
        )
        .bind(contract_address)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }
}
