use crate::db::DbPool;
use crate::models::senseiguard::{
    ActivityFeedItem, ActivityFeedItemWithAddress, Alert, ContractFingerprint, ContractScan,
    MonitoredTransaction, ProtectionAutoScan, ScamReport, SecurityScan, Threat, ThreatCampaign,
    ThreatCampaignEvidence, ThreatEntityEdge, ThreatEvent, ThreatRemediationAction,
    UserBlockedContract, UserContractWatchlist, UserProtectionSettings, WalletApproval,
    WalletApprovalAlert, WalletAsset, WalletSecurityRule,
};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use sqlx::Error;
use uuid::Uuid;

fn month_start_utc(dt: DateTime<Utc>) -> DateTime<Utc> {
    NaiveDate::from_ymd_opt(dt.year(), dt.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| DateTime::from_naive_utc_and_offset(t, Utc))
        .unwrap_or_else(|| dt)
}

/// Row for Activity Monitor "Connected dApps" list.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DappConnectionRow {
    pub wallet_address: String,
    pub domain: String,
    pub dapp_name: String,
    pub description: Option<String>,
    pub tokens: Option<String>,
    pub connected_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
}

/// Row from threat_intelligence_catalog table (View threat modal).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ThreatIntelligenceCatalogRow {
    pub threat_type: String,
    pub title: String,
    pub description: String,
    pub severity: String,
}

/// Row for Community-Reported Threats list: threat type with aggregated report count and last seen.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CommunityReportedThreatRow {
    pub threat_type: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub risk_level: String,
    pub report_count: i64,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Actual threat detection for dashboard threat-intelligence (from threats table + wallet address).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ThreatDetectionRow {
    pub id: Uuid,
    pub wallet_address: String,
    pub threat_type: Option<String>,
    pub title: String,
    pub severity: String,
    pub explanation: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub source_contract: Option<String>,
}

/// Detailed threat row for per-live-signal detail endpoint.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ThreatDetectionDetailRow {
    pub id: Uuid,
    pub wallet_address: String,
    pub threat_type: Option<String>,
    pub title: String,
    pub severity: String,
    pub explanation: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub source_contract: Option<String>,
    pub surface: Option<String>,
    pub risk_breakdown: Option<serde_json::Value>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ThreatCampaignDashboardRow {
    pub id: Uuid,
    pub wallet_address: String,
    pub campaign_type: String,
    pub status: String,
    pub confidence_score: i32,
    pub risk_score: i32,
    pub narrative: String,
    pub signal_categories: serde_json::Value,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub evidence_count: i64,
}

/// Row for Activity Monitor "Connected wallet" list: wallet + security_score + last_scan_at.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActivityMonitorWalletRow {
    pub address: String,
    pub chain_id: i64,
    pub wallet_type: String,
    pub connected_at: DateTime<Utc>,
    pub is_active: bool,
    pub user_id: Option<String>,
    pub security_score: Option<i32>,
    pub last_scan_at: Option<DateTime<Utc>>,
}

/// Row from wallet_scan_history (GET /api/protection/scan-history).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WalletScanHistoryRow {
    pub id: Uuid,
    pub wallet_address: String,
    pub scan_type: String,
    pub risk_score: i32,
    pub issues_found: i32,
    pub details: Option<serde_json::Value>,
    pub scanned_at: DateTime<Utc>,
}

/// Row for Live activity feed: activity_feed + wallet address and wallet_type.
#[derive(Debug, sqlx::FromRow)]
pub struct ActivityFeedRowLive {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub wallet_address: String,
    pub wallet_type: String,
    pub activity_type: String,
    pub title: String,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

pub struct SenseiguardRepository;

impl SenseiguardRepository {
    pub async fn get_latest_scan(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<Option<SecurityScan>, Error> {
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

    pub async fn update_wallet_security_score(
        pool: &DbPool,
        wallet_id: Uuid,
        score: i32,
    ) -> Result<(), Error> {
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
        Ok(())
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

    pub async fn list_active_threats(
        pool: &DbPool,
        wallet_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Threat>, Error> {
        sqlx::query_as(
            "SELECT * FROM threats WHERE wallet_id = $1 AND status = 'open' ORDER BY detected_at DESC LIMIT $2",
        )
        .bind(wallet_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn list_threat_history(
        pool: &DbPool,
        wallet_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Threat>, Error> {
        sqlx::query_as(
            "SELECT * FROM threats WHERE wallet_id = $1 AND status IN ('resolved','dismissed') ORDER BY detected_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(wallet_id)
        .bind(limit)
        .bind(offset.max(0))
        .fetch_all(pool)
        .await
    }

    pub async fn count_threat_history(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM threats WHERE wallet_id = $1 AND status IN ('resolved','dismissed')",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn count_open_threats(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM threats WHERE wallet_id = $1 AND status = 'open'",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn count_recent_high_risk_alerts(
        pool: &DbPool,
        wallet_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND severity = 'high' AND created_at >= $2",
        )
        .bind(wallet_id)
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn get_threat_by_id_for_wallet(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_id: Uuid,
    ) -> Result<Option<Threat>, Error> {
        sqlx::query_as("SELECT * FROM threats WHERE id = $1 AND wallet_id = $2")
            .bind(threat_id)
            .bind(wallet_id)
            .fetch_optional(pool)
            .await
    }

    pub async fn update_threat_verification(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_id: Uuid,
        verification_status: &str,
        verification_method: Option<&str>,
        verification_message: Option<&str>,
        verified_at: Option<DateTime<Utc>>,
    ) -> Result<Option<Threat>, Error> {
        sqlx::query_as(
            r#"
            UPDATE threats
            SET verification_status = $3,
                verification_method = $4,
                verification_message = $5,
                verified_at = $6
            WHERE id = $1 AND wallet_id = $2
            RETURNING *
            "#,
        )
        .bind(threat_id)
        .bind(wallet_id)
        .bind(verification_status)
        .bind(verification_method)
        .bind(verification_message)
        .bind(verified_at)
        .fetch_optional(pool)
        .await
    }

    pub async fn resolve_threat(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_id: Uuid,
        resolution_note: Option<&str>,
    ) -> Result<Option<Threat>, Error> {
        sqlx::query_as(
            r#"
            UPDATE threats
            SET status = 'resolved',
                resolved_at = COALESCE(resolved_at, NOW()),
                resolution_note = COALESCE($3, resolution_note)
            WHERE id = $1 AND wallet_id = $2
            RETURNING *
            "#,
        )
        .bind(threat_id)
        .bind(wallet_id)
        .bind(resolution_note)
        .fetch_optional(pool)
        .await
    }

    pub async fn dismiss_threat(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_id: Uuid,
        dismiss_reason: Option<&str>,
    ) -> Result<Option<Threat>, Error> {
        sqlx::query_as(
            r#"
            UPDATE threats
            SET status = 'dismissed',
                dismissed_at = COALESCE(dismissed_at, NOW()),
                dismiss_reason = COALESCE($3, dismiss_reason)
            WHERE id = $1 AND wallet_id = $2
            RETURNING *
            "#,
        )
        .bind(threat_id)
        .bind(wallet_id)
        .bind(dismiss_reason)
        .fetch_optional(pool)
        .await
    }

    pub async fn create_threat_remediation_action(
        pool: &DbPool,
        threat_id: Uuid,
        wallet_id: Uuid,
        action: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<ThreatRemediationAction, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO threat_remediation_actions (threat_id, wallet_id, action, metadata)
            VALUES ($1, $2, $3, COALESCE($4, '{}'::jsonb))
            RETURNING *
            "#,
        )
        .bind(threat_id)
        .bind(wallet_id)
        .bind(action)
        .bind(metadata)
        .fetch_one(pool)
        .await
    }

    pub async fn list_threat_remediation_actions(
        pool: &DbPool,
        threat_id: Uuid,
        wallet_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ThreatRemediationAction>, Error> {
        sqlx::query_as(
            "SELECT * FROM threat_remediation_actions WHERE threat_id = $1 AND wallet_id = $2 ORDER BY created_at DESC LIMIT $3",
        )
        .bind(threat_id)
        .bind(wallet_id)
        .bind(limit.clamp(1, 200))
        .fetch_all(pool)
        .await
    }

    /// List threats for a wallet filtered by threat_type (e.g. risky_token).
    pub async fn list_threats_by_type(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_type: &str,
        limit: i64,
    ) -> Result<Vec<Threat>, Error> {
        sqlx::query_as(
            "SELECT * FROM threats WHERE wallet_id = $1 AND threat_type = $2 ORDER BY detected_at DESC LIMIT $3",
        )
        .bind(wallet_id)
        .bind(threat_type)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn list_threat_intelligence_catalog(
        pool: &DbPool,
    ) -> Result<Vec<ThreatIntelligenceCatalogRow>, Error> {
        sqlx::query_as(
            "SELECT threat_type, title, description, severity FROM threat_intelligence_catalog ORDER BY display_order ASC, threat_type",
        )
        .fetch_all(pool)
        .await
    }

    /// Community-Reported Threats: threat types with report count, last seen, risk level. Joins catalog for title/description.
    pub async fn list_community_reported_threats(
        pool: &DbPool,
        limit: i64,
        offset: i64,
        risk_level_filter: Option<&str>,
        search: Option<&str>,
    ) -> Result<Vec<CommunityReportedThreatRow>, Error> {
        let limit = limit.clamp(1, 200);
        let offset = offset.max(0);
        let mut q = String::from(
            r#"
            SELECT agg.threat_type, c.title, c.description,
                   COALESCE(agg.risk_level, c.severity) AS risk_level,
                   agg.report_count, agg.last_seen
            FROM (
                SELECT COALESCE(t.threat_type, 'unknown') AS threat_type,
                       COUNT(*)::bigint AS report_count,
                       MAX(t.detected_at) AS last_seen,
                       MAX(t.severity) AS risk_level
                FROM threats t
                GROUP BY COALESCE(t.threat_type, 'unknown')
            ) agg
            LEFT JOIN threat_intelligence_catalog c ON c.threat_type = agg.threat_type
            WHERE 1=1
            "#,
        );
        if let Some(r) = risk_level_filter {
            let r = r.trim().to_lowercase();
            if !r.is_empty() {
                q.push_str(" AND LOWER(COALESCE(agg.risk_level, c.severity)) = $1");
            }
        }
        if let Some(s) = search {
            let s = s.trim();
            if !s.is_empty() {
                let param = if risk_level_filter
                    .as_ref()
                    .map(|r| !r.trim().is_empty())
                    .unwrap_or(false)
                {
                    "$2"
                } else {
                    "$1"
                };
                q.push_str(&format!(
                    " AND (agg.threat_type ILIKE {} OR c.title ILIKE {} OR c.description ILIKE {})",
                    param, param, param
                ));
            }
        }
        q.push_str(" ORDER BY agg.report_count DESC, agg.last_seen DESC NULLS LAST LIMIT ");
        q.push_str(&limit.to_string());
        q.push_str(" OFFSET ");
        q.push_str(&offset.to_string());

        let mut query = sqlx::query_as::<_, CommunityReportedThreatRow>(&q);
        if let Some(r) = risk_level_filter {
            let r = r.trim().to_lowercase();
            if !r.is_empty() {
                query = query.bind(r);
            }
        }
        if let Some(s) = search {
            let s = s.trim();
            if !s.is_empty() {
                let pat = format!("%{}%", s);
                query = query.bind(pat);
            }
        }
        query.fetch_all(pool).await
    }

    /// Total count of community-reported threat types (for pagination). Same filters as list_community_reported_threats.
    pub async fn count_community_reported_threats(
        pool: &DbPool,
        risk_level_filter: Option<&str>,
        search: Option<&str>,
    ) -> Result<i64, Error> {
        let mut q = String::from(
            r#"
            SELECT COUNT(*)::bigint FROM (
                SELECT COALESCE(t.threat_type, 'unknown') AS threat_type,
                       MAX(t.severity) AS risk_level
                FROM threats t
                GROUP BY COALESCE(t.threat_type, 'unknown')
            ) agg
            LEFT JOIN threat_intelligence_catalog c ON c.threat_type = agg.threat_type
            WHERE 1=1
            "#,
        );
        if let Some(r) = risk_level_filter {
            let r = r.trim().to_lowercase();
            if !r.is_empty() {
                q.push_str(" AND LOWER(COALESCE(agg.risk_level, c.severity)) = $1");
            }
        }
        if let Some(s) = search {
            let s = s.trim();
            if !s.is_empty() {
                let param = if risk_level_filter
                    .as_ref()
                    .map(|r| !r.trim().is_empty())
                    .unwrap_or(false)
                {
                    "$2"
                } else {
                    "$1"
                };
                q.push_str(&format!(
                    " AND (agg.threat_type ILIKE {} OR c.title ILIKE {} OR c.description ILIKE {})",
                    param, param, param
                ));
            }
        }
        let mut query = sqlx::query_scalar::<_, i64>(&q);
        if let Some(r) = risk_level_filter {
            let r = r.trim().to_lowercase();
            if !r.is_empty() {
                query = query.bind(r);
            }
        }
        if let Some(s) = search {
            let s = s.trim();
            if !s.is_empty() {
                let pat = format!("%{}%", s);
                query = query.bind(pat);
            }
        }
        query.fetch_one(pool).await
    }

    /// Distinct chain_id per threat_type (for network column). Returns (threat_type, chain_id).
    pub async fn list_threat_type_networks(pool: &DbPool) -> Result<Vec<(String, i64)>, Error> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT COALESCE(t.threat_type, 'unknown') AS threat_type, w.chain_id
            FROM threats t
            JOIN wallets w ON w.id = t.wallet_id
            GROUP BY COALESCE(t.threat_type, 'unknown'), w.chain_id
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Recent threat detections for dashboard threat-intelligence. Optional user_id scopes to that user's wallets.
    pub async fn list_threats_for_dashboard(
        pool: &DbPool,
        user_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ThreatDetectionRow>, Error> {
        let limit = limit.clamp(1, 200);
        match user_id {
            Some(uid) if !uid.trim().is_empty() => {
                sqlx::query_as(
                    r#"
                    SELECT t.id, w.address AS wallet_address, t.threat_type, t.title, t.severity,
                           t.explanation, t.detected_at, t.source_contract
                    FROM threats t
                    JOIN wallets w ON w.id = t.wallet_id
                    WHERE w.is_active = true
                      AND w.user_id = $1
                      AND t.status = 'open'
                      AND COALESCE(LOWER(t.threat_type), '') <> 'policy_enforcement'
                    ORDER BY t.detected_at DESC
                    LIMIT $2
                    "#,
                )
                .bind(uid)
                .bind(limit)
                .fetch_all(pool)
                .await
            }
            _ => {
                sqlx::query_as(
                    r#"
                    SELECT t.id, w.address AS wallet_address, t.threat_type, t.title, t.severity,
                           t.explanation, t.detected_at, t.source_contract
                    FROM threats t
                    JOIN wallets w ON w.id = t.wallet_id
                    WHERE w.is_active = true
                      AND t.status = 'open'
                      AND COALESCE(LOWER(t.threat_type), '') <> 'policy_enforcement'
                    ORDER BY t.detected_at DESC
                    LIMIT $1
                    "#,
                )
                .bind(limit)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Fetch one threat detection by id for live-signal detail view. Optional user_id scopes access.
    pub async fn get_threat_for_dashboard_by_id(
        pool: &DbPool,
        id: Uuid,
        user_id: Option<&str>,
    ) -> Result<Option<ThreatDetectionDetailRow>, Error> {
        match user_id {
            Some(uid) if !uid.trim().is_empty() => {
                sqlx::query_as(
                    r#"
                    SELECT t.id, w.address AS wallet_address, t.threat_type, t.title, t.severity,
                           t.explanation, t.detected_at, t.created_at, t.source_contract, t.surface, t.risk_breakdown
                    FROM threats t
                    JOIN wallets w ON w.id = t.wallet_id
                    WHERE t.id = $1
                      AND w.is_active = true
                      AND w.user_id = $2
                      AND t.status = 'open'
                      AND COALESCE(LOWER(t.threat_type), '') <> 'policy_enforcement'
                    LIMIT 1
                    "#,
                )
                .bind(id)
                .bind(uid)
                .fetch_optional(pool)
                .await
            }
            _ => {
                sqlx::query_as(
                    r#"
                    SELECT t.id, w.address AS wallet_address, t.threat_type, t.title, t.severity,
                           t.explanation, t.detected_at, t.created_at, t.source_contract, t.surface, t.risk_breakdown
                    FROM threats t
                    JOIN wallets w ON w.id = t.wallet_id
                    WHERE t.id = $1
                      AND w.is_active = true
                      AND t.status = 'open'
                      AND COALESCE(LOWER(t.threat_type), '') <> 'policy_enforcement'
                    LIMIT 1
                    "#,
                )
                .bind(id)
                .fetch_optional(pool)
                .await
            }
        }
    }

    /// Total threat count for user's active wallets (last 30 days).
    pub async fn count_threats_for_user(pool: &DbPool, user_id: &str) -> Result<i64, Error> {
        let start = Utc::now() - chrono::Duration::days(30);
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint FROM threats t
            JOIN wallets w ON w.id = t.wallet_id
            WHERE w.is_active = true AND w.user_id = $1 AND t.detected_at >= $2
            "#,
        )
        .bind(user_id)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Distinct chain_id count (networks affected) for user's wallets that have at least one threat in last 30 days.
    pub async fn count_networks_affected_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<i64, Error> {
        let start = Utc::now() - chrono::Duration::days(30);
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(DISTINCT w.chain_id)::bigint FROM threats t
            JOIN wallets w ON w.id = t.wallet_id
            WHERE w.is_active = true AND w.user_id = $1 AND t.detected_at >= $2
            "#,
        )
        .bind(user_id)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Threat counts per day for last N days (for scam frequency chart). Returns (date_iso, count).
    pub async fn threats_per_day_for_user(
        pool: &DbPool,
        user_id: &str,
        days: i64,
    ) -> Result<Vec<(chrono::NaiveDate, i64)>, Error> {
        let start = Utc::now() - chrono::Duration::days(days);
        let rows: Vec<(chrono::NaiveDate, i64)> = sqlx::query_as(
            r#"
            SELECT (t.detected_at AT TIME ZONE 'UTC')::date AS day, COUNT(*)::bigint
            FROM threats t
            JOIN wallets w ON w.id = t.wallet_id
            WHERE w.is_active = true AND w.user_id = $1 AND t.detected_at >= $2
            GROUP BY (t.detected_at AT TIME ZONE 'UTC')::date
            ORDER BY day ASC
            "#,
        )
        .bind(user_id)
        .bind(start)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Count distinct threat_type values for user's threats (last 30 days) — "detected patterns".
    pub async fn count_distinct_threat_types_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<i64, Error> {
        let start = Utc::now() - chrono::Duration::days(30);
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(DISTINCT COALESCE(t.threat_type, 'unknown'))::bigint
            FROM threats t
            JOIN wallets w ON w.id = t.wallet_id
            WHERE w.is_active = true AND w.user_id = $1 AND t.detected_at >= $2
            "#,
        )
        .bind(user_id)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Total number of scam reports (community reports) in the system.
    pub async fn count_scam_reports_global(pool: &DbPool) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM scam_reports")
            .fetch_one(pool)
            .await?;
        Ok(row.0)
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

    /// Scans in the previous 30-day window (days 31–60 ago) for trend vs count_scans_this_month.
    pub async fn count_scans_previous_period(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let now = Utc::now();
        let end = now - chrono::Duration::days(30);
        let start = now - chrono::Duration::days(60);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM security_scans WHERE wallet_id = $1 AND scanned_at >= $2 AND scanned_at < $3",
        )
        .bind(wallet_id)
        .bind(start)
        .bind(end)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Threats in the previous 30-day window (days 31–60 ago) for trend.
    pub async fn count_threats_previous_period(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<i64, Error> {
        let now = Utc::now();
        let end = now - chrono::Duration::days(30);
        let start = now - chrono::Duration::days(60);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM threats WHERE wallet_id = $1 AND detected_at >= $2 AND detected_at < $3",
        )
        .bind(wallet_id)
        .bind(start)
        .bind(end)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Unread alerts created this month vs previous month for trend (calendar months).
    pub async fn count_unread_alerts_this_month(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<i64, Error> {
        let start = month_start_utc(Utc::now());
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND read_at IS NULL AND created_at >= $2",
        )
        .bind(wallet_id)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn count_unread_alerts_previous_month(
        pool: &DbPool,
        wallet_id: Uuid,
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
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND read_at IS NULL AND created_at >= $2 AND created_at < $3",
        )
        .bind(wallet_id)
        .bind(prev_start)
        .bind(this_start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Alerts created in current calendar month (for trend).
    pub async fn count_alerts_created_this_month(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<i64, Error> {
        let start = month_start_utc(Utc::now());
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND created_at >= $2",
        )
        .bind(wallet_id)
        .bind(start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Alerts created in previous calendar month (for trend).
    pub async fn count_alerts_created_previous_month(
        pool: &DbPool,
        wallet_id: Uuid,
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
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND created_at >= $2 AND created_at < $3",
        )
        .bind(wallet_id)
        .bind(prev_start)
        .bind(this_start)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Unread alerts by severity for one wallet: (high, medium, low).
    pub async fn alerts_count_by_severity(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<(i64, i64, i64), Error> {
        let high: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND read_at IS NULL AND severity = 'high'",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        let medium: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND read_at IS NULL AND severity = 'medium'",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        let low: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE wallet_id = $1 AND read_at IS NULL AND severity = 'low'",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        Ok((high.0, medium.0, low.0))
    }

    /// Activity feed items for one wallet since given time.
    pub async fn activity_count_since(
        pool: &DbPool,
        wallet_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM activity_feed WHERE wallet_id = $1 AND created_at >= $2",
        )
        .bind(wallet_id)
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Suspicious or blocked activity count since given time.
    pub async fn activity_suspicious_count_since(
        pool: &DbPool,
        wallet_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM activity_feed WHERE wallet_id = $1 AND created_at >= $2 AND activity_type IN ('suspicious_approval', 'blocked_interaction')",
        )
        .bind(wallet_id)
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    // ---- Dashboard overview (aggregate across wallets; use _for_user to scope by one user) ----

    /// Minimum security score among active wallets (for security-overview risk cards).
    pub async fn min_security_score_active_wallets(pool: &DbPool) -> Result<Option<i32>, Error> {
        let row: (Option<i32>,) = sqlx::query_as(
            "SELECT MIN(COALESCE(wm.security_score, 100)) FROM wallet_monitoring wm JOIN wallets w ON w.id = wm.wallet_id WHERE w.is_active = true",
        )
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Minimum security score among active wallets for one user.
    pub async fn min_security_score_active_wallets_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<i32>, Error> {
        let row: (Option<i32>,) = sqlx::query_as(
            "SELECT MIN(COALESCE(wm.security_score, 100)) FROM wallet_monitoring wm JOIN wallets w ON w.id = wm.wallet_id WHERE w.is_active = true AND w.user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Latest scan time across all wallets (from wallet_monitoring.last_scan_at or security_scans).
    pub async fn global_last_scan_at(pool: &DbPool) -> Result<Option<DateTime<Utc>>, Error> {
        let row: (Option<DateTime<Utc>>,) =
            sqlx::query_as("SELECT MAX(last_scan_at) FROM wallet_monitoring")
                .fetch_one(pool)
                .await?;
        if row.0.is_some() {
            return Ok(row.0);
        }
        let row2: (Option<DateTime<Utc>>,) =
            sqlx::query_as("SELECT MAX(scanned_at) FROM security_scans")
                .fetch_one(pool)
                .await?;
        Ok(row2.0)
    }

    /// Latest scan time across wallets for one user.
    pub async fn global_last_scan_at_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let row: (Option<DateTime<Utc>>,) = sqlx::query_as(
            "SELECT MAX(wm.last_scan_at) FROM wallet_monitoring wm JOIN wallets w ON w.id = wm.wallet_id WHERE w.is_active = true AND w.user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        if row.0.is_some() {
            return Ok(row.0);
        }
        let row2: (Option<DateTime<Utc>>,) = sqlx::query_as(
            "SELECT MAX(ss.scanned_at) FROM security_scans ss JOIN wallets w ON w.id = ss.wallet_id WHERE w.is_active = true AND w.user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok(row2.0)
    }

    /// Wallets for Activity Monitor "Connected wallet" tab: wallet + security_score + last_scan_at. When user_id is None, returns all active wallets (fallback).
    pub async fn list_activity_monitor_wallets(
        pool: &DbPool,
        user_id: Option<&str>,
    ) -> Result<Vec<ActivityMonitorWalletRow>, Error> {
        let rows = if let Some(uid) = user_id {
            sqlx::query_as::<_, ActivityMonitorWalletRow>(
                r#"
                SELECT w.address, w.chain_id, w.wallet_type, w.connected_at, w.is_active, w.user_id,
                       wm.security_score, wm.last_scan_at
                FROM wallets w
                LEFT JOIN wallet_monitoring wm ON wm.wallet_id = w.id
                WHERE w.is_active = true AND w.user_id = $1
                ORDER BY w.connected_at DESC
                "#,
            )
            .bind(uid)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as::<_, ActivityMonitorWalletRow>(
                r#"
                SELECT w.address, w.chain_id, w.wallet_type, w.connected_at, w.is_active, w.user_id,
                       wm.security_score, wm.last_scan_at
                FROM wallets w
                LEFT JOIN wallet_monitoring wm ON wm.wallet_id = w.id
                WHERE w.is_active = true
                ORDER BY w.connected_at DESC
                "#,
            )
            .fetch_all(pool)
            .await?
        };
        Ok(rows)
    }

    /// Unread alerts by severity across all wallets: (high, medium, low).
    pub async fn alerts_count_by_severity_global(pool: &DbPool) -> Result<(i64, i64, i64), Error> {
        let high: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE read_at IS NULL AND severity = 'high'",
        )
        .fetch_one(pool)
        .await?;
        let medium: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE read_at IS NULL AND severity = 'medium'",
        )
        .fetch_one(pool)
        .await?;
        let low: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts WHERE read_at IS NULL AND severity = 'low'",
        )
        .fetch_one(pool)
        .await?;
        Ok((high.0, medium.0, low.0))
    }

    /// Unread alerts by severity across wallets for one user: (high, medium, low).
    pub async fn alerts_count_by_severity_global_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(i64, i64, i64), Error> {
        let high: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts a JOIN wallets w ON w.id = a.wallet_id WHERE w.is_active = true AND w.user_id = $1 AND a.read_at IS NULL AND a.severity = 'high'",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        let medium: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts a JOIN wallets w ON w.id = a.wallet_id WHERE w.is_active = true AND w.user_id = $1 AND a.read_at IS NULL AND a.severity = 'medium'",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        let low: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM alerts a JOIN wallets w ON w.id = a.wallet_id WHERE w.is_active = true AND w.user_id = $1 AND a.read_at IS NULL AND a.severity = 'low'",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok((high.0, medium.0, low.0))
    }

    /// Threat detections by severity across active wallets for one user (last 30 days).
    /// Used as a fallback source for Active Alerts when alert rows are missing.
    pub async fn threat_count_by_severity_global_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(i64, i64, i64), Error> {
        let row: (i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COALESCE(SUM(CASE WHEN LOWER(t.severity) IN ('critical', 'high') THEN 1 ELSE 0 END), 0)::bigint AS high_count,
                COALESCE(SUM(CASE WHEN LOWER(t.severity) IN ('medium', 'warning') THEN 1 ELSE 0 END), 0)::bigint AS medium_count,
                COALESCE(SUM(CASE WHEN LOWER(t.severity) IN ('low', 'info') OR t.severity IS NULL OR t.severity = '' THEN 1 ELSE 0 END), 0)::bigint AS low_count
            FROM threats t
            JOIN wallets w ON w.id = t.wallet_id
            WHERE w.is_active = true
              AND w.user_id = $1
              AND t.detected_at >= (NOW() - INTERVAL '30 days')
            "#,
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Activity feed across all active wallets, most recent first.
    pub async fn list_activity_across_wallets(
        pool: &DbPool,
        limit: i64,
    ) -> Result<Vec<ActivityFeedItemWithAddress>, Error> {
        sqlx::query_as(
            r#"
            SELECT af.id, af.wallet_id, w.address AS wallet_address, af.activity_type, af.title, af.description, af.metadata, af.created_at
            FROM activity_feed af
            JOIN wallets w ON w.id = af.wallet_id
            WHERE w.is_active = true
            ORDER BY af.created_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Activity feed across active wallets for one user, most recent first.
    pub async fn list_activity_across_wallets_for_user(
        pool: &DbPool,
        user_id: &str,
        limit: i64,
    ) -> Result<Vec<ActivityFeedItemWithAddress>, Error> {
        sqlx::query_as(
            r#"
            SELECT af.id, af.wallet_id, w.address AS wallet_address, af.activity_type, af.title, af.description, af.metadata, af.created_at
            FROM activity_feed af
            JOIN wallets w ON w.id = af.wallet_id
            WHERE w.is_active = true AND w.user_id = $1
            ORDER BY af.created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Total activity count in the last 24h across all active wallets.
    pub async fn activity_count_since_global(
        pool: &DbPool,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint FROM activity_feed af
            JOIN wallets w ON w.id = af.wallet_id
            WHERE w.is_active = true AND af.created_at >= $1
            "#,
        )
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Total activity count in the last 24h across active wallets for one user.
    pub async fn activity_count_since_global_for_user(
        pool: &DbPool,
        user_id: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint FROM activity_feed af
            JOIN wallets w ON w.id = af.wallet_id
            WHERE w.is_active = true AND w.user_id = $1 AND af.created_at >= $2
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Suspicious/blocked activity count in the last 24h across all wallets.
    pub async fn activity_suspicious_count_since_global(
        pool: &DbPool,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint FROM activity_feed af
            JOIN wallets w ON w.id = af.wallet_id
            WHERE w.is_active = true AND af.created_at >= $1 AND af.activity_type IN ('suspicious_approval', 'blocked_interaction')
            "#,
        )
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Suspicious/blocked activity count in the last 24h across wallets for one user.
    pub async fn activity_suspicious_count_since_global_for_user(
        pool: &DbPool,
        user_id: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint FROM activity_feed af
            JOIN wallets w ON w.id = af.wallet_id
            WHERE w.is_active = true AND w.user_id = $1 AND af.created_at >= $2 AND af.activity_type IN ('suspicious_approval', 'blocked_interaction')
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Contract-call activity count in the last 24h across wallets for one user.
    pub async fn activity_contract_calls_count_since_global_for_user(
        pool: &DbPool,
        user_id: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint FROM activity_feed af
            JOIN wallets w ON w.id = af.wallet_id
            WHERE w.is_active = true
              AND w.user_id = $1
              AND af.created_at >= $2
              AND af.activity_type IN ('contract_call', 'contract')
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// Transaction monitoring totals across all wallets: (total_rows, high_risk_count).
    pub async fn transaction_monitoring_global_totals(pool: &DbPool) -> Result<(i64, i64), Error> {
        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM transaction_monitoring tm JOIN wallets w ON w.id = tm.wallet_id WHERE w.is_active = true",
        )
        .fetch_one(pool)
        .await?;
        let high: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM transaction_monitoring tm JOIN wallets w ON w.id = tm.wallet_id WHERE w.is_active = true AND tm.risk_level = 'high'",
        )
        .fetch_one(pool)
        .await?;
        Ok((total.0, high.0))
    }

    /// Transaction monitoring totals across wallets for one user.
    pub async fn transaction_monitoring_global_totals_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(i64, i64), Error> {
        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM transaction_monitoring tm JOIN wallets w ON w.id = tm.wallet_id WHERE w.is_active = true AND w.user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        let high: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM transaction_monitoring tm JOIN wallets w ON w.id = tm.wallet_id WHERE w.is_active = true AND w.user_id = $1 AND tm.risk_level = 'high'",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok((total.0, high.0))
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

    /// Unread alerts for the "Unread Alert" modal (read_at IS NULL).
    pub async fn list_unread_alerts(
        pool: &DbPool,
        wallet_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Alert>, Error> {
        sqlx::query_as(
            "SELECT * FROM alerts WHERE wallet_id = $1 AND read_at IS NULL ORDER BY created_at DESC LIMIT $2",
        )
        .bind(wallet_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn mark_alert_read(
        pool: &DbPool,
        wallet_id: Uuid,
        alert_id: Uuid,
    ) -> Result<Option<Alert>, Error> {
        sqlx::query_as(
            r#"
            UPDATE alerts
            SET read_at = COALESCE(read_at, NOW())
            WHERE id = $1 AND wallet_id = $2
            RETURNING *
            "#,
        )
        .bind(alert_id)
        .bind(wallet_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn mark_all_alerts_read(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let result = sqlx::query(
            r#"
            UPDATE alerts
            SET read_at = COALESCE(read_at, NOW())
            WHERE wallet_id = $1
            "#,
        )
        .bind(wallet_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() as i64)
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

    /// Paginated Live activity feed. Optional filter by user_id. Returns (rows, total).
    pub async fn list_activity_feed_live(
        pool: &DbPool,
        user_id: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<ActivityFeedRowLive>, i64), Error> {
        let offset = (page.saturating_sub(1) as i64) * (per_page as i64);
        let limit = per_page as i64;

        let total: i64 = if let Some(uid) = user_id {
            let row: (i64,) = sqlx::query_as(
                r#"
                SELECT COUNT(*)::bigint FROM activity_feed af
                JOIN wallets w ON w.id = af.wallet_id
                WHERE w.is_active = true AND w.user_id = $1
                "#,
            )
            .bind(uid)
            .fetch_one(pool)
            .await?;
            row.0
        } else {
            let row: (i64,) = sqlx::query_as(
                r#"
                SELECT COUNT(*)::bigint FROM activity_feed af
                JOIN wallets w ON w.id = af.wallet_id
                WHERE w.is_active = true
                "#,
            )
            .fetch_one(pool)
            .await?;
            row.0
        };

        let rows: Vec<ActivityFeedRowLive> = if let Some(uid) = user_id {
            sqlx::query_as(
                r#"
                SELECT af.id, af.wallet_id, w.address AS wallet_address, w.wallet_type,
                       af.activity_type, af.title, af.description, af.metadata, af.created_at
                FROM activity_feed af
                JOIN wallets w ON w.id = af.wallet_id
                WHERE w.is_active = true AND w.user_id = $1
                ORDER BY af.created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(uid)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT af.id, af.wallet_id, w.address AS wallet_address, w.wallet_type,
                       af.activity_type, af.title, af.description, af.metadata, af.created_at
                FROM activity_feed af
                JOIN wallets w ON w.id = af.wallet_id
                WHERE w.is_active = true
                ORDER BY af.created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        };

        Ok((rows, total))
    }

    /// Count of active approvals for this wallet (for Security tab "Active Approval").
    pub async fn count_approvals(pool: &DbPool, wallet_id: Uuid) -> Result<i64, Error> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*)::bigint FROM wallet_approvals WHERE wallet_id = $1")
                .bind(wallet_id)
                .fetch_one(pool)
                .await?;
        Ok(row.0)
    }

    /// Risk exposure: (high_risk_count, total_count) for transaction_monitoring. Percent = high*100/total when total > 0.
    pub async fn transaction_monitoring_risk_counts(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<(i64, i64), Error> {
        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM transaction_monitoring WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        let high: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM transaction_monitoring WHERE wallet_id = $1 AND risk_level = 'high'",
        )
        .bind(wallet_id)
        .fetch_one(pool)
        .await?;
        Ok((high.0, total.0))
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

    pub async fn get_wallet_issues_this_month(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<i32, Error> {
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
            r#"SELECT id, wallet_id, symbol, name, balance, usd_value::float8, change_percent::float8,
                      chain_id, contract_address, created_at, updated_at
               FROM wallet_assets WHERE wallet_id = $1 ORDER BY usd_value DESC"#,
        )
        .bind(wallet_id)
        .fetch_all(pool)
        .await
    }

    /// Remove Moralis-synced rows for one chain before re-inserting (avoids stale tokens).
    pub async fn delete_indexed_assets_for_chain(
        pool: &DbPool,
        wallet_id: Uuid,
        chain_id: i32,
    ) -> Result<u64, Error> {
        let r = sqlx::query(
            "DELETE FROM wallet_assets WHERE wallet_id = $1 AND chain_id = $2 AND contract_address IS NOT NULL",
        )
        .bind(wallet_id)
        .bind(chain_id)
        .execute(pool)
        .await?;
        Ok(r.rows_affected())
    }

    pub async fn upsert_indexed_token(
        pool: &DbPool,
        wallet_id: Uuid,
        chain_id: i32,
        contract_address: &str,
        symbol: &str,
        name: &str,
        balance: &str,
        usd_value: f64,
        change_percent: f64,
    ) -> Result<WalletAsset, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO wallet_assets (wallet_id, symbol, name, balance, usd_value, change_percent, chain_id, contract_address, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (wallet_id, chain_id, contract_address) WHERE contract_address IS NOT NULL AND chain_id IS NOT NULL
            DO UPDATE SET symbol = EXCLUDED.symbol, name = EXCLUDED.name, balance = EXCLUDED.balance,
                          usd_value = EXCLUDED.usd_value, change_percent = EXCLUDED.change_percent, updated_at = NOW()
            RETURNING id, wallet_id, symbol, name, balance, usd_value::float8, change_percent::float8,
                      chain_id, contract_address, created_at, updated_at
            "#,
        )
        .bind(wallet_id)
        .bind(symbol)
        .bind(name)
        .bind(balance)
        .bind(usd_value)
        .bind(change_percent)
        .bind(chain_id)
        .bind(contract_address)
        .fetch_one(pool)
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
        let sym = symbol.to_lowercase();
        sqlx::query_as(
            r#"
            INSERT INTO wallet_assets (wallet_id, symbol, name, balance, usd_value, change_percent, chain_id, contract_address, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NOW())
            ON CONFLICT (wallet_id, symbol) WHERE contract_address IS NULL
            DO UPDATE SET name = EXCLUDED.name, balance = EXCLUDED.balance, usd_value = EXCLUDED.usd_value,
                          change_percent = EXCLUDED.change_percent, updated_at = NOW()
            RETURNING id, wallet_id, symbol, name, balance, usd_value::float8, change_percent::float8,
                      chain_id, contract_address, created_at, updated_at
            "#,
        )
        .bind(wallet_id)
        .bind(&sym)
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
        Self::create_threat_with_surface(
            pool,
            wallet_id,
            severity,
            title,
            source_contract,
            None,
            None,
            None,
        )
        .await
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

    pub async fn create_threat_event(
        pool: &DbPool,
        wallet_id: Uuid,
        threat_id: Option<Uuid>,
        event_type: &str,
        signal_category: &str,
        threat_type: Option<&str>,
        surface: Option<&str>,
        risk_score: i32,
        confidence_score: i32,
        source_contract: Option<&str>,
        domain: Option<&str>,
        metadata: Option<serde_json::Value>,
        event_time: Option<DateTime<Utc>>,
    ) -> Result<ThreatEvent, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO threat_events (
                wallet_id, threat_id, event_type, signal_category, threat_type, surface,
                risk_score, confidence_score, source_contract, domain, metadata, event_time
            )
            VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10, COALESCE($11, '{}'::jsonb), COALESCE($12, NOW())
            )
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(threat_id)
        .bind(event_type)
        .bind(signal_category)
        .bind(threat_type)
        .bind(surface)
        .bind(risk_score.clamp(0, 100))
        .bind(confidence_score.clamp(0, 100))
        .bind(source_contract)
        .bind(domain)
        .bind(metadata)
        .bind(event_time)
        .fetch_one(pool)
        .await
    }

    pub async fn list_recent_threat_events(
        pool: &DbPool,
        wallet_id: Uuid,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<ThreatEvent>, Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM threat_events
            WHERE wallet_id = $1 AND event_time >= $2
            ORDER BY event_time DESC
            LIMIT $3
            "#,
        )
        .bind(wallet_id)
        .bind(since)
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
    }

    pub async fn create_threat_entity_edge(
        pool: &DbPool,
        wallet_id: Uuid,
        from_entity_type: &str,
        from_entity_id: &str,
        edge_type: &str,
        to_entity_type: &str,
        to_entity_id: &str,
        weight: i32,
        metadata: Option<serde_json::Value>,
    ) -> Result<ThreatEntityEdge, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO threat_entity_edges (
                wallet_id, from_entity_type, from_entity_id, edge_type,
                to_entity_type, to_entity_id, weight, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, '{}'::jsonb))
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(from_entity_type)
        .bind(from_entity_id)
        .bind(edge_type)
        .bind(to_entity_type)
        .bind(to_entity_id)
        .bind(weight.clamp(1, 100))
        .bind(metadata)
        .fetch_one(pool)
        .await
    }

    pub async fn find_recent_open_campaign_by_type(
        pool: &DbPool,
        wallet_id: Uuid,
        campaign_type: &str,
        since: DateTime<Utc>,
    ) -> Result<Option<ThreatCampaign>, Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM threat_campaigns
            WHERE wallet_id = $1
              AND campaign_type = $2
              AND status IN ('open', 'investigating')
              AND last_seen_at >= $3
            ORDER BY last_seen_at DESC
            LIMIT 1
            "#,
        )
        .bind(wallet_id)
        .bind(campaign_type)
        .bind(since)
        .fetch_optional(pool)
        .await
    }

    pub async fn create_threat_campaign(
        pool: &DbPool,
        wallet_id: Uuid,
        campaign_type: &str,
        risk_score: i32,
        confidence_score: i32,
        narrative: &str,
        signal_categories: &serde_json::Value,
        first_seen_at: Option<DateTime<Utc>>,
        last_seen_at: Option<DateTime<Utc>>,
    ) -> Result<ThreatCampaign, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO threat_campaigns (
                wallet_id, campaign_type, status, risk_score, confidence_score, narrative,
                signal_categories, first_seen_at, last_seen_at, updated_at
            )
            VALUES (
                $1, $2, 'open', $3, $4, $5,
                $6, COALESCE($7, NOW()), COALESCE($8, NOW()), NOW()
            )
            RETURNING *
            "#,
        )
        .bind(wallet_id)
        .bind(campaign_type)
        .bind(risk_score.clamp(0, 100))
        .bind(confidence_score.clamp(0, 100))
        .bind(narrative)
        .bind(signal_categories)
        .bind(first_seen_at)
        .bind(last_seen_at)
        .fetch_one(pool)
        .await
    }

    pub async fn update_threat_campaign_scores(
        pool: &DbPool,
        campaign_id: Uuid,
        risk_score: i32,
        confidence_score: i32,
        narrative: &str,
        signal_categories: &serde_json::Value,
        last_seen_at: Option<DateTime<Utc>>,
    ) -> Result<ThreatCampaign, Error> {
        sqlx::query_as(
            r#"
            UPDATE threat_campaigns
            SET risk_score = $2,
                confidence_score = $3,
                narrative = $4,
                signal_categories = $5,
                last_seen_at = COALESCE($6, NOW()),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(campaign_id)
        .bind(risk_score.clamp(0, 100))
        .bind(confidence_score.clamp(0, 100))
        .bind(narrative)
        .bind(signal_categories)
        .bind(last_seen_at)
        .fetch_one(pool)
        .await
    }

    pub async fn create_threat_campaign_evidence(
        pool: &DbPool,
        campaign_id: Uuid,
        event_id: Option<Uuid>,
        edge_id: Option<Uuid>,
        evidence_type: &str,
        evidence_rank: i32,
        detail: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> Result<ThreatCampaignEvidence, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO threat_campaign_evidence (
                campaign_id, event_id, edge_id, evidence_type, evidence_rank, detail, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, '{}'::jsonb))
            RETURNING *
            "#,
        )
        .bind(campaign_id)
        .bind(event_id)
        .bind(edge_id)
        .bind(evidence_type)
        .bind(evidence_rank.max(0))
        .bind(detail)
        .bind(metadata)
        .fetch_one(pool)
        .await
    }

    pub async fn count_campaign_evidence(pool: &DbPool, campaign_id: Uuid) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM threat_campaign_evidence WHERE campaign_id = $1",
        )
        .bind(campaign_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    pub async fn list_campaigns_for_dashboard(
        pool: &DbPool,
        user_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ThreatCampaignDashboardRow>, Error> {
        let limit = limit.clamp(1, 200);
        match user_id {
            Some(uid) if !uid.trim().is_empty() => {
                sqlx::query_as(
                    r#"
                    SELECT c.id, w.address AS wallet_address, c.campaign_type, c.status, c.confidence_score,
                           c.risk_score, c.narrative, c.signal_categories, c.first_seen_at, c.last_seen_at,
                           COUNT(e.id)::bigint AS evidence_count
                    FROM threat_campaigns c
                    JOIN wallets w ON w.id = c.wallet_id
                    LEFT JOIN threat_campaign_evidence e ON e.campaign_id = c.id
                    WHERE w.is_active = true
                      AND w.user_id = $1
                    GROUP BY c.id, w.address
                    ORDER BY c.last_seen_at DESC, c.confidence_score DESC
                    LIMIT $2
                    "#,
                )
                .bind(uid)
                .bind(limit)
                .fetch_all(pool)
                .await
            }
            _ => {
                sqlx::query_as(
                    r#"
                    SELECT c.id, w.address AS wallet_address, c.campaign_type, c.status, c.confidence_score,
                           c.risk_score, c.narrative, c.signal_categories, c.first_seen_at, c.last_seen_at,
                           COUNT(e.id)::bigint AS evidence_count
                    FROM threat_campaigns c
                    JOIN wallets w ON w.id = c.wallet_id
                    LEFT JOIN threat_campaign_evidence e ON e.campaign_id = c.id
                    WHERE w.is_active = true
                    GROUP BY c.id, w.address
                    ORDER BY c.last_seen_at DESC, c.confidence_score DESC
                    LIMIT $1
                    "#,
                )
                .bind(limit)
                .fetch_all(pool)
                .await
            }
        }
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
        chain_id: Option<i64>,
    ) -> Result<ContractScan, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO contract_scans (contract_address, trust_score, critical_risk_flags, token_controlled, owner_admin_count, details, scanned_at, scanned_for_address, chain_id)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8)
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
        .bind(chain_id)
        .fetch_one(pool)
        .await
    }

    pub async fn get_contract_scan_by_id(
        pool: &DbPool,
        scan_id: Uuid,
    ) -> Result<Option<ContractScan>, Error> {
        sqlx::query_as("SELECT id, contract_address, trust_score, critical_risk_flags, token_controlled, owner_admin_count, details, scanned_at, created_at, scanned_for_address, chain_id FROM contract_scans WHERE id = $1")
            .bind(scan_id)
            .fetch_optional(pool)
            .await
    }

    /// Latest trust score for a contract (most recent scan). None if never scanned.
    pub async fn get_latest_trust_score(
        pool: &DbPool,
        contract_address: &str,
    ) -> Result<Option<i32>, Error> {
        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT trust_score FROM contract_scans WHERE contract_address = $1 ORDER BY scanned_at DESC LIMIT 1",
        )
        .bind(contract_address)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r| r.0))
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

    /// Count how many times this wallet has scanned this contract (for user anomaly).
    pub async fn count_scans_for_wallet_contract(
        pool: &DbPool,
        wallet_address: &str,
        contract_address: &str,
    ) -> Result<i64, Error> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM contract_scans WHERE scanned_for_address = $1 AND contract_address = $2",
        )
        .bind(wallet_address)
        .bind(contract_address)
        .fetch_one(pool)
        .await?;
        Ok(count)
    }

    /// Recent contract scans for this wallet (for risk-profile cached contract risks).
    pub async fn list_contract_scans_for_wallet(
        pool: &DbPool,
        wallet_address: &str,
        limit: i64,
    ) -> Result<Vec<ContractScan>, Error> {
        sqlx::query_as(
            "SELECT id, contract_address, trust_score, critical_risk_flags, token_controlled, owner_admin_count, details, scanned_at, created_at, scanned_for_address, chain_id FROM contract_scans WHERE scanned_for_address = $1 ORDER BY scanned_at DESC LIMIT $2",
        )
        .bind(wallet_address)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Latest scan for a contract (for scam-pattern and contract-scoped APIs).
    pub async fn get_latest_contract_scan_by_address(
        pool: &DbPool,
        contract_address: &str,
    ) -> Result<Option<ContractScan>, Error> {
        sqlx::query_as(
            "SELECT id, contract_address, trust_score, critical_risk_flags, token_controlled, owner_admin_count, details, scanned_at, created_at, scanned_for_address, chain_id FROM contract_scans WHERE contract_address = $1 ORDER BY scanned_at DESC LIMIT 1",
        )
        .bind(contract_address)
        .fetch_optional(pool)
        .await
    }

    /// Count threats where source_contract matches (for community-signals confirmed_exploits).
    pub async fn count_threats_for_contract(
        pool: &DbPool,
        contract_address: &str,
    ) -> Result<i64, Error> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*)::bigint FROM threats WHERE source_contract = $1")
                .bind(contract_address)
                .fetch_one(pool)
                .await?;
        Ok(row.0)
    }

    /// Count distinct reporters for a contract (scam_reports).
    pub async fn count_distinct_reporters_for_contract(
        pool: &DbPool,
        contract_address: &str,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT COALESCE(reporter_wallet_address, id::text))::bigint FROM scam_reports WHERE contract_address = $1",
        )
        .bind(contract_address)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
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
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM scam_reports WHERE contract_address = $1")
                .bind(contract_address)
                .fetch_one(pool)
                .await?;
        Ok(row.0)
    }

    pub async fn get_protection_settings(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<Option<UserProtectionSettings>, Error> {
        let wallet_address_normalized = wallet_address.to_lowercase();
        sqlx::query_as(
            "SELECT wallet_address, auto_security_scan, high_risk_tx_warnings, new_approval_alerts, new_dapp_connection_alerts, auto_block_high_risk, COALESCE(emergency_lock, false) as emergency_lock, whitelisted_addresses, created_at, updated_at FROM user_protection_settings WHERE LOWER(wallet_address) = LOWER($1)",
        )
        .bind(wallet_address_normalized)
        .fetch_optional(pool)
        .await
    }

    pub async fn upsert_protection_settings(
        pool: &DbPool,
        wallet_address: &str,
        auto_security_scan: bool,
        high_risk_tx_warnings: bool,
        new_approval_alerts: bool,
        new_dapp_connection_alerts: bool,
        auto_block_high_risk: bool,
    ) -> Result<UserProtectionSettings, Error> {
        Self::upsert_protection_settings_full(
            pool,
            wallet_address,
            auto_security_scan,
            high_risk_tx_warnings,
            new_approval_alerts,
            new_dapp_connection_alerts,
            auto_block_high_risk,
            None,
            None,
        )
        .await
    }

    /// Full upsert including emergency_lock and whitelisted_addresses.
    pub async fn upsert_protection_settings_full(
        pool: &DbPool,
        wallet_address: &str,
        auto_security_scan: bool,
        high_risk_tx_warnings: bool,
        new_approval_alerts: bool,
        new_dapp_connection_alerts: bool,
        auto_block_high_risk: bool,
        emergency_lock: Option<bool>,
        whitelisted_addresses: Option<serde_json::Value>,
    ) -> Result<UserProtectionSettings, Error> {
        let wallet_address_normalized = wallet_address.to_lowercase();
        let (em_lock, whitelist) = match (emergency_lock, whitelisted_addresses) {
            (Some(el), Some(w)) => (el, w),
            (Some(el), None) => (el, serde_json::json!([])),
            (None, Some(w)) => (false, w),
            (None, None) => {
                let existing = Self::get_protection_settings(pool, wallet_address).await?;
                match existing {
                    Some(s) => (
                        s.emergency_lock,
                        s.whitelisted_addresses.unwrap_or(serde_json::json!([])),
                    ),
                    None => (false, serde_json::json!([])),
                }
            }
        };
        sqlx::query_as(
            r#"
            INSERT INTO user_protection_settings (wallet_address, auto_security_scan, high_risk_tx_warnings, new_approval_alerts, new_dapp_connection_alerts, auto_block_high_risk, emergency_lock, whitelisted_addresses, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (wallet_address) DO UPDATE SET
                auto_security_scan = EXCLUDED.auto_security_scan,
                high_risk_tx_warnings = EXCLUDED.high_risk_tx_warnings,
                new_approval_alerts = EXCLUDED.new_approval_alerts,
                new_dapp_connection_alerts = EXCLUDED.new_dapp_connection_alerts,
                auto_block_high_risk = EXCLUDED.auto_block_high_risk,
                emergency_lock = EXCLUDED.emergency_lock,
                whitelisted_addresses = EXCLUDED.whitelisted_addresses,
                updated_at = NOW()
            RETURNING wallet_address, auto_security_scan, high_risk_tx_warnings, new_approval_alerts, new_dapp_connection_alerts, auto_block_high_risk, emergency_lock, whitelisted_addresses, created_at, updated_at
            "#,
        )
        .bind(wallet_address_normalized)
        .bind(auto_security_scan)
        .bind(high_risk_tx_warnings)
        .bind(new_approval_alerts)
        .bind(new_dapp_connection_alerts)
        .bind(auto_block_high_risk)
        .bind(em_lock)
        .bind(whitelist)
        .fetch_one(pool)
        .await
    }

    // ---- Protection auto-scan (protection_auto_scan table) ----
    pub async fn get_protection_auto_scan(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<Option<ProtectionAutoScan>, Error> {
        let wallet_address_normalized = wallet_address.to_lowercase();
        sqlx::query_as(
            "SELECT wallet_address, auto_scan_enabled, last_scan_at, scan_interval_seconds, updated_at FROM protection_auto_scan WHERE LOWER(wallet_address) = LOWER($1)",
        )
        .bind(wallet_address_normalized)
        .fetch_optional(pool)
        .await
    }

    pub async fn upsert_protection_auto_scan(
        pool: &DbPool,
        wallet_address: &str,
        auto_scan_enabled: bool,
        scan_interval_seconds: i32,
    ) -> Result<ProtectionAutoScan, Error> {
        let wallet_address_normalized = wallet_address.to_lowercase();
        sqlx::query_as(
            r#"
            INSERT INTO protection_auto_scan (wallet_address, auto_scan_enabled, scan_interval_seconds, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (wallet_address) DO UPDATE SET
                auto_scan_enabled = EXCLUDED.auto_scan_enabled,
                scan_interval_seconds = EXCLUDED.scan_interval_seconds,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(wallet_address_normalized)
        .bind(auto_scan_enabled)
        .bind(scan_interval_seconds)
        .fetch_one(pool)
        .await
    }

    pub async fn list_wallets_to_monitor(pool: &DbPool) -> Result<Vec<ProtectionAutoScan>, Error> {
        sqlx::query_as(
            "SELECT wallet_address, auto_scan_enabled, last_scan_at, scan_interval_seconds, updated_at FROM protection_auto_scan WHERE auto_scan_enabled = true",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn update_auto_scan_last_scan_at(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<u64, Error> {
        let wallet_address_normalized = wallet_address.to_lowercase();
        let r = sqlx::query(
            "UPDATE protection_auto_scan SET last_scan_at = NOW(), updated_at = NOW() WHERE LOWER(wallet_address) = LOWER($1)",
        )
        .bind(wallet_address_normalized)
        .execute(pool)
        .await?;
        Ok(r.rows_affected())
    }

    // ---- Wallet scan history ----
    pub async fn create_wallet_scan_history(
        pool: &DbPool,
        wallet_address: &str,
        scan_type: &str,
        risk_score: i32,
        issues_found: i32,
        details: &serde_json::Value,
    ) -> Result<WalletScanHistoryRow, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO wallet_scan_history (wallet_address, scan_type, risk_score, issues_found, details, scanned_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING id, wallet_address, scan_type, risk_score, issues_found, details, scanned_at
            "#,
        )
        .bind(wallet_address)
        .bind(scan_type)
        .bind(risk_score)
        .bind(issues_found)
        .bind(details)
        .fetch_one(pool)
        .await
    }

    pub async fn list_wallet_scan_history(
        pool: &DbPool,
        wallet_address: &str,
        limit: i64,
    ) -> Result<Vec<WalletScanHistoryRow>, Error> {
        let limit = limit.clamp(1, 100);
        sqlx::query_as(
            "SELECT id, wallet_address, scan_type, risk_score, issues_found, details, scanned_at FROM wallet_scan_history WHERE wallet_address = $1 ORDER BY scanned_at DESC LIMIT $2",
        )
        .bind(wallet_address)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    // ---- Wallet approval alerts ----
    pub async fn list_approval_alerts(
        pool: &DbPool,
        wallet_address: &str,
        limit: i64,
    ) -> Result<Vec<WalletApprovalAlert>, Error> {
        sqlx::query_as(
            "SELECT id, wallet_address, token_address, spender_address, amount_raw, risk_score, created_at FROM wallet_approval_alerts WHERE wallet_address = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(wallet_address)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn create_approval_alert(
        pool: &DbPool,
        wallet_address: &str,
        token_address: Option<&str>,
        spender_address: &str,
        amount_raw: Option<&str>,
        risk_score: i32,
    ) -> Result<WalletApprovalAlert, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO wallet_approval_alerts (wallet_address, token_address, spender_address, amount_raw, risk_score)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(wallet_address)
        .bind(token_address)
        .bind(spender_address)
        .bind(amount_raw)
        .bind(risk_score)
        .fetch_one(pool)
        .await
    }

    // ---- Wallet security rules ----
    pub async fn create_security_rule(
        pool: &DbPool,
        wallet_address: &str,
        rule_type: &str,
        condition_json: &serde_json::Value,
        action: &str,
    ) -> Result<WalletSecurityRule, Error> {
        sqlx::query_as(
            r#"
            INSERT INTO wallet_security_rules (wallet_address, rule_type, condition_json, action, enabled)
            VALUES ($1, $2, $3, $4, true)
            RETURNING *
            "#,
        )
        .bind(wallet_address)
        .bind(rule_type)
        .bind(condition_json)
        .bind(action)
        .fetch_one(pool)
        .await
    }

    pub async fn list_security_rules(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<Vec<WalletSecurityRule>, Error> {
        sqlx::query_as(
            "SELECT id, wallet_address, rule_type, condition_json, action, enabled, created_at FROM wallet_security_rules WHERE wallet_address = $1 ORDER BY created_at ASC",
        )
        .bind(wallet_address)
        .fetch_all(pool)
        .await
    }

    pub async fn update_security_rule(
        pool: &DbPool,
        rule_id: Uuid,
        wallet_address: &str,
        enabled: Option<bool>,
        condition_json: Option<&serde_json::Value>,
        action: Option<&str>,
    ) -> Result<Option<WalletSecurityRule>, Error> {
        let current: Option<WalletSecurityRule> = sqlx::query_as(
            "SELECT id, wallet_address, rule_type, condition_json, action, enabled, created_at FROM wallet_security_rules WHERE id = $1 AND wallet_address = $2",
        )
        .bind(rule_id)
        .bind(wallet_address)
        .fetch_optional(pool)
        .await?;
        let Some(rule) = current else {
            return Ok(None);
        };
        let enabled = enabled.unwrap_or(rule.enabled);
        let condition_json = condition_json.unwrap_or(&rule.condition_json);
        let action = action.unwrap_or(&rule.action);
        let updated: WalletSecurityRule = sqlx::query_as(
            r#"
            UPDATE wallet_security_rules SET enabled = $1, condition_json = $2, action = $3 WHERE id = $4 AND wallet_address = $5
            RETURNING *
            "#,
        )
        .bind(enabled)
        .bind(condition_json)
        .bind(action)
        .bind(rule_id)
        .bind(wallet_address)
        .fetch_one(pool)
        .await?;
        Ok(Some(updated))
    }

    pub async fn delete_security_rule(
        pool: &DbPool,
        rule_id: Uuid,
        wallet_address: &str,
    ) -> Result<u64, Error> {
        let r =
            sqlx::query("DELETE FROM wallet_security_rules WHERE id = $1 AND wallet_address = $2")
                .bind(rule_id)
                .bind(wallet_address)
                .execute(pool)
                .await?;
        Ok(r.rows_affected())
    }

    // ---- Activity Monitor: dApp connections ----
    /// Upsert one wallet->dApp connection and bump `last_activity_at`.
    pub async fn upsert_dapp_connection(
        pool: &DbPool,
        wallet_address: &str,
        domain: &str,
        dapp_name: &str,
        description: Option<&str>,
        tokens: Option<&str>,
    ) -> Result<DappConnectionRow, Error> {
        sqlx::query_as::<_, DappConnectionRow>(
            r#"
            INSERT INTO dapp_connections (
                wallet_address, domain, dapp_name, description, tokens, connected_at, last_activity_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), NOW())
            ON CONFLICT (wallet_address, domain) DO UPDATE SET
                dapp_name = EXCLUDED.dapp_name,
                description = COALESCE(EXCLUDED.description, dapp_connections.description),
                tokens = COALESCE(EXCLUDED.tokens, dapp_connections.tokens),
                last_activity_at = NOW(),
                updated_at = NOW()
            RETURNING wallet_address, domain, dapp_name, description, tokens, connected_at, last_activity_at
            "#,
        )
        .bind(wallet_address)
        .bind(domain)
        .bind(dapp_name)
        .bind(description)
        .bind(tokens)
        .fetch_one(pool)
        .await
    }

    /// List dApp connections for a user's wallets (for Activity Monitor "Connected dApps" tab).
    pub async fn list_dapp_connections_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<DappConnectionRow>, Error> {
        sqlx::query_as::<_, DappConnectionRow>(
            r#"
            SELECT dc.wallet_address, dc.domain, dc.dapp_name, dc.description, dc.tokens,
                   dc.connected_at, dc.last_activity_at
            FROM dapp_connections dc
            JOIN wallets w ON LOWER(w.address) = LOWER(dc.wallet_address) AND w.is_active = true
            WHERE w.user_id = $1
            ORDER BY dc.last_activity_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Count connected dApps across a user's active wallets for dashboard overview.
    pub async fn count_dapp_connections_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<i64, Error> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint
            FROM dapp_connections dc
            JOIN wallets w ON LOWER(w.address) = LOWER(dc.wallet_address) AND w.is_active = true
            WHERE w.user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    /// List all dApp connections (when no user_id; fallback for activity monitor).
    pub async fn list_dapp_connections_all(pool: &DbPool) -> Result<Vec<DappConnectionRow>, Error> {
        sqlx::query_as::<_, DappConnectionRow>(
            "SELECT wallet_address, domain, dapp_name, description, tokens, connected_at, last_activity_at FROM dapp_connections ORDER BY last_activity_at DESC",
        )
        .fetch_all(pool)
        .await
    }

    /// Distinct addresses relevant to this wallet: from approval alerts (spender, token), watchlist, blocked.
    pub async fn list_relevant_addresses_for_wallet(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<Vec<String>, Error> {
        #[derive(sqlx::FromRow)]
        struct AddrRow {
            addr: String,
        }
        let rows = sqlx::query_as::<_, AddrRow>(
            r#"
            SELECT DISTINCT addr FROM (
                SELECT spender_address AS addr FROM wallet_approval_alerts WHERE wallet_address = $1
                UNION
                SELECT token_address AS addr FROM wallet_approval_alerts WHERE wallet_address = $1 AND token_address IS NOT NULL
                UNION
                SELECT contract_address AS addr FROM user_contract_watchlist WHERE wallet_address = $1
                UNION
                SELECT contract_address AS addr FROM user_blocked_contracts WHERE wallet_address = $1
            ) t WHERE addr IS NOT NULL AND trim(addr) != ''
            "#,
        )
        .bind(wallet_address)
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.addr).collect())
    }
}
