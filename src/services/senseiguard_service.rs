use crate::db::DbPool;
use crate::models::senseiguard::{
    threat_types, ActivityFeedItem, Alert, DashboardMetricsResponse, DashboardSummaryResponse,
    FullScanReportResponse, IngestActivityRequest, MetricCard, ScanObservation,
    SecurityStatusResponse, SecurityScan, Threat, ThreatLevelCard, WalletApproval, WalletAsset,
};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::repositories::wallet_repository::WalletRepository;
use chrono::{Datelike, DateTime, NaiveDate, Utc};
use sqlx::Error;
use uuid::Uuid;

pub struct SenseiguardService;

impl SenseiguardService {
    async fn wallet_id_by_address(pool: &DbPool, address: &str) -> Result<Uuid, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        Ok(wallet.id)
    }

    pub async fn get_security_status(
        pool: &DbPool,
        address: &str,
    ) -> Result<SecurityStatusResponse, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let latest = SenseiguardRepository::get_latest_scan(pool, wallet_id).await?;
        let (score, status, last_scan_at) = match &latest {
            Some(s) => (
                s.score,
                s.status.clone(),
                Some(s.scanned_at),
            ),
            None => {
                let sc: (i32,) = sqlx::query_as(
                    "SELECT COALESCE(security_score, 0) FROM wallet_monitoring WHERE wallet_id = $1",
                )
                .bind(wallet_id)
                .fetch_optional(pool)
                .await?
                .unwrap_or((0,));
                let at: (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
                    "SELECT last_scan_at FROM wallet_monitoring WHERE wallet_id = $1",
                )
                .bind(wallet_id)
                .fetch_optional(pool)
                .await?
                .unwrap_or((None,));
                (sc.0, Self::status_from_score(sc.0), at.0)
            }
        };
        let message = match status.as_str() {
            "strong" => "Your wallet is well protected. A few settings can be improved for stronger security.",
            "moderate" => "Your wallet has moderate protection. Run a scan and address the findings.",
            "weak" => "Your wallet needs attention. Run a full scan and fix critical issues.",
            _ => "Run a full scan to see your security status.",
        };
        Ok(SecurityStatusResponse {
            score,
            status,
            message: message.to_string(),
            last_scan_at,
        })
    }

    fn status_from_score(score: i32) -> String {
        match score {
            0..=39 => "weak".to_string(),
            40..=69 => "moderate".to_string(),
            _ => "strong".to_string(),
        }
    }

    pub async fn run_full_scan(
        pool: &DbPool,
        address: &str,
    ) -> Result<FullScanReportResponse, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;

        let threats_count = SenseiguardRepository::count_threats_this_month(pool, wallet_id).await?;
        let high_risk_alerts =
            SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;
        let unread_alerts = SenseiguardRepository::unread_alerts_count(pool, wallet_id).await?;
        let assets = SenseiguardRepository::list_assets(pool, wallet_id).await?;
        let activity = SenseiguardRepository::list_activity(pool, wallet_id, 10).await?;

        let mut observations: Vec<ScanObservation> = Vec::new();

        observations.push(ScanObservation {
            observation_type: "threats".to_string(),
            title: "Threats this month".to_string(),
            description: Some(format!("{} threat(s) detected in the last 30 days.", threats_count)),
            severity: if threats_count > 0 {
                Some("warning".to_string())
            } else {
                Some("ok".to_string())
            },
            detail: Some(serde_json::json!({ "count": threats_count })),
        });

        observations.push(ScanObservation {
            observation_type: "alerts".to_string(),
            title: "Unread alerts".to_string(),
            description: Some(format!("{} unread alert(s), {} high risk.", unread_alerts, high_risk_alerts)),
            severity: if high_risk_alerts > 0 {
                Some("critical".to_string())
            } else if unread_alerts > 0 {
                Some("warning".to_string())
            } else {
                Some("ok".to_string())
            },
            detail: Some(serde_json::json!({
                "unread": unread_alerts,
                "high_risk": high_risk_alerts
            })),
        });

        observations.push(ScanObservation {
            observation_type: "assets".to_string(),
            title: "Connected wallet assets".to_string(),
            description: Some(format!("{} asset(s) tracked.", assets.len())),
            severity: Some("info".to_string()),
            detail: Some(serde_json::json!({
                "count": assets.len(),
                "symbols": assets.iter().map(|a| a.symbol.as_str()).collect::<Vec<_>>()
            })),
        });

        let suspicious_activity = activity
            .iter()
            .filter(|a| {
                a.activity_type == "suspicious_approval"
                    || a.activity_type == "blocked_interaction"
            })
            .count();
        observations.push(ScanObservation {
            observation_type: "activity".to_string(),
            title: "Recent activity".to_string(),
            description: Some(format!(
                "{} recent event(s). {} suspicious or blocked.",
                activity.len(),
                suspicious_activity
            )),
            severity: if suspicious_activity > 0 {
                Some("warning".to_string())
            } else {
                Some("ok".to_string())
            },
            detail: Some(serde_json::json!({
                "total_recent": activity.len(),
                "suspicious_or_blocked": suspicious_activity
            })),
        });

        observations.push(ScanObservation {
            observation_type: "summary".to_string(),
            title: "Scan complete".to_string(),
            description: Some("Wallet scanned. No on-chain data fetched in this version; integrate RPC/indexer for full analysis.".to_string()),
            severity: Some("info".to_string()),
            detail: None,
        });

        let score = (100i32)
            .saturating_sub(threats_count as i32 * 5)
            .saturating_sub(high_risk_alerts as i32 * 10)
            .clamp(0, 100);

        let observations_json = serde_json::to_value(&observations).unwrap_or_else(|_| serde_json::json!([]));
        let scan = SenseiguardRepository::create_scan(pool, wallet_id, score, &observations_json).await?;

        Ok(FullScanReportResponse {
            scan_id: scan.id,
            wallet_id: scan.wallet_id,
            score: scan.score,
            status: scan.status,
            scanned_at: scan.scanned_at,
            observations,
        })
    }

    pub async fn dashboard_summary(
        pool: &DbPool,
        address: &str,
    ) -> Result<DashboardSummaryResponse, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let security_status = Self::get_security_status(pool, address).await?;
        let threats_this_month =
            SenseiguardRepository::count_threats_this_month(pool, wallet_id).await?;
        let scans_this_month =
            SenseiguardRepository::count_scans_this_month(pool, wallet_id).await?;
        let total_asset_usd = SenseiguardRepository::total_asset_usd(pool, wallet_id).await?;
        let unread_alerts = SenseiguardRepository::unread_alerts_count(pool, wallet_id).await?;
        let high_risk_alerts =
            SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;
        let issues_this_month =
            SenseiguardRepository::get_wallet_issues_this_month(pool, wallet_id).await?;

        Ok(DashboardSummaryResponse {
            security_status,
            threats_this_month,
            threats_trend_percent: -2.3,
            scans_this_month,
            scans_trend_percent: 2.3,
            total_asset_usd: format!("{:.2}", total_asset_usd),
            total_asset_trend_percent: 2.3,
            unread_alerts,
            high_risk_alerts,
            alerts_trend_percent: -2.3,
            issues_this_month,
        })
    }

    pub async fn get_latest_scan_report(
        pool: &DbPool,
        address: &str,
    ) -> Result<Option<FullScanReportResponse>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let scan = SenseiguardRepository::get_latest_scan(pool, wallet_id).await?;
        let scan = match scan {
            Some(s) => s,
            None => return Ok(None),
        };
        let observations: Vec<ScanObservation> = scan
            .observations
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        Ok(Some(FullScanReportResponse {
            scan_id: scan.id,
            wallet_id: scan.wallet_id,
            score: scan.score,
            status: scan.status,
            scanned_at: scan.scanned_at,
            observations,
        }))
    }

    pub async fn ingest_activity(
        pool: &DbPool,
        address: &str,
        request: IngestActivityRequest,
    ) -> Result<ActivityFeedItem, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::create_activity(
            pool,
            wallet_id,
            &request.activity_type,
            &request.title,
            request.description.as_deref(),
            request.metadata,
        )
        .await
    }

    pub async fn list_threats(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<Threat>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_threats(pool, wallet_id, limit).await
    }

    pub async fn list_scans(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<SecurityScan>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_scans(pool, wallet_id, limit).await
    }

    pub async fn list_alerts(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<Alert>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_alerts(pool, wallet_id, limit).await
    }

    pub async fn list_activity(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<ActivityFeedItem>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_activity(pool, wallet_id, limit).await
    }

    /// List approvals for Approval & Permission UI. period = "this_month" filters to current calendar month.
    pub async fn list_approvals(
        pool: &DbPool,
        address: &str,
        period: Option<&str>,
        limit: i64,
    ) -> Result<Vec<WalletApproval>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let since = if period == Some("this_month") {
            let now = Utc::now();
            NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|t| DateTime::from_naive_utc_and_offset(t, Utc))
        } else {
            None
        };
        SenseiguardRepository::list_approvals(pool, wallet_id, since, limit).await
    }

    pub async fn list_assets(pool: &DbPool, address: &str) -> Result<Vec<WalletAsset>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_assets(pool, wallet_id).await
    }

    /// Recent activity for all active wallets. Used when polling every 6s for live activity.
    pub async fn recent_activity_all_wallets(
        pool: &DbPool,
        limit_per_wallet: i64,
    ) -> Result<Vec<(String, Vec<ActivityFeedItem>)>, Error> {
        let wallets = WalletRepository::get_all_active_wallets(pool).await?;
        let mut out = Vec::with_capacity(wallets.len());
        for w in wallets {
            let activities = SenseiguardRepository::list_activity(pool, w.id, limit_per_wallet)
                .await
                .unwrap_or_default();
            out.push((w.address, activities));
        }
        Ok(out)
    }

    /// Four dashboard metric cards: malicious tx, phishing, risky tokens, active threat level (this month + trend %).
    pub async fn get_dashboard_metrics(
        pool: &DbPool,
        address: &str,
    ) -> Result<DashboardMetricsResponse, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;

        let (mal_this, mal_prev) = (
            SenseiguardRepository::count_threats_by_type_this_month(
                pool,
                wallet_id,
                threat_types::MALICIOUS_TRANSACTION,
            )
            .await?,
            SenseiguardRepository::count_threats_by_type_previous_month(
                pool,
                wallet_id,
                threat_types::MALICIOUS_TRANSACTION,
            )
            .await?,
        );
        let phish_this = SenseiguardRepository::count_threats_by_type_this_month(
            pool,
            wallet_id,
            threat_types::PHISHING_INDICATOR,
        )
        .await?
        + SenseiguardRepository::count_threats_by_type_this_month(
            pool,
            wallet_id,
            threat_types::FRONTEND_PHISHING,
        )
        .await?;
        let phish_prev = SenseiguardRepository::count_threats_by_type_previous_month(
            pool,
            wallet_id,
            threat_types::PHISHING_INDICATOR,
        )
        .await?
        + SenseiguardRepository::count_threats_by_type_previous_month(
            pool,
            wallet_id,
            threat_types::FRONTEND_PHISHING,
        )
        .await?;
        let (risk_this, risk_prev) = (
            SenseiguardRepository::count_threats_by_type_this_month(
                pool,
                wallet_id,
                threat_types::RISKY_TOKEN,
            )
            .await?,
            SenseiguardRepository::count_threats_by_type_previous_month(
                pool,
                wallet_id,
                threat_types::RISKY_TOKEN,
            )
            .await?,
        );

        let score: i32 = sqlx::query_as(
            "SELECT COALESCE(security_score, 0) FROM wallet_monitoring WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await?
        .map(|r: (i32,)| r.0)
        .unwrap_or(0);

        Ok(DashboardMetricsResponse {
            malicious_transaction: MetricCard {
                value: mal_this,
                change_percent: change_percent(mal_this, mal_prev),
            },
            phishing_indicators: MetricCard {
                value: phish_this,
                change_percent: change_percent(phish_this, phish_prev),
            },
            risky_tokens: MetricCard {
                value: risk_this,
                change_percent: change_percent(risk_this, risk_prev),
            },
            active_threat_level: ThreatLevelCard {
                value: score_to_level(score),
                change_percent: 0.0, // no historical score stored yet
            },
        })
    }
}

fn change_percent(this_month: i64, prev_month: i64) -> f64 {
    if prev_month == 0 {
        return 0.0;
    }
    let d = (this_month - prev_month) as f64 / prev_month as f64 * 100.0;
    (d * 10.0).round() / 10.0
}

fn score_to_level(score: i32) -> String {
    match score {
        0..=33 => "High".to_string(),
        34..=66 => "Medium".to_string(),
        _ => "Low".to_string(),
    }
}
