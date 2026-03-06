use crate::clients::rpc;
use crate::db::DbPool;
use crate::models::senseiguard::{
    threat_types, ActiveAlertsOverview, ActivityFeedItem, Alert, ConnectedRiskOverview,
    ConnectedWalletModalBalance, ConnectedWalletModalDetails, ConnectedWalletModalResponse,
    ConnectedWalletModalSecurity, DashboardMetricsResponse, DashboardOverviewResponse,
    DashboardSummaryResponse, FullScanReportResponse, IngestActivityRequest, LiveActivityFeedItem,
    MetricCard, MonitoredTransaction, RecentActivityOverview, ScanObservation, SecurityStatusResponse,
    SecurityScan, Threat, ThreatLevelCard, WalletApproval, WalletAsset, WalletStatusOverview,
};
use crate::repositories::senseiguard_repository::{SenseiguardRepository, ActivityFeedRowLive};
use crate::repositories::wallet_repository::WalletRepository;
use chrono::{Datelike, Duration, DateTime, NaiveDate, Utc};
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
        let threats_prev =
            SenseiguardRepository::count_threats_previous_period(pool, wallet_id).await?;
        let scans_this_month =
            SenseiguardRepository::count_scans_this_month(pool, wallet_id).await?;
        let scans_prev =
            SenseiguardRepository::count_scans_previous_period(pool, wallet_id).await?;
        let total_asset_usd = SenseiguardRepository::total_asset_usd(pool, wallet_id).await?;
        let unread_alerts = SenseiguardRepository::unread_alerts_count(pool, wallet_id).await?;
        let high_risk_alerts =
            SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;
        let alerts_created_this =
            SenseiguardRepository::count_alerts_created_this_month(pool, wallet_id).await?;
        let alerts_created_prev =
            SenseiguardRepository::count_alerts_created_previous_month(pool, wallet_id).await?;
        let issues_this_month =
            SenseiguardRepository::get_wallet_issues_this_month(pool, wallet_id).await?;

        Ok(DashboardSummaryResponse {
            security_status,
            threats_this_month,
            threats_trend_percent: Self::change_percent(threats_this_month, threats_prev),
            scans_this_month,
            scans_trend_percent: Self::change_percent(scans_this_month, scans_prev),
            total_asset_usd: format!("{:.2}", total_asset_usd),
            total_asset_trend_percent: 0.0, // no historical asset snapshots in DB
            unread_alerts,
            high_risk_alerts,
            alerts_trend_percent: Self::change_percent(alerts_created_this, alerts_created_prev),
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

    /// Live activity feed for the UI table. Paginated, optional user_id. Real data from activity_feed + metadata (asset, amount, counterparty, risk_level, status).
    pub async fn get_live_activity_feed(
        pool: &DbPool,
        user_id: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<LiveActivityFeedItem>, i64), Error> {
        let (rows, total) =
            SenseiguardRepository::list_activity_feed_live(pool, user_id, page, per_page).await?;
        let items = rows
            .into_iter()
            .map(|r| row_to_live_feed_item(r))
            .collect();
        Ok((items, total))
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

    /// Paginated list for Transaction monitoring UI: title + risk level per row.
    pub async fn list_transaction_monitoring(
        pool: &DbPool,
        address: &str,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<MonitoredTransaction>, i64), Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_transaction_monitoring_paginated(pool, wallet_id, page, per_page)
            .await
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
                change_percent: Self::change_percent(mal_this, mal_prev),
            },
            phishing_indicators: MetricCard {
                value: phish_this,
                change_percent: Self::change_percent(phish_this, phish_prev),
            },
            risky_tokens: MetricCard {
                value: risk_this,
                change_percent: Self::change_percent(risk_this, risk_prev),
            },
            active_threat_level: ThreatLevelCard {
                value: Self::score_to_level(score),
                change_percent: 0.0, // no historical score stored yet
            },
        })
    }

    /// Dashboard overview for the UI: all real data from DB, scoped to one user's wallets.
    pub async fn get_dashboard_overview(
        pool: &DbPool,
        user_id: &str,
        timeline_limit: i64,
    ) -> Result<DashboardOverviewResponse, Error> {
        let wallets = WalletRepository::get_all_active_wallets_by_user(pool, user_id).await?;
        let active_wallet_count = wallets.len() as i64;

        let min_score =
            SenseiguardRepository::min_security_score_active_wallets_for_user(pool, user_id).await?;
        let status = match min_score {
            None => "safe".to_string(),
            Some(s) => Self::overview_status_from_score(s),
        };

        let last_scan_at =
            SenseiguardRepository::global_last_scan_at_for_user(pool, user_id).await?;
        let (alerts_high, alerts_medium, alerts_low) =
            SenseiguardRepository::alerts_count_by_severity_global_for_user(pool, user_id).await?;
        let activity_timeline =
            SenseiguardRepository::list_activity_across_wallets_for_user(pool, user_id, timeline_limit).await?;

        let since_24h = Utc::now() - chrono::Duration::hours(24);
        let transactions_24h =
            SenseiguardRepository::activity_count_since_global_for_user(pool, user_id, since_24h).await?;
        let suspicious_events_24h =
            SenseiguardRepository::activity_suspicious_count_since_global_for_user(pool, user_id, since_24h).await?;

        let (total_risk_items, high_risk_connections) =
            SenseiguardRepository::transaction_monitoring_global_totals_for_user(pool, user_id).await?;

        Ok(DashboardOverviewResponse {
            wallet_status: WalletStatusOverview {
                active_wallet_count,
                status,
                last_scan_at,
            },
            active_alerts: ActiveAlertsOverview {
                total: alerts_high + alerts_medium + alerts_low,
                high: alerts_high,
                medium: alerts_medium,
                low: alerts_low,
            },
            activity_timeline,
            recent_activity: RecentActivityOverview {
                transactions_24h,
                contract_calls_24h: 0, // not tracked in DB; use ingest or external API to populate
                suspicious_events_24h,
            },
            connected_risk: ConnectedRiskOverview {
                total_risk_items,
                high_risk_connections,
                active_dapps: 0, // no dApp table; use ingest or external API to populate
            },
        })
    }

fn overview_status_from_score(score: i32) -> String {
    match score {
        0..=39 => "attention".to_string(),
        40..=69 => "moderate".to_string(),
        _ => "safe".to_string(),
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

    /// Real data for connected-wallet modal (Details, Balance, Security, Activity). No stubs.
    pub async fn get_connected_wallet_modal(
        pool: &DbPool,
        address: &str,
        activity_limit: i64,
    ) -> Result<ConnectedWalletModalResponse, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;

        let security = Self::get_security_status(pool, address).await?;
        let assets = SenseiguardRepository::list_assets(pool, wallet.id).await?;
        let total_usd = SenseiguardRepository::total_asset_usd(pool, wallet.id).await.unwrap_or(0.0);
        let approval_count = SenseiguardRepository::count_approvals(pool, wallet.id).await.unwrap_or(0);
        let (high_risk, total_monitored) =
            SenseiguardRepository::transaction_monitoring_risk_counts(pool, wallet.id)
                .await
                .unwrap_or((0, 0));
        let risk_exposure_percent = if total_monitored > 0 {
            (high_risk as f64 / total_monitored as f64 * 100.0).round()
        } else {
            0.0
        };

        let native_balance_wei = rpc::fetch_balance_wei(address, Some(wallet.chain_id as u64))
            .await
            .unwrap_or_else(|_| "0x0".to_string());
        let native_balance_eth =
            parse_wei_hex(&native_balance_wei).map(|w| w as f64 / 1e18).unwrap_or(0.0);

        let activity =
            SenseiguardRepository::list_activity(pool, wallet.id, activity_limit).await?;

        let provider = match wallet.wallet_type.to_lowercase().as_str() {
            "metamask" => "MetaMask".to_string(),
            "coinbase" => "Coinbase".to_string(),
            _ => {
                let mut s = wallet.wallet_type.clone();
                if let Some(r) = s.get_mut(0..1) {
                    r.make_ascii_uppercase();
                }
                s
            }
        };
        let network = chain_id_to_network(wallet.chain_id);
        let security_status = match security.status.as_str() {
            "strong" => "Secured",
            "moderate" => "Moderate",
            _ => "At risk",
        };
        let last_scan_ago = security
            .last_scan_at
            .map(|t| format_duration_ago(Utc::now() - t));

        Ok(ConnectedWalletModalResponse {
            details: ConnectedWalletModalDetails {
                provider,
                wallet_address: wallet.address,
                network,
                connected_at: wallet.connected_at,
                wallet_type: "Non-Custodial".to_string(),
                connected_via: "Browser Extension".to_string(),
                security_status: security_status.to_string(),
            },
            balance: ConnectedWalletModalBalance {
                total_usd,
                native_balance_eth,
                native_balance_wei: native_balance_wei.clone(),
                assets,
            },
            security: ConnectedWalletModalSecurity {
                two_fa: None,
                active_approvals: approval_count,
                last_scan_at: security.last_scan_at,
                last_scan_ago,
                threat_level: Self::score_to_level(security.score),
                risk_exposure_percent,
            },
            activity,
        })
    }
}

fn parse_wei_hex(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

fn chain_id_to_network(chain_id: i64) -> String {
    match chain_id {
        1 => "Ethereum Mainnet".to_string(),
        56 => "BNB Smart Chain".to_string(),
        137 => "Polygon".to_string(),
        8453 => "Base".to_string(),
        42161 => "Arbitrum One".to_string(),
        10 => "Optimism".to_string(),
        5 => "Goerli".to_string(),
        11155111 => "Sepolia".to_string(),
        _ => format!("Chain {}", chain_id),
    }
}

fn row_to_live_feed_item(r: ActivityFeedRowLive) -> LiveActivityFeedItem {
    let wallet = wallet_type_to_display(&r.wallet_type);
    let type_display = activity_type_to_display(&r.activity_type);
    let (asset, amount, counterparty, risk_level, status) = r.metadata.as_ref().map_or(
        (None, None, None, None, None),
        |m| {
            (
                m.get("asset").and_then(|v| v.as_str()).map(String::from),
                m.get("amount").and_then(|v| v.as_str()).map(String::from),
                m.get("counterparty").and_then(|v| v.as_str()).map(String::from),
                m.get("risk_level").and_then(|v| v.as_str()).map(String::from),
                m.get("status").and_then(|v| v.as_str()).map(String::from),
            )
        },
    );
    LiveActivityFeedItem {
        id: r.id,
        created_at: r.created_at,
        wallet,
        wallet_address: r.wallet_address,
        type_display,
        asset,
        amount,
        counterparty,
        risk_level,
        status,
        title: r.title,
        description: r.description,
    }
}

fn wallet_type_to_display(wt: &str) -> String {
    match wt.to_lowercase().as_str() {
        "metamask" => "MetaMask".to_string(),
        "coinbase" => "Coinbase".to_string(),
        "binance" => "Binance".to_string(),
        "walletconnect" => "WalletConnect".to_string(),
        "kraken" => "Kraken".to_string(),
        "trust wallet" | "trust" => "Trust Wallet".to_string(),
        "gemini" => "Gemini".to_string(),
        _ => {
            let mut s = wt.to_string();
            if let Some(r) = s.get_mut(0..1) {
                r.make_ascii_uppercase();
            }
            s
        }
    }
}

fn activity_type_to_display(at: &str) -> String {
    match at.to_lowercase().as_str() {
        "incoming_tx" | "incoming" => "Incoming".to_string(),
        "outgoing_tx" | "outgoing" => "Outgoing".to_string(),
        "contract_call" | "contract" => "Contract".to_string(),
        "approval" | "suspicious_approval" => "Approval".to_string(),
        _ => {
            let mut s = at.to_string();
            if let Some(r) = s.get_mut(0..1) {
                r.make_ascii_uppercase();
            }
            s.replace('_', " ")
        }
    }
}

fn format_duration_ago(d: Duration) -> String {
    let secs = d.num_seconds();
    if secs < 60 {
        return "just now".to_string();
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}min ago", mins);
    }
    let hours = secs / 3600;
    if hours < 24 {
        return format!("{}hr ago", hours);
    }
    let days = secs / 86400;
    if days == 1 {
        return "1 day ago".to_string();
    }
    if days < 30 {
        return format!("{} days ago", days);
    }
    let months = days / 30;
    if months == 1 {
        return "1 month ago".to_string();
    }
    format!("{} months ago", months)
}
