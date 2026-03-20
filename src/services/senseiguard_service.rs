use crate::clients::{native_price, rpc};
use crate::db::DbPool;
use crate::models::senseiguard::{
    threat_types, ActiveAlertsOverview, ActivityFeedItem, ActivityMonitorDappResponse,
    ActivityMonitorWalletResponse, Alert, ActiveThreatsCard, AiThreatExplanationCard, ConnectedRiskOverview,
    ConnectedWalletModalBalance, ConnectedWalletModalDetails, ConnectedWalletModalResponse,
    ConnectedWalletModalSecurity, DashboardMetricsResponse, DashboardOverviewResponse, DashboardSummaryResponse,
    NativeChainBalance,
    FullScanReportResponse, IngestActivityRequest, LiveActivityFeedItem, LiveScamSignalItem, MetricCard,
    MonitoredTransaction, OverallRiskCard, RecentActivityOverview, ReportedThreatsCard, ScamFrequencyDay,
    ScamPatternInsightsCard, ScamPatternsCard, ScanObservation, SecurityOverviewResponse, SecurityStatusResponse,
    SecurityScan, Threat, ThreatLevelCard, WalletApproval, WalletAsset, WalletStatusOverview,
};
use crate::repositories::senseiguard_repository::{SenseiguardRepository, ActivityFeedRowLive, ThreatDetectionRow};
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::protection_engine;
use chrono::{Datelike, Duration, DateTime, NaiveDate, Utc};
use sqlx::Error;
use uuid::Uuid;

pub struct SenseiguardService;

#[derive(Debug, Default)]
struct LiveNativeBalanceBreakdown {
    native_balance_wei: String,
    native_balance_eth: f64,
    native_usd: f64,
    price_source: Option<String>,
    pricing_error: Option<String>,
    rpc_error: Option<String>,
}

#[derive(Debug)]
struct MultiChainNativeAggregate {
    /// Sum of `native_usd` across scanned chains.
    total_usd: f64,
    per_chain: Vec<NativeChainBalance>,
    /// DB `chain_id` row (for legacy fields / modal wei).
    primary: LiveNativeBalanceBreakdown,
}

impl SenseiguardService {
    async fn wallet_id_by_address(pool: &DbPool, address: &str) -> Result<Uuid, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        Ok(wallet.id)
    }

    /// Live native balance + USD (RPC + price APIs). Surfaces rpc/pricing errors for API diagnostics.
    async fn live_native_balance_breakdown(address: &str, chain_id: i64) -> LiveNativeBalanceBreakdown {
        let mut out = LiveNativeBalanceBreakdown::default();
        match rpc::fetch_balance_wei(address, Some(chain_id as u64)).await {
            Ok(wei_hex) => {
                out.native_balance_wei = wei_hex.clone();
                out.native_balance_eth = rpc::wei_hex_to_eth_f64(&wei_hex);
            }
            Err(e) => {
                tracing::warn!(chain_id, error = %e, "eth_getBalance failed");
                out.rpc_error = Some(e);
                out.native_balance_wei = "0x0".to_string();
            }
        }
        match native_price::fetch_native_usd_detailed(chain_id).await {
            Some(q) => {
                out.price_source = Some(q.source.to_string());
                out.native_usd = out.native_balance_eth * q.usd_per_unit;
            }
            None => {
                out.pricing_error = Some(
                    "USD price unavailable (CoinGecko, CoinCap, Binance, Coinbase all failed or blocked)"
                        .to_string(),
                );
                tracing::warn!(chain_id, "native token USD price unavailable");
            }
        }
        out
    }

    /// EVM chains to scan for `eth_getBalance` (same address on each). Env `NATIVE_BALANCE_SCAN_CHAIN_IDS=1,56,...`
    fn default_native_scan_chain_ids() -> Vec<u64> {
        if let Ok(s) = std::env::var("NATIVE_BALANCE_SCAN_CHAIN_IDS") {
            let v: Vec<u64> = s
                .split(',')
                .filter_map(|x| x.trim().parse().ok())
                .filter(|&id| id > 0)
                .collect();
            if !v.is_empty() {
                return v;
            }
        }
        vec![
            1, 56, 137, 8453, 42161, 10, 324, 59144, 534352, 43114, 250,
        ]
    }

    fn merge_wallet_chain_id(mut ids: Vec<u64>, wallet_chain_id: i64) -> Vec<u64> {
        if wallet_chain_id > 0 {
            let w = wallet_chain_id as u64;
            if !ids.contains(&w) {
                ids.push(w);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn native_token_symbol(chain_id: u64) -> &'static str {
        match chain_id {
            56 => "BNB",
            137 => "MATIC",
            43114 => "AVAX",
            250 => "FTM",
            _ => "ETH",
        }
    }

    /// Sum native USD across all scan chains that have an RPC URL configured.
    async fn multi_chain_native_aggregate(
        address: &str,
        wallet_chain_id: i64,
    ) -> MultiChainNativeAggregate {
        let ids = Self::merge_wallet_chain_id(Self::default_native_scan_chain_ids(), wallet_chain_id);
        let mut per_chain = Vec::new();
        let mut total_usd = 0.0_f64;
        let mut primary = LiveNativeBalanceBreakdown::default();

        for cid in ids {
            if rpc::rpc_url_for_chain(Some(cid)).is_none() {
                continue;
            }
            let b = Self::live_native_balance_breakdown(address, cid as i64).await;
            if cid == wallet_chain_id as u64 {
                primary = LiveNativeBalanceBreakdown {
                    native_balance_wei: b.native_balance_wei.clone(),
                    native_balance_eth: b.native_balance_eth,
                    native_usd: b.native_usd,
                    price_source: b.price_source.clone(),
                    pricing_error: b.pricing_error.clone(),
                    rpc_error: b.rpc_error.clone(),
                };
            }
            let pricing_err = if b.native_balance_eth > 1e-12 && b.native_usd <= 1e-12 {
                b.pricing_error.clone()
            } else {
                None
            };
            total_usd += b.native_usd;
            per_chain.push(NativeChainBalance {
                chain_id: cid as i64,
                symbol: Self::native_token_symbol(cid).to_string(),
                balance: b.native_balance_eth,
                usd: b.native_usd,
                price_source: b.price_source.clone(),
                rpc_error: b.rpc_error.clone(),
                pricing_error: pricing_err,
            });
        }

        MultiChainNativeAggregate {
            total_usd,
            per_chain,
            primary,
        }
    }

    fn aggregate_summary_errors(
        agg: &MultiChainNativeAggregate,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let price_src = agg
            .per_chain
            .iter()
            .find(|p| p.usd > 1e-12)
            .and_then(|p| p.price_source.clone());

        let rpc_err = if agg.total_usd <= 1e-12 {
            agg.per_chain
                .iter()
                .find_map(|p| p.rpc_error.clone())
        } else {
            None
        };

        let pricing_err = if agg.total_usd <= 1e-12
            && agg.per_chain.iter().any(|p| p.balance > 1e-12)
        {
            Some(
                "USD pricing failed for one or more chains with non-zero native balance".to_string(),
            )
        } else if agg.total_usd <= 1e-12 {
            agg.primary.pricing_error.clone()
        } else {
            None
        };

        (rpc_err, pricing_err, price_src)
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
        let level = match status.as_str() {
            "strong" => "safe",
            "moderate" => "moderate",
            _ => "dangerous",
        };
        let last_updated = last_scan_at;
        let risk_breakdown = None;
        Ok(SecurityStatusResponse {
            score,
            status,
            message: message.to_string(),
            last_scan_at,
            level: level.to_string(),
            risk_breakdown,
            last_updated,
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
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        let wallet_id = wallet.id;
        let security_status = Self::get_security_status(pool, address).await?;
        let threats_this_month =
            SenseiguardRepository::count_threats_this_month(pool, wallet_id).await?;
        let threats_prev =
            SenseiguardRepository::count_threats_previous_period(pool, wallet_id).await?;
        let scans_this_month =
            SenseiguardRepository::count_scans_this_month(pool, wallet_id).await?;
        let scans_prev =
            SenseiguardRepository::count_scans_previous_period(pool, wallet_id).await?;
        // DB rows + native USD summed across NATIVE_BALANCE_SCAN_CHAIN_IDS (each chain must have RPC env set).
        let total_db_usd = SenseiguardRepository::total_asset_usd(pool, wallet_id).await?;
        let agg = Self::multi_chain_native_aggregate(address, wallet.chain_id).await;
        let total_asset_usd = total_db_usd + agg.total_usd;
        let (rpc_err, pricing_err, price_src) = Self::aggregate_summary_errors(&agg);
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
            wallet_assets_usd: total_db_usd,
            // Legacy: native on DB `chain_id` only (e.g. Ethereum 0 while BNB lives on 56).
            native_balance_eth: agg.primary.native_balance_eth,
            // Total native USD across all scanned chains with RPC.
            native_usd: agg.total_usd,
            native_price_source: price_src,
            rpc_error: rpc_err,
            native_pricing_error: pricing_err,
            native_per_chain: agg.per_chain,
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

    /// List risky-token threats for a wallet (threat_type = risky_token).
    pub async fn list_risky_tokens(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<Threat>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_threats_by_type(
            pool,
            wallet_id,
            threat_types::RISKY_TOKEN,
            limit,
        )
        .await
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

    /// Unread alerts for the "Unread Alert" modal (read_at IS NULL).
    pub async fn list_unread_alerts(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<Alert>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_unread_alerts(pool, wallet_id, limit).await
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

    /// Security dashboard cards: overall risk, active threats, scam insights, reported threats, live signals. All real DB data.
    pub async fn get_security_overview(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<SecurityOverviewResponse, Error> {
        let min_score =
            SenseiguardRepository::min_security_score_active_wallets_for_user(pool, user_id).await?;
        // security_score is 0–100 higher=better; risk_score is 0–100 higher=worse.
        let risk_score = min_score.map(|s| 100 - s).unwrap_or(0);
        let risk_level = protection_engine::score_to_band(risk_score).to_string();

        let threat_count =
            SenseiguardRepository::count_threats_for_user(pool, user_id).await.unwrap_or(0);
        let networks_affected =
            SenseiguardRepository::count_networks_affected_for_user(pool, user_id).await.unwrap_or(0);

        let daily_rows =
            SenseiguardRepository::threats_per_day_for_user(pool, user_id, 7).await.unwrap_or_default();
        let daily: Vec<ScamFrequencyDay> = daily_rows
            .into_iter()
            .map(|(d, c)| ScamFrequencyDay {
                day: d.format("%Y-%m-%d").to_string(),
                count: c,
            })
            .collect();

        let distinct_patterns =
            SenseiguardRepository::count_distinct_threat_types_for_user(pool, user_id).await.unwrap_or(0);
        let scam_pattern_status = if distinct_patterns >= 3 {
            "High"
        } else if distinct_patterns >= 1 {
            "Medium"
        } else {
            "Low"
        };

        let verified =
            SenseiguardRepository::count_scam_reports_global(pool).await.unwrap_or(0);

        let live_rows =
            SenseiguardRepository::list_threats_for_dashboard(pool, Some(user_id), 10).await?;
        let live_scam_signals: Vec<LiveScamSignalItem> = live_rows
            .into_iter()
            .map(|r| Self::threat_row_to_live_signal(r))
            .collect();

        let ai_risk_display = Self::risk_level_to_ai_display(&risk_level);
        let (signals, reasons, description) = Self::build_ai_threat_explanation(
            risk_score,
            threat_count,
            distinct_patterns,
            verified,
            &ai_risk_display,
        );
        let ai_threat_explanation = AiThreatExplanationCard {
            description,
            risk_level: ai_risk_display,
            view_summary_available: threat_count > 0 || distinct_patterns > 0,
            reasons,
            signals,
        };

        Ok(SecurityOverviewResponse {
            overall_risk: OverallRiskCard {
                risk_score,
                risk_level,
            },
            active_threats: ActiveThreatsCard {
                networks_affected,
                count: threat_count,
            },
            scam_pattern_insights: ScamPatternInsightsCard {
                period: "last_7_days".to_string(),
                daily,
            },
            scam_patterns: ScamPatternsCard {
                status: scam_pattern_status.to_string(),
                detected_count: distinct_patterns,
            },
            reported_threats: ReportedThreatsCard {
                verified,
                detected: threat_count,
            },
            live_scam_signals,
            ai_threat_explanation,
        })
    }

    /// Map band (Safe/Warning/Dangerous/Block) to display label for AI Threat Explanation card.
    fn risk_level_to_ai_display(band: &str) -> String {
        match band {
            "Block" => "Critical".to_string(),
            "Dangerous" => "Elevated".to_string(),
            "Warning" => "Moderate".to_string(),
            _ => "Safe".to_string(),
        }
    }

    /// Build AI threat explanation from risk signals (contextual, not static).
    /// Returns (signals, reasons, description) for the card. Template-based today; can add LLM summarization later.
    fn build_ai_threat_explanation(
        risk_score: i32,
        threat_count: i64,
        distinct_patterns: i64,
        verified_reports: i64,
        risk_level_display: &str,
    ) -> (Vec<String>, Vec<String>, String) {
        let mut signals: Vec<String> = Vec::new();
        let mut reasons: Vec<String> = Vec::new();

        if threat_count > 0 {
            signals.push("active_threats".to_string());
            reasons.push("Threats have been detected on your wallets in the last 30 days.".to_string());
        }
        if distinct_patterns >= 3 {
            signals.push("high_scam_pattern_count".to_string());
            reasons.push("Several distinct threat types (e.g. phishing, malicious contracts, risky approvals) have been identified.".to_string());
        } else if distinct_patterns >= 1 {
            signals.push("multiple_scam_patterns".to_string());
            reasons.push("Scam patterns have been detected in recent activity.".to_string());
        }
        if risk_score >= 80 {
            signals.push("critical_risk_score".to_string());
            reasons.push("Your overall risk score is in the critical range. Review blocked or high-risk items.".to_string());
        } else if risk_score >= 50 {
            signals.push("elevated_risk_score".to_string());
            reasons.push("Your overall risk score is elevated based on wallet and activity signals.".to_string());
        } else if risk_score >= 30 {
            signals.push("moderate_risk_score".to_string());
            reasons.push("Some risk signals are present; consider reviewing connected contracts and approvals.".to_string());
        }
        if verified_reports > 0 {
            signals.push("community_reports".to_string());
            reasons.push("Community reports indicate verified scam or abuse activity in the ecosystem.".to_string());
        }

        let description = if reasons.is_empty() {
            "SenseiGuard analyzes transaction patterns, contract behavior, and community reports to identify potential threats. No significant risk signals are currently present.".to_string()
        } else {
            format!(
                "SenseiGuard detected risk signals. Risk level: {}. Review the reasons below and consider taking action.",
                risk_level_display
            )
        };

        (signals, reasons, description)
    }

    fn threat_row_to_live_signal(r: ThreatDetectionRow) -> LiveScamSignalItem {
        let address = r
            .source_contract
            .as_deref()
            .unwrap_or(&r.wallet_address);
        let short = if address.len() >= 10 {
            format!("{}...{}", &address[..6], &address[address.len() - 4..])
        } else {
            address.to_string()
        };
        let risk_level = match r.severity.to_lowercase().as_str() {
            "critical" => "Critical",
            "high" => "High Risk",
            "medium" => "Medium",
            _ => "Low",
        };
        let threat_type: String = match r.threat_type.as_deref().unwrap_or("").to_lowercase().as_str() {
            "phishing_indicator" | "frontend_phishing" => "Phishing".to_string(),
            "malicious_transaction" => "Malware".to_string(),
            "unlimited_approval" => "Approval".to_string(),
            "risky_token" => "Risky Token".to_string(),
            _ => r
                .threat_type
                .as_deref()
                .unwrap_or(&r.title)
                .replace('_', " ")
                .split_whitespace()
                .next()
                .map(|s| {
                    let mut c = s.chars();
                    c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_else(|| s.to_string())
                })
                .unwrap_or_else(|| "Threat".to_string()),
        };
        LiveScamSignalItem {
            address: short,
            threat_type,
            detected_at: r.detected_at.format("%H:%M").to_string(),
            risk_level: risk_level.to_string(),
        }
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

    /// Activity Monitor "Connected wallet" tab: wallets with security level and last activity.
    pub async fn get_activity_monitor_wallets(
        pool: &DbPool,
        user_id: Option<&str>,
    ) -> Result<Vec<ActivityMonitorWalletResponse>, Error> {
        let rows = SenseiguardRepository::list_activity_monitor_wallets(pool, user_id).await?;
        let out: Vec<ActivityMonitorWalletResponse> = rows
            .into_iter()
            .map(|r| {
                let score = r.security_score.unwrap_or(100);
                let last_dt = r.last_scan_at.unwrap_or(r.connected_at);
                ActivityMonitorWalletResponse {
                    address: r.address,
                    wallet_type_display: wallet_type_to_display(&r.wallet_type),
                    chain_id: r.chain_id,
                    chain_name: Self::activity_monitor_chain_name(r.chain_id),
                    status: if r.is_active { "Active" } else { "Inactive" }.to_string(),
                    security_level: Self::security_level_from_score(score),
                    last_activity: Self::format_relative_time(last_dt),
                }
            })
            .collect();
        Ok(out)
    }

    fn security_level_from_score(score: i32) -> String {
        match score {
            0..=33 => "High".to_string(),
            34..=66 => "Moderate".to_string(),
            _ => "Safe".to_string(),
        }
    }

    fn format_relative_time(dt: DateTime<Utc>) -> String {
        let now = Utc::now();
        let d = now.signed_duration_since(dt);
        if d.num_minutes() < 1 {
            "Just now".to_string()
        } else if d.num_minutes() < 60 {
            format!("{} minutes ago", d.num_minutes())
        } else if d.num_hours() < 24 {
            format!("{} hour{} ago", d.num_hours(), if d.num_hours() == 1 { "" } else { "s" })
        } else if d.num_days() < 7 {
            format!("{} day{} ago", d.num_days(), if d.num_days() == 1 { "" } else { "s" })
        } else {
            format!("{} days ago", d.num_days())
        }
    }

    fn activity_monitor_chain_name(chain_id: i64) -> String {
        match chain_id {
            1 => "Ethereum".to_string(),
            56 => "Binance Smart Chain".to_string(),
            137 => "Polygon".to_string(),
            8453 => "Base".to_string(),
            42161 => "Arbitrum".to_string(),
            10 => "Optimism".to_string(),
            _ => format!("Chain {}", chain_id),
        }
    }

    /// Activity Monitor "Connected dApps" tab: dApps connected to the user's wallets.
    pub async fn get_activity_monitor_dapps(
        pool: &DbPool,
        user_id: Option<&str>,
    ) -> Result<Vec<ActivityMonitorDappResponse>, Error> {
        let rows = if let Some(uid) = user_id {
            SenseiguardRepository::list_dapp_connections_for_user(pool, uid).await?
        } else {
            SenseiguardRepository::list_dapp_connections_all(pool).await?
        };
        let out: Vec<ActivityMonitorDappResponse> = rows
            .into_iter()
            .map(|r| ActivityMonitorDappResponse {
                dapp_name: r.dapp_name,
                description: r.description.unwrap_or_default(),
                tokens: r.tokens.unwrap_or_default(),
                status: "Active".to_string(),
                connected_wallet_address: r.wallet_address,
                last_activity: Self::format_relative_time(r.last_activity_at),
            })
            .collect();
        Ok(out)
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
        let wallet_assets_usd =
            SenseiguardRepository::total_asset_usd(pool, wallet.id).await.unwrap_or(0.0);
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

        let agg = Self::multi_chain_native_aggregate(address, wallet.chain_id).await;
        let (_, pricing_err, _) = Self::aggregate_summary_errors(&agg);
        let total_usd = wallet_assets_usd + agg.total_usd;
        let primary = &agg.primary;

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
                wallet_assets_usd,
                native_balance_eth: primary.native_balance_eth,
                native_usd: agg.total_usd,
                native_balance_wei: primary.native_balance_wei.clone(),
                native_price_source: primary.price_source.clone(),
                rpc_error: primary.rpc_error.clone(),
                native_pricing_error: pricing_err.or_else(|| primary.pricing_error.clone()),
                native_per_chain: agg.per_chain,
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
