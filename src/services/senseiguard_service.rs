use crate::clients::{moralis_wallet, native_price, rpc};
use crate::db::DbPool;
use crate::models::senseiguard::{
    threat_types, ActiveAlertsOverview, ActiveThreatsCard, ActivityFeedItem,
    ActivityMonitorDappResponse, ActivityMonitorWalletResponse, AiThreatExplanationCard, Alert,
    ConnectedRiskOverview, ConnectedWalletModalBalance, ConnectedWalletModalDetails,
    ConnectedWalletModalResponse, ConnectedWalletModalSecurity, DashboardMetricsResponse,
    DashboardOverviewResponse, DashboardSummaryResponse, FullScanReportResponse,
    IndexedTokenSyncChainOutcome, IngestActivityRequest, LiveActivityFeedItem, LiveScamSignalItem,
    MetricCard, MonitoredTransaction, NativeChainBalance, OverallRiskCard, RecentActivityOverview,
    ReportedThreatsCard, ScamFrequencyDay, ScamPatternInsightsCard, ScamPatternsCard,
    ScanObservation, SecurityOverviewResponse, SecurityScan, SecurityStatusResponse, Threat,
    ThreatLevelCard, ThreatRemediationAction, WalletApproval, WalletAsset, WalletConnectionStatus,
    WalletStatusOverview,
};
use crate::repositories::senseiguard_repository::{
    ActivityFeedRowLive, SenseiguardRepository, ThreatDetectionRow,
};
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::protection_engine;
use crate::services::threat_scoring_v2::{ThreatScoringV2, SCORING_MODEL_V2};
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use sqlx::Error;
use std::collections::HashMap;
use uuid::Uuid;

pub struct SenseiguardService;

pub struct WalletHealthRefresh {
    pub previous_score: i32,
    pub score: i32,
    pub risk_score: i32,
    pub risk_level: String,
    pub open_threats: i64,
}

pub struct ThreatVerificationResult {
    pub threat: Threat,
    pub verified: bool,
    pub verification_status: String,
    pub verification_method: Option<String>,
    pub verification_message: String,
}

pub struct VerifyAllThreatsResult {
    pub verified_count: i64,
    pub failed_count: i64,
    pub not_applicable_count: i64,
    pub results: Vec<ThreatVerificationResult>,
    pub health: WalletHealthRefresh,
}

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
    fn is_policy_enforcement_threat(t: &Threat) -> bool {
        if t.threat_type
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case(threat_types::POLICY_ENFORCEMENT))
            .unwrap_or(false)
        {
            return true;
        }
        let title = t.title.to_lowercase();
        let explanation = t.explanation.as_deref().unwrap_or("").to_lowercase();
        title.contains("emergency lock is on")
            || explanation.contains("emergency lock is on")
            || title.contains("whitelisted addresses are allowed")
            || explanation.contains("whitelisted addresses are allowed")
    }

    pub fn threat_with_guidance(t: &Threat) -> serde_json::Value {
        serde_json::json!({
            "id": t.id,
            "wallet_id": t.wallet_id,
            "severity": t.severity,
            "title": t.title,
            "source_contract": t.source_contract,
            "detected_at": t.detected_at,
            "created_at": t.created_at,
            "threat_type": t.threat_type,
            "surface": t.surface,
            "explanation": t.explanation,
            "risk_breakdown": t.risk_breakdown,
            "status": t.status,
            "resolved_at": t.resolved_at,
            "dismissed_at": t.dismissed_at,
            "resolution_note": t.resolution_note,
            "dismiss_reason": t.dismiss_reason,
            "verification_status": t.verification_status,
            "verified_at": t.verified_at,
            "verification_method": t.verification_method,
            "verification_message": t.verification_message,
            "kill_chain_stage": t.kill_chain_stage,
            "campaign_id": t.campaign_id,
            "where_to_fix": Self::threat_fix_location(t),
            "recommended_action": Self::threat_recommended_action(t),
            "fix_steps": Self::threat_fix_steps(t),
        })
    }

    async fn wallet_id_by_address(pool: &DbPool, address: &str) -> Result<Uuid, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        Ok(wallet.id)
    }

    /// Live native balance + USD (RPC + price APIs). Surfaces rpc/pricing errors for API diagnostics.
    async fn live_native_balance_breakdown(
        address: &str,
        chain_id: i64,
    ) -> LiveNativeBalanceBreakdown {
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
        vec![1, 56, 137, 8453, 42161, 10, 324, 59144, 534352, 43114, 250]
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

    /// Chains to pull ERC-20 balances from Moralis. Defaults to [`Self::default_native_scan_chain_ids`].
    fn default_token_balance_scan_chain_ids() -> Vec<u64> {
        if let Ok(s) = std::env::var("TOKEN_BALANCE_SCAN_CHAIN_IDS") {
            let v: Vec<u64> = s
                .split(',')
                .filter_map(|x| x.trim().parse().ok())
                .filter(|&id| id > 0)
                .collect();
            if !v.is_empty() {
                return v;
            }
        }
        Self::default_native_scan_chain_ids()
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

    /// Canonical wrapped gas-token contract per chain (lowercase). Used so we do not add RPC `native_usd`
    /// and Moralis wrapped balance USD twice for the same chain (common ~$1 drift vs MetaMask).
    fn wrapped_native_contract_lower(chain_id: i64) -> Option<&'static str> {
        match chain_id {
            1 => Some("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"), // WETH
            56 => Some("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"), // WBNB
            137 => Some("0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"), // WMATIC
            42161 => Some("0x82af49447d8a07e3bd95bd0d56f35241523fbab1"), // Arbitrum WETH
            10 | 8453 => Some("0x4200000000000000000000000000000000000006"), // OP / Base WETH
            59144 => Some("0xe5d7c2a44ffddf6b295a15c148167daa1f934cbf"), // Linea WETH
            43114 => Some("0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7"), // WAVAX
            250 => Some("0x21be370d5312f443cb1a44b11e1e2fa7db6553f7"), // WFTM
            534352 => Some("0x5300000000000000000000000000000000000004"), // Scroll WETH
            _ => None,
        }
    }

    /// When both RPC native and wrapped native token have USD on the same chain, count once (max),
    /// matching how many wallet UIs avoid stacking the same economic position.
    fn merge_wrapped_and_native_usd(native_usd: f64, wrapped_token_usd: f64) -> f64 {
        const EPS: f64 = 1e-9;
        let n = native_usd.max(0.0);
        let w = wrapped_token_usd.max(0.0);
        if n > EPS && w > EPS {
            n.max(w)
        } else {
            n + w
        }
    }

    /// Single portfolio USD number: all `wallet_assets` by chain, plus per-chain native, deduping wrapped gas token vs RPC native.
    fn portfolio_total_usd_deduped(
        db_rows: &[WalletAsset],
        agg: &MultiChainNativeAggregate,
        wallet_chain_id: i64,
    ) -> f64 {
        let mut by_chain: HashMap<i64, (f64, f64)> = HashMap::new();
        for a in db_rows {
            let cid = match a.chain_id {
                Some(c) if c > 0 => c as i64,
                _ => wallet_chain_id,
            };
            if cid <= 0 {
                continue;
            }
            let usd = a.usd_value.max(0.0);
            let addr_l = a.contract_address.as_deref().map(|s| s.to_lowercase());
            let is_wrapped = addr_l
                .as_deref()
                .and_then(|addr| Self::wrapped_native_contract_lower(cid).map(|w| addr == w))
                .unwrap_or(false);
            let e = by_chain.entry(cid).or_insert((0.0, 0.0));
            if is_wrapped {
                e.1 += usd;
            } else {
                e.0 += usd;
            }
        }

        let mut total = 0.0_f64;
        for (&cid, &(non_wrapped, wrapped)) in &by_chain {
            let n = agg
                .per_chain
                .iter()
                .find(|p| p.chain_id == cid)
                .map(|p| p.usd)
                .unwrap_or(0.0);
            total += non_wrapped + Self::merge_wrapped_and_native_usd(n, wrapped);
        }
        for p in &agg.per_chain {
            if !by_chain.contains_key(&p.chain_id) {
                total += p.usd;
            }
        }
        total
    }

    /// Sum native USD across all scan chains that have an RPC URL configured.
    async fn multi_chain_native_aggregate(
        address: &str,
        wallet_chain_id: i64,
    ) -> MultiChainNativeAggregate {
        let ids =
            Self::merge_wallet_chain_id(Self::default_native_scan_chain_ids(), wallet_chain_id);
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
            agg.per_chain.iter().find_map(|p| p.rpc_error.clone())
        } else {
            None
        };

        let pricing_err =
            if agg.total_usd <= 1e-12 && agg.per_chain.iter().any(|p| p.balance > 1e-12) {
                Some(
                    "USD pricing failed for one or more chains with non-zero native balance"
                        .to_string(),
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
        let latest_scan = SenseiguardRepository::get_latest_scan(pool, wallet_id).await?;
        let mon: (i32, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            "SELECT COALESCE(security_score, 0), last_scan_at FROM wallet_monitoring WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or((0, None));

        let has_full_scan = latest_scan.is_some();
        let has_health_touch = mon.1.is_some();

        // Never scanned and never health-refreshed: DB default score 0 is not "weak".
        if !has_full_scan && !has_health_touch {
            return Ok(SecurityStatusResponse {
                score: 100,
                status: "unscanned".to_string(),
                message: "Run a full scan to see your security score and findings.".to_string(),
                last_scan_at: None,
                level: "safe".to_string(),
                risk_breakdown: None,
                last_updated: None,
                scoring_model: None,
                open_campaign_count: None,
            });
        }

        // Live score from open threats + unread high alerts — not a stale security_scans row.
        let (score, _, _) = Self::compute_live_security_score(pool, wallet_id).await?;
        let v2 = ThreatScoringV2::enabled();
        let open_campaign_count = if v2 {
            Some(
                SenseiguardRepository::count_open_campaigns_for_wallet(pool, wallet_id)
                    .await
                    .unwrap_or(0),
            )
        } else {
            None
        };
        let status = Self::status_from_score(score);
        let last_scan_at = latest_scan
            .as_ref()
            .map(|s| s.scanned_at)
            .or(mon.1);
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
        Ok(SecurityStatusResponse {
            score,
            status,
            message: message.to_string(),
            last_scan_at,
            level: level.to_string(),
            risk_breakdown: None,
            last_updated: last_scan_at,
            scoring_model: if v2 {
                Some(SCORING_MODEL_V2.to_string())
            } else {
                None
            },
            open_campaign_count,
        })
    }

    /// Current security score from open threats/campaigns and unread high alerts (ignores stale scan history).
    async fn compute_live_security_score(
        pool: &DbPool,
        wallet_id: Uuid,
    ) -> Result<(i32, i64, i64), Error> {
        let unread_high = SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;

        if ThreatScoringV2::enabled() {
            let campaigns =
                SenseiguardRepository::list_open_campaigns_for_wallet(pool, wallet_id, 500)
                    .await?;
            let mut campaign_penalty: i32 = 0;
            for c in &campaigns {
                campaign_penalty += match c.risk_score {
                    r if r >= 80 => 14,
                    r if r >= 50 => 10,
                    r if r >= 30 => 6,
                    _ => 3,
                };
            }
            let score = 100_i32
                .saturating_sub(campaign_penalty)
                .saturating_sub((unread_high as i32).saturating_mul(3))
                .clamp(0, 100);
            return Ok((score, campaigns.len() as i64, unread_high));
        }

        let open = SenseiguardRepository::list_active_threats(pool, wallet_id, 500).await?;
        let mut threat_penalty: i32 = 0;
        for t in &open {
            if Self::is_policy_enforcement_threat(t) {
                continue;
            }
            threat_penalty += match t.severity.to_lowercase().as_str() {
                "critical" => 14,
                "high" => 12,
                "medium" => 7,
                _ => 3,
            };
        }
        let unread_high = SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;
        let score = 100_i32
            .saturating_sub(threat_penalty)
            .saturating_sub((unread_high as i32).saturating_mul(3))
            .clamp(0, 100);
        Ok((score, open.len() as i64, unread_high))
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

        let threats_count =
            SenseiguardRepository::count_threats_this_month(pool, wallet_id).await?;
        let high_risk_alerts =
            SenseiguardRepository::high_risk_alerts_count(pool, wallet_id).await?;
        let unread_alerts = SenseiguardRepository::unread_alerts_count(pool, wallet_id).await?;
        let assets = SenseiguardRepository::list_assets(pool, wallet_id).await?;
        let activity = SenseiguardRepository::list_activity(pool, wallet_id, 10).await?;
        let recent_threats = SenseiguardRepository::list_threats(pool, wallet_id, 12).await?;
        let approval_alerts =
            SenseiguardRepository::list_approval_alerts(pool, address, 12).await?;
        let blocked_contracts =
            SenseiguardRepository::list_blocked_contracts(pool, address).await?;

        let mut observations: Vec<ScanObservation> = Vec::new();

        observations.push(ScanObservation {
            observation_type: "threats".to_string(),
            title: "Threats this month".to_string(),
            description: Some(format!(
                "{} threat(s) detected in the last 30 days.",
                threats_count
            )),
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
            description: Some(format!(
                "{} unread alert(s), {} high risk.",
                unread_alerts, high_risk_alerts
            )),
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
                a.activity_type == "suspicious_approval" || a.activity_type == "blocked_interaction"
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

        if !recent_threats.is_empty() {
            let causes: Vec<serde_json::Value> =
                recent_threats.iter().map(Self::threat_to_cause).collect();
            observations.push(ScanObservation {
                observation_type: "threat_causes".to_string(),
                title: "Detected threat causes".to_string(),
                description: Some(format!(
                    "{} concrete threat cause(s) found in recent detections.",
                    causes.len()
                )),
                severity: Some(
                    if recent_threats
                        .iter()
                        .any(|t| t.severity.eq_ignore_ascii_case("high"))
                    {
                        "critical".to_string()
                    } else {
                        "warning".to_string()
                    },
                ),
                detail: Some(serde_json::json!({ "causes": causes })),
            });
        }

        if !approval_alerts.is_empty() {
            let causes: Vec<serde_json::Value> = approval_alerts
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "type": "approval_alert",
                        "title": "High-risk approval detected",
                        "reason": format!(
                            "Approval to {} scored {} risk.",
                            Self::short_address(&a.spender_address),
                            a.risk_score
                        ),
                        "severity": if a.risk_score >= 80 { "high" } else { "medium" },
                        "contract": a.spender_address,
                        "detected_at": a.created_at,
                    })
                })
                .collect();
            observations.push(ScanObservation {
                observation_type: "approval_causes".to_string(),
                title: "Approval-based risk causes".to_string(),
                description: Some("High-risk approvals can allow token draining.".to_string()),
                severity: Some("warning".to_string()),
                detail: Some(serde_json::json!({ "causes": causes })),
            });
        }

        if !blocked_contracts.is_empty() {
            observations.push(ScanObservation {
                observation_type: "blocked_contracts".to_string(),
                title: "Blocked contract interactions".to_string(),
                description: Some(format!(
                    "{} contract(s) are blocked by protection settings.",
                    blocked_contracts.len()
                )),
                severity: Some("info".to_string()),
                detail: Some(serde_json::json!({
                    "contracts": blocked_contracts
                        .iter()
                        .take(8)
                        .map(|c| c.contract_address.clone())
                        .collect::<Vec<_>>()
                })),
            });
        }

        observations.push(ScanObservation {
            observation_type: "summary".to_string(),
            title: "Scan complete".to_string(),
            description: Some(
                "Wallet scanned with exact threat-cause extraction from recent detections and approval alerts."
                    .to_string(),
            ),
            severity: Some("info".to_string()),
            detail: None,
        });

        let threat_penalty: i32 = recent_threats
            .iter()
            .map(|t| match t.severity.to_lowercase().as_str() {
                "high" => 12,
                "medium" => 7,
                _ => 3,
            })
            .sum();
        let approval_penalty: i32 = approval_alerts
            .iter()
            .map(|a| {
                if a.risk_score >= 85 {
                    10
                } else if a.risk_score >= 60 {
                    6
                } else {
                    3
                }
            })
            .sum();

        let score = (100i32)
            .saturating_sub(threat_penalty)
            .saturating_sub(approval_penalty)
            .saturating_sub((suspicious_activity as i32).saturating_mul(4))
            .saturating_sub((high_risk_alerts as i32).saturating_mul(4))
            .clamp(0, 100);

        let observations_json =
            serde_json::to_value(&observations).unwrap_or_else(|_| serde_json::json!([]));
        let scan =
            SenseiguardRepository::create_scan(pool, wallet_id, score, &observations_json).await?;

        Ok(FullScanReportResponse {
            scan_id: scan.id,
            wallet_id: scan.wallet_id,
            score: scan.score,
            status: scan.status,
            scanned_at: scan.scanned_at,
            observations,
        })
    }

    fn threat_to_cause(t: &Threat) -> serde_json::Value {
        serde_json::json!({
            "type": t.threat_type.clone().unwrap_or_else(|| "unknown".to_string()),
            "title": t.title,
            "reason": t
                .explanation
                .clone()
                .unwrap_or_else(|| "Threat detected by security engine signals.".to_string()),
            "severity": t.severity,
            "contract": t.source_contract,
            "detected_at": t.detected_at,
            "surface": t.surface,
            "where_to_fix": Self::threat_fix_location(t),
            "recommended_action": Self::threat_recommended_action(t),
            "fix_steps": Self::threat_fix_steps(t),
        })
    }

    pub fn threat_fix_location(t: &Threat) -> String {
        if Self::is_policy_enforcement_threat(t) {
            return "Protection settings (Emergency lock whitelist)".to_string();
        }
        match t.surface.as_deref().unwrap_or("").to_lowercase().as_str() {
            "tx_intent" => "Pending transaction in wallet confirmation".to_string(),
            "wallet_state" => "Wallet approvals and connected contracts".to_string(),
            "contract" => "Contract interaction target".to_string(),
            "off_chain" => "Website/domain or dApp connection".to_string(),
            _ => {
                if t.source_contract.is_some() {
                    "Flagged contract interaction".to_string()
                } else {
                    "Wallet security activity".to_string()
                }
            }
        }
    }

    pub fn threat_recommended_action(t: &Threat) -> String {
        if Self::is_policy_enforcement_threat(t) {
            return "Add trusted destination to whitelist or keep transaction blocked".to_string();
        }
        let threat_type = t.threat_type.as_deref().unwrap_or("").to_lowercase();
        match threat_type.as_str() {
            "malicious_transaction" | "signature_phishing" | "drainer_pattern" => {
                "Reject/Cancel this interaction immediately".to_string()
            }
            "unlimited_approval" => "Revoke the approval and limit future allowances".to_string(),
            "phishing_indicator" | "frontend_phishing" => {
                "Disconnect and avoid this website/domain".to_string()
            }
            "risky_token" => "Avoid approvals or swaps involving this token".to_string(),
            "behavioral_anomaly" => {
                "Review recent activity and lock down wallet permissions".to_string()
            }
            _ => "Review threat details and apply wallet protection controls".to_string(),
        }
    }

    pub fn threat_fix_steps(t: &Threat) -> Vec<String> {
        if Self::is_policy_enforcement_threat(t) {
            return vec![
                "Open protection settings and review Emergency lock configuration.".to_string(),
                "If destination is trusted, add it to the whitelist.".to_string(),
                "If destination is not trusted, keep it blocked and ignore this event.".to_string(),
            ];
        }
        let mut steps = Vec::new();
        let threat_type = t.threat_type.as_deref().unwrap_or("").to_lowercase();
        let source_contract = t.source_contract.clone();

        match threat_type.as_str() {
            "malicious_transaction" | "signature_phishing" | "drainer_pattern" => {
                steps.push(
                    "Cancel or reject the pending transaction/signature request.".to_string(),
                );
                if let Some(contract) = source_contract.as_deref() {
                    steps.push(format!(
                        "Block contract {} in protection settings.",
                        contract
                    ));
                }
                steps.push(
                    "Enable high-risk transaction warnings and auto-block high-risk interactions."
                        .to_string(),
                );
            }
            "unlimited_approval" => {
                if let Some(contract) = source_contract.as_deref() {
                    steps.push(format!("Revoke token approval for spender {}.", contract));
                } else {
                    steps.push("Revoke unlimited token approvals from your wallet.".to_string());
                }
                steps.push("Re-approve with exact amount only when needed.".to_string());
                steps.push(
                    "Turn on New Approval Alerts for instant warning on risky approvals."
                        .to_string(),
                );
            }
            "phishing_indicator" | "frontend_phishing" => {
                steps.push("Disconnect the wallet from the suspicious dApp/domain.".to_string());
                steps.push("Do not sign messages or transactions from that domain.".to_string());
                steps.push("Report the domain and add it to blocklist/watchlist.".to_string());
            }
            "risky_token" => {
                steps.push("Do not grant new approvals to this token/contract.".to_string());
                steps.push("Avoid swapping or bridging this asset until verified.".to_string());
                steps.push(
                    "Cross-check contract source, liquidity lock, and community abuse reports."
                        .to_string(),
                );
            }
            "behavioral_anomaly" => {
                steps.push("Review last 24h wallet activity for unknown interactions.".to_string());
                steps.push(
                    "Enable emergency lock and whitelist trusted addresses only.".to_string(),
                );
                steps.push(
                    "Rotate to a clean wallet if suspicious outgoing actions continue.".to_string(),
                );
            }
            _ => {
                steps.push("Review the threat explanation and source contract.".to_string());
                steps.push("Block or watchlist suspicious contracts/domains.".to_string());
                steps.push("Re-scan wallet after applying protections.".to_string());
            }
        }

        steps
    }

    fn short_address(addr: &str) -> String {
        if addr.len() < 12 {
            return addr.to_string();
        }
        format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
    }

    pub async fn dashboard_summary(
        pool: &DbPool,
        address: &str,
    ) -> Result<DashboardSummaryResponse, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        let wallet_id = wallet.id;
        let monitoring_status: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM wallet_monitoring WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await?;
        let wallet_status = WalletConnectionStatus {
            connection: if wallet.is_active {
                "active".to_string()
            } else {
                "inactive".to_string()
            },
            monitoring: monitoring_status
                .map(|r| r.0)
                .unwrap_or_else(|| "active".to_string()),
        };
        let security_status = Self::get_security_status(pool, address).await?;
        let threats_this_month =
            SenseiguardRepository::count_threats_this_month(pool, wallet_id).await?;
        let threats_prev =
            SenseiguardRepository::count_threats_previous_period(pool, wallet_id).await?;
        let scans_this_month =
            SenseiguardRepository::count_scans_this_month(pool, wallet_id).await?;
        let scans_prev =
            SenseiguardRepository::count_scans_previous_period(pool, wallet_id).await?;
        let total_db_usd = SenseiguardRepository::total_asset_usd(pool, wallet_id).await?;
        let db_asset_rows = SenseiguardRepository::list_assets(pool, wallet_id).await?;
        let agg = Self::multi_chain_native_aggregate(address, wallet.chain_id).await;
        let total_asset_usd =
            Self::portfolio_total_usd_deduped(&db_asset_rows, &agg, wallet.chain_id);
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
            wallet_status,
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

    pub async fn list_active_threats(
        pool: &DbPool,
        address: &str,
        limit: i64,
    ) -> Result<Vec<Threat>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_active_threats(pool, wallet_id, limit).await
    }

    pub async fn list_threat_history(
        pool: &DbPool,
        address: &str,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<Threat>, i64), Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let p = page.max(1);
        let pp = per_page.clamp(1, 100);
        let offset = ((p - 1) as i64) * (pp as i64);
        let rows =
            SenseiguardRepository::list_threat_history(pool, wallet_id, pp as i64, offset).await?;
        let total = SenseiguardRepository::count_threat_history(pool, wallet_id).await?;
        Ok((rows, total))
    }

    pub async fn resolve_threat(
        pool: &DbPool,
        address: &str,
        threat_id: Uuid,
        resolution_note: Option<&str>,
    ) -> Result<Option<Threat>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::resolve_threat(pool, wallet_id, threat_id, resolution_note).await
    }

    pub async fn dismiss_threat(
        pool: &DbPool,
        address: &str,
        threat_id: Uuid,
        dismiss_reason: Option<&str>,
    ) -> Result<Option<Threat>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::dismiss_threat(pool, wallet_id, threat_id, dismiss_reason).await
    }

    pub async fn record_threat_action(
        pool: &DbPool,
        address: &str,
        threat_id: Uuid,
        action: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<Option<ThreatRemediationAction>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let Some(_threat) =
            SenseiguardRepository::get_threat_by_id_for_wallet(pool, wallet_id, threat_id).await?
        else {
            return Ok(None);
        };
        let row = SenseiguardRepository::create_threat_remediation_action(
            pool, threat_id, wallet_id, action, metadata,
        )
        .await?;
        Ok(Some(row))
    }

    fn has_action(actions: &[ThreatRemediationAction], names: &[&str]) -> bool {
        actions
            .iter()
            .any(|a| names.iter().any(|n| a.action.eq_ignore_ascii_case(n)))
    }

    async fn verify_single_open_threat(
        pool: &DbPool,
        address: &str,
        wallet_id: Uuid,
        threat: Threat,
    ) -> Result<ThreatVerificationResult, Error> {
        let actions =
            SenseiguardRepository::list_threat_remediation_actions(pool, threat.id, wallet_id, 100)
                .await
                .unwrap_or_default();
        let threat_type = threat
            .threat_type
            .clone()
            .unwrap_or_default()
            .to_lowercase();
        let mut status = "not_applicable".to_string();
        let mut method: Option<String> = None;
        let mut message = "No applicable verification strategy for this threat.".to_string();
        let mut verified = false;

        if Self::is_policy_enforcement_threat(&threat) {
            if Self::has_action(
                &actions,
                &[
                    "whitelist_address",
                    "allow_address",
                    "disable_emergency_lock",
                ],
            ) {
                status = "verified".to_string();
                method = Some("policy_action_log".to_string());
                message = "Emergency-lock policy adjustment was recorded.".to_string();
                verified = true;
            } else {
                status = "not_applicable".to_string();
                method = Some("policy_enforcement_event".to_string());
                message = "This is a policy enforcement event, not a malware incident. Adjust whitelist settings if needed.".to_string();
            }
        } else {
            match threat_type.as_str() {
                threat_types::UNLIMITED_APPROVAL => {
                    if Self::has_action(&actions, &["revoke_approval", "limit_approval"]) {
                        status = "verified".to_string();
                        method = Some("action_log_revoke_approval".to_string());
                        message = "Approval mitigation action was recorded.".to_string();
                        verified = true;
                    } else {
                        status = "not_applicable".to_string();
                        method = Some("insufficient_allowance_context".to_string());
                        message =
                        "No approval-revocation evidence found. Record a revoke action to verify."
                            .to_string();
                    }
                }
                threat_types::MALICIOUS_TRANSACTION
                | threat_types::DRAINER_PATTERN
                | threat_types::SIGNATURE_PHISHING => {
                    let blocked = if let Some(contract) = threat.source_contract.as_deref() {
                        SenseiguardRepository::is_contract_blocked(pool, address, contract)
                            .await
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    if blocked {
                        status = "verified".to_string();
                        method = Some("blocked_contract_check".to_string());
                        message = "Threat source contract is blocked for this wallet.".to_string();
                        verified = true;
                    } else if Self::has_action(
                        &actions,
                        &[
                            "block_contract",
                            "reject_tx",
                            "cancel_transaction",
                            "proceed_anyway",
                        ],
                    ) {
                        status = "verified".to_string();
                        method = Some("action_log_tx_mitigation".to_string());
                        message = "Protective transaction action was recorded.".to_string();
                        verified = true;
                    } else {
                        status = "failed".to_string();
                        method = Some("no_mitigation_signal".to_string());
                        message = "No blocked-contract or transaction mitigation signal found."
                            .to_string();
                    }
                }
                threat_types::PHISHING_INDICATOR | threat_types::FRONTEND_PHISHING => {
                    if Self::has_action(
                        &actions,
                        &[
                            "disconnect_dapp",
                            "block_domain",
                            "report_scam",
                            "block_contract",
                        ],
                    ) {
                        status = "verified".to_string();
                        method = Some("action_log_domain_mitigation".to_string());
                        message = "Phishing mitigation action was recorded.".to_string();
                        verified = true;
                    } else {
                        status = "failed".to_string();
                        method = Some("no_domain_mitigation".to_string());
                        message =
                            "No phishing mitigation action found for this threat.".to_string();
                    }
                }
                threat_types::RISKY_TOKEN => {
                    if Self::has_action(
                        &actions,
                        &[
                            "hide_token",
                            "revoke_approval",
                            "block_contract",
                            "analyze_contract",
                        ],
                    ) {
                        status = "verified".to_string();
                        method = Some("action_log_token_mitigation".to_string());
                        message = "Risky-token mitigation action was recorded.".to_string();
                        verified = true;
                    } else {
                        status = "failed".to_string();
                        method = Some("no_token_mitigation".to_string());
                        message =
                            "No risky-token mitigation action found for this threat.".to_string();
                    }
                }
                threat_types::BEHAVIORAL_ANOMALY => {
                    let has_action = Self::has_action(
                        &actions,
                        &[
                            "enable_emergency_lock",
                            "freeze_wallet",
                            "block_contract",
                            "revoke_approval",
                        ],
                    );
                    if !has_action {
                        status = "not_applicable".to_string();
                        method = Some("requires_explicit_user_action".to_string());
                        message =
                            "Record a protective action to verify behavioral anomaly mitigation."
                                .to_string();
                    } else {
                        let recent_high = SenseiguardRepository::count_recent_high_risk_alerts(
                            pool,
                            wallet_id,
                            Utc::now() - Duration::hours(24),
                        )
                        .await
                        .unwrap_or(0);
                        if recent_high == 0 {
                            status = "verified".to_string();
                            method = Some("action_log_plus_recent_alert_window".to_string());
                            message =
                            "Protective action recorded and no recent high-risk alerts observed."
                                .to_string();
                            verified = true;
                        } else {
                            status = "failed".to_string();
                            method = Some("recent_high_alerts_present".to_string());
                            message =
                            "Recent high-risk alerts still present; mitigation not yet confirmed."
                                .to_string();
                        }
                    }
                }
                _ => {}
            }
        }

        let verified_at = if verified { Some(Utc::now()) } else { None };
        let updated = SenseiguardRepository::update_threat_verification(
            pool,
            wallet_id,
            threat.id,
            &status,
            method.as_deref(),
            Some(&message),
            verified_at,
        )
        .await?;
        let mut out_threat = updated.unwrap_or(threat);
        if verified {
            if let Some(resolved) = SenseiguardRepository::resolve_threat(
                pool,
                wallet_id,
                out_threat.id,
                Some("Auto-resolved after successful threat verification."),
            )
            .await?
            {
                out_threat = resolved;
            }
        }
        Ok(ThreatVerificationResult {
            threat: out_threat,
            verified,
            verification_status: status,
            verification_method: method,
            verification_message: message,
        })
    }

    pub async fn verify_threat_for_wallet(
        pool: &DbPool,
        address: &str,
        threat_id: Uuid,
    ) -> Result<Option<(ThreatVerificationResult, WalletHealthRefresh)>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let Some(threat) =
            SenseiguardRepository::get_threat_by_id_for_wallet(pool, wallet_id, threat_id).await?
        else {
            return Ok(None);
        };
        let verification =
            Self::verify_single_open_threat(pool, address, wallet_id, threat).await?;
        let health = Self::refresh_wallet_health(pool, address).await?;
        Ok(Some((verification, health)))
    }

    pub async fn verify_all_open_threats_for_wallet(
        pool: &DbPool,
        address: &str,
    ) -> Result<VerifyAllThreatsResult, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let open = SenseiguardRepository::list_active_threats(pool, wallet_id, 500).await?;
        let mut results = Vec::with_capacity(open.len());
        let mut verified_count = 0i64;
        let mut failed_count = 0i64;
        let mut not_applicable_count = 0i64;

        for threat in open {
            let item = Self::verify_single_open_threat(pool, address, wallet_id, threat).await?;
            match item.verification_status.as_str() {
                "verified" => verified_count += 1,
                "failed" => failed_count += 1,
                _ => not_applicable_count += 1,
            }
            results.push(item);
        }

        let health = Self::refresh_wallet_health(pool, address).await?;
        Ok(VerifyAllThreatsResult {
            verified_count,
            failed_count,
            not_applicable_count,
            results,
            health,
        })
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

    pub async fn mark_alert_read(
        pool: &DbPool,
        address: &str,
        alert_id: Uuid,
    ) -> Result<Option<Alert>, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::mark_alert_read(pool, wallet_id, alert_id).await
    }

    pub async fn mark_all_alerts_read(pool: &DbPool, address: &str) -> Result<i64, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::mark_all_alerts_read(pool, wallet_id).await
    }

    pub async fn refresh_wallet_health(
        pool: &DbPool,
        address: &str,
    ) -> Result<WalletHealthRefresh, Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        let previous: i32 = sqlx::query_as(
            "SELECT COALESCE(security_score, 0) FROM wallet_monitoring WHERE wallet_id = $1",
        )
        .bind(wallet_id)
        .fetch_optional(pool)
        .await?
        .map(|r: (i32,)| r.0)
        .unwrap_or(0);
        let (score, open_count, _) = Self::compute_live_security_score(pool, wallet_id).await?;
        SenseiguardRepository::update_wallet_security_score(pool, wallet_id, score).await?;
        let risk_score = 100 - score;
        let risk_level = protection_engine::score_to_band(risk_score).to_string();
        Ok(WalletHealthRefresh {
            previous_score: previous,
            score,
            risk_score,
            risk_level,
            open_threats: open_count,
        })
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
        let items = rows.into_iter().map(|r| row_to_live_feed_item(r)).collect();
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

    fn merge_live_native_into_assets(
        assets: &mut Vec<WalletAsset>,
        wallet_id: Uuid,
        wallet_chain_id: i64,
        agg: &MultiChainNativeAggregate,
    ) {
        let now = Utc::now();
        let primary = wallet_chain_id;
        for a in &agg.per_chain {
            if a.balance <= 0.0 {
                continue;
            }
            let symbol = a.symbol.clone();
            let name = format!("{} ({})", chain_id_to_network(a.chain_id), symbol);
            let balance = format!("{:.18}", a.balance);
            let cid = a.chain_id as i32;
            if let Some(existing) = assets.iter_mut().find(|x| {
                x.symbol == symbol
                    && x.contract_address.is_none()
                    && (x.chain_id == Some(cid) || (x.chain_id.is_none() && a.chain_id == primary))
            }) {
                existing.balance = balance;
                existing.usd_value = existing.usd_value.max(a.usd);
                existing.chain_id = Some(cid);
                existing.updated_at = now;
            } else {
                assets.push(WalletAsset {
                    id: Uuid::new_v4(),
                    wallet_id,
                    symbol,
                    name,
                    balance,
                    usd_value: a.usd,
                    change_percent: 0.0,
                    chain_id: Some(cid),
                    contract_address: None,
                    created_at: now,
                    updated_at: now,
                });
            }
        }
    }

    pub async fn list_assets(pool: &DbPool, address: &str) -> Result<Vec<WalletAsset>, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        let mut assets = SenseiguardRepository::list_assets(pool, wallet.id).await?;
        let agg = Self::multi_chain_native_aggregate(address, wallet.chain_id).await;
        Self::merge_live_native_into_assets(&mut assets, wallet.id, wallet.chain_id, &agg);
        assets.sort_by(|a, b| {
            b.usd_value
                .partial_cmp(&a.usd_value)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(assets)
    }

    /// Moralis aggregated token balances → `wallet_assets` (per chain: delete indexed rows, then upsert).
    pub async fn sync_wallet_indexed_tokens(
        pool: &DbPool,
        address: &str,
    ) -> Result<Vec<IndexedTokenSyncChainOutcome>, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;
        let wallet_id = wallet.id;
        let ids = Self::merge_wallet_chain_id(
            Self::default_token_balance_scan_chain_ids(),
            wallet.chain_id,
        );
        let mut outcomes = Vec::with_capacity(ids.len());

        for cid in ids {
            if moralis_wallet::moralis_chain_param(cid).is_none() {
                outcomes.push(IndexedTokenSyncChainOutcome {
                    chain_id: cid,
                    status: "skipped".to_string(),
                    tokens_upserted: 0,
                    detail: Some(
                        "chain not supported by Moralis wallet token API (e.g. zkSync 324, Scroll 534352)"
                            .to_string(),
                    ),
                });
                continue;
            }
            let fetch = moralis_wallet::fetch_wallet_tokens(address, cid).await;
            let tokens = match fetch {
                Ok(t) => t,
                Err(e) => {
                    outcomes.push(IndexedTokenSyncChainOutcome {
                        chain_id: cid,
                        status: "error".to_string(),
                        tokens_upserted: 0,
                        detail: Some(e),
                    });
                    continue;
                }
            };
            SenseiguardRepository::delete_indexed_assets_for_chain(pool, wallet_id, cid as i32)
                .await?;
            let mut n: u32 = 0;
            for t in tokens {
                SenseiguardRepository::upsert_indexed_token(
                    pool,
                    wallet_id,
                    cid as i32,
                    &t.contract_address,
                    &t.symbol,
                    &t.name,
                    &t.balance_display,
                    t.usd_value,
                    0.0,
                )
                .await?;
                n = n.saturating_add(1);
            }
            outcomes.push(IndexedTokenSyncChainOutcome {
                chain_id: cid,
                status: "ok".to_string(),
                tokens_upserted: n,
                detail: None,
            });
        }
        Ok(outcomes)
    }

    /// Paginated list for Transaction monitoring UI: title + risk level per row.
    pub async fn list_transaction_monitoring(
        pool: &DbPool,
        address: &str,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<MonitoredTransaction>, i64), Error> {
        let wallet_id = Self::wallet_id_by_address(pool, address).await?;
        SenseiguardRepository::list_transaction_monitoring_paginated(
            pool, wallet_id, page, per_page,
        )
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

        let score = Self::get_security_status(pool, address)
            .await
            .map(|s| s.score)
            .unwrap_or(100);

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

        // Wallet status is operational (connected/monitoring), not derived from security score.
        let status = if active_wallet_count > 0 {
            "active".to_string()
        } else {
            "inactive".to_string()
        };

        let last_scan_at =
            SenseiguardRepository::global_last_scan_at_for_user(pool, user_id).await?;
        let (alerts_high_raw, alerts_medium_raw, alerts_low_raw) =
            SenseiguardRepository::alerts_count_by_severity_global_for_user(pool, user_id).await?;
        let (threats_high, threats_medium, threats_low) =
            SenseiguardRepository::threat_count_by_severity_global_for_user(pool, user_id).await?;
        // Some detection paths write `threats` without creating `alerts`; take the max per bucket
        // so Active Alerts does not incorrectly show zero for flagged wallets.
        let alerts_high = alerts_high_raw.max(threats_high);
        let alerts_medium = alerts_medium_raw.max(threats_medium);
        let alerts_low = alerts_low_raw.max(threats_low);
        let activity_timeline = SenseiguardRepository::list_activity_across_wallets_for_user(
            pool,
            user_id,
            timeline_limit,
        )
        .await?;

        let since_24h = Utc::now() - chrono::Duration::hours(24);
        let transactions_24h =
            SenseiguardRepository::activity_count_since_global_for_user(pool, user_id, since_24h)
                .await?;
        let suspicious_events_24h =
            SenseiguardRepository::activity_suspicious_count_since_global_for_user(
                pool, user_id, since_24h,
            )
            .await?;
        let contract_calls_24h =
            SenseiguardRepository::activity_contract_calls_count_since_global_for_user(
                pool, user_id, since_24h,
            )
            .await?;

        let (total_risk_items_raw, high_risk_connections_raw) =
            SenseiguardRepository::transaction_monitoring_global_totals_for_user(pool, user_id)
                .await?;
        // Fallback to detected threats when transaction_monitoring rows are missing/stale.
        let threat_total = threats_high + threats_medium + threats_low;
        let total_risk_items = total_risk_items_raw.max(threat_total);
        let high_risk_connections = high_risk_connections_raw.max(threats_high);
        let active_dapps = SenseiguardRepository::count_dapp_connections_for_user(pool, user_id)
            .await
            .unwrap_or(0);

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
                contract_calls_24h,
                suspicious_events_24h,
            },
            connected_risk: ConnectedRiskOverview {
                total_risk_items,
                high_risk_connections,
                active_dapps,
            },
        })
    }

    /// Security dashboard cards: overall risk, active threats, scam insights, reported threats, live signals. All real DB data.
    pub async fn get_security_overview(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<SecurityOverviewResponse, Error> {
        let min_score =
            SenseiguardRepository::min_security_score_active_wallets_for_user(pool, user_id)
                .await?;
        // security_score is 0–100 higher=better; risk_score is 0–100 higher=worse.
        let risk_score = min_score.map(|s| 100 - s).unwrap_or(0);
        let risk_level = protection_engine::score_to_band(risk_score).to_string();

        let threat_count = SenseiguardRepository::count_threats_for_user(pool, user_id)
            .await
            .unwrap_or(0);
        let networks_affected =
            SenseiguardRepository::count_networks_affected_for_user(pool, user_id)
                .await
                .unwrap_or(0);

        let daily_rows = SenseiguardRepository::threats_per_day_for_user(pool, user_id, 7)
            .await
            .unwrap_or_default();
        let daily: Vec<ScamFrequencyDay> = daily_rows
            .into_iter()
            .map(|(d, c)| ScamFrequencyDay {
                day: d.format("%Y-%m-%d").to_string(),
                count: c,
            })
            .collect();

        let distinct_patterns =
            SenseiguardRepository::count_distinct_threat_types_for_user(pool, user_id)
                .await
                .unwrap_or(0);
        let scam_pattern_status = if distinct_patterns >= 3 {
            "High"
        } else if distinct_patterns >= 1 {
            "Medium"
        } else {
            "Low"
        };

        let verified = SenseiguardRepository::count_scam_reports_global(pool)
            .await
            .unwrap_or(0);

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
            reasons.push(
                "Threats have been detected on your wallets in the last 30 days.".to_string(),
            );
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
            reasons.push(
                "Your overall risk score is elevated based on wallet and activity signals."
                    .to_string(),
            );
        } else if risk_score >= 30 {
            signals.push("moderate_risk_score".to_string());
            reasons.push("Some risk signals are present; consider reviewing connected contracts and approvals.".to_string());
        }
        if verified_reports > 0 {
            signals.push("community_reports".to_string());
            reasons.push(
                "Community reports indicate verified scam or abuse activity in the ecosystem."
                    .to_string(),
            );
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
        let address = r.source_contract.as_deref().unwrap_or(&r.wallet_address);
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
        let threat_type: String = match r
            .threat_type
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .as_str()
        {
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
                    c.next()
                        .map(|f| f.to_uppercase().chain(c).collect::<String>())
                        .unwrap_or_else(|| s.to_string())
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
            format!(
                "{} hour{} ago",
                d.num_hours(),
                if d.num_hours() == 1 { "" } else { "s" }
            )
        } else if d.num_days() < 7 {
            format!(
                "{} day{} ago",
                d.num_days(),
                if d.num_days() == 1 { "" } else { "s" }
            )
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
        let mut assets = SenseiguardRepository::list_assets(pool, wallet.id).await?;
        let wallet_assets_usd = SenseiguardRepository::total_asset_usd(pool, wallet.id)
            .await
            .unwrap_or(0.0);
        let approval_count = SenseiguardRepository::count_approvals(pool, wallet.id)
            .await
            .unwrap_or(0);
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
        let total_usd = Self::portfolio_total_usd_deduped(&assets, &agg, wallet.chain_id);
        Self::merge_live_native_into_assets(&mut assets, wallet.id, wallet.chain_id, &agg);
        assets.sort_by(|a, b| {
            b.usd_value
                .partial_cmp(&a.usd_value)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
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
            "unscanned" => "Not scanned",
            "weak" => "At risk",
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
    let (asset, amount, counterparty, risk_level, status) =
        r.metadata
            .as_ref()
            .map_or((None, None, None, None, None), |m| {
                (
                    m.get("asset").and_then(|v| v.as_str()).map(String::from),
                    m.get("amount").and_then(|v| v.as_str()).map(String::from),
                    m.get("counterparty")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    m.get("risk_level")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    m.get("status").and_then(|v| v.as_str()).map(String::from),
                )
            });
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
