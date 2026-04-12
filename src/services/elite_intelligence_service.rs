use crate::clients::etherscan;
use crate::db::DbPool;
use crate::models::senseiguard::{EliteRiskAssessment, EliteRiskReason, UserRiskProfile};
use crate::services::reputation_service::ReputationService;
use chrono::Utc;
use serde_json::{json, Value};

const RISK_UNLIMITED_APPROVAL: i32 = 40;
const RISK_UNKNOWN_CONTRACT: i32 = 25;
const RISK_FIRST_TIME_INTERACTION: i32 = 10;
const RISK_DELEGATECALL: i32 = 20;
const RISK_HIGH_BALANCE_EXPOSURE: i32 = 20;
const RISK_LIQUIDITY_DROP_SPIKE: i32 = 25;
const RISK_DEV_WALLET_DUMP: i32 = 20;
const RISK_MINT_BURST: i32 = 15;
const RISK_ABNORMAL_VOLUME: i32 = 15;
const RISK_NEW_CONTRACT: i32 = 20;
const RISK_RECENT_UPGRADE: i32 = 15;
const RISK_RECENT_EXPLOIT: i32 = 20;
const RISK_SIGNATURE_PERMIT: i32 = 22;
const RISK_SIGNATURE_OFFCHAIN_APPROVAL: i32 = 25;
const RISK_SIGNATURE_GENERIC: i32 = 15;
const RISK_SIGNATURE_SEAPORT: i32 = 30;

#[derive(Debug, Clone, Default)]
pub struct EliteAssessmentRequest {
    pub wallet_address: String,
    pub method: Option<String>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub data: Option<String>,
    pub params: Option<Vec<Value>>,
    pub base_protocol_risk: i32,
    pub tx_engine_risk: i32,
    pub contract_reputation_risk: i32,
    pub behavioral_risk: i32,
    pub liquidity_drop_1h_pct: Option<f64>,
    pub dev_wallet_sell_pct_supply: Option<f64>,
    pub token_mint_burst_count: Option<i64>,
    pub abnormal_volume_zscore: Option<f64>,
    pub recently_upgraded_hours_ago: Option<i64>,
    pub recently_exploited_days_ago: Option<i64>,
    pub interaction_count_with_contract: Option<i64>,
    pub wallet_balance_usd: Option<f64>,
    pub tx_value_usd: Option<f64>,
    pub profile: UserRiskProfile,
}

pub struct EliteIntelligenceService;

impl EliteIntelligenceService {
    pub async fn assess_transaction(
        pool: &DbPool,
        req: EliteAssessmentRequest,
    ) -> EliteRiskAssessment {
        let mut reasons: Vec<EliteRiskReason> = Vec::new();
        let mut hard_stop_codes: Vec<String> = Vec::new();

        // 1) Protocol baseline risk from existing scanners.
        let base_protocol =
            (req.base_protocol_risk + req.contract_reputation_risk / 2).clamp(0, 35);
        if base_protocol >= 20 {
            reasons.push(reason(
                "baseline_protocol_risk",
                "protocol",
                base_protocol,
                "Protocol baseline and reputation indicate elevated risk.",
            ));
        }

        // 2) Transaction-level scoring.
        let mut tx_risk = req.tx_engine_risk.clamp(0, 45);
        if has_unlimited_approval(req.data.as_deref()) {
            tx_risk += RISK_UNLIMITED_APPROVAL;
            reasons.push(reason(
                "unlimited_approval",
                "transaction",
                RISK_UNLIMITED_APPROVAL,
                "Unlimited approval grants broad token spending rights.",
            ));
            hard_stop_codes.push("unlimited_approval_unknown_spender".to_string());
        }
        if is_unknown_contract(req.to.as_deref()) {
            tx_risk += RISK_UNKNOWN_CONTRACT;
            reasons.push(reason(
                "unknown_contract_interaction",
                "transaction",
                RISK_UNKNOWN_CONTRACT,
                "Transaction targets an unknown or empty contract destination.",
            ));
        }
        if req.interaction_count_with_contract.unwrap_or(0) == 0 {
            tx_risk += RISK_FIRST_TIME_INTERACTION;
            reasons.push(reason(
                "first_time_interaction",
                "transaction",
                RISK_FIRST_TIME_INTERACTION,
                "First interaction with this destination contract.",
            ));
        }
        if has_delegatecall(req.data.as_deref()) {
            tx_risk += RISK_DELEGATECALL;
            reasons.push(reason(
                "delegatecall_pattern",
                "transaction",
                RISK_DELEGATECALL,
                "Transaction payload includes a delegatecall-linked signature.",
            ));
        }
        if let (Some(value), Some(balance)) = (req.tx_value_usd, req.wallet_balance_usd) {
            if balance > 0.0 && value / balance >= 0.8 {
                tx_risk += RISK_HIGH_BALANCE_EXPOSURE;
                reasons.push(reason(
                    "high_wallet_exposure",
                    "transaction",
                    RISK_HIGH_BALANCE_EXPOSURE,
                    "Transaction value represents a large share of wallet balance.",
                ));
            }
        }
        tx_risk = tx_risk.clamp(0, 100);

        // 3) Signature intelligence.
        let (signature_risk, signature_reasons, signature_hard_stops) =
            Self::score_signature_intent(req.method.as_deref(), req.params.as_ref());
        reasons.extend(signature_reasons);
        hard_stop_codes.extend(signature_hard_stops);

        // 4) Live behavioral signals.
        let mut live_behavior = req.behavioral_risk.clamp(0, 35);
        if req.liquidity_drop_1h_pct.unwrap_or(0.0) >= 40.0 {
            live_behavior += RISK_LIQUIDITY_DROP_SPIKE;
            reasons.push(reason(
                "liquidity_drop_spike",
                "live_behavior",
                RISK_LIQUIDITY_DROP_SPIKE,
                "Liquidity dropped more than 40% within 1 hour.",
            ));
        }
        if req.dev_wallet_sell_pct_supply.unwrap_or(0.0) >= 5.0 {
            live_behavior += RISK_DEV_WALLET_DUMP;
            reasons.push(reason(
                "dev_wallet_dump",
                "live_behavior",
                RISK_DEV_WALLET_DUMP,
                "Developer-linked wallet sold a large percentage of supply.",
            ));
        }
        if req.token_mint_burst_count.unwrap_or(0) >= 3 {
            live_behavior += RISK_MINT_BURST;
            reasons.push(reason(
                "token_mint_burst",
                "live_behavior",
                RISK_MINT_BURST,
                "Observed burst minting activity in a short window.",
            ));
        }
        if req.abnormal_volume_zscore.unwrap_or(0.0) >= 3.0 {
            live_behavior += RISK_ABNORMAL_VOLUME;
            reasons.push(reason(
                "abnormal_volume_pattern",
                "live_behavior",
                RISK_ABNORMAL_VOLUME,
                "Volume significantly deviates from baseline behavior.",
            ));
        }
        live_behavior = live_behavior.clamp(0, 100);

        // 5) Time-based risk.
        let mut time_risk = 0i32;
        if let Some(contract_age_days) = Self::contract_age_days(req.to.as_deref()).await {
            if contract_age_days < 7 {
                time_risk += RISK_NEW_CONTRACT;
                reasons.push(reason(
                    "new_contract_window",
                    "time",
                    RISK_NEW_CONTRACT,
                    "Contract age is under 7 days.",
                ));
            } else if contract_age_days < 30 {
                time_risk += 10;
            }
        }
        if req.recently_upgraded_hours_ago.unwrap_or(i64::MAX) <= 72 {
            time_risk += RISK_RECENT_UPGRADE;
            reasons.push(reason(
                "recent_upgrade_window",
                "time",
                RISK_RECENT_UPGRADE,
                "Contract appears to be recently upgraded (within 72 hours).",
            ));
        }
        if req.recently_exploited_days_ago.unwrap_or(i64::MAX) <= 90 {
            time_risk += RISK_RECENT_EXPLOIT;
            reasons.push(reason(
                "recent_exploit_decay_window",
                "time",
                RISK_RECENT_EXPLOIT,
                "Entity is still inside post-exploit elevated-risk window.",
            ));
            hard_stop_codes.push("recent_exploit_window".to_string());
        }
        time_risk = time_risk.clamp(0, 100);

        // 6) Reputation graph intelligence.
        let graph = ReputationService::analyze_reputation_graph(
            pool,
            req.to.as_deref(),
            Some(req.wallet_address.as_str()),
        )
        .await;
        let graph_risk = graph.risk_score.clamp(0, 100);
        if graph_risk > 0 {
            reasons.push(reason(
                "reputation_graph_exposure",
                "graph",
                graph_risk,
                &graph.summary,
            ));
        }
        if graph.hard_stop {
            hard_stop_codes.push("malicious_graph_linkage".to_string());
        }

        let mut score =
            (base_protocol + tx_risk + signature_risk + live_behavior + time_risk + graph_risk)
                .clamp(0, 100);
        if graph.hard_stop {
            score = score.max(90);
        }

        // 7) User-aware policy adjustments.
        let (policy_adjust, warn_threshold, block_threshold) = policy_for_profile(&req.profile);
        score = (score + policy_adjust).clamp(0, 100);

        let hard_stop = !hard_stop_codes.is_empty();
        let risk_tier = if hard_stop || score >= block_threshold {
            "block"
        } else if score >= warn_threshold {
            "warn"
        } else {
            "allow"
        };

        let recommended_action = match risk_tier {
            "block" => "Reject transaction",
            "warn" => "Review before signing",
            _ => "Proceed",
        }
        .to_string();

        // Confidence score.
        let confidence = Self::confidence_score(&req, graph.has_sufficient_links);
        let confidence_summary = confidence_summary(confidence);
        let component_scores = json!({
            "base_protocol": base_protocol,
            "transaction": tx_risk,
            "signature": signature_risk,
            "live_behavior": live_behavior,
            "time_based": time_risk,
            "reputation_graph": graph_risk,
            "policy_adjustment": policy_adjust,
            "warn_threshold": warn_threshold,
            "block_threshold": block_threshold
        });

        let mut uniq_hard_stops = hard_stop_codes;
        uniq_hard_stops.sort();
        uniq_hard_stops.dedup();

        EliteRiskAssessment {
            risk_score: score,
            risk_tier: risk_tier.to_string(),
            recommended_action,
            confidence_score: confidence,
            confidence_summary,
            hard_stop_codes: uniq_hard_stops,
            profile: profile_name(&req.profile).to_string(),
            shadow_mode: elite_shadow_mode(),
            component_scores,
            reasons,
        }
    }

    fn score_signature_intent(
        method: Option<&str>,
        params: Option<&Vec<Value>>,
    ) -> (i32, Vec<EliteRiskReason>, Vec<String>) {
        let mut score = 0i32;
        let mut reasons = Vec::new();
        let mut hard_stops = Vec::new();

        let method = method.unwrap_or_default();
        if method.starts_with("eth_signTypedData") {
            score += RISK_SIGNATURE_GENERIC;
            reasons.push(reason(
                "typed_data_signature",
                "signature",
                RISK_SIGNATURE_GENERIC,
                "Typed data signature request detected.",
            ));
        } else if method == "eth_sign" || method == "personal_sign" {
            score += RISK_SIGNATURE_GENERIC;
            reasons.push(reason(
                "raw_signature",
                "signature",
                RISK_SIGNATURE_GENERIC,
                "Raw message signature can authorize off-chain actions.",
            ));
        }

        if let Some(values) = params {
            let blob = serde_json::to_string(values)
                .unwrap_or_default()
                .to_lowercase();
            if blob.contains("permit2") || blob.contains("eip2612") || blob.contains("permit") {
                score += RISK_SIGNATURE_PERMIT;
                reasons.push(reason(
                    "permit_signature",
                    "signature",
                    RISK_SIGNATURE_PERMIT,
                    "Permit-like signature can grant transferable approvals.",
                ));
            }
            if blob.contains("seaport") || blob.contains("fulfillorder") {
                score += RISK_SIGNATURE_SEAPORT;
                reasons.push(reason(
                    "seaport_order_signature",
                    "signature",
                    RISK_SIGNATURE_SEAPORT,
                    "Seaport-like order signature detected; review order intent carefully.",
                ));
            }
            if blob.contains("setapprovalforall")
                || blob.contains("approval")
                || blob.contains("spender")
            {
                score += RISK_SIGNATURE_OFFCHAIN_APPROVAL;
                reasons.push(reason(
                    "offchain_approval_signature",
                    "signature",
                    RISK_SIGNATURE_OFFCHAIN_APPROVAL,
                    "Signature appears to include off-chain approval semantics.",
                ));
                hard_stops.push("offchain_approval_signature".to_string());
            }
        }

        (score.clamp(0, 100), reasons, hard_stops)
    }

    async fn contract_age_days(to: Option<&str>) -> Option<i64> {
        let addr = to?;
        let Ok(Some(creation)) = etherscan::fetch_contract_creation(addr, None).await else {
            return None;
        };
        let age =
            Utc::now() - chrono::DateTime::<Utc>::from_timestamp(creation.timestamp as i64, 0)?;
        Some(age.num_days())
    }

    fn confidence_score(req: &EliteAssessmentRequest, graph_coverage: bool) -> i32 {
        let mut coverage = 45i32;
        if req.to.as_deref().is_some_and(|s| !s.is_empty()) {
            coverage += 10;
        }
        if req.method.as_deref().is_some_and(|s| !s.is_empty()) {
            coverage += 10;
        }
        if req.params.is_some() {
            coverage += 10;
        }
        if req.value.as_deref().is_some_and(|v| v != "0x0" && v != "0") {
            coverage += 5;
        }
        if req.liquidity_drop_1h_pct.is_some()
            || req.dev_wallet_sell_pct_supply.is_some()
            || req.token_mint_burst_count.is_some()
            || req.abnormal_volume_zscore.is_some()
        {
            coverage += 10;
        }
        if graph_coverage {
            coverage += 10;
        }

        // Freshness and model agreement are approximated by how recent dynamic windows are present.
        let mut freshness = 65i32;
        if req.recently_upgraded_hours_ago.is_some() || req.recently_exploited_days_ago.is_some() {
            freshness += 10;
        }
        if req.interaction_count_with_contract.is_some() {
            freshness += 5;
        }
        let agreement = if (req.tx_engine_risk - req.base_protocol_risk).abs() <= 30 {
            75
        } else {
            60
        };

        ((coverage + freshness + agreement) / 3).clamp(0, 100)
    }
}

fn has_unlimited_approval(data: Option<&str>) -> bool {
    let Some(d) = data else {
        return false;
    };
    let lower = d.to_lowercase();
    (lower.starts_with("0x095ea7b3") || lower.starts_with("0xa22cb465"))
        && lower.contains("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
}

fn has_delegatecall(data: Option<&str>) -> bool {
    // 0x5c60da1b = implementation(), often used around upgrade proxy patterns.
    // 0x3659cfe6 = upgradeTo(address)
    let Some(d) = data else {
        return false;
    };
    let lower = d.to_lowercase();
    lower.starts_with("0x3659cfe6") || lower.contains("5c60da1b")
}

fn is_unknown_contract(to: Option<&str>) -> bool {
    match to {
        Some(addr) => {
            addr.trim().is_empty()
                || addr.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
        }
        None => true,
    }
}

fn policy_for_profile(profile: &UserRiskProfile) -> (i32, i32, i32) {
    match profile {
        UserRiskProfile::Beginner => (10, 40, 70),
        UserRiskProfile::Standard => (0, 50, 80),
        UserRiskProfile::Pro => (-8, 60, 88),
    }
}

fn profile_name(profile: &UserRiskProfile) -> &'static str {
    match profile {
        UserRiskProfile::Beginner => "beginner",
        UserRiskProfile::Standard => "standard",
        UserRiskProfile::Pro => "pro",
    }
}

fn confidence_summary(confidence: i32) -> String {
    if confidence >= 80 {
        "High confidence from broad signal coverage.".to_string()
    } else if confidence >= 60 {
        "Moderate confidence with partial real-time and graph coverage.".to_string()
    } else {
        "Low confidence due to limited telemetry or sparse reputation graph.".to_string()
    }
}

fn reason(code: &str, category: &str, score_impact: i32, message: &str) -> EliteRiskReason {
    EliteRiskReason {
        code: code.to_string(),
        category: category.to_string(),
        score_impact,
        message: message.to_string(),
    }
}

fn elite_shadow_mode() -> bool {
    std::env::var("ELITE_RISK_SHADOW_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    #[test]
    fn detects_unlimited_approval() {
        let data = "0x095ea7b3000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(has_unlimited_approval(Some(data)));
    }

    #[test]
    fn signature_scoring_detects_permit_and_seaport() {
        let params = vec![json!({
            "domain": {"name": "Seaport"},
            "message": {"permit2": "yes", "spender": "0xabc"}
        })];
        let (score, reasons, hard_stops) = EliteIntelligenceService::score_signature_intent(
            Some("eth_signTypedData_v4"),
            Some(&params),
        );
        assert!(score >= 60);
        assert!(reasons.iter().any(|r| r.code == "permit_signature"));
        assert!(hard_stops
            .iter()
            .any(|s| s == "offchain_approval_signature"));
    }

    #[test]
    fn beginner_policy_is_stricter() {
        let beginner = policy_for_profile(&UserRiskProfile::Beginner);
        let pro = policy_for_profile(&UserRiskProfile::Pro);
        assert!(beginner.0 > pro.0);
        assert!(beginner.1 < pro.1);
        assert!(beginner.2 < pro.2);
    }

    #[test]
    fn confidence_summary_ranges() {
        assert!(confidence_summary(85).contains("High confidence"));
        assert!(confidence_summary(65).contains("Moderate confidence"));
        assert!(confidence_summary(40).contains("Low confidence"));
    }

    #[test]
    fn time_window_examples_for_docs() {
        let now = Utc::now();
        let upgraded = now - Duration::hours(12);
        let exploited = now - Duration::days(20);
        assert!(upgraded > now - Duration::hours(72));
        assert!(exploited > now - Duration::days(90));
    }
}
