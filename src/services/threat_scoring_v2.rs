//! Threat Model v2: kill-chain signals, campaign-grouped deduped scoring, FP-aware bands.
//! Enabled via `THREAT_SCORING_V2=true`.

use crate::models::senseiguard::{kill_chain, threat_types, SignalGroupSummary};
use crate::services::protection_engine::score_to_band;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

const RISK_SIGNATURE_GENERIC: i32 = 15;
const RISK_SIGNATURE_PERMIT: i32 = 22;
const RISK_SIGNATURE_OFFCHAIN_APPROVAL: i32 = 25;
const RISK_SIGNATURE_SEAPORT: i32 = 30;

pub const SCORING_MODEL_V2: &str = "v2";

const BLOCK_THRESHOLD: i32 = 80;
const HIGH_WARNING_THRESHOLD: i32 = 50;
const MEDIUM_WARNING_THRESHOLD: i32 = 30;
const MULTI_STAGE_BOOST: i32 = 8;
const HOOK_BLOCK_MIN_GROUP: i32 = 70;
const HOOK_PERSIST_CONFIDENCE: i32 = 70;
const CAMPAIGN_BLOCK_CONFIDENCE: i32 = 80;

/// Single normalized detection signal for v2 scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignal {
    pub stage: String,
    pub category: String,
    pub threat_type: Option<String>,
    pub risk_contribution: i32,
    pub confidence: i32,
    pub campaign_key: String,
    #[serde(default)]
    pub metadata: Value,
}

impl ThreatSignal {
    pub fn new(
        stage: &str,
        category: &str,
        threat_type: Option<&str>,
        risk_contribution: i32,
        confidence: i32,
        campaign_key: impl Into<String>,
    ) -> Self {
        Self {
            stage: stage.to_string(),
            category: category.to_string(),
            threat_type: threat_type.map(String::from),
            risk_contribution: risk_contribution.clamp(0, 100),
            confidence: confidence.clamp(0, 100),
            campaign_key: campaign_key.into(),
            metadata: json!({}),
        }
    }

    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }
}

#[derive(Debug, Clone)]
pub struct ScoredVerdict {
    pub risk_score: i32,
    pub band: String,
    pub threat_types: Vec<String>,
    pub kill_chain_stage: Option<String>,
    pub signal_groups: Vec<SignalGroupSummary>,
    pub stages_present: Vec<String>,
    pub should_persist_threat: bool,
    pub explanation: Option<String>,
    pub risk_breakdown: Value,
    pub recommended_action: String,
}

pub struct ThreatScoringV2;

impl ThreatScoringV2 {
    pub fn enabled() -> bool {
        std::env::var("THREAT_SCORING_V2")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Group by campaign_key, max per group, multi-stage boost, FP-aware band.
    pub fn evaluate_signals(signals: &[ThreatSignal]) -> ScoredVerdict {
        if signals.is_empty() {
            return ScoredVerdict {
                risk_score: 0,
                band: "Safe".to_string(),
                threat_types: vec![],
                kill_chain_stage: None,
                signal_groups: vec![],
                stages_present: vec![],
                should_persist_threat: false,
                explanation: None,
                risk_breakdown: json!({}),
                recommended_action: "Proceed".to_string(),
            };
        }

        let mut groups: HashMap<String, SignalGroupSummary> = HashMap::new();
        let mut stages: HashSet<String> = HashSet::new();

        for s in signals {
            stages.insert(s.stage.clone());
            let entry =
                groups
                    .entry(s.campaign_key.clone())
                    .or_insert_with(|| SignalGroupSummary {
                        campaign_key: s.campaign_key.clone(),
                        stage: s.stage.clone(),
                        max_risk: 0,
                        max_confidence: 0,
                        threat_types: vec![],
                    });
            entry.max_risk = entry.max_risk.max(s.risk_contribution);
            entry.max_confidence = entry.max_confidence.max(s.confidence);
            if let Some(tt) = &s.threat_type {
                if !entry.threat_types.iter().any(|t| t == tt) {
                    entry.threat_types.push(tt.clone());
                }
            }
        }

        let signal_groups: Vec<SignalGroupSummary> = groups.into_values().collect();
        let mut base_score: i32 = signal_groups.iter().map(|g| g.max_risk).sum();
        let stages_present: Vec<String> = stages.iter().cloned().collect();

        if stages.len() >= 2 {
            base_score += MULTI_STAGE_BOOST;
        }
        let risk_score = base_score.clamp(0, 100);

        let mut threat_types: Vec<String> = Vec::new();
        for g in &signal_groups {
            for tt in &g.threat_types {
                if !threat_types.contains(tt) {
                    threat_types.push(tt.clone());
                }
            }
        }

        let kill_chain_stage = Self::dominant_stage(signals);
        let has_lure = stages.contains(kill_chain::LURE);
        let has_hook = stages.contains(kill_chain::HOOK);
        let has_execute = stages.contains(kill_chain::EXECUTE);
        let hook_group_max = signal_groups
            .iter()
            .filter(|g| g.stage == kill_chain::HOOK)
            .map(|g| g.max_risk)
            .max()
            .unwrap_or(0);
        let execute_group_max = signal_groups
            .iter()
            .filter(|g| g.stage == kill_chain::EXECUTE)
            .map(|g| g.max_risk)
            .max()
            .unwrap_or(0);
        let hook_confidence_max = signal_groups
            .iter()
            .filter(|g| g.stage == kill_chain::HOOK)
            .map(|g| g.max_confidence)
            .max()
            .unwrap_or(0);

        let standalone_approval_only = threat_types.len() == 1
            && threat_types[0] == threat_types::UNLIMITED_APPROVAL
            && !has_lure
            && !has_hook
            && stages.len() <= 1;

        let mut band = score_to_band(risk_score).to_string();

        // FP budget: Block requires high-confidence Hook/Execute or multi-stage chain.
        if band == "Block" {
            let allow_block = hook_group_max >= HOOK_BLOCK_MIN_GROUP
                || execute_group_max >= HOOK_BLOCK_MIN_GROUP
                || (has_lure && has_hook)
                || (has_hook && has_execute)
                || stages.len() >= 3;
            if !allow_block {
                band = if risk_score >= HIGH_WARNING_THRESHOLD {
                    "Dangerous".to_string()
                } else if risk_score >= MEDIUM_WARNING_THRESHOLD {
                    "Warning".to_string()
                } else {
                    "Safe".to_string()
                };
            }
        }

        let should_persist_threat = !standalone_approval_only
            && (risk_score >= 60
                || (has_hook && hook_confidence_max >= HOOK_PERSIST_CONFIDENCE)
                || (has_lure && has_execute)
                || (has_hook && has_execute));

        let explanation = Self::build_explanation(&signal_groups, &stages_present, risk_score);
        let recommended_action = match band.as_str() {
            "Block" => "Reject transaction",
            "Dangerous" | "Warning" => "Review before signing",
            _ => "Proceed",
        }
        .to_string();

        let risk_breakdown = json!({
            "scoring_model": SCORING_MODEL_V2,
            "group_count": signal_groups.len(),
            "stages_present": stages_present,
            "multi_stage_boost": if stages.len() >= 2 { MULTI_STAGE_BOOST } else { 0 },
            "standalone_approval_only": standalone_approval_only,
            "groups": signal_groups,
        });

        ScoredVerdict {
            risk_score,
            band,
            threat_types,
            kill_chain_stage,
            signal_groups,
            stages_present,
            should_persist_threat,
            explanation,
            risk_breakdown,
            recommended_action,
        }
    }

    /// Merge campaign correlation score when v2 is active.
    pub fn merge_campaign_score(
        verdict: &mut ScoredVerdict,
        campaign_risk: i32,
        campaign_confidence: i32,
    ) {
        if campaign_confidence >= CAMPAIGN_BLOCK_CONFIDENCE {
            verdict.risk_score = verdict.risk_score.max(campaign_risk);
            verdict.band = score_to_band(verdict.risk_score).to_string();
            verdict.should_persist_threat = true;
        } else if campaign_risk > 0 {
            verdict.risk_score = verdict.risk_score.max(campaign_risk.saturating_sub(5));
        }
    }

    fn dominant_stage(signals: &[ThreatSignal]) -> Option<String> {
        let order = [
            kill_chain::EXFILTRATE,
            kill_chain::EXECUTE,
            kill_chain::HOOK,
            kill_chain::LURE,
        ];
        for stage in order {
            if signals.iter().any(|s| s.stage == stage) {
                return Some(stage.to_string());
            }
        }
        signals.first().map(|s| s.stage.clone())
    }

    fn build_explanation(
        groups: &[SignalGroupSummary],
        stages: &[String],
        score: i32,
    ) -> Option<String> {
        if groups.is_empty() {
            return None;
        }
        let stage_str = stages.join(" → ");
        Some(format!(
            "Threat model v2: {} signal group(s) across [{}]; composite risk {}.",
            groups.len(),
            stage_str,
            score
        ))
    }

    pub fn campaign_key_contract(addr: &str) -> String {
        format!("contract:{}", addr.to_lowercase())
    }

    pub fn campaign_key_domain(domain: &str) -> String {
        format!("domain:{}", domain.to_lowercase())
    }

    pub fn campaign_key_signature(spender: &str) -> String {
        format!("signature:{}", spender.to_lowercase())
    }

    pub fn campaign_key_generic(category: &str) -> String {
        format!("generic:{}", category)
    }

    /// Hook-stage signals from wallet signing methods (eth_sign, signTypedData, permit).
    pub fn collect_signature_signals(
        method: Option<&str>,
        params: Option<&Vec<Value>>,
    ) -> Vec<ThreatSignal> {
        let mut out = Vec::new();
        let method = method.unwrap_or_default();
        let campaign_key = ThreatScoringV2::campaign_key_generic("signature");

        if method.starts_with("eth_signTypedData") {
            out.push(ThreatSignal::new(
                kill_chain::HOOK,
                "signature",
                Some(threat_types::SIGNATURE_PHISHING),
                RISK_SIGNATURE_GENERIC,
                65,
                &campaign_key,
            ));
        } else if method == "eth_sign" || method == "personal_sign" {
            out.push(ThreatSignal::new(
                kill_chain::HOOK,
                "signature",
                Some(threat_types::SIGNATURE_PHISHING),
                RISK_SIGNATURE_GENERIC,
                60,
                &campaign_key,
            ));
        }

        if let Some(values) = params {
            let blob = serde_json::to_string(values)
                .unwrap_or_default()
                .to_lowercase();
            if blob.contains("permit2") || blob.contains("eip2612") || blob.contains("permit") {
                out.push(ThreatSignal::new(
                    kill_chain::HOOK,
                    "signature",
                    Some(threat_types::SIGNATURE_PHISHING),
                    RISK_SIGNATURE_PERMIT,
                    72,
                    ThreatScoringV2::campaign_key_signature("permit"),
                ));
            }
            if blob.contains("seaport") || blob.contains("fulfillorder") {
                out.push(ThreatSignal::new(
                    kill_chain::HOOK,
                    "signature",
                    Some(threat_types::SIGNATURE_PHISHING),
                    RISK_SIGNATURE_SEAPORT,
                    68,
                    ThreatScoringV2::campaign_key_signature("seaport"),
                ));
            }
            if blob.contains("setapprovalforall")
                || blob.contains("approval")
                || blob.contains("spender")
            {
                out.push(ThreatSignal::new(
                    kill_chain::HOOK,
                    "signature",
                    Some(threat_types::SIGNATURE_PHISHING),
                    RISK_SIGNATURE_OFFCHAIN_APPROVAL,
                    75,
                    ThreatScoringV2::campaign_key_signature("offchain_approval"),
                ));
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlated_lure_execute_does_not_double_count_to_block_on_weak_signals() {
        let signals = vec![
            ThreatSignal::new(
                kill_chain::LURE,
                "domain",
                Some(threat_types::FRONTEND_PHISHING),
                25,
                60,
                "domain:evil.com",
            ),
            ThreatSignal::new(
                kill_chain::EXECUTE,
                "transaction",
                Some(threat_types::MALICIOUS_TRANSACTION),
                25,
                55,
                "contract:0xabc",
            ),
        ];
        let v = ThreatScoringV2::evaluate_signals(&signals);
        assert!(v.risk_score < BLOCK_THRESHOLD);
        assert_ne!(v.band, "Block");
    }

    #[test]
    fn standalone_approve_warn_only_no_persist() {
        let signals = vec![ThreatSignal::new(
            kill_chain::EXECUTE,
            "approval",
            Some(threat_types::UNLIMITED_APPROVAL),
            35,
            55,
            "contract:0xspender",
        )];
        let v = ThreatScoringV2::evaluate_signals(&signals);
        assert_eq!(v.band, "Warning");
        assert!(!v.should_persist_threat);
    }

    #[test]
    fn lure_hook_execute_sequence_escalates() {
        let signals = vec![
            ThreatSignal::new(
                kill_chain::LURE,
                "domain",
                Some(threat_types::FRONTEND_PHISHING),
                25,
                70,
                "domain:fake.org",
            ),
            ThreatSignal::new(
                kill_chain::HOOK,
                "signature",
                Some(threat_types::SIGNATURE_PHISHING),
                40,
                75,
                "signature:0xbad",
            ),
            ThreatSignal::new(
                kill_chain::EXECUTE,
                "approval",
                Some(threat_types::UNLIMITED_APPROVAL),
                35,
                70,
                "contract:0xbad",
            ),
        ];
        let v = ThreatScoringV2::evaluate_signals(&signals);
        assert!(v.stages_present.len() >= 3);
        assert_eq!(v.risk_score, 100);
        assert!(v.should_persist_threat);
    }

    #[test]
    fn max_per_group_not_sum_within_same_campaign_key() {
        let signals = vec![
            ThreatSignal::new(
                kill_chain::EXECUTE,
                "tx",
                Some(threat_types::MALICIOUS_TRANSACTION),
                20,
                50,
                "contract:0xsame",
            ),
            ThreatSignal::new(
                kill_chain::EXECUTE,
                "tx",
                Some(threat_types::UNLIMITED_APPROVAL),
                35,
                60,
                "contract:0xsame",
            ),
        ];
        let v = ThreatScoringV2::evaluate_signals(&signals);
        assert_eq!(v.risk_score, 35);
    }
}
