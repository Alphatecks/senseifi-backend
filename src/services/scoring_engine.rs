//! Explainable trust score: weighted formula and risk_breakdown.
//! Weights: Contract Age 15%, Owner Privileges 20%, Simulation 30%, Reputation 15%, Anomaly 10%, Token Control 10%.

use crate::models::senseiguard::{
    OwnerPrivileges, ReputationInfo, RiskBreakdown, SimulationResult,
};

/// Weights (percent of total risk contribution when factor is "full risk").
const W_SIMULATION: u8 = 30;
const W_OWNER_PRIVILEGES: u8 = 20;
const W_REPUTATION: u8 = 15;
const W_ANOMALY: u8 = 10;
const W_TOKEN_SCOPE: u8 = 10;
const W_CONTRACT_AGE: u8 = 15;

pub struct ScoringEngine;

impl ScoringEngine {
    /// Compute risk contribution 0..=100 per factor (higher = more risk).
    fn simulation_risk(s: &SimulationResult) -> u8 {
        let mut r = 0u8;
        if s.drains_full_balance == Some(true) {
            r += 50;
        }
        if s.approval_scope.as_deref() == Some("unlimited") {
            r += 30;
        }
        let hidden = s.hidden_internal_calls.unwrap_or(0);
        if hidden > 0 {
            r = r.saturating_add((hidden as u8).min(20));
        }
        r.min(100)
    }

    fn owner_risk(o: &OwnerPrivileges) -> u8 {
        let mut r = 0u8;
        if o.mint == Some(true) {
            r += 25;
        }
        if o.withdraw_liquidity == Some(true) {
            r += 25;
        }
        if o.upgradeable == Some(true) {
            r += 25;
        }
        if o.pause == Some(true) {
            r += 15;
        }
        if o.blacklist == Some(true) {
            r += 10;
        }
        r.min(100)
    }

    fn reputation_risk(rep: &ReputationInfo) -> u8 {
        let mut r = 0u8;
        if rep.reported_scam == Some(true) {
            r += 80;
        }
        if rep.verified_source != Some(true) {
            r = r.saturating_add(10);
        }
        let flags = rep.community_flags.unwrap_or(0);
        r = r.saturating_add((flags as u8).min(20));
        r.min(100)
    }

    /// Trust score 0--100 (higher = safer). risk_breakdown = contribution per factor (percent of total).
    pub fn compute(
        simulation: &SimulationResult,
        owner_privileges: &OwnerPrivileges,
        reputation: &ReputationInfo,
        user_anomaly_score: f64,
        token_control_risk: u8,
        contract_age_risk: u8,
    ) -> (i32, RiskBreakdown) {
        let s_risk = Self::simulation_risk(simulation);
        let o_risk = Self::owner_risk(owner_privileges);
        let r_risk = Self::reputation_risk(reputation);
        let a_risk = (user_anomaly_score * 100.0).round().min(100.0) as u8;

        let weighted: f64 = (s_risk as f64) * (W_SIMULATION as f64) / 100.0
            + (o_risk as f64) * (W_OWNER_PRIVILEGES as f64) / 100.0
            + (r_risk as f64) * (W_REPUTATION as f64) / 100.0
            + (a_risk as f64) * (W_ANOMALY as f64) / 100.0
            + (token_control_risk as f64) * (W_TOKEN_SCOPE as f64) / 100.0
            + (contract_age_risk as f64) * (W_CONTRACT_AGE as f64) / 100.0;

        let trust_score = (100.0 - weighted).round().max(0.0).min(100.0) as i32;

        let total = (s_risk as f64) * (W_SIMULATION as f64) / 100.0
            + (o_risk as f64) * (W_OWNER_PRIVILEGES as f64) / 100.0
            + (r_risk as f64) * (W_REPUTATION as f64) / 100.0
            + (a_risk as f64) * (W_ANOMALY as f64) / 100.0
            + (token_control_risk as f64) * (W_TOKEN_SCOPE as f64) / 100.0
            + (contract_age_risk as f64) * (W_CONTRACT_AGE as f64) / 100.0;

        let pct = |v: f64| {
            if total <= 0.0 {
                0u8
            } else {
                ((v / total) * 100.0).round().min(100.0) as u8
            }
        };

        let sim_contrib = (s_risk as f64) * (W_SIMULATION as f64) / 100.0;
        let own_contrib = (o_risk as f64) * (W_OWNER_PRIVILEGES as f64) / 100.0;
        let rep_contrib = (r_risk as f64) * (W_REPUTATION as f64) / 100.0;
        let anom_contrib = (a_risk as f64) * (W_ANOMALY as f64) / 100.0;
        let tok_contrib = (token_control_risk as f64) * (W_TOKEN_SCOPE as f64) / 100.0;
        let age_contrib = (contract_age_risk as f64) * (W_CONTRACT_AGE as f64) / 100.0;

        let risk_breakdown = RiskBreakdown {
            simulation: Some(pct(sim_contrib)),
            owner_privileges: Some(pct(own_contrib)),
            reputation: Some(pct(rep_contrib)),
            anomaly: Some(pct(anom_contrib)),
            token_control_scope: Some(pct(tok_contrib)),
            contract_age: Some(pct(age_contrib)),
        };

        (trust_score, risk_breakdown)
    }

    /// Rug pull probability from owner privileges.
    pub fn rug_pull_probability(owner_privileges: &OwnerPrivileges) -> String {
        let r = Self::owner_risk(owner_privileges);
        if r >= 70 {
            "High".to_string()
        } else if r >= 40 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        }
    }
}
