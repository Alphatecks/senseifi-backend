//! AI explanation engine: turn technical details into human-readable risk narrative.

use crate::models::senseiguard::{
    OwnerPrivileges, ReputationInfo, RiskBreakdown, SimulationResult,
};

pub struct AiInsightService;

impl AiInsightService {
    /// Plain-language scan summary aligned with trust score and factor breakdown.
    pub fn explain_risks(
        trust_score: i32,
        simulation: &SimulationResult,
        owner_privileges: &OwnerPrivileges,
        reputation: &ReputationInfo,
        risk_breakdown: &RiskBreakdown,
        token_controlled: &str,
    ) -> String {
        let score = trust_score.clamp(0, 100);
        let headline = trust_headline(score);
        let mut bullets: Vec<String> = Vec::new();

        let token_label = if token_controlled.is_empty() || token_controlled == "Unknown" {
            "tokens".to_string()
        } else {
            token_controlled.to_string()
        };

        if simulation.drains_full_balance == Some(true) {
            bullets.push(format!(
                "Simulation: Can transfer 100% of your {token_label} if you grant approval — high risk."
            ));
        } else {
            bullets.push(
                "Simulation: No full-balance drain detected in the test simulation.".to_string(),
            );
        }

        if simulation.hidden_internal_calls.unwrap_or(0) > 0 {
            bullets.push(format!(
                "Simulation: {} hidden internal call(s) that may affect allowances or balances.",
                simulation.hidden_internal_calls.unwrap_or(0)
            ));
        }

        bullets.push(owner_privilege_bullet(owner_privileges, score));

        bullets.push(reputation_bullet(reputation));

        if reputation.verified_source == Some(true) {
            bullets.push("Source: Contract source is verified on the block explorer.".to_string());
        }

        if let Some(top) = top_risk_factors(risk_breakdown) {
            bullets.push(format!("Score drivers: {top}."));
        }

        bullets.push(action_bullet(score, simulation, reputation, owner_privileges));

        format!(
            "{headline}\n\n{}",
            bullets
                .into_iter()
                .map(|b| format!("• {b}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

fn trust_headline(score: i32) -> String {
    let band = if score >= 80 {
        "Generally trustworthy"
    } else if score >= 60 {
        "Moderate trust — review before interacting"
    } else if score >= 40 {
        "Elevated risk — proceed with caution"
    } else {
        "High risk — avoid unless you fully understand the contract"
    };
    format!("Trust score: {score}/100 — {band}.")
}

fn owner_privilege_bullet(owner: &OwnerPrivileges, trust_score: i32) -> String {
    let mint = owner.mint == Some(true);
    let withdraw = owner.withdraw_liquidity == Some(true);
    let upgrade = owner.upgradeable == Some(true);
    let pause = owner.pause == Some(true);

    if !mint && !withdraw && !upgrade && !pause {
        return "Owner privileges: No notable admin mint, pause, upgrade, or liquidity-withdraw functions detected.".to_string();
    }

    let mut caps = Vec::new();
    if mint {
        caps.push("mint");
    }
    if withdraw {
        caps.push("withdraw liquidity");
    }
    if upgrade {
        caps.push("upgrade");
    }
    if pause {
        caps.push("pause");
    }
    let joined = caps.join(", ");

    if trust_score >= 70 {
        format!(
            "Owner privileges: Admin functions detected ({joined}). Common on established tokens and protocols; verify the team and audits."
        )
    } else {
        format!(
            "Owner privileges: Admin functions detected ({joined}). Combined with other signals, this increases centralization and rug-pull risk."
        )
    }
}

fn reputation_bullet(reputation: &ReputationInfo) -> String {
    let local = reputation.local_report_count.unwrap_or(0);
    let info = reputation.informational_flags.unwrap_or(0);

    if local >= 3 {
        return format!(
            "Reputation: {local} community scam report(s) on file in our database."
        );
    }

    if reputation.reported_scam == Some(true) {
        if local > 0 {
            return format!(
                "Reputation: External threat feeds flagged this address; {local} local report(s) also recorded."
            );
        }
        return "Reputation: External threat feeds flagged this address — verify on a block explorer before interacting.".to_string();
    }

    if local > 0 {
        return format!(
            "Reputation: {local} isolated report(s); below our threshold for a scam classification."
        );
    }

    if info > 0 {
        return format!(
            "Reputation: No credible scam reports; {info} informational token-security flag(s) (e.g. mintable) from external feeds."
        );
    }

    "Reputation: No credible community scam reports found.".to_string()
}

fn top_risk_factors(breakdown: &RiskBreakdown) -> Option<String> {
    let mut factors: Vec<(&str, u8)> = vec![
        ("simulation", breakdown.simulation.unwrap_or(0)),
        ("owner privileges", breakdown.owner_privileges.unwrap_or(0)),
        ("reputation", breakdown.reputation.unwrap_or(0)),
        ("wallet anomaly", breakdown.anomaly.unwrap_or(0)),
        ("token scope", breakdown.token_control_scope.unwrap_or(0)),
        ("contract age", breakdown.contract_age.unwrap_or(0)),
    ];
    factors.retain(|(_, pct)| *pct > 0);
    factors.sort_by(|a, b| b.1.cmp(&a.1));
    factors.truncate(3);

    if factors.is_empty() {
        return None;
    }

    Some(
        factors
            .into_iter()
            .map(|(name, pct)| format!("{name} {pct}%"))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn action_bullet(
    trust_score: i32,
    simulation: &SimulationResult,
    reputation: &ReputationInfo,
    owner: &OwnerPrivileges,
) -> String {
    let local = reputation.local_report_count.unwrap_or(0);
    let credible_scam = local >= 3 || reputation.reported_scam == Some(true);
    let drain = simulation.drains_full_balance == Some(true);
    let privileged = owner.mint == Some(true) || owner.withdraw_liquidity == Some(true);

    if drain || (credible_scam && trust_score < 50) {
        "Next step: Do not approve unlimited permissions; revoke existing approvals if unsure.".to_string()
    } else if credible_scam || trust_score < 60 {
        "Next step: Confirm contract address, team, and audits on a block explorer before signing.".to_string()
    } else if privileged && trust_score >= 70 {
        "Next step: Standard due diligence — verify you are on the official contract address.".to_string()
    } else {
        "Next step: Always double-check approvals and the exact contract you are interacting with.".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::senseiguard::RiskBreakdown;

    fn usdc_like_reputation() -> ReputationInfo {
        ReputationInfo {
            reported_scam: Some(false),
            community_flags: Some(1),
            verified_source: Some(true),
            local_report_count: Some(0),
            informational_flags: Some(1),
        }
    }

    fn usdc_like_owner() -> OwnerPrivileges {
        OwnerPrivileges {
            mint: Some(true),
            withdraw_liquidity: Some(false),
            upgradeable: Some(false),
            pause: Some(false),
            blacklist: Some(false),
        }
    }

    fn clean_simulation() -> SimulationResult {
        SimulationResult {
            drains_full_balance: Some(false),
            hidden_internal_calls: Some(0),
            approval_scope: None,
            dangerous_functions: None,
        }
    }

    #[test]
    fn high_trust_mintable_contract_uses_soft_wording() {
        let summary = AiInsightService::explain_risks(
            82,
            &clean_simulation(),
            &usdc_like_owner(),
            &usdc_like_reputation(),
            &RiskBreakdown {
                owner_privileges: Some(35),
                reputation: Some(10),
                contract_age: Some(25),
                ..Default::default()
            },
            "USDC",
        );

        assert!(summary.contains("Trust score: 82/100"));
        assert!(summary.contains("Generally trustworthy"));
        assert!(!summary.contains("reported as a scam"));
        assert!(!summary.contains("rug pull"));
        assert!(summary.contains("informational"));
        assert!(summary.contains("mint"));
    }

    #[test]
    fn credible_scam_reports_use_strong_wording() {
        let summary = AiInsightService::explain_risks(
            35,
            &clean_simulation(),
            &usdc_like_owner(),
            &ReputationInfo {
                reported_scam: Some(true),
                local_report_count: Some(4),
                ..Default::default()
            },
            &RiskBreakdown {
                reputation: Some(60),
                owner_privileges: Some(25),
                ..Default::default()
            },
            "Token",
        );

        assert!(summary.contains("4 community scam report"));
        assert!(summary.contains("High risk") || summary.contains("Elevated risk"));
    }
}
