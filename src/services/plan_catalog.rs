//! Shared plan tier and billing cycle normalization for BoomFi subscriptions.

use crate::models::subscription::PlanDescriptor;

/// Normalize UI/API plan strings to DB values: `basic`, `pro`, `premium`.
pub fn normalize_plan(plan: &str) -> Option<String> {
    let mut p = plan.trim().to_lowercase();
    if let Some(s) = p.strip_suffix(" plan") {
        p = s.trim().to_string();
    }
    let p = p.replace('-', "_").replace(' ', "_");
    match p.as_str() {
        "basic" => Some("basic".to_string()),
        "pro" => Some("pro".to_string()),
        "premium" => Some("premium".to_string()),
        // Legacy aliases
        "pro+" | "pro_plus" => Some("pro".to_string()),
        _ => None,
    }
}

pub fn normalize_billing_cycle(cycle: Option<&str>) -> Option<String> {
    let normalized = cycle.unwrap_or("monthly").trim().to_lowercase();
    match normalized.as_str() {
        "monthly" | "month" => Some("monthly".to_string()),
        "annual" | "yearly" | "year" => Some("annual".to_string()),
        _ => None,
    }
}

fn label_for_plan_key(key: &str) -> &'static str {
    match key {
        "basic" => "Basic Plan",
        "pro" => "PRO Plan",
        "premium" => "PREMIUM Plan",
        _ => "Plan",
    }
}

/// USD list prices for subscription SKUs (`BOOMFI_PRICE_*` env with code defaults).
pub struct SubscriptionPriceTable {
    pub basic_monthly: f64,
    pub basic_annual: f64,
    pub pro_monthly: f64,
    pub pro_annual: f64,
    pub premium_monthly: f64,
    pub premium_annual: f64,
}

impl SubscriptionPriceTable {
    pub fn from_env_or_default() -> Self {
        Self {
            basic_monthly: parse_env_f64("BOOMFI_PRICE_BASIC_MONTHLY", 15.0),
            basic_annual: parse_env_f64("BOOMFI_PRICE_BASIC_ANNUAL", 150.0),
            pro_monthly: parse_env_f64("BOOMFI_PRICE_PRO_MONTHLY", 30.0),
            pro_annual: parse_env_f64("BOOMFI_PRICE_PRO_ANNUAL", 300.0),
            premium_monthly: parse_env_f64("BOOMFI_PRICE_PREMIUM_MONTHLY", 200.0),
            premium_annual: parse_env_f64("BOOMFI_PRICE_PREMIUM_ANNUAL", 2000.0),
        }
    }

    pub fn price_usd(&self, plan: &str, billing_cycle: &str) -> Option<f64> {
        match (plan, billing_cycle) {
            ("basic", "monthly") => Some(self.basic_monthly),
            ("basic", "annual") => Some(self.basic_annual),
            ("pro", "monthly") => Some(self.pro_monthly),
            ("pro", "annual") => Some(self.pro_annual),
            ("premium", "monthly") => Some(self.premium_monthly),
            ("premium", "annual") => Some(self.premium_annual),
            _ => None,
        }
    }

    pub fn list_descriptors(&self) -> Vec<PlanDescriptor> {
        let tiers = [
            ("basic", self.basic_monthly, self.basic_annual),
            ("pro", self.pro_monthly, self.pro_annual),
            ("premium", self.premium_monthly, self.premium_annual),
        ];
        let mut out = Vec::with_capacity(6);
        for (key, monthly, annual) in tiers {
            out.push(PlanDescriptor {
                key: key.to_string(),
                label: label_for_plan_key(key).to_string(),
                billing_cycle: "monthly".to_string(),
                price_usd: monthly,
                currency: "USD".to_string(),
                savings_label: None,
            });
            let save = (monthly * 12.0 - annual).max(0.0);
            out.push(PlanDescriptor {
                key: key.to_string(),
                label: label_for_plan_key(key).to_string(),
                billing_cycle: "annual".to_string(),
                price_usd: annual,
                currency: "USD".to_string(),
                savings_label: if save > f64::EPSILON {
                    Some(format!("Save ${save:.0} USD vs paying monthly"))
                } else {
                    None
                },
            });
        }
        out
    }
}

fn parse_env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&x| x.is_finite() && x > 0.0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_ui_aliases() {
        assert_eq!(normalize_plan("BASIC").as_deref(), Some("basic"));
        assert_eq!(normalize_plan("Basic Plan").as_deref(), Some("basic"));
        assert_eq!(normalize_plan("PRO").as_deref(), Some("pro"));
        assert_eq!(normalize_plan("PRO Plan").as_deref(), Some("pro"));
        assert_eq!(normalize_plan("PREMIUM").as_deref(), Some("premium"));
        assert_eq!(normalize_plan("pro_plus").as_deref(), Some("pro"));
    }

    #[test]
    fn price_table_defaults() {
        let t = SubscriptionPriceTable::from_env_or_default();
        assert!((t.pro_monthly - 30.0).abs() < f64::EPSILON);
        assert!((t.price_usd("basic", "monthly").unwrap() - 15.0).abs() < f64::EPSILON);
    }
}
