//! Shared plan tier and billing cycle normalization (Stripe + onchain) and onchain USD pricing.

use serde::Serialize;
use tiny_keccak::{Hasher, Keccak};
use uuid::Uuid;

/// Normalize UI/API plan strings to DB values: `pro`, `pro_plus`, `premium`.
pub fn normalize_plan(plan: &str) -> Option<String> {
    let mut p = plan.trim().to_lowercase();
    if let Some(s) = p.strip_suffix(" plan") {
        p = s.trim().to_string();
    }
    let p = p.replace('-', "_").replace(' ', "_");
    match p.as_str() {
        "pro" => Some("pro".to_string()),
        "pro+" | "pro_plus" => Some("pro_plus".to_string()),
        "premium" => Some("premium".to_string()),
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
        "pro" => "Pro Plan",
        "pro_plus" => "Pro+ Plan",
        "premium" => "Premium Plan",
        _ => "Plan",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OnchainPlanDescriptor {
    pub key: String,
    pub label: String,
    pub billing_cycle: String,
    pub price_usd: f64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub savings_label: Option<String>,
}

/// USD prices for onchain subscription SKUs (env `ONCHAIN_PRICE_*` with code defaults).
pub struct OnchainPriceTable {
    pub pro_monthly: f64,
    pub pro_annual: f64,
    pub pro_plus_monthly: f64,
    pub pro_plus_annual: f64,
    pub premium_monthly: f64,
    pub premium_annual: f64,
}

impl OnchainPriceTable {
    pub fn from_env_or_default() -> Self {
        Self {
            pro_monthly: parse_env_f64("ONCHAIN_PRICE_PRO_MONTHLY", 30.0),
            pro_annual: parse_env_f64("ONCHAIN_PRICE_PRO_ANNUAL", 300.0),
            pro_plus_monthly: parse_env_f64("ONCHAIN_PRICE_PRO_PLUS_MONTHLY", 50.0),
            pro_plus_annual: parse_env_f64("ONCHAIN_PRICE_PRO_PLUS_ANNUAL", 500.0),
            premium_monthly: parse_env_f64("ONCHAIN_PRICE_PREMIUM_MONTHLY", 200.0),
            premium_annual: parse_env_f64("ONCHAIN_PRICE_PREMIUM_ANNUAL", 2000.0),
        }
    }

    pub fn price_usd(&self, plan: &str, billing_cycle: &str) -> Option<f64> {
        match (plan, billing_cycle) {
            ("pro", "monthly") => Some(self.pro_monthly),
            ("pro", "annual") => Some(self.pro_annual),
            ("pro_plus", "monthly") => Some(self.pro_plus_monthly),
            ("pro_plus", "annual") => Some(self.pro_plus_annual),
            ("premium", "monthly") => Some(self.premium_monthly),
            ("premium", "annual") => Some(self.premium_annual),
            _ => None,
        }
    }

    pub fn list_descriptors(&self) -> Vec<OnchainPlanDescriptor> {
        let tiers = [
            ("pro", self.pro_monthly, self.pro_annual),
            ("pro_plus", self.pro_plus_monthly, self.pro_plus_annual),
            ("premium", self.premium_monthly, self.premium_annual),
        ];
        let mut out = Vec::with_capacity(6);
        for (key, monthly, annual) in tiers {
            out.push(OnchainPlanDescriptor {
                key: key.to_string(),
                label: label_for_plan_key(key).to_string(),
                billing_cycle: "monthly".to_string(),
                price_usd: monthly,
                currency: "USD".to_string(),
                savings_label: None,
            });
            let save = (monthly * 12.0 - annual).max(0.0);
            out.push(OnchainPlanDescriptor {
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
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// `keccak256` over UTF-8 bytes of the hyphenated UUID string (matches typical ethers `solidityPackedKeccak256` on the same string).
/// Use this value as `bytes32` when calling `upsertBilling` on the payment contract.
pub fn subscription_id_bytes32_hex(subscription_uuid: &Uuid) -> String {
    let s = subscription_uuid.to_string();
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(s.as_bytes());
    hasher.finalize(&mut out);
    format!("0x{}", hex::encode(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_ui_aliases() {
        assert_eq!(normalize_plan("PRO").as_deref(), Some("pro"));
        assert_eq!(normalize_plan("PRO_PLUS").as_deref(), Some("pro_plus"));
        assert_eq!(normalize_plan("Pro Plan").as_deref(), Some("pro"));
        assert_eq!(normalize_plan("pro-plus").as_deref(), Some("pro_plus"));
    }

    #[test]
    fn price_table_defaults() {
        let t = OnchainPriceTable::from_env_or_default();
        assert!((t.pro_monthly - 30.0).abs() < f64::EPSILON);
        assert!((t.price_usd("pro", "annual").unwrap() - 300.0).abs() < f64::EPSILON);
    }
}
