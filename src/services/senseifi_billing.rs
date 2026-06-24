//! Integration helpers for the deployed **SenseiFiBilling** contract (biller model).
//!
//! Production Base Sepolia uses `billers` + `charge(bytes32,uint256)` + `getBilling(bytes32)`.
//! The in-repo `SenseifiSubscriptionPayments.sol` (relayer + ChargeRequest tuple) is not deployed.

use rust_decimal::Decimal;
use serde_json::Value;
use uuid::Uuid;

/// `BillingUpserted` topic0 on SenseiFiBilling (Base Sepolia deploy).
pub const BILLING_UPSERTED_TOPIC: &str =
    "0xfc9e90ff10f03805a915deee8b20f37a2f9177f132e6705b397f328343a770f7";

pub fn payment_contract_style() -> &'static str {
    match std::env::var("ONCHAIN_PAYMENT_CONTRACT_STYLE")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("biller") => "biller",
        Some("relayer") => "relayer",
        _ => "biller",
    }
}

pub fn uses_biller_contract() -> bool {
    payment_contract_style() != "relayer"
}

/// USDC base units (6 decimals) → Decimal USD amount.
pub fn usdc_raw_to_decimal(raw: u64) -> Decimal {
    Decimal::from_i128_with_scale(i128::from(raw), 6)
}

/// Parse `chargedUsdcRaw` from webhook body or nested `payload`.
/// The second uint in `BillingUpserted` event data is **not** a boolean active flag.
pub fn parse_charged_usdc_raw(body: &Value) -> Option<u64> {
    parse_u64_field(body, "charged_usdc_raw")
        .or_else(|| parse_u64_field(body, "chargedUsdcRaw"))
        .or_else(|| {
            body.get("payload")
                .and_then(|p| parse_u64_field(p, "charged_usdc_raw"))
        })
        .or_else(|| {
            body.get("payload")
                .and_then(|p| parse_u64_field(p, "chargedUsdcRaw"))
        })
        .or_else(|| {
            // Legacy mis-decode guard: do not treat small integers as booleans.
            body.get("allowance_status")
                .and_then(|v| v.as_str())
                .and_then(|s| s.trim().parse::<u64>().ok())
        })
}

pub fn parse_payer_address(body: &Value) -> Option<String> {
    parse_address_field(body, "payer_address")
        .or_else(|| parse_address_field(body, "payer"))
        .or_else(|| {
            body.get("payload")
                .and_then(|p| parse_address_field(p, "payer_address"))
        })
        .or_else(|| body.get("payload").and_then(|p| parse_address_field(p, "payer")))
}

pub fn parse_subscription_id(body: &Value) -> Option<Uuid> {
    body.get("subscription_id")
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                Uuid::parse_str(s.trim()).ok()
            } else {
                None
            }
        })
        .or_else(|| {
            body.get("payload").and_then(|p| {
                p.get("subscription_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s.trim()).ok())
            })
        })
}

fn parse_u64_field(obj: &Value, key: &str) -> Option<u64> {
    obj.get(key).and_then(|v| {
        if let Some(n) = v.as_u64() {
            return Some(n);
        }
        if let Some(s) = v.as_str() {
            return s.trim().parse().ok();
        }
        if let Some(n) = v.as_i64() {
            return u64::try_from(n).ok();
        }
        if let Some(n) = v.as_f64() {
            return Some(n as u64);
        }
        None
    })
}

fn parse_address_field(obj: &Value, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| s.starts_with("0x") && s.len() >= 42)
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_charged_usdc_raw_from_payload() {
        let body = json!({
            "payload": { "charged_usdc_raw": 30000000 }
        });
        assert_eq!(parse_charged_usdc_raw(&body), Some(30_000_000));
    }

    #[test]
    fn parse_charged_usdc_raw_not_boolean_active() {
        let body = json!({ "charged_usdc_raw": 30000000 });
        assert_eq!(parse_charged_usdc_raw(&body), Some(30_000_000));
    }

    #[test]
    fn usdc_raw_to_decimal_converts_six_decimals() {
        let d = usdc_raw_to_decimal(30_000_000);
        assert_eq!(d.to_string(), "30.000000");
    }
}
