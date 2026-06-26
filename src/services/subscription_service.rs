use crate::db::DbPool;
use crate::models::subscription::PlanDescriptor;
use crate::repositories::dashboard_user_repository::DashboardUserRepository;
use crate::repositories::subscription_repository::{
    SubscriptionRepository, UpsertSubscriptionInput,
};
use crate::services::plan_catalog::{normalize_billing_cycle, normalize_plan, SubscriptionPriceTable};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use rsa::pkcs1v15::VerifyingKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::{pkcs1v15::Signature, RsaPublicKey};
use sha2::Sha256;
use serde_json::Value;

const WEBHOOK_TOLERANCE_SECONDS: i64 = 300;

#[derive(Clone, Debug)]
struct BoomFiConfig {
    org_id: String,
    webhook_public_key_pem: String,
    success_url: String,
    cancel_url: String,
    portal_url: String,
    basic_monthly_paylink: String,
    basic_annual_paylink: String,
    pro_monthly_paylink: String,
    pro_annual_paylink: String,
    premium_monthly_paylink: String,
    premium_annual_paylink: String,
    basic_monthly_plan_id: String,
    basic_annual_plan_id: String,
    pro_monthly_plan_id: String,
    pro_annual_plan_id: String,
    premium_monthly_plan_id: String,
    premium_annual_plan_id: String,
}

impl BoomFiConfig {
    fn from_env() -> Result<Self, String> {
        fn required(name: &str) -> Result<String, String> {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{name} must be set"))
        }
        fn optional(name: &str) -> String {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_default()
        }

        Ok(Self {
            org_id: required("BOOMFI_ORG_ID")?,
            webhook_public_key_pem: required("BOOMFI_WEBHOOK_PUBLIC_KEY")?,
            success_url: required("BOOMFI_SUCCESS_URL")?,
            cancel_url: required("BOOMFI_CANCEL_URL")?,
            portal_url: required("BOOMFI_SUBSCRIPTION_PORTAL_URL")?,
            basic_monthly_paylink: optional("BOOMFI_PAYLINK_BASIC_MONTHLY"),
            basic_annual_paylink: optional("BOOMFI_PAYLINK_BASIC_ANNUAL"),
            pro_monthly_paylink: optional("BOOMFI_PAYLINK_PRO_MONTHLY"),
            pro_annual_paylink: optional("BOOMFI_PAYLINK_PRO_ANNUAL"),
            premium_monthly_paylink: optional("BOOMFI_PAYLINK_PREMIUM_MONTHLY"),
            premium_annual_paylink: optional("BOOMFI_PAYLINK_PREMIUM_ANNUAL"),
            basic_monthly_plan_id: optional("BOOMFI_PLAN_BASIC_MONTHLY"),
            basic_annual_plan_id: optional("BOOMFI_PLAN_BASIC_ANNUAL"),
            pro_monthly_plan_id: optional("BOOMFI_PLAN_PRO_MONTHLY"),
            pro_annual_plan_id: optional("BOOMFI_PLAN_PRO_ANNUAL"),
            premium_monthly_plan_id: optional("BOOMFI_PLAN_PREMIUM_MONTHLY"),
            premium_annual_plan_id: optional("BOOMFI_PLAN_PREMIUM_ANNUAL"),
        })
    }

    fn paylink_for_plan(&self, plan: &str, billing_cycle: &str) -> Option<String> {
        match (plan, billing_cycle) {
            ("basic", "monthly") => non_empty(&self.basic_monthly_paylink),
            ("basic", "annual") => non_empty(&self.basic_annual_paylink),
            ("pro", "monthly") => non_empty(&self.pro_monthly_paylink),
            ("pro", "annual") => non_empty(&self.pro_annual_paylink),
            ("premium", "monthly") => non_empty(&self.premium_monthly_paylink),
            ("premium", "annual") => non_empty(&self.premium_annual_paylink),
            _ => None,
        }
    }

    fn paylink_env_var(plan: &str, billing_cycle: &str) -> &'static str {
        match (plan, billing_cycle) {
            ("basic", "monthly") => "BOOMFI_PAYLINK_BASIC_MONTHLY",
            ("basic", "annual") => "BOOMFI_PAYLINK_BASIC_ANNUAL",
            ("pro", "monthly") => "BOOMFI_PAYLINK_PRO_MONTHLY",
            ("pro", "annual") => "BOOMFI_PAYLINK_PRO_ANNUAL",
            ("premium", "monthly") => "BOOMFI_PAYLINK_PREMIUM_MONTHLY",
            ("premium", "annual") => "BOOMFI_PAYLINK_PREMIUM_ANNUAL",
            _ => "BOOMFI_PAYLINK_*",
        }
    }

    fn plan_id_for_plan(&self, plan: &str, billing_cycle: &str) -> Option<String> {
        match (plan, billing_cycle) {
            ("basic", "monthly") => non_empty(&self.basic_monthly_plan_id),
            ("basic", "annual") => non_empty(&self.basic_annual_plan_id),
            ("pro", "monthly") => non_empty(&self.pro_monthly_plan_id),
            ("pro", "annual") => non_empty(&self.pro_annual_plan_id),
            ("premium", "monthly") => non_empty(&self.premium_monthly_plan_id),
            ("premium", "annual") => non_empty(&self.premium_annual_plan_id),
            _ => None,
        }
    }

    fn plan_and_cycle_for_boomfi_plan_id(&self, plan_id: &str) -> Option<(String, String)> {
        if plan_id == self.basic_monthly_plan_id {
            return Some(("basic".to_string(), "monthly".to_string()));
        }
        if plan_id == self.basic_annual_plan_id {
            return Some(("basic".to_string(), "annual".to_string()));
        }
        if plan_id == self.pro_monthly_plan_id {
            return Some(("pro".to_string(), "monthly".to_string()));
        }
        if plan_id == self.pro_annual_plan_id {
            return Some(("pro".to_string(), "annual".to_string()));
        }
        if plan_id == self.premium_monthly_plan_id {
            return Some(("premium".to_string(), "monthly".to_string()));
        }
        if plan_id == self.premium_annual_plan_id {
            return Some(("premium".to_string(), "annual".to_string()));
        }
        None
    }
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn append_query_param(base: &str, key: &str, value: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{key}={}", urlencoding::encode(value))
}

fn build_checkout_url(cfg: &BoomFiConfig, plan: &str, billing_cycle: &str, user_id: &str) -> Result<String, String> {
    let paylink = cfg.paylink_for_plan(plan, billing_cycle).ok_or_else(|| {
        let env_var = BoomFiConfig::paylink_env_var(plan, billing_cycle);
        format!(
            "{env_var} is empty or unset on this server (plan={plan}, billing_cycle={billing_cycle})."
        )
    })?;
    let with_customer = append_query_param(&paylink, "customer_ident", user_id);
    Ok(append_query_param(&with_customer, "reference", user_id))
}

fn verify_boomfi_webhook_signature(
    public_key_pem: &str,
    timestamp: &str,
    body: &str,
    signature_b64: &str,
) -> Result<(), String> {
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| "Invalid X-BoomFi-Timestamp".to_string())?;
    let now = Utc::now().timestamp();
    if (now - ts).abs() > WEBHOOK_TOLERANCE_SECONDS {
        return Err("BoomFi webhook timestamp is stale".to_string());
    }

    let message = format!("{timestamp}.{body}");
    let signature_bytes = STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| format!("Invalid X-BoomFi-Signature base64: {e}"))?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| format!("Invalid RSA signature bytes: {e}"))?;
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("Invalid BOOMFI_WEBHOOK_PUBLIC_KEY: {e}"))?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| "Invalid BoomFi webhook signature".to_string())
}

fn parse_rfc3339_unix(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp())
}

fn normalize_boomfi_status(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" | "succeeded" | "success" => "active".to_string(),
        "pending" => "checkout_pending".to_string(),
        "canceled" | "cancelled" => "canceled".to_string(),
        "unpaid" | "failed" => "past_due".to_string(),
        other => other.to_string(),
    }
}

fn json_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string())
}

async fn resolve_user_id_from_webhook(pool: &DbPool, body: &Value) -> Result<Option<String>, String> {
    if let Some(reference) = body
        .get("customer")
        .and_then(|c| json_str(c, "reference"))
        .or_else(|| json_str(body, "reference"))
    {
        return Ok(Some(reference));
    }

    if let Some(customer_id) = json_str(body, "customer_id") {
        if let Some(row) = SubscriptionRepository::get_by_boomfi_customer_id(pool, &customer_id)
            .await
            .map_err(|e| format!("Failed to resolve BoomFi customer: {e}"))?
        {
            return Ok(Some(row.user_id));
        }
    }

    if let Some(subscription_id) = json_str(body, "id") {
        if body.get("event").and_then(|v| v.as_str()).is_some_and(|e| e.starts_with("Subscription.")) {
            if let Some(row) =
                SubscriptionRepository::get_by_boomfi_subscription_id(pool, &subscription_id)
                    .await
                    .map_err(|e| format!("Failed to resolve BoomFi subscription: {e}"))?
            {
                return Ok(Some(row.user_id));
            }
        }
    }

    Ok(None)
}

pub struct SubscriptionService;

impl SubscriptionService {
    pub fn list_plans() -> Result<Vec<PlanDescriptor>, String> {
        Ok(SubscriptionPriceTable::from_env_or_default().list_descriptors())
    }

    pub async fn get_subscription_status(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<crate::models::subscription::UserSubscription>, String> {
        if DashboardUserRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to validate user_id: {e}"))?
            .is_none()
        {
            return Err("Unknown user_id. Connect wallet first.".to_string());
        }
        SubscriptionRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to fetch subscription status: {e}"))
    }

    pub async fn create_checkout_session(
        pool: &DbPool,
        user_id: &str,
        plan: &str,
        billing_cycle: Option<&str>,
        success_url: Option<&str>,
        cancel_url: Option<&str>,
    ) -> Result<String, String> {
        let cfg = BoomFiConfig::from_env()?;
        let normalized_plan = normalize_plan(plan)
            .ok_or_else(|| "Invalid plan. Use basic, pro, or premium.".to_string())?;
        let normalized_cycle = normalize_billing_cycle(billing_cycle)
            .ok_or_else(|| "Invalid billing_cycle. Use monthly or annual.".to_string())?;

        if DashboardUserRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to validate user_id: {e}"))?
            .is_none()
        {
            return Err("Unknown user_id. Connect wallet first.".to_string());
        }

        let mut checkout_url = build_checkout_url(&cfg, &normalized_plan, &normalized_cycle, user_id)?;
        let success = success_url.unwrap_or(&cfg.success_url);
        let cancel = cancel_url.unwrap_or(&cfg.cancel_url);
        checkout_url = append_query_param(&checkout_url, "success_url", success);
        checkout_url = append_query_param(&checkout_url, "cancel_url", cancel);

        let boomfi_plan_id = cfg.plan_id_for_plan(&normalized_plan, &normalized_cycle);

        SubscriptionRepository::upsert(
            pool,
            UpsertSubscriptionInput {
                user_id,
                plan: &normalized_plan,
                billing_cycle: &normalized_cycle,
                status: "checkout_pending",
                boomfi_customer_id: None,
                boomfi_subscription_id: None,
                boomfi_plan_id: boomfi_plan_id.as_deref(),
                checkout_session_id: None,
                current_period_end_unix: None,
                cancel_at_period_end: false,
            },
        )
        .await
        .map_err(|e| format!("Failed to save pending checkout: {e}"))?;

        Ok(checkout_url)
    }

    pub async fn create_billing_portal_session(
        pool: &DbPool,
        user_id: &str,
        return_url: Option<&str>,
    ) -> Result<String, String> {
        let cfg = BoomFiConfig::from_env()?;
        if DashboardUserRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to validate user_id: {e}"))?
            .is_none()
        {
            return Err("Unknown user_id. Connect wallet first.".to_string());
        }

        let _existing = SubscriptionRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to fetch subscription: {e}"))?
            .ok_or_else(|| "No subscription found for this user.".to_string())?;

        let portal = if let Some(ret) = return_url {
            append_query_param(&cfg.portal_url, "return_url", ret)
        } else {
            cfg.portal_url.clone()
        };
        Ok(portal)
    }

    pub async fn process_boomfi_webhook(
        pool: &DbPool,
        timestamp_header: &str,
        signature_header: &str,
        payload: &str,
    ) -> Result<(), String> {
        let cfg = BoomFiConfig::from_env()?;
        verify_boomfi_webhook_signature(
            &cfg.webhook_public_key_pem,
            timestamp_header,
            payload,
            signature_header,
        )?;

        let body: Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid webhook payload: {e}"))?;

        if let Some(org_id) = json_str(&body, "org_id") {
            if org_id != cfg.org_id {
                return Err("BoomFi webhook org_id mismatch".to_string());
            }
        }

        let event = json_str(&body, "event").unwrap_or_default();
        if !event.starts_with("Subscription.") && event != "Payment.Updated" {
            return Ok(());
        }

        let Some(user_id) = resolve_user_id_from_webhook(pool, &body).await? else {
            return Ok(());
        };

        let boomfi_subscription_id = json_str(&body, "id").filter(|_| event.starts_with("Subscription."));
        let boomfi_customer_id = json_str(&body, "customer_id").or_else(|| {
            body.get("customer")
                .and_then(|c| json_str(c, "id"))
        });
        let boomfi_plan_id = body
            .get("plan")
            .and_then(|p| json_str(p, "id"))
            .or_else(|| json_str(&body, "plan_id"));

        let mut plan = body
            .get("metadata")
            .and_then(|m| json_str(m, "plan"))
            .and_then(|p| normalize_plan(&p));
        let mut billing_cycle = body
            .get("metadata")
            .and_then(|m| json_str(m, "billing_cycle"))
            .and_then(|c| normalize_billing_cycle(Some(&c)));

        if (plan.is_none() || billing_cycle.is_none()) && boomfi_plan_id.is_some() {
            if let Some((p, cycle)) =
                cfg.plan_and_cycle_for_boomfi_plan_id(boomfi_plan_id.as_deref().unwrap_or_default())
            {
                if plan.is_none() {
                    plan = Some(p);
                }
                if billing_cycle.is_none() {
                    billing_cycle = Some(cycle);
                }
            }
        }

        if plan.is_none() {
            plan = SubscriptionRepository::get_by_user_id(pool, &user_id)
                .await
                .map_err(|e| format!("Failed to resolve existing plan: {e}"))?
                .map(|row| row.plan);
        }
        if billing_cycle.is_none() {
            billing_cycle = SubscriptionRepository::get_by_user_id(pool, &user_id)
                .await
                .map_err(|e| format!("Failed to resolve existing billing cycle: {e}"))?
                .map(|row| row.billing_cycle);
        }

        let plan = plan.unwrap_or_else(|| "basic".to_string());
        let billing_cycle = billing_cycle.unwrap_or_else(|| "monthly".to_string());

        let status = if event == "Payment.Updated" {
            normalize_boomfi_status(json_str(&body, "status").unwrap_or_default().as_str())
        } else {
            normalize_boomfi_status(json_str(&body, "status").unwrap_or_default().as_str())
        };

        let cancel_at_period_end = body
            .get("cancel_at_period_end")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let current_period_end_unix = body
            .get("current_period_end")
            .and_then(|v| v.as_i64())
            .or_else(|| {
                body.get("updated_at")
                    .and_then(|v| v.as_str())
                    .and_then(parse_rfc3339_unix)
            });

        SubscriptionRepository::upsert(
            pool,
            UpsertSubscriptionInput {
                user_id: &user_id,
                plan: &plan,
                billing_cycle: &billing_cycle,
                status: &status,
                boomfi_customer_id: boomfi_customer_id.as_deref(),
                boomfi_subscription_id: boomfi_subscription_id.as_deref(),
                boomfi_plan_id: boomfi_plan_id.as_deref(),
                checkout_session_id: None,
                current_period_end_unix,
                cancel_at_period_end,
            },
        )
        .await
        .map_err(|e| format!("Failed to persist BoomFi webhook update: {e}"))?;

        Ok(())
    }
}
