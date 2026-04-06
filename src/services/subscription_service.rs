use crate::db::DbPool;
use crate::models::subscription::{PlanDescriptor, UserSubscription};
use crate::repositories::dashboard_user_repository::DashboardUserRepository;
use crate::repositories::subscription_repository::{
    SubscriptionRepository, UpsertSubscriptionInput,
};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

const WEBHOOK_TOLERANCE_SECONDS: i64 = 300;

#[derive(Clone, Debug)]
struct StripeConfig {
    secret_key: String,
    webhook_secret: String,
    success_url: String,
    cancel_url: String,
    portal_return_url: String,
    pro_monthly_price_id: String,
    pro_annual_price_id: String,
    pro_plus_monthly_price_id: String,
    pro_plus_annual_price_id: String,
    premium_monthly_price_id: String,
    premium_annual_price_id: String,
}

#[derive(Deserialize)]
struct StripeCheckoutSession {
    id: String,
    url: Option<String>,
}

#[derive(Deserialize)]
struct StripePortalSession {
    url: String,
}

#[derive(Clone, Debug)]
struct StripeSubscriptionSnapshot {
    status: String,
    current_period_end: Option<i64>,
    cancel_at_period_end: bool,
    customer_id: Option<String>,
    price_id: Option<String>,
}

impl StripeConfig {
    fn from_env() -> Result<Self, String> {
        fn required(name: &str) -> Result<String, String> {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{name} must be set"))
        }
        fn optional_or_fallback(primary: &str, fallback: &str) -> Result<String, String> {
            if let Some(v) = std::env::var(primary)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
            {
                return Ok(v);
            }
            required(fallback)
        }

        Ok(Self {
            secret_key: required("STRIPE_SECRET_KEY")?,
            webhook_secret: required("STRIPE_WEBHOOK_SECRET")?,
            success_url: required("STRIPE_SUCCESS_URL")?,
            cancel_url: required("STRIPE_CANCEL_URL")?,
            portal_return_url: required("STRIPE_BILLING_PORTAL_RETURN_URL")?,
            pro_monthly_price_id: optional_or_fallback("STRIPE_PRICE_PRO_MONTHLY", "STRIPE_PRICE_PRO")?,
            pro_annual_price_id: required("STRIPE_PRICE_PRO_ANNUAL")?,
            pro_plus_monthly_price_id: optional_or_fallback(
                "STRIPE_PRICE_PRO_PLUS_MONTHLY",
                "STRIPE_PRICE_PRO_PLUS",
            )?,
            pro_plus_annual_price_id: required("STRIPE_PRICE_PRO_PLUS_ANNUAL")?,
            premium_monthly_price_id: optional_or_fallback(
                "STRIPE_PRICE_PREMIUM_MONTHLY",
                "STRIPE_PRICE_PREMIUM",
            )?,
            premium_annual_price_id: required("STRIPE_PRICE_PREMIUM_ANNUAL")?,
        })
    }

    fn plans(&self) -> Vec<PlanDescriptor> {
        vec![
            PlanDescriptor {
                key: "pro".to_string(),
                label: "Pro Plan".to_string(),
                billing_cycle: "monthly".to_string(),
                stripe_price_id: self.pro_monthly_price_id.clone(),
            },
            PlanDescriptor {
                key: "pro".to_string(),
                label: "Pro Plan".to_string(),
                billing_cycle: "annual".to_string(),
                stripe_price_id: self.pro_annual_price_id.clone(),
            },
            PlanDescriptor {
                key: "pro_plus".to_string(),
                label: "Pro+ Plan".to_string(),
                billing_cycle: "monthly".to_string(),
                stripe_price_id: self.pro_plus_monthly_price_id.clone(),
            },
            PlanDescriptor {
                key: "pro_plus".to_string(),
                label: "Pro+ Plan".to_string(),
                billing_cycle: "annual".to_string(),
                stripe_price_id: self.pro_plus_annual_price_id.clone(),
            },
            PlanDescriptor {
                key: "premium".to_string(),
                label: "Premium Plan".to_string(),
                billing_cycle: "monthly".to_string(),
                stripe_price_id: self.premium_monthly_price_id.clone(),
            },
            PlanDescriptor {
                key: "premium".to_string(),
                label: "Premium Plan".to_string(),
                billing_cycle: "annual".to_string(),
                stripe_price_id: self.premium_annual_price_id.clone(),
            },
        ]
    }

    fn normalize_plan(plan: &str) -> Option<String> {
        let p = plan.trim().to_lowercase();
        match p.as_str() {
            "pro" => Some("pro".to_string()),
            "pro+" | "pro_plus" | "pro-plus" => Some("pro_plus".to_string()),
            "premium" => Some("premium".to_string()),
            _ => None,
        }
    }

    fn normalize_billing_cycle(cycle: Option<&str>) -> Option<String> {
        let normalized = cycle.unwrap_or("monthly").trim().to_lowercase();
        match normalized.as_str() {
            "monthly" | "month" => Some("monthly".to_string()),
            "annual" | "yearly" | "year" => Some("annual".to_string()),
            _ => None,
        }
    }

    fn price_id_for_plan(&self, plan: &str, billing_cycle: &str) -> Option<String> {
        match (plan, billing_cycle) {
            ("pro", "monthly") => Some(self.pro_monthly_price_id.clone()),
            ("pro", "annual") => Some(self.pro_annual_price_id.clone()),
            ("pro_plus", "monthly") => Some(self.pro_plus_monthly_price_id.clone()),
            ("pro_plus", "annual") => Some(self.pro_plus_annual_price_id.clone()),
            ("premium", "monthly") => Some(self.premium_monthly_price_id.clone()),
            ("premium", "annual") => Some(self.premium_annual_price_id.clone()),
            _ => None,
        }
    }

    fn plan_and_cycle_for_price_id(&self, price_id: &str) -> Option<(String, String)> {
        if price_id == self.pro_monthly_price_id {
            return Some(("pro".to_string(), "monthly".to_string()));
        }
        if price_id == self.pro_annual_price_id {
            return Some(("pro".to_string(), "annual".to_string()));
        }
        if price_id == self.pro_plus_monthly_price_id {
            return Some(("pro_plus".to_string(), "monthly".to_string()));
        }
        if price_id == self.pro_plus_annual_price_id {
            return Some(("pro_plus".to_string(), "annual".to_string()));
        }
        if price_id == self.premium_monthly_price_id {
            return Some(("premium".to_string(), "monthly".to_string()));
        }
        if price_id == self.premium_annual_price_id {
            return Some(("premium".to_string(), "annual".to_string()));
        }
        None
    }
}

fn stripe_client() -> Client {
    Client::new()
}

async fn stripe_post_form<T: for<'de> Deserialize<'de>>(
    client: &Client,
    secret_key: &str,
    path: &str,
    form: &HashMap<String, String>,
) -> Result<T, String> {
    client
        .post(format!("https://api.stripe.com{path}"))
        .bearer_auth(secret_key)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(form)
        .send()
        .await
        .map_err(|e| format!("Stripe request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Stripe returned error status: {e}"))?
        .json::<T>()
        .await
        .map_err(|e| format!("Failed to decode Stripe response: {e}"))
}

async fn stripe_get_json(client: &Client, secret_key: &str, path: &str) -> Result<Value, String> {
    client
        .get(format!("https://api.stripe.com{path}"))
        .bearer_auth(secret_key)
        .send()
        .await
        .map_err(|e| format!("Stripe request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Stripe returned error status: {e}"))?
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to decode Stripe response: {e}"))
}

fn parse_subscription_snapshot(object: &Value) -> StripeSubscriptionSnapshot {
    let price_id = object
        .get("items")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.get("price"))
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    StripeSubscriptionSnapshot {
        status: object
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("inactive")
            .to_string(),
        current_period_end: object.get("current_period_end").and_then(|v| v.as_i64()),
        cancel_at_period_end: object
            .get("cancel_at_period_end")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        customer_id: object
            .get("customer")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        price_id,
    }
}

async fn fetch_subscription_snapshot(
    client: &Client,
    secret_key: &str,
    subscription_id: &str,
) -> Result<StripeSubscriptionSnapshot, String> {
    let path = format!("/v1/subscriptions/{subscription_id}");
    let json = stripe_get_json(client, secret_key, &path).await?;
    Ok(parse_subscription_snapshot(&json))
}

fn parse_webhook_signature(signature_header: &str) -> Option<(i64, String)> {
    let mut timestamp: Option<i64> = None;
    let mut v1: Option<String> = None;

    for segment in signature_header.split(',') {
        let mut parts = segment.splitn(2, '=');
        let key = parts.next()?.trim();
        let value = parts.next()?.trim();
        match key {
            "t" => timestamp = value.parse::<i64>().ok(),
            "v1" => v1 = Some(value.to_string()),
            _ => {}
        }
    }

    match (timestamp, v1) {
        (Some(t), Some(sig)) => Some((t, sig)),
        _ => None,
    }
}

fn verify_webhook_signature(payload: &str, signature_header: &str, webhook_secret: &str) -> bool {
    let (timestamp, sent_signature) = match parse_webhook_signature(signature_header) {
        Some(parts) => parts,
        None => return false,
    };

    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > WEBHOOK_TOLERANCE_SECONDS {
        return false;
    }

    let signed_payload = format!("{timestamp}.{payload}");
    let mut mac = match HmacSha256::new_from_slice(webhook_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    expected == sent_signature
}

pub struct SubscriptionService;

impl SubscriptionService {
    pub fn list_plans() -> Result<Vec<PlanDescriptor>, String> {
        Ok(StripeConfig::from_env()?.plans())
    }

    pub async fn get_subscription_status(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<UserSubscription>, String> {
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
        let cfg = StripeConfig::from_env()?;
        let normalized_plan = StripeConfig::normalize_plan(plan)
            .ok_or_else(|| "Invalid plan. Use pro, pro+, or premium.".to_string())?;
        let normalized_cycle = StripeConfig::normalize_billing_cycle(billing_cycle)
            .ok_or_else(|| "Invalid billing_cycle. Use monthly or annual.".to_string())?;
        let price_id = cfg
            .price_id_for_plan(&normalized_plan, &normalized_cycle)
            .ok_or_else(|| "Plan is missing Stripe price mapping.".to_string())?;

        if DashboardUserRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to validate user_id: {e}"))?
            .is_none()
        {
            return Err("Unknown user_id. Connect wallet first.".to_string());
        }

        let existing = SubscriptionRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to fetch existing subscription: {e}"))?;

        let client = stripe_client();

        let customer_id = match existing.as_ref().and_then(|s| s.stripe_customer_id.clone()) {
            Some(cid) => cid,
            None => {
                let mut form = HashMap::new();
                form.insert("metadata[user_id]".to_string(), user_id.to_string());
                let customer_json =
                    stripe_post_form::<Value>(&client, &cfg.secret_key, "/v1/customers", &form)
                        .await?;
                customer_json
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Stripe customer id missing in response".to_string())?
            }
        };

        let mut form = HashMap::new();
        form.insert("mode".to_string(), "subscription".to_string());
        form.insert("customer".to_string(), customer_id.clone());
        form.insert(
            "success_url".to_string(),
            success_url.unwrap_or(&cfg.success_url).to_string(),
        );
        form.insert(
            "cancel_url".to_string(),
            cancel_url.unwrap_or(&cfg.cancel_url).to_string(),
        );
        form.insert("line_items[0][price]".to_string(), price_id.clone());
        form.insert("line_items[0][quantity]".to_string(), "1".to_string());
        form.insert("allow_promotion_codes".to_string(), "true".to_string());
        form.insert("metadata[user_id]".to_string(), user_id.to_string());
        form.insert("metadata[plan]".to_string(), normalized_plan.clone());
        form.insert(
            "metadata[billing_cycle]".to_string(),
            normalized_cycle.clone(),
        );
        form.insert(
            "subscription_data[metadata][user_id]".to_string(),
            user_id.to_string(),
        );
        form.insert(
            "subscription_data[metadata][plan]".to_string(),
            normalized_plan.clone(),
        );
        form.insert(
            "subscription_data[metadata][billing_cycle]".to_string(),
            normalized_cycle.clone(),
        );

        let checkout = stripe_post_form::<StripeCheckoutSession>(
            &client,
            &cfg.secret_key,
            "/v1/checkout/sessions",
            &form,
        )
        .await?;

        SubscriptionRepository::upsert(
            pool,
            UpsertSubscriptionInput {
                user_id,
                plan: &normalized_plan,
                billing_cycle: &normalized_cycle,
                status: "checkout_pending",
                stripe_customer_id: Some(&customer_id),
                stripe_subscription_id: None,
                stripe_price_id: Some(&price_id),
                checkout_session_id: Some(&checkout.id),
                current_period_end_unix: None,
                cancel_at_period_end: false,
            },
        )
        .await
        .map_err(|e| format!("Failed to save pending checkout: {e}"))?;

        checkout
            .url
            .ok_or_else(|| "Stripe did not return checkout URL.".to_string())
    }

    pub async fn create_billing_portal_session(
        pool: &DbPool,
        user_id: &str,
        return_url: Option<&str>,
    ) -> Result<String, String> {
        let cfg = StripeConfig::from_env()?;
        if DashboardUserRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to validate user_id: {e}"))?
            .is_none()
        {
            return Err("Unknown user_id. Connect wallet first.".to_string());
        }

        let existing = SubscriptionRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to fetch subscription: {e}"))?
            .ok_or_else(|| "No subscription/customer found for this user.".to_string())?;

        let customer_id = existing
            .stripe_customer_id
            .ok_or_else(|| "No Stripe customer found for this user.".to_string())?;

        let mut form = HashMap::new();
        form.insert("customer".to_string(), customer_id);
        form.insert(
            "return_url".to_string(),
            return_url.unwrap_or(&cfg.portal_return_url).to_string(),
        );

        let session = stripe_post_form::<StripePortalSession>(
            &stripe_client(),
            &cfg.secret_key,
            "/v1/billing_portal/sessions",
            &form,
        )
        .await?;
        Ok(session.url)
    }

    pub async fn process_webhook(
        pool: &DbPool,
        signature_header: &str,
        payload: &str,
    ) -> Result<(), String> {
        let cfg = StripeConfig::from_env()?;
        if !verify_webhook_signature(payload, signature_header, &cfg.webhook_secret) {
            return Err("Invalid Stripe webhook signature".to_string());
        }

        let event: Value =
            serde_json::from_str(payload).map_err(|e| format!("Invalid webhook payload: {e}"))?;
        let event_type = event
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Stripe event type is missing".to_string())?;
        let object = event
            .get("data")
            .and_then(|v| v.get("object"))
            .ok_or_else(|| "Stripe event object missing".to_string())?;

        match event_type {
            "checkout.session.completed" => {
                let mut customer_id = object
                    .get("customer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let subscription_id = object
                    .get("subscription")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let metadata_user_id = object
                    .get("metadata")
                    .and_then(|v| v.get("user_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let metadata_plan = object
                    .get("metadata")
                    .and_then(|v| v.get("plan"))
                    .and_then(|v| v.as_str())
                    .and_then(StripeConfig::normalize_plan);
                let metadata_billing_cycle = object
                    .get("metadata")
                    .and_then(|v| v.get("billing_cycle"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| StripeConfig::normalize_billing_cycle(Some(s)));

                let user_id = match metadata_user_id {
                    Some(uid) => uid,
                    None => {
                        if let Some(cid) = customer_id.as_deref() {
                            if let Some(existing) =
                                SubscriptionRepository::get_by_customer_id(pool, cid)
                                    .await
                                    .map_err(|e| {
                                        format!("Failed to resolve customer subscription: {e}")
                                    })?
                            {
                                existing.user_id
                            } else {
                                return Ok(());
                            }
                        } else {
                            return Ok(());
                        }
                    }
                };

                let mut status = "active".to_string();
                let mut current_period_end_unix: Option<i64> = None;
                let mut cancel_at_period_end = false;
                let mut price_id: Option<String> = None;

                if let Some(sub_id) = subscription_id.as_deref() {
                    let snap =
                        fetch_subscription_snapshot(&stripe_client(), &cfg.secret_key, sub_id)
                            .await?;
                    status = snap.status;
                    current_period_end_unix = snap.current_period_end;
                    cancel_at_period_end = snap.cancel_at_period_end;
                    if customer_id.is_none() {
                        customer_id = snap.customer_id;
                    }
                    price_id = snap.price_id;
                }

                let mut derived_plan = metadata_plan;
                let mut derived_billing_cycle = metadata_billing_cycle;
                if (derived_plan.is_none() || derived_billing_cycle.is_none()) && price_id.is_some() {
                    if let Some((p, cycle)) = cfg
                        .plan_and_cycle_for_price_id(price_id.as_deref().unwrap_or_default())
                    {
                        if derived_plan.is_none() {
                            derived_plan = Some(p);
                        }
                        if derived_billing_cycle.is_none() {
                            derived_billing_cycle = Some(cycle);
                        }
                    }
                }
                let derived_plan = derived_plan.unwrap_or_else(|| "pro".to_string());
                let derived_billing_cycle =
                    derived_billing_cycle.unwrap_or_else(|| "monthly".to_string());

                SubscriptionRepository::upsert(
                    pool,
                    UpsertSubscriptionInput {
                        user_id: &user_id,
                        plan: &derived_plan,
                        billing_cycle: &derived_billing_cycle,
                        status: &status,
                        stripe_customer_id: customer_id.as_deref(),
                        stripe_subscription_id: subscription_id.as_deref(),
                        stripe_price_id: price_id.as_deref(),
                        checkout_session_id: object.get("id").and_then(|v| v.as_str()),
                        current_period_end_unix,
                        cancel_at_period_end,
                    },
                )
                .await
                .map_err(|e| format!("Failed to persist checkout webhook update: {e}"))?;
            }
            "customer.subscription.created"
            | "customer.subscription.updated"
            | "customer.subscription.deleted" => {
                let subscription_id = object
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "subscription id missing".to_string())?;
                let customer_id = object
                    .get("customer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let status = object
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("inactive");
                let current_period_end = object.get("current_period_end").and_then(|v| v.as_i64());
                let cancel_at_period_end = object
                    .get("cancel_at_period_end")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let price_id = object
                    .get("items")
                    .and_then(|v| v.get("data"))
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.get("price"))
                    .and_then(|v| v.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let mut user_id = object
                    .get("metadata")
                    .and_then(|v| v.get("user_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if user_id.is_none() {
                    if let Some(cid) = customer_id.as_deref() {
                        user_id = SubscriptionRepository::get_by_customer_id(pool, cid)
                            .await
                            .map_err(|e| format!("Failed to resolve customer subscription: {e}"))?
                            .map(|row| row.user_id);
                    }
                }
                if user_id.is_none() {
                    user_id = SubscriptionRepository::get_by_subscription_id(pool, subscription_id)
                        .await
                        .map_err(|e| format!("Failed to resolve subscription by id: {e}"))?
                        .map(|row| row.user_id);
                }

                let Some(user_id) = user_id else {
                    return Ok(());
                };

                let mut plan = object
                    .get("metadata")
                    .and_then(|v| v.get("plan"))
                    .and_then(|v| v.as_str())
                    .and_then(StripeConfig::normalize_plan);
                let mut billing_cycle = object
                    .get("metadata")
                    .and_then(|v| v.get("billing_cycle"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| StripeConfig::normalize_billing_cycle(Some(s)));
                if (plan.is_none() || billing_cycle.is_none()) && price_id.is_some() {
                    if let Some((p, cycle)) = cfg
                        .plan_and_cycle_for_price_id(price_id.as_deref().unwrap_or_default())
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
                let plan = plan.unwrap_or_else(|| "free".to_string());
                let billing_cycle = billing_cycle.unwrap_or_else(|| "monthly".to_string());

                SubscriptionRepository::upsert(
                    pool,
                    UpsertSubscriptionInput {
                        user_id: &user_id,
                        plan: &plan,
                        billing_cycle: &billing_cycle,
                        status,
                        stripe_customer_id: customer_id.as_deref(),
                        stripe_subscription_id: Some(subscription_id),
                        stripe_price_id: price_id.as_deref(),
                        checkout_session_id: None,
                        current_period_end_unix: current_period_end,
                        cancel_at_period_end,
                    },
                )
                .await
                .map_err(|e| format!("Failed to persist subscription webhook update: {e}"))?;
            }
            _ => {}
        }

        Ok(())
    }
}
