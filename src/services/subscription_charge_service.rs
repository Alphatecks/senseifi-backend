use crate::db::DbPool;
use crate::models::onchain_payment::{SubscriptionChargeAttempt, SubscriptionCycle};
use crate::repositories::onchain_payment_repository::{
    CreateChargeAttemptInput, OnchainPaymentRepository, UpdateChargeAttemptOutcomeInput,
};
use crate::repositories::subscription_repository::{
    SubscriptionRepository, UpsertSubscriptionInput,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

pub struct SubscriptionChargeService;

#[derive(Debug, Clone)]
pub struct RelayerSubmissionResult {
    pub tx_hash: String,
}

impl SubscriptionChargeService {
    pub fn can_transition_attempt(from: &str, to: &str) -> bool {
        match from {
            "created" => matches!(to, "submitted" | "failed" | "cancelled"),
            "submitted" => matches!(to, "pending_confirmation" | "failed"),
            "pending_confirmation" => matches!(to, "confirmed" | "failed"),
            "confirmed" | "failed" | "cancelled" => false,
            _ => false,
        }
    }

    pub fn can_transition_cycle(from: &str, to: &str) -> bool {
        match from {
            "scheduled" => matches!(to, "charging" | "cancelled"),
            "charging" => matches!(to, "paid" | "grace" | "failed"),
            "failed" => matches!(to, "charging" | "grace" | "cancelled"),
            "grace" => matches!(to, "charging" | "paid" | "cancelled"),
            "paid" | "cancelled" => false,
            _ => false,
        }
    }

    pub fn validate_base_only_chain(chain_id: i32) -> Result<(), String> {
        let expected = crate::models::wallet::onchain_billing_chain_id();
        if chain_id != expected {
            return Err(format!(
                "Only Base chain_id={expected} is supported for onchain billing"
            ));
        }
        Ok(())
    }

    pub fn configured_onchain_chain_id() -> i32 {
        crate::models::wallet::onchain_billing_chain_id()
    }

    pub fn build_idempotency_key(
        subscription_id: Uuid,
        period_start: chrono::DateTime<Utc>,
        period_end: chrono::DateTime<Utc>,
    ) -> String {
        format!(
            "{subscription_id}:{}:{}",
            period_start.timestamp(),
            period_end.timestamp()
        )
    }

    pub async fn create_attempt_for_cycle(
        pool: &DbPool,
        cycle: &SubscriptionCycle,
    ) -> Result<SubscriptionChargeAttempt, String> {
        let chain_id = Self::configured_onchain_chain_id();
        Self::validate_base_only_chain(chain_id)?;
        let period_end = cycle.due_at
            + if cycle.billing_cycle == "annual" {
                Duration::days(365)
            } else {
                Duration::days(30)
            };
        let key = Self::build_idempotency_key(cycle.subscription_id, cycle.due_at, period_end);
        let attempt = OnchainPaymentRepository::create_charge_attempt(
            pool,
            CreateChargeAttemptInput {
                user_id: &cycle.user_id,
                subscription_id: cycle.subscription_id,
                chain_id,
                period_start: cycle.due_at,
                period_end,
                amount_usdc: cycle.amount_due_usdc,
                idempotency_key: &key,
            },
        )
        .await
        .map_err(|e| format!("Failed to create charge attempt: {e}"))?;
        Ok(attempt)
    }

    pub async fn mark_attempt_submitted(
        pool: &DbPool,
        attempt_id: Uuid,
        tx_hash: &str,
    ) -> Result<SubscriptionChargeAttempt, String> {
        let current = OnchainPaymentRepository::get_charge_attempt_by_id(pool, attempt_id)
            .await
            .map_err(|e| format!("Failed to fetch charge attempt: {e}"))?
            .ok_or_else(|| "Charge attempt not found".to_string())?;
        if !Self::can_transition_attempt(&current.status, "submitted") {
            return Err(format!(
                "Invalid charge attempt transition {} -> submitted",
                current.status
            ));
        }
        OnchainPaymentRepository::update_charge_attempt_outcome(
            pool,
            attempt_id,
            UpdateChargeAttemptOutcomeInput {
                status: "submitted",
                tx_hash: Some(tx_hash),
                failure_code: None,
                failure_reason: None,
            },
        )
        .await
        .map_err(|e| format!("Failed to update charge attempt: {e}"))?
        .ok_or_else(|| "Charge attempt not found after submit update".to_string())
    }

    pub async fn mark_attempt_pending_confirmation(
        pool: &DbPool,
        attempt_id: Uuid,
    ) -> Result<SubscriptionChargeAttempt, String> {
        let current = OnchainPaymentRepository::get_charge_attempt_by_id(pool, attempt_id)
            .await
            .map_err(|e| format!("Failed to fetch charge attempt: {e}"))?
            .ok_or_else(|| "Charge attempt not found".to_string())?;
        if !Self::can_transition_attempt(&current.status, "pending_confirmation") {
            return Err(format!(
                "Invalid charge attempt transition {} -> pending_confirmation",
                current.status
            ));
        }
        OnchainPaymentRepository::update_charge_attempt_outcome(
            pool,
            attempt_id,
            UpdateChargeAttemptOutcomeInput {
                status: "pending_confirmation",
                tx_hash: None,
                failure_code: None,
                failure_reason: None,
            },
        )
        .await
        .map_err(|e| format!("Failed to update pending_confirmation: {e}"))?
        .ok_or_else(|| "Charge attempt not found after pending update".to_string())
    }

    pub async fn mark_attempt_confirmed(
        pool: &DbPool,
        attempt_id: Uuid,
    ) -> Result<SubscriptionChargeAttempt, String> {
        let current = OnchainPaymentRepository::get_charge_attempt_by_id(pool, attempt_id)
            .await
            .map_err(|e| format!("Failed to fetch charge attempt: {e}"))?
            .ok_or_else(|| "Charge attempt not found".to_string())?;
        if !Self::can_transition_attempt(&current.status, "confirmed") {
            return Err(format!(
                "Invalid charge attempt transition {} -> confirmed",
                current.status
            ));
        }
        OnchainPaymentRepository::update_charge_attempt_outcome(
            pool,
            attempt_id,
            UpdateChargeAttemptOutcomeInput {
                status: "confirmed",
                tx_hash: None,
                failure_code: None,
                failure_reason: None,
            },
        )
        .await
        .map_err(|e| format!("Failed to set attempt confirmed: {e}"))?
        .ok_or_else(|| "Charge attempt not found after confirm update".to_string())
    }

    pub async fn mark_attempt_failed(
        pool: &DbPool,
        attempt_id: Uuid,
        failure_code: Option<&str>,
        failure_reason: Option<&str>,
    ) -> Result<SubscriptionChargeAttempt, String> {
        let current = OnchainPaymentRepository::get_charge_attempt_by_id(pool, attempt_id)
            .await
            .map_err(|e| format!("Failed to fetch charge attempt: {e}"))?
            .ok_or_else(|| "Charge attempt not found".to_string())?;
        if !Self::can_transition_attempt(&current.status, "failed") {
            return Err(format!(
                "Invalid charge attempt transition {} -> failed",
                current.status
            ));
        }
        OnchainPaymentRepository::update_charge_attempt_outcome(
            pool,
            attempt_id,
            UpdateChargeAttemptOutcomeInput {
                status: "failed",
                tx_hash: None,
                failure_code,
                failure_reason,
            },
        )
        .await
        .map_err(|e| format!("Failed to set attempt failed: {e}"))?
        .ok_or_else(|| "Charge attempt not found after failure update".to_string())
    }

    pub async fn apply_confirmed_charge_to_subscription(
        pool: &DbPool,
        cycle_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<(), String> {
        let cycle = OnchainPaymentRepository::get_subscription_cycle_by_id(pool, cycle_id)
            .await
            .map_err(|e| format!("Failed to fetch subscription cycle: {e}"))?
            .ok_or_else(|| "Subscription cycle not found".to_string())?;
        if !Self::can_transition_cycle(&cycle.status, "paid") {
            return Err(format!(
                "Invalid subscription cycle transition {} -> paid",
                cycle.status
            ));
        }
        OnchainPaymentRepository::update_subscription_cycle_status(
            pool,
            cycle.id,
            "paid",
            Some(attempt_id),
        )
        .await
        .map_err(|e| format!("Failed to mark cycle paid: {e}"))?;

        let subscription = SubscriptionRepository::get_by_id(pool, cycle.subscription_id)
            .await
            .map_err(|e| format!("Failed to fetch subscription row: {e}"))?
            .ok_or_else(|| "Subscription row not found".to_string())?;
        let next_period_end = if cycle.billing_cycle == "annual" {
            cycle.due_at + Duration::days(365)
        } else {
            cycle.due_at + Duration::days(30)
        };
        SubscriptionRepository::upsert(
            pool,
            UpsertSubscriptionInput {
                user_id: &cycle.user_id,
                plan: &subscription.plan,
                billing_cycle: &subscription.billing_cycle,
                status: "active",
                stripe_customer_id: subscription.stripe_customer_id.as_deref(),
                stripe_subscription_id: subscription.stripe_subscription_id.as_deref(),
                stripe_price_id: subscription.stripe_price_id.as_deref(),
                checkout_session_id: subscription.checkout_session_id.as_deref(),
                current_period_end_unix: Some(next_period_end.timestamp()),
                cancel_at_period_end: false,
            },
        )
        .await
        .map_err(|e| format!("Failed to update subscription status: {e}"))?;
        Ok(())
    }

    pub async fn apply_failed_charge_to_cycle(
        pool: &DbPool,
        cycle_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<(), String> {
        let cycle = OnchainPaymentRepository::get_subscription_cycle_by_id(pool, cycle_id)
            .await
            .map_err(|e| format!("Failed to fetch subscription cycle: {e}"))?
            .ok_or_else(|| "Subscription cycle not found".to_string())?;
        if !Self::can_transition_cycle(&cycle.status, "grace") {
            return Err(format!(
                "Invalid subscription cycle transition {} -> grace",
                cycle.status
            ));
        }
        OnchainPaymentRepository::update_subscription_cycle_status(
            pool,
            cycle.id,
            "grace",
            Some(attempt_id),
        )
        .await
        .map_err(|e| format!("Failed to mark cycle grace: {e}"))?;
        SubscriptionRepository::upsert(
            pool,
            UpsertSubscriptionInput {
                user_id: &cycle.user_id,
                plan: &cycle.plan,
                billing_cycle: &cycle.billing_cycle,
                status: "grace",
                stripe_customer_id: None,
                stripe_subscription_id: None,
                stripe_price_id: None,
                checkout_session_id: None,
                current_period_end_unix: None,
                cancel_at_period_end: false,
            },
        )
        .await
        .map_err(|e| format!("Failed to set subscription grace status: {e}"))?;
        Ok(())
    }
}
