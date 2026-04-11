use crate::db::DbPool;
use crate::models::onchain_payment::{OnchainWebhookRequest, SubscriptionChargeAttempt};
use crate::repositories::onchain_payment_repository::{
    InsertEventLogInput, OnchainPaymentRepository, UpsertPaymentProfileInput,
};
use crate::repositories::subscription_repository::SubscriptionRepository;
use crate::services::subscription_charge_service::{
    RelayerSubmissionResult, SubscriptionChargeService,
};
use chrono::Utc;
use reqwest::Client;
use serde_json::json;
use uuid::Uuid;

pub struct OnchainPaymentWebhookService;

impl OnchainPaymentWebhookService {
    pub fn is_onchain_enabled() -> bool {
        std::env::var("PAYMENTS_ONCHAIN_ENABLED")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    }

    pub fn is_shadow_mode() -> bool {
        std::env::var("PAYMENTS_ONCHAIN_SHADOW_MODE")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(true)
    }

    pub fn verify_webhook_token(
        expected_env_var: &str,
        provided: Option<&str>,
    ) -> Result<(), String> {
        let expected = std::env::var(expected_env_var)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{expected_env_var} must be configured"))?;
        let provided = provided.unwrap_or("").trim();
        if provided.is_empty() || provided != expected {
            return Err("Invalid webhook token".to_string());
        }
        Ok(())
    }

    pub async fn upsert_payment_profile(
        pool: &DbPool,
        user_id: &str,
        payer_address: &str,
        chain_id: i32,
        token_contract: &str,
        payment_contract: &str,
        max_charge_usdc: Option<f64>,
    ) -> Result<(), String> {
        SubscriptionChargeService::validate_base_only_chain(chain_id)?;
        if SubscriptionRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to validate user subscription row: {e}"))?
            .is_none()
        {
            return Err("Subscription row not found for user_id".to_string());
        }
        OnchainPaymentRepository::upsert_profile(
            pool,
            UpsertPaymentProfileInput {
                user_id,
                payer_address,
                chain_id,
                token_contract,
                payment_contract,
                max_charge_usdc,
            },
        )
        .await
        .map_err(|e| format!("Failed to upsert payment profile: {e}"))?;
        Ok(())
    }

    pub async fn process_contract_event(
        pool: &DbPool,
        provider: &str,
        req: &OnchainWebhookRequest,
    ) -> Result<(), String> {
        let chain_id = req.chain_id.unwrap_or(8453);
        SubscriptionChargeService::validate_base_only_chain(chain_id)?;
        let payload = req.payload.clone().unwrap_or_else(|| json!({}));
        if let Some(existing) =
            OnchainPaymentRepository::get_event_log_by_provider_event(pool, provider, &req.event_id)
                .await
                .map_err(|e| format!("Failed to check existing event: {e}"))?
        {
            if existing.processing_status == "processed" {
                return Ok(());
            }
        }

        OnchainPaymentRepository::insert_event_log(
            pool,
            InsertEventLogInput {
                provider,
                event_id: &req.event_id,
                event_type: &req.event_type,
                chain_id,
                tx_hash: req.tx_hash.as_deref(),
                payload,
            },
        )
        .await
        .map_err(|e| format!("Failed to persist event log: {e}"))?;

        let handle_result = async {
            match req.event_type.as_str() {
                "charge_submitted" => Self::handle_charge_submitted(pool, req).await,
                "charge_pending_confirmation" => {
                    Self::handle_charge_pending_confirmation(pool, req).await
                }
                "charge_confirmed" => Self::handle_charge_confirmed(pool, req).await,
                "charge_failed" => Self::handle_charge_failed(pool, req).await,
                "allowance_updated" => Self::handle_allowance_updated(pool, req).await,
                _ => Ok(()),
            }
        }
        .await;

        match handle_result {
            Ok(()) => {
                OnchainPaymentRepository::mark_event_processed(pool, provider, &req.event_id)
                    .await
                    .map_err(|e| format!("Failed to mark event processed: {e}"))?;
                Ok(())
            }
            Err(error) => {
                OnchainPaymentRepository::mark_event_failed(pool, provider, &req.event_id, &error)
                    .await
                    .map_err(|e| format!("Failed to mark event failed: {e}"))?;
                Err(error)
            }
        }
    }

    async fn handle_charge_submitted(
        pool: &DbPool,
        req: &OnchainWebhookRequest,
    ) -> Result<(), String> {
        let attempt_id = req
            .charge_attempt_id
            .ok_or_else(|| "charge_attempt_id is required for charge_submitted".to_string())?;
        let tx_hash = req
            .tx_hash
            .as_deref()
            .ok_or_else(|| "tx_hash is required for charge_submitted".to_string())?;
        SubscriptionChargeService::mark_attempt_submitted(pool, attempt_id, tx_hash).await?;
        Ok(())
    }

    async fn handle_charge_pending_confirmation(
        pool: &DbPool,
        req: &OnchainWebhookRequest,
    ) -> Result<(), String> {
        let attempt_id = req.charge_attempt_id.ok_or_else(|| {
            "charge_attempt_id is required for charge_pending_confirmation".to_string()
        })?;
        SubscriptionChargeService::mark_attempt_pending_confirmation(pool, attempt_id).await?;
        Ok(())
    }

    async fn handle_charge_confirmed(
        pool: &DbPool,
        req: &OnchainWebhookRequest,
    ) -> Result<(), String> {
        let attempt_id = if let Some(id) = req.charge_attempt_id {
            id
        } else if let Some(tx_hash) = req.tx_hash.as_deref() {
            let chain_id = req.chain_id.unwrap_or(8453);
            OnchainPaymentRepository::get_charge_attempt_by_tx_hash(pool, chain_id, tx_hash)
                .await
                .map_err(|e| format!("Failed to resolve attempt from tx hash: {e}"))?
                .map(|a| a.id)
                .ok_or_else(|| "Charge attempt not found for tx hash".to_string())?
        } else {
            return Err(
                "charge_attempt_id or tx_hash is required for charge_confirmed".to_string(),
            );
        };

        let attempt = SubscriptionChargeService::mark_attempt_confirmed(pool, attempt_id).await?;
        let cycle_id = Self::resolve_cycle_for_attempt(pool, &attempt).await?;
        SubscriptionChargeService::apply_confirmed_charge_to_subscription(
            pool, cycle_id, attempt.id,
        )
        .await?;
        Ok(())
    }

    async fn handle_charge_failed(
        pool: &DbPool,
        req: &OnchainWebhookRequest,
    ) -> Result<(), String> {
        let attempt_id = if let Some(id) = req.charge_attempt_id {
            id
        } else if let Some(tx_hash) = req.tx_hash.as_deref() {
            let chain_id = req.chain_id.unwrap_or(8453);
            OnchainPaymentRepository::get_charge_attempt_by_tx_hash(pool, chain_id, tx_hash)
                .await
                .map_err(|e| format!("Failed to resolve attempt from tx hash: {e}"))?
                .map(|a| a.id)
                .ok_or_else(|| "Charge attempt not found for tx hash".to_string())?
        } else {
            return Err("charge_attempt_id or tx_hash is required for charge_failed".to_string());
        };

        let attempt = SubscriptionChargeService::mark_attempt_failed(
            pool,
            attempt_id,
            req.failure_code.as_deref(),
            req.failure_reason.as_deref(),
        )
        .await?;
        let cycle_id = Self::resolve_cycle_for_attempt(pool, &attempt).await?;
        SubscriptionChargeService::apply_failed_charge_to_cycle(pool, cycle_id, attempt.id).await?;
        Ok(())
    }

    async fn handle_allowance_updated(
        pool: &DbPool,
        req: &OnchainWebhookRequest,
    ) -> Result<(), String> {
        let user_id = req
            .user_id
            .as_deref()
            .ok_or_else(|| "user_id is required for allowance_updated".to_string())?;
        let status = req.allowance_status.as_deref().unwrap_or("active");
        OnchainPaymentRepository::update_allowance_status(pool, user_id, status)
            .await
            .map_err(|e| format!("Failed to update allowance status: {e}"))?;
        Ok(())
    }

    async fn resolve_cycle_for_attempt(
        pool: &DbPool,
        attempt: &SubscriptionChargeAttempt,
    ) -> Result<Uuid, String> {
        if let Some(cycle) =
            OnchainPaymentRepository::get_subscription_cycle_by_charge_attempt_id(pool, attempt.id)
                .await
                .map_err(|e| format!("Failed to resolve cycle from charge_attempt_id: {e}"))?
        {
            return Ok(cycle.id);
        }
        let cycles = OnchainPaymentRepository::get_due_cycles(pool, Utc::now(), 500)
            .await
            .map_err(|e| format!("Failed to fetch due cycles: {e}"))?;
        cycles
            .into_iter()
            .find(|c| c.subscription_id == attempt.subscription_id && c.user_id == attempt.user_id)
            .map(|c| c.id)
            .ok_or_else(|| "No matching subscription cycle found for charge attempt".to_string())
    }

    pub async fn trigger_due_charge_job(pool: &DbPool, limit: i64) -> Result<Vec<Uuid>, String> {
        let due_cycles = OnchainPaymentRepository::get_due_cycles(pool, Utc::now(), limit)
            .await
            .map_err(|e| format!("Failed to fetch due cycles: {e}"))?;
        let mut submitted_attempts = Vec::new();

        for cycle in due_cycles {
            if !SubscriptionChargeService::can_transition_cycle(&cycle.status, "charging") {
                continue;
            }

            let attempt = SubscriptionChargeService::create_attempt_for_cycle(pool, &cycle).await?;
            OnchainPaymentRepository::update_subscription_cycle_status(
                pool,
                cycle.id,
                "charging",
                Some(attempt.id),
            )
            .await
            .map_err(|e| format!("Failed to set cycle charging: {e}"))?;

            if Self::is_shadow_mode() {
                submitted_attempts.push(attempt.id);
                continue;
            }

            let submission = Self::submit_charge_to_relayer(&attempt).await?;
            SubscriptionChargeService::mark_attempt_submitted(
                pool,
                attempt.id,
                &submission.tx_hash,
            )
            .await?;
            submitted_attempts.push(attempt.id);
        }

        Ok(submitted_attempts)
    }

    pub async fn handle_grace_expiry_job(pool: &DbPool, limit: i64) -> Result<usize, String> {
        let due_cycles = OnchainPaymentRepository::get_due_cycles(pool, Utc::now(), limit)
            .await
            .map_err(|e| format!("Failed to fetch due cycles for grace expiry: {e}"))?;
        let mut cancelled = 0usize;
        for cycle in due_cycles {
            if cycle.status != "grace" {
                continue;
            }
            if cycle
                .grace_expires_at
                .map(|ts| ts <= Utc::now())
                .unwrap_or(false)
            {
                OnchainPaymentRepository::update_subscription_cycle_status(
                    pool,
                    cycle.id,
                    "cancelled",
                    None,
                )
                .await
                .map_err(|e| format!("Failed to cancel grace-expired cycle: {e}"))?;
                cancelled += 1;
            }
        }
        Ok(cancelled)
    }

    async fn submit_charge_to_relayer(
        attempt: &SubscriptionChargeAttempt,
    ) -> Result<RelayerSubmissionResult, String> {
        let relayer_url = std::env::var("ONCHAIN_RELAYER_URL")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "ONCHAIN_RELAYER_URL must be configured".to_string())?;
        let relayer_api_key = std::env::var("ONCHAIN_RELAYER_API_KEY")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "ONCHAIN_RELAYER_API_KEY must be configured".to_string())?;

        let client = Client::new();
        let response = client
            .post(format!("{relayer_url}/charge"))
            .bearer_auth(relayer_api_key)
            .json(&json!({
                "idempotency_key": attempt.idempotency_key,
                "user_id": attempt.user_id,
                "subscription_id": attempt.subscription_id,
                "amount_usdc": attempt.amount_usdc,
                "chain_id": attempt.chain_id,
            }))
            .send()
            .await
            .map_err(|e| format!("Relayer request failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("Relayer returned error status: {e}"))?;

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to decode relayer response: {e}"))?;
        let tx_hash = payload
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Relayer response missing tx_hash".to_string())?
            .to_string();
        Ok(RelayerSubmissionResult { tx_hash })
    }
}
