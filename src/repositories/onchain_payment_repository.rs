use crate::db::DbPool;
use crate::models::onchain_payment::{
    OnchainEventLog, OnchainPaymentProfile, SubscriptionChargeAttempt, SubscriptionCycle,
};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::Error;
use uuid::Uuid;

pub struct OnchainPaymentRepository;

pub struct UpsertPaymentProfileInput<'a> {
    pub user_id: &'a str,
    pub payer_address: &'a str,
    pub chain_id: i32,
    pub token_contract: &'a str,
    pub payment_contract: &'a str,
    pub max_charge_usdc: Option<Decimal>,
}

pub struct CreateSubscriptionCycleInput<'a> {
    pub user_id: &'a str,
    pub subscription_id: Uuid,
    pub plan: &'a str,
    pub billing_cycle: &'a str,
    pub amount_due_usdc: Decimal,
    pub due_at: DateTime<Utc>,
    pub grace_expires_at: Option<DateTime<Utc>>,
}

pub struct CreateChargeAttemptInput<'a> {
    pub user_id: &'a str,
    pub subscription_id: Uuid,
    pub chain_id: i32,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub amount_usdc: Decimal,
    pub idempotency_key: &'a str,
}

pub struct InsertEventLogInput<'a> {
    pub provider: &'a str,
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub chain_id: i32,
    pub tx_hash: Option<&'a str>,
    pub payload: Value,
}

pub struct UpdateChargeAttemptOutcomeInput<'a> {
    pub status: &'a str,
    pub tx_hash: Option<&'a str>,
    pub failure_code: Option<&'a str>,
    pub failure_reason: Option<&'a str>,
}

impl OnchainPaymentRepository {
    pub async fn get_event_log_by_provider_event(
        pool: &DbPool,
        provider: &str,
        event_id: &str,
    ) -> Result<Option<OnchainEventLog>, Error> {
        sqlx::query_as::<_, OnchainEventLog>(
            "SELECT * FROM onchain_event_log WHERE provider = $1 AND event_id = $2",
        )
        .bind(provider)
        .bind(event_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_profile_by_user_id(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<OnchainPaymentProfile>, Error> {
        sqlx::query_as::<_, OnchainPaymentProfile>(
            "SELECT * FROM onchain_payment_profiles WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn upsert_profile(
        pool: &DbPool,
        input: UpsertPaymentProfileInput<'_>,
    ) -> Result<OnchainPaymentProfile, Error> {
        sqlx::query_as::<_, OnchainPaymentProfile>(
            r#"
            INSERT INTO onchain_payment_profiles (
                user_id,
                payer_address,
                chain_id,
                token_contract,
                payment_contract,
                allowance_status,
                max_charge_usdc,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, 'active', $6, NOW(), NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                payer_address = EXCLUDED.payer_address,
                chain_id = EXCLUDED.chain_id,
                token_contract = EXCLUDED.token_contract,
                payment_contract = EXCLUDED.payment_contract,
                allowance_status = 'active',
                max_charge_usdc = EXCLUDED.max_charge_usdc,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(input.user_id)
        .bind(input.payer_address)
        .bind(input.chain_id)
        .bind(input.token_contract)
        .bind(input.payment_contract)
        .bind(input.max_charge_usdc)
        .fetch_one(pool)
        .await
    }

    pub async fn update_allowance_status(
        pool: &DbPool,
        user_id: &str,
        allowance_status: &str,
    ) -> Result<Option<OnchainPaymentProfile>, Error> {
        sqlx::query_as::<_, OnchainPaymentProfile>(
            r#"
            UPDATE onchain_payment_profiles
            SET allowance_status = $2, updated_at = NOW()
            WHERE user_id = $1
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(allowance_status)
        .fetch_optional(pool)
        .await
    }

    pub async fn create_subscription_cycle(
        pool: &DbPool,
        input: CreateSubscriptionCycleInput<'_>,
    ) -> Result<SubscriptionCycle, Error> {
        sqlx::query_as::<_, SubscriptionCycle>(
            r#"
            INSERT INTO subscription_cycles (
                user_id,
                subscription_id,
                plan,
                billing_cycle,
                amount_due_usdc,
                due_at,
                status,
                grace_expires_at,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, 'scheduled', $7, NOW(), NOW())
            RETURNING *
            "#,
        )
        .bind(input.user_id)
        .bind(input.subscription_id)
        .bind(input.plan)
        .bind(input.billing_cycle)
        .bind(input.amount_due_usdc)
        .bind(input.due_at)
        .bind(input.grace_expires_at)
        .fetch_one(pool)
        .await
    }

    pub async fn get_subscription_cycle_by_id(
        pool: &DbPool,
        cycle_id: Uuid,
    ) -> Result<Option<SubscriptionCycle>, Error> {
        sqlx::query_as::<_, SubscriptionCycle>("SELECT * FROM subscription_cycles WHERE id = $1")
            .bind(cycle_id)
            .fetch_optional(pool)
            .await
    }

    pub async fn get_subscription_cycle_by_charge_attempt_id(
        pool: &DbPool,
        charge_attempt_id: Uuid,
    ) -> Result<Option<SubscriptionCycle>, Error> {
        sqlx::query_as::<_, SubscriptionCycle>(
            "SELECT * FROM subscription_cycles WHERE charge_attempt_id = $1",
        )
        .bind(charge_attempt_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_due_cycles(
        pool: &DbPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<SubscriptionCycle>, Error> {
        sqlx::query_as::<_, SubscriptionCycle>(
            r#"
            SELECT *
            FROM subscription_cycles
            WHERE status IN ('scheduled', 'failed', 'grace')
              AND due_at <= $1
            ORDER BY due_at ASC
            LIMIT $2
            "#,
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn update_subscription_cycle_status(
        pool: &DbPool,
        cycle_id: Uuid,
        status: &str,
        charge_attempt_id: Option<Uuid>,
    ) -> Result<Option<SubscriptionCycle>, Error> {
        sqlx::query_as::<_, SubscriptionCycle>(
            r#"
            UPDATE subscription_cycles
            SET status = $2,
                charge_attempt_id = COALESCE($3, charge_attempt_id),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(cycle_id)
        .bind(status)
        .bind(charge_attempt_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn create_charge_attempt(
        pool: &DbPool,
        input: CreateChargeAttemptInput<'_>,
    ) -> Result<SubscriptionChargeAttempt, Error> {
        sqlx::query_as::<_, SubscriptionChargeAttempt>(
            r#"
            INSERT INTO subscription_charge_attempts (
                user_id,
                subscription_id,
                chain_id,
                period_start,
                period_end,
                amount_usdc,
                status,
                idempotency_key,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, 'created', $7, NOW(), NOW())
            ON CONFLICT (idempotency_key) DO UPDATE SET
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(input.user_id)
        .bind(input.subscription_id)
        .bind(input.chain_id)
        .bind(input.period_start)
        .bind(input.period_end)
        .bind(input.amount_usdc)
        .bind(input.idempotency_key)
        .fetch_one(pool)
        .await
    }

    pub async fn get_charge_attempt_by_id(
        pool: &DbPool,
        attempt_id: Uuid,
    ) -> Result<Option<SubscriptionChargeAttempt>, Error> {
        sqlx::query_as::<_, SubscriptionChargeAttempt>(
            "SELECT * FROM subscription_charge_attempts WHERE id = $1",
        )
        .bind(attempt_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_charge_attempt_by_tx_hash(
        pool: &DbPool,
        chain_id: i32,
        tx_hash: &str,
    ) -> Result<Option<SubscriptionChargeAttempt>, Error> {
        sqlx::query_as::<_, SubscriptionChargeAttempt>(
            "SELECT * FROM subscription_charge_attempts WHERE chain_id = $1 AND onchain_tx_hash = $2",
        )
        .bind(chain_id)
        .bind(tx_hash)
        .fetch_optional(pool)
        .await
    }

    pub async fn update_charge_attempt_outcome(
        pool: &DbPool,
        attempt_id: Uuid,
        input: UpdateChargeAttemptOutcomeInput<'_>,
    ) -> Result<Option<SubscriptionChargeAttempt>, Error> {
        sqlx::query_as::<_, SubscriptionChargeAttempt>(
            r#"
            UPDATE subscription_charge_attempts
            SET status = $2,
                onchain_tx_hash = COALESCE($3, onchain_tx_hash),
                failure_code = $4,
                failure_reason = $5,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(attempt_id)
        .bind(input.status)
        .bind(input.tx_hash)
        .bind(input.failure_code)
        .bind(input.failure_reason)
        .fetch_optional(pool)
        .await
    }

    pub async fn insert_event_log(
        pool: &DbPool,
        input: InsertEventLogInput<'_>,
    ) -> Result<OnchainEventLog, Error> {
        sqlx::query_as::<_, OnchainEventLog>(
            r#"
            INSERT INTO onchain_event_log (
                provider,
                event_id,
                event_type,
                chain_id,
                tx_hash,
                payload,
                received_at,
                processing_status
            ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), 'received')
            ON CONFLICT (provider, event_id) DO UPDATE SET
                payload = EXCLUDED.payload
            RETURNING *
            "#,
        )
        .bind(input.provider)
        .bind(input.event_id)
        .bind(input.event_type)
        .bind(input.chain_id)
        .bind(input.tx_hash)
        .bind(input.payload)
        .fetch_one(pool)
        .await
    }

    pub async fn mark_event_processed(
        pool: &DbPool,
        provider: &str,
        event_id: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            r#"
            UPDATE onchain_event_log
            SET processing_status = 'processed',
                processed_at = NOW(),
                error = NULL
            WHERE provider = $1 AND event_id = $2
            "#,
        )
        .bind(provider)
        .bind(event_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn mark_event_failed(
        pool: &DbPool,
        provider: &str,
        event_id: &str,
        error: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            r#"
            UPDATE onchain_event_log
            SET processing_status = 'failed',
                processed_at = NOW(),
                error = $3
            WHERE provider = $1 AND event_id = $2
            "#,
        )
        .bind(provider)
        .bind(event_id)
        .bind(error)
        .execute(pool)
        .await?;
        Ok(())
    }
}
