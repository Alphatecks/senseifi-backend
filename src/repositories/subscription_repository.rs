use crate::db::DbPool;
use crate::models::subscription::UserSubscription;
use sqlx::Error;

pub struct SubscriptionRepository;

#[derive(Debug, Clone)]
pub struct UpsertSubscriptionInput<'a> {
    pub user_id: &'a str,
    pub plan: &'a str,
    pub billing_cycle: &'a str,
    pub status: &'a str,
    pub boomfi_customer_id: Option<&'a str>,
    pub boomfi_subscription_id: Option<&'a str>,
    pub boomfi_plan_id: Option<&'a str>,
    pub checkout_session_id: Option<&'a str>,
    pub current_period_end_unix: Option<i64>,
    pub cancel_at_period_end: bool,
}

impl SubscriptionRepository {
    pub async fn get_by_id(
        pool: &DbPool,
        id: uuid::Uuid,
    ) -> Result<Option<UserSubscription>, Error> {
        sqlx::query_as::<_, UserSubscription>("SELECT * FROM user_subscriptions WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    pub async fn get_by_user_id(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<UserSubscription>, Error> {
        sqlx::query_as::<_, UserSubscription>("SELECT * FROM user_subscriptions WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
    }

    pub async fn get_by_boomfi_customer_id(
        pool: &DbPool,
        customer_id: &str,
    ) -> Result<Option<UserSubscription>, Error> {
        sqlx::query_as::<_, UserSubscription>(
            "SELECT * FROM user_subscriptions WHERE boomfi_customer_id = $1",
        )
        .bind(customer_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_by_boomfi_subscription_id(
        pool: &DbPool,
        subscription_id: &str,
    ) -> Result<Option<UserSubscription>, Error> {
        sqlx::query_as::<_, UserSubscription>(
            "SELECT * FROM user_subscriptions WHERE boomfi_subscription_id = $1",
        )
        .bind(subscription_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn upsert(
        pool: &DbPool,
        input: UpsertSubscriptionInput<'_>,
    ) -> Result<UserSubscription, Error> {
        sqlx::query_as::<_, UserSubscription>(
            r#"
            INSERT INTO user_subscriptions (
                user_id,
                plan,
                billing_cycle,
                status,
                boomfi_customer_id,
                boomfi_subscription_id,
                boomfi_plan_id,
                checkout_session_id,
                current_period_end,
                cancel_at_period_end,
                created_at,
                updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, to_timestamp($9), $10, NOW(), NOW()
            )
            ON CONFLICT (user_id) DO UPDATE SET
                plan = EXCLUDED.plan,
                billing_cycle = EXCLUDED.billing_cycle,
                status = EXCLUDED.status,
                boomfi_customer_id = COALESCE(EXCLUDED.boomfi_customer_id, user_subscriptions.boomfi_customer_id),
                boomfi_subscription_id = COALESCE(EXCLUDED.boomfi_subscription_id, user_subscriptions.boomfi_subscription_id),
                boomfi_plan_id = COALESCE(EXCLUDED.boomfi_plan_id, user_subscriptions.boomfi_plan_id),
                checkout_session_id = COALESCE(EXCLUDED.checkout_session_id, user_subscriptions.checkout_session_id),
                current_period_end = COALESCE(EXCLUDED.current_period_end, user_subscriptions.current_period_end),
                cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(input.user_id)
        .bind(input.plan)
        .bind(input.billing_cycle)
        .bind(input.status)
        .bind(input.boomfi_customer_id)
        .bind(input.boomfi_subscription_id)
        .bind(input.boomfi_plan_id)
        .bind(input.checkout_session_id)
        .bind(input.current_period_end_unix)
        .bind(input.cancel_at_period_end)
        .fetch_one(pool)
        .await
    }
}
