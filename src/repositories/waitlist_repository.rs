use crate::db::DbPool;
use crate::models::waitlist::{UserXpClaim, WaitlistXpBreakdown, XpUsageEvent};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Error;
use uuid::Uuid;

pub struct WaitlistRepository;

/// Reserved `waitlist_entries.id` for auto-granted connect-wallet XP (not a real waitlist signup).
pub const WELCOME_WAITLIST_ENTRY_ID: i32 = -1;

#[derive(Debug, Clone)]
pub struct WaitlistEntryRow {
    pub id: i32,
    pub email: String,
}

impl WaitlistRepository {
    pub async fn find_entry_by_email(
        pool: &DbPool,
        email: &str,
    ) -> Result<Option<WaitlistEntryRow>, Error> {
        sqlx::query_as::<_, (i32, String)>(
            "SELECT id, email FROM waitlist_entries WHERE LOWER(TRIM(email)) = LOWER(TRIM($1))",
        )
        .bind(email)
        .fetch_optional(pool)
        .await
        .map(|row| row.map(|(id, email)| WaitlistEntryRow { id, email }))
    }

    pub async fn compute_xp_breakdown(
        pool: &DbPool,
        waitlist_entry_id: i32,
        email: &str,
        xp_per_referral: i32,
        xp_per_level2: i32,
    ) -> Result<WaitlistXpBreakdown, Error> {
        let direct: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM waitlist_referrals WHERE referrer_id = $1",
        )
        .bind(waitlist_entry_id)
        .fetch_one(pool)
        .await?;

        let level2: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::bigint
            FROM waitlist_referrals r2
            INNER JOIN waitlist_referrals r1 ON r2.referrer_id = r1.referred_id
            WHERE r1.referrer_id = $1
            "#,
        )
        .bind(waitlist_entry_id)
        .fetch_one(pool)
        .await?;

        let direct_referrals = direct.min(i64::from(i32::MAX)) as i32;
        let level2_referrals = level2.min(i64::from(i32::MAX)) as i32;
        let xp = direct_referrals
            .saturating_mul(xp_per_referral)
            .saturating_add(level2_referrals.saturating_mul(xp_per_level2));

        Ok(WaitlistXpBreakdown {
            email: email.to_string(),
            waitlist_entry_id,
            direct_referrals,
            level2_referrals,
            xp,
            xp_per_referral,
            xp_per_level2_referral: xp_per_level2,
        })
    }

    pub async fn get_claim_by_email(
        pool: &DbPool,
        email: &str,
    ) -> Result<Option<UserXpClaim>, Error> {
        Self::map_claim_row(
            sqlx::query_as::<_, ClaimRow>(
                r#"
                SELECT user_id, wallet_address, waitlist_entry_id, email, xp, xp_spent,
                       direct_referrals, level2_referrals, claimed_at
                FROM user_xp_claims
                WHERE LOWER(TRIM(email)) = LOWER(TRIM($1))
                "#,
            )
            .bind(email)
            .fetch_optional(pool)
            .await?,
        )
    }

    pub async fn get_claim_by_user_id(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Option<UserXpClaim>, Error> {
        Self::map_claim_row(
            sqlx::query_as::<_, ClaimRow>(
                r#"
                SELECT user_id, wallet_address, waitlist_entry_id, email, xp, xp_spent,
                       direct_referrals, level2_referrals, claimed_at
                FROM user_xp_claims
                WHERE user_id = $1
                "#,
            )
            .bind(user_id)
            .fetch_optional(pool)
            .await?,
        )
    }

    pub async fn get_claim_by_wallet(
        pool: &DbPool,
        wallet_address: &str,
    ) -> Result<Option<UserXpClaim>, Error> {
        let lookup = crate::models::wallet::normalize_wallet_address_for_lookup(wallet_address);
        let row = if crate::models::wallet::is_valid_solana_address(&lookup) {
            sqlx::query_as::<_, ClaimRow>(
                r#"
                SELECT user_id, wallet_address, waitlist_entry_id, email, xp, xp_spent,
                       direct_referrals, level2_referrals, claimed_at
                FROM user_xp_claims
                WHERE wallet_address = $1
                "#,
            )
            .bind(&lookup)
            .fetch_optional(pool)
            .await?
        } else {
            sqlx::query_as::<_, ClaimRow>(
                r#"
                SELECT user_id, wallet_address, waitlist_entry_id, email, xp, xp_spent,
                       direct_referrals, level2_referrals, claimed_at
                FROM user_xp_claims
                WHERE LOWER(wallet_address) = LOWER($1)
                "#,
            )
            .bind(&lookup)
            .fetch_optional(pool)
            .await?
        };
        Self::map_claim_row(row)
    }

    pub async fn insert_claim(
        pool: &DbPool,
        user_id: &str,
        wallet_address: &str,
        waitlist_entry_id: i32,
        email: &str,
        xp: i32,
        direct_referrals: i32,
        level2_referrals: i32,
    ) -> Result<UserXpClaim, Error> {
        let row = sqlx::query_as::<_, ClaimRow>(
            r#"
            INSERT INTO user_xp_claims (
                user_id, wallet_address, waitlist_entry_id, email,
                xp, direct_referrals, level2_referrals
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING user_id, wallet_address, waitlist_entry_id, email, xp, xp_spent,
                      direct_referrals, level2_referrals, claimed_at
            "#,
        )
        .bind(user_id)
        .bind(wallet_address)
        .bind(waitlist_entry_id)
        .bind(email)
        .bind(xp)
        .bind(direct_referrals)
        .bind(level2_referrals)
        .fetch_one(pool)
        .await?;

        Self::map_claim_row(Some(row)).map(|c| c.expect("insert returned row"))
    }

    pub fn is_welcome_claim(claim: &UserXpClaim) -> bool {
        claim.waitlist_entry_id == WELCOME_WAITLIST_ENTRY_ID
    }

    /// Replace a welcome-only claim with waitlist referral XP (same user_id).
    pub async fn upgrade_welcome_claim_to_waitlist(
        pool: &DbPool,
        user_id: &str,
        wallet_address: &str,
        waitlist_entry_id: i32,
        email: &str,
        xp: i32,
        direct_referrals: i32,
        level2_referrals: i32,
    ) -> Result<UserXpClaim, Error> {
        let row = sqlx::query_as::<_, ClaimRow>(
            r#"
            UPDATE user_xp_claims
            SET wallet_address = $2,
                waitlist_entry_id = $3,
                email = $4,
                xp = $5,
                direct_referrals = $6,
                level2_referrals = $7
            WHERE user_id = $1
              AND waitlist_entry_id = $8
            RETURNING user_id, wallet_address, waitlist_entry_id, email, xp, xp_spent,
                      direct_referrals, level2_referrals, claimed_at
            "#,
        )
        .bind(user_id)
        .bind(wallet_address)
        .bind(waitlist_entry_id)
        .bind(email)
        .bind(xp)
        .bind(direct_referrals)
        .bind(level2_referrals)
        .bind(WELCOME_WAITLIST_ENTRY_ID)
        .fetch_optional(pool)
        .await?;

        Self::map_claim_row(row)?.ok_or(Error::RowNotFound)
    }

    /// Atomically deduct XP and append a ledger row. Returns None if balance insufficient.
    pub async fn deduct_xp_for_usage(
        pool: &DbPool,
        user_id: &str,
        wallet_address: &str,
        action_type: &str,
        xp_cost: i32,
        metadata: Option<Value>,
    ) -> Result<Option<(i32, i32, i32)>, Error> {
        let mut tx = pool.begin().await?;

        let updated = sqlx::query_as::<_, (i32, i32)>(
            r#"
            UPDATE user_xp_claims
            SET xp_spent = xp_spent + $2
            WHERE user_id = $1 AND xp - xp_spent >= $2
            RETURNING xp, xp_spent
            "#,
        )
        .bind(user_id)
        .bind(xp_cost)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((xp_earned, xp_spent)) = updated else {
            tx.rollback().await?;
            return Ok(None);
        };

        let xp_balance = xp_earned.saturating_sub(xp_spent);
        sqlx::query(
            r#"
            INSERT INTO xp_usage_events (
                user_id, wallet_address, action_type, xp_cost, xp_balance_after, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(user_id)
        .bind(wallet_address)
        .bind(action_type)
        .bind(xp_cost)
        .bind(xp_balance)
        .bind(metadata)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some((xp_earned, xp_spent, xp_balance)))
    }

    pub async fn list_usage_events(
        pool: &DbPool,
        user_id: &str,
        limit: i64,
    ) -> Result<Vec<XpUsageEvent>, Error> {
        let rows = sqlx::query_as::<_, UsageRow>(
            r#"
            SELECT id, user_id, wallet_address, action_type, xp_cost, xp_balance_after, created_at
            FROM xp_usage_events
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    user_id,
                    wallet_address,
                    action_type,
                    xp_cost,
                    xp_balance_after,
                    created_at,
                )| {
                    XpUsageEvent {
                        id,
                        user_id,
                        wallet_address,
                        action_type,
                        xp_cost,
                        xp_balance_after,
                        created_at,
                    }
                },
            )
            .collect())
    }

    fn map_claim_row(row: Option<ClaimRow>) -> Result<Option<UserXpClaim>, Error> {
        Ok(row.map(
            |(
                user_id,
                wallet_address,
                waitlist_entry_id,
                email,
                xp,
                xp_spent,
                direct_referrals,
                level2_referrals,
                claimed_at,
            )| {
                UserXpClaim {
                    user_id,
                    wallet_address,
                    email,
                    waitlist_entry_id,
                    xp,
                    xp_spent,
                    direct_referrals,
                    level2_referrals,
                    claimed_at,
                }
            },
        ))
    }
}

type ClaimRow = (
    String,
    String,
    i32,
    String,
    i32,
    i32,
    i32,
    i32,
    DateTime<Utc>,
);

type UsageRow = (Uuid, String, String, String, i32, i32, DateTime<Utc>);
