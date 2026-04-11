use crate::db::DbPool;
use crate::models::wallet::Wallet;
use sqlx::Error;

pub struct WalletRepository;

impl WalletRepository {
    pub async fn create_wallet(
        pool: &DbPool,
        address: &str,
        chain_id: i64,
        wallet_type: &str,
        user_id: Option<&str>,
    ) -> Result<Wallet, Error> {
        let wallet = sqlx::query_as::<_, Wallet>(
            r#"
            INSERT INTO wallets (address, chain_id, wallet_type, connected_at, is_active, user_id)
            VALUES ($1, $2, $3, NOW(), true, $4)
            ON CONFLICT (address)
            DO UPDATE SET
                chain_id = EXCLUDED.chain_id,
                wallet_type = EXCLUDED.wallet_type,
                is_active = true,
                user_id = EXCLUDED.user_id,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(address)
        .bind(chain_id)
        .bind(wallet_type)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(wallet)
    }

    pub async fn get_wallet_by_address(
        pool: &DbPool,
        address: &str,
    ) -> Result<Option<Wallet>, Error> {
        let wallet =
            sqlx::query_as::<_, Wallet>("SELECT * FROM wallets WHERE LOWER(address) = LOWER($1)")
                .bind(address)
                .fetch_optional(pool)
                .await?;

        Ok(wallet)
    }

    pub async fn update_wallet_status(
        pool: &DbPool,
        address: &str,
        is_active: bool,
    ) -> Result<(), Error> {
        sqlx::query(
            "UPDATE wallets SET is_active = $1, updated_at = NOW() WHERE LOWER(address) = LOWER($2)",
        )
        .bind(is_active)
        .bind(address)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Set user_id on a wallet (e.g. after resolving from dashboard_user so overview shows it).
    pub async fn update_wallet_user_id(
        pool: &DbPool,
        address: &str,
        user_id: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "UPDATE wallets SET user_id = $1, updated_at = NOW() WHERE LOWER(address) = LOWER($2)",
        )
        .bind(user_id)
        .bind(address)
        .execute(pool)
        .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_all_active_wallets(pool: &DbPool) -> Result<Vec<Wallet>, Error> {
        let wallets = sqlx::query_as::<_, Wallet>(
            "SELECT * FROM wallets WHERE is_active = true ORDER BY connected_at DESC",
        )
        .fetch_all(pool)
        .await?;

        Ok(wallets)
    }

    /// Active wallets for one user (dashboard overview scope).
    pub async fn get_all_active_wallets_by_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<Wallet>, Error> {
        let wallets = sqlx::query_as::<_, Wallet>(
            "SELECT * FROM wallets WHERE is_active = true AND user_id = $1 ORDER BY connected_at DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        Ok(wallets)
    }

    /// Paginated list of active wallets for Connected Wallet UI. Returns (wallets, total_count).
    pub async fn list_wallets_paginated(
        pool: &DbPool,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<Wallet>, i64), Error> {
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*)::bigint FROM wallets WHERE is_active = true")
                .fetch_one(pool)
                .await?;

        let offset = (page.saturating_sub(1) as i64) * (per_page as i64);
        let limit = per_page as i64;
        let wallets = sqlx::query_as::<_, Wallet>(
            "SELECT * FROM wallets WHERE is_active = true ORDER BY connected_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok((wallets, total.0))
    }

    /// List only the wallet(s) for the active account (by address). Returns 0 or 1 row; used for Connected Wallet UI scoped to current user.
    pub async fn list_wallets_for_address(
        pool: &DbPool,
        address: &str,
    ) -> Result<(Vec<Wallet>, i64), Error> {
        let wallet = sqlx::query_as::<_, Wallet>(
            "SELECT * FROM wallets WHERE LOWER(address) = LOWER($1) AND is_active = true",
        )
        .bind(address)
        .fetch_optional(pool)
        .await?;
        let (list, total) = match wallet {
            Some(w) => (vec![w], 1i64),
            None => (vec![], 0i64),
        };
        Ok((list, total))
    }
}
