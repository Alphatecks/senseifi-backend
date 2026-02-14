use crate::db::DbPool;
use crate::models::wallet::{ConnectWalletRequest, WalletResponse, WalletStatusResponse};
use crate::repositories::wallet_repository::WalletRepository;
use sqlx::Error;

pub struct WalletService;

impl WalletService {
    pub async fn connect_wallet(
        pool: &DbPool,
        request: ConnectWalletRequest,
    ) -> Result<WalletResponse, Error> {
        // Validate wallet address format (basic check)
        if !request.address.starts_with("0x") || request.address.len() != 42 {
            return Err(Error::RowNotFound);
        }

        // Create or update wallet
        let wallet = WalletRepository::create_wallet(
            pool,
            &request.address,
            request.chain_id,
            &request.wallet_type,
        )
        .await?;

        // Start monitoring (best-effort; do not fail connect if monitoring table missing/broken)
        if let Err(e) = Self::start_monitoring(pool, &wallet.address).await {
            eprintln!("Warning: start_monitoring failed (wallet still connected): {}", e);
        }

        Ok(WalletResponse::from(wallet))
    }

    pub async fn get_wallet_status(
        pool: &DbPool,
        address: &str,
    ) -> Result<WalletStatusResponse, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;

        // Get monitoring status (placeholder - will be enhanced later)
        let monitoring_status = "active".to_string();

        Ok(WalletStatusResponse {
            address: wallet.address,
            chain_id: wallet.chain_id,
            is_active: wallet.is_active,
            monitoring_status,
            connected_at: wallet.connected_at,
        })
    }

    pub async fn start_monitoring(pool: &DbPool, address: &str) -> Result<(), Error> {
        // Get wallet to ensure it exists
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;

        // Create or update monitoring record
        sqlx::query(
            r#"
            INSERT INTO wallet_monitoring (wallet_id, status, last_checked)
            VALUES ($1, 'active', NOW())
            ON CONFLICT (wallet_id) 
            DO UPDATE SET 
                status = 'active',
                last_checked = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(wallet.id)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn get_wallet(pool: &DbPool, address: &str) -> Result<WalletResponse, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;

        Ok(WalletResponse::from(wallet))
    }

    pub async fn disconnect_wallet(pool: &DbPool, address: &str) -> Result<(), Error> {
        // Verify wallet exists
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;

        // Set wallet to inactive
        WalletRepository::update_wallet_status(pool, address, false).await?;

        // Stop monitoring (set status to inactive)
        sqlx::query(
            r#"
            UPDATE wallet_monitoring 
            SET status = 'inactive', updated_at = NOW() 
            WHERE wallet_id = $1
            "#,
        )
        .bind(wallet.id)
        .execute(pool)
        .await?;

        Ok(())
    }
}
