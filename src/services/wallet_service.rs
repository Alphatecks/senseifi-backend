use crate::db::DbPool;
use crate::models::wallet::{
    ConnectWalletRequest, ConnectedWalletItem, WalletResponse, WalletStatusResponse,
};
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
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;

        let updated = sqlx::query(
            r#"
            UPDATE wallet_monitoring SET status = 'active', last_checked = NOW(), updated_at = NOW()
            WHERE wallet_id = $1
            "#,
        )
        .bind(wallet.id)
        .execute(pool)
        .await?;

        if updated.rows_affected() == 0 {
            sqlx::query(
                r#"
                INSERT INTO wallet_monitoring (wallet_id, status, last_checked)
                VALUES ($1, 'active', NOW())
                "#,
            )
            .bind(wallet.id)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    pub async fn get_wallet(pool: &DbPool, address: &str) -> Result<WalletResponse, Error> {
        let wallet = WalletRepository::get_wallet_by_address(pool, address)
            .await?
            .ok_or(Error::RowNotFound)?;

        Ok(WalletResponse::from(wallet))
    }

    /// Paginated list for Connected Wallet UI: provider, currency, address per row.
    pub async fn list_connected_wallets(
        pool: &DbPool,
        page: u32,
        per_page: u32,
    ) -> Result<(Vec<ConnectedWalletItem>, i64), Error> {
        let (wallets, total) =
            WalletRepository::list_wallets_paginated(pool, page, per_page).await?;
        let items = wallets
            .into_iter()
            .map(|w| ConnectedWalletItem {
                id: w.id,
                address: w.address,
                provider: wallet_type_to_provider(&w.wallet_type),
                currency: chain_id_to_currency(w.chain_id),
                connected_at: w.connected_at,
            })
            .collect();
        Ok((items, total))
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

fn wallet_type_to_provider(wallet_type: &str) -> String {
    match wallet_type.to_lowercase().as_str() {
        "metamask" => "MetaMask".to_string(),
        "coinbase" => "Coinbase".to_string(),
        "binance" => "Binance".to_string(),
        "kraken" => "Kraken".to_string(),
        "bitstamp" => "Bitstamp".to_string(),
        _ => {
            let mut s = wallet_type.to_string();
            if let Some(r) = s.get_mut(0..1) {
                r.make_ascii_uppercase();
            }
            s
        }
    }
}

fn chain_id_to_currency(chain_id: i64) -> String {
    match chain_id {
        1 => "Ethereum".to_string(),
        56 => "BNB".to_string(),
        137 => "Polygon".to_string(),
        43114 => "Avalanche".to_string(),
        8453 => "Base".to_string(),
        42161 => "Arbitrum".to_string(),
        10 => "Optimism".to_string(),
        250 => "Fantom".to_string(),
        5 => "Goerli".to_string(),
        11155111 => "Sepolia".to_string(),
        _ => format!("Chain {}", chain_id),
    }
}
