use crate::db::DbPool;
use crate::models::wallet::{
    canonical_eth_address, is_valid_wallet_address, normalize_solana_network,
    resolve_connect_chain_family, wallet_chain_family, wallet_display_name, wallet_network_label,
    ConnectWalletRequest, ChainFamily, ConnectedWalletItem, WalletResponse, WalletStatusResponse,
    SOLANA_MAINNET_CHAIN_ID,
};
use crate::repositories::wallet_repository::WalletRepository;
use sqlx::Error;

pub struct WalletService;

impl WalletService {
    pub async fn connect_wallet(
        pool: &DbPool,
        request: ConnectWalletRequest,
    ) -> Result<WalletResponse, Error> {
        let chain_family = resolve_connect_chain_family(request.chain_family.as_deref(), &request.address);
        if !is_valid_wallet_address(&request.address, chain_family) {
            return Err(Error::RowNotFound);
        }

        let addr = match chain_family {
            ChainFamily::Evm => canonical_eth_address(&request.address),
            ChainFamily::Solana => request.address.clone(),
        };
        let chain_id = match chain_family {
            ChainFamily::Solana => SOLANA_MAINNET_CHAIN_ID,
            ChainFamily::Evm => request.chain_id,
        };
        let network = match chain_family {
            ChainFamily::Solana => normalize_solana_network(request.network.as_deref()),
            ChainFamily::Evm => None,
        };
        // Create or update wallet (user_id scopes dashboard to this user)
        let wallet = WalletRepository::create_wallet(
            pool,
            &addr,
            chain_id,
            &request.wallet_type,
            request.wallet_provider.as_deref(),
            request.wallet_name.as_deref(),
            network.as_deref(),
            request.user_id.as_deref(),
        )
        .await?;

        // Start monitoring (best-effort; do not fail connect if monitoring table missing/broken)
        if let Err(e) = Self::start_monitoring(pool, &wallet.address).await {
            eprintln!(
                "Warning: start_monitoring failed (wallet still connected): {}",
                e
            );
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

    /// Connected Wallet list scoped to the active account (single address). Returns only the wallet for that address (0 or 1 row).
    pub async fn list_connected_wallets_for_account(
        pool: &DbPool,
        address: &str,
    ) -> Result<(Vec<ConnectedWalletItem>, i64), Error> {
        let (wallets, total) = WalletRepository::list_wallets_for_address(pool, address).await?;
        Ok((wallets.into_iter().map(wallet_to_connected_item).collect(), total))
    }

    /// All active connected networks for one user (EVM + Solana).
    pub async fn list_connected_wallets_for_user(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(Vec<ConnectedWalletItem>, i64), Error> {
        let wallets = WalletRepository::get_all_active_wallets_by_user(pool, user_id).await?;
        let total = wallets.len() as i64;
        Ok((
            wallets.into_iter().map(wallet_to_connected_item).collect(),
            total,
        ))
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

fn wallet_to_connected_item(w: crate::models::wallet::Wallet) -> ConnectedWalletItem {
    let family = wallet_chain_family(&w);
    let network_label = wallet_network_label(w.chain_id, &w.address, w.network.as_deref());
    ConnectedWalletItem {
        id: w.id,
        address: w.address.clone(),
        provider: wallet_display_name(
            &w.wallet_type,
            w.wallet_provider.as_deref(),
            w.wallet_name.as_deref(),
        ),
        chain_family: family.as_str().to_string(),
        chain_id: if family == ChainFamily::Solana {
            SOLANA_MAINNET_CHAIN_ID
        } else {
            w.chain_id
        },
        currency: network_label.clone(),
        network: w.network.clone(),
        network_label,
        connected_at: w.connected_at,
    }
}
