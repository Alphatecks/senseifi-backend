use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Wallet {
    pub id: Uuid,
    pub address: String,
    pub chain_id: i64,
    pub wallet_type: String,
    pub connected_at: DateTime<Utc>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ConnectWalletRequest {
    pub address: String,
    pub chain_id: i64,
    pub wallet_type: String, // "metamask" or "coinbase"
}

#[derive(Debug, Serialize)]
pub struct WalletResponse {
    pub id: Uuid,
    pub address: String,
    pub chain_id: i64,
    pub wallet_type: String,
    pub connected_at: DateTime<Utc>,
    pub is_active: bool,
}

impl From<Wallet> for WalletResponse {
    fn from(wallet: Wallet) -> Self {
        WalletResponse {
            id: wallet.id,
            address: wallet.address,
            chain_id: wallet.chain_id,
            wallet_type: wallet.wallet_type,
            connected_at: wallet.connected_at,
            is_active: wallet.is_active,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WalletStatusResponse {
    pub address: String,
    pub chain_id: i64,
    pub is_active: bool,
    pub monitoring_status: String,
    pub connected_at: DateTime<Utc>,
}
