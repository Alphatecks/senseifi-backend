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

/// Valid Ethereum address: 0x + 40 hex chars. Used to reject path/body injection and malformed input.
pub fn is_valid_eth_address(s: &str) -> bool {
    s.len() == 42
        && s.starts_with("0x")
        && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Allowed wallet types (allowlist to prevent injection).
pub const ALLOWED_WALLET_TYPES: &[&str] = &["metamask", "coinbase"];

/// Chain ID range (EIP-155 style). Reject obviously invalid values.
pub const CHAIN_ID_MIN: i64 = 1;
pub const CHAIN_ID_MAX: i64 = 999_999;

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
