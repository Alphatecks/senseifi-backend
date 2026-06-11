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
    /// User who connected this wallet (e.g. auth provider sub). NULL = legacy.
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConnectWalletRequest {
    pub address: String,
    pub chain_id: i64,
    pub wallet_type: String,
    /// Current user identifier (e.g. from auth). Required for dashboard to show only this user's wallets.
    pub user_id: Option<String>,
    /// `evm` (default) or `solana`.
    #[serde(default)]
    pub chain_family: Option<String>,
    /// Solana cluster identifier (e.g. mainnet-beta, devnet). Informational for popup connect.
    #[serde(default)]
    pub network: Option<String>,
}

/// Supported chain families for multi-chain protection and wallet connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainFamily {
    #[default]
    Evm,
    Solana,
}

impl ChainFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            ChainFamily::Evm => "evm",
            ChainFamily::Solana => "solana",
        }
    }
}

/// Parse optional chain_family request field; defaults to EVM for backward compatibility.
pub fn parse_chain_family(raw: Option<&str>) -> ChainFamily {
    match raw.unwrap_or("evm").trim().to_lowercase().as_str() {
        "solana" => ChainFamily::Solana,
        _ => ChainFamily::Evm,
    }
}

/// Valid Ethereum address: 0x + 40 hex chars. Used to reject path/body injection and malformed input.
pub fn is_valid_eth_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Valid Solana pubkey: base58-encoded 32-byte key (32–44 chars, no 0/O/I/l).
pub fn is_valid_solana_address(s: &str) -> bool {
    if s.len() < 32 || s.len() > 44 {
        return false;
    }
    if !s.chars().all(is_base58_char) {
        return false;
    }
    bs58::decode(s)
        .into_vec()
        .ok()
        .is_some_and(|bytes| bytes.len() == 32)
}

fn is_base58_char(c: char) -> bool {
    matches!(
        c,
        '1'..='9'
            | 'A'..='H'
            | 'J'..='N'
            | 'P'..='Z'
            | 'a'..='k'
            | 'm'..='z'
    )
}

/// Family-aware wallet address validation.
pub fn is_valid_wallet_address(address: &str, family: ChainFamily) -> bool {
    match family {
        ChainFamily::Evm => is_valid_eth_address(address),
        ChainFamily::Solana => is_valid_solana_address(address),
    }
}

/// Canonical form for DB storage and lookups: `0x` + lowercase hex (avoids checksum vs all-lower mismatches).
pub fn canonical_eth_address(address: &str) -> String {
    if address.len() == 42 && address.starts_with("0x") {
        format!("0x{}", address[2..].to_lowercase())
    } else {
        address.to_string()
    }
}

/// Allowed EVM wallet types (allowlist to prevent injection).
pub const ALLOWED_EVM_WALLET_TYPES: &[&str] = &["metamask", "coinbase"];

/// Allowed Solana wallet types for popup connect.
pub const ALLOWED_SOLANA_WALLET_TYPES: &[&str] = &["phantom", "solflare", "backpack"];

/// Backward-compatible alias.
pub const ALLOWED_WALLET_TYPES: &[&str] = ALLOWED_EVM_WALLET_TYPES;

/// Solana mainnet chain_id convention (EIP-155-style label used in dashboard).
pub const SOLANA_MAINNET_CHAIN_ID: i64 = 101;

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

/// One row for Connected Wallet list UI: provider name, currency, address.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectedWalletItem {
    pub id: Uuid,
    pub address: String,
    pub provider: String,
    pub currency: String,
    pub connected_at: DateTime<Utc>,
}

/// Dashboard identity for a connected wallet: random user_id (API), display name, "User N" number.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardUser {
    pub user_id: String,
    pub display_name: String,
    pub user_number: i32,
}

impl DashboardUser {
    /// Label for UI e.g. "User 2314".
    pub fn user_label(&self) -> String {
        format!("User {}", self.user_number)
    }
}
