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
    /// Wallet app slug from WalletConnect metadata or direct connect (e.g. trustwallet, rainbow).
    pub wallet_provider: Option<String>,
    /// Human-readable wallet label from the client (e.g. "Trust Wallet").
    pub wallet_name: Option<String>,
    /// Solana cluster (`mainnet` / `devnet`). NULL for EVM wallets.
    pub network: Option<String>,
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
    /// Wallet app slug from WalletConnect `walletInfo` / session peer metadata.
    #[serde(default)]
    pub wallet_provider: Option<String>,
    /// Human-readable wallet name from the client (optional; used for dashboard display).
    #[serde(default)]
    pub wallet_name: Option<String>,
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

/// Resolve chain family from an explicit request field or wallet address format.
pub fn resolve_connect_chain_family(chain_family: Option<&str>, address: &str) -> ChainFamily {
    if chain_family.is_some() {
        return parse_chain_family(chain_family);
    }
    if is_valid_solana_address(address) {
        ChainFamily::Solana
    } else {
        ChainFamily::Evm
    }
}

/// Canonical chain_id stored for a connect request (Solana always uses 101).
pub fn connect_chain_id(chain_family: ChainFamily, request_chain_id: i64) -> Result<i64, ()> {
    match chain_family {
        ChainFamily::Solana => Ok(SOLANA_MAINNET_CHAIN_ID),
        ChainFamily::Evm => {
            if request_chain_id < CHAIN_ID_MIN || request_chain_id > CHAIN_ID_MAX {
                Err(())
            } else {
                Ok(request_chain_id)
            }
        }
    }
}

/// Human-readable network label for connected-wallet UI (address-aware for Solana).
pub fn wallet_network_label(chain_id: i64, address: &str, network: Option<&str>) -> String {
    if is_solana_wallet_row(chain_id, address) {
        match network.map(str::trim).filter(|s| !s.is_empty()) {
            Some("devnet") => "Solana Devnet".to_string(),
            _ => "Solana".to_string(),
        }
    } else {
        evm_chain_id_to_network_label(chain_id)
    }
}

fn is_solana_wallet_row(chain_id: i64, address: &str) -> bool {
    chain_id == SOLANA_MAINNET_CHAIN_ID || is_valid_solana_address(address)
}

fn evm_chain_id_to_network_label(chain_id: i64) -> String {
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

/// Normalize wallet address for XP billing and scan-history lookups (case-sensitive for Solana).
pub fn normalize_wallet_address_for_lookup(address: &str) -> String {
    let s = address.trim();
    if is_valid_eth_address(s) {
        canonical_eth_address(s)
    } else {
        s.to_string()
    }
}

/// Allowed EVM wallet types (allowlist to prevent injection).
pub const ALLOWED_EVM_WALLET_TYPES: &[&str] = &[
    "metamask",
    "coinbase",
    "trustwallet",
    "trust",
    "walletconnect",
    "binance",
];

/// Canonical stored value for EVM wallet_type (aliases normalized on connect).
pub fn normalize_evm_wallet_type(wallet_type: &str) -> Option<&'static str> {
    match wallet_type.trim().to_lowercase().as_str() {
        "metamask" => Some("metamask"),
        "coinbase" => Some("coinbase"),
        "trustwallet" | "trust wallet" | "trust" => Some("trustwallet"),
        "walletconnect" | "wallet connect" => Some("walletconnect"),
        "binance" | "binance wallet" | "binancewallet" => Some("binance"),
        _ => None,
    }
}

/// Max length for stored wallet_provider slug.
pub const WALLET_PROVIDER_MAX_LEN: usize = 32;

/// Max length for stored wallet_name label.
pub const WALLET_NAME_MAX_LEN: usize = 64;

/// Safe wallet_provider slug: lowercase alphanumeric, hyphen, underscore.
pub fn is_valid_wallet_provider_slug(slug: &str) -> bool {
    let s = slug.trim();
    (2..=WALLET_PROVIDER_MAX_LEN).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Normalize a wallet provider string from the client into a storage slug.
pub fn slugify_wallet_provider(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.trim().to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        }
    }
    out.truncate(WALLET_PROVIDER_MAX_LEN);
    out
}

/// Trim and bound wallet_name; reject control characters.
pub fn sanitize_wallet_name(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    if s.chars().any(|c| c.is_control()) {
        return None;
    }
    let mut name = s.to_string();
    name.truncate(WALLET_NAME_MAX_LEN);
    Some(name)
}

#[derive(Debug, Clone)]
pub struct ResolvedWalletConnectFields {
    pub wallet_type: String,
    pub wallet_provider: Option<String>,
    pub wallet_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletConnectValidationError {
    InvalidWalletType,
    InvalidWalletProvider,
    InvalidWalletName,
}

impl WalletConnectValidationError {
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidWalletType => "Invalid wallet_type",
            Self::InvalidWalletProvider => {
                "Invalid wallet_provider; use 2-32 lowercase letters, digits, hyphen, or underscore"
            }
            Self::InvalidWalletName => "Invalid wallet_name",
        }
    }
}

/// Resolve and validate wallet_type / wallet_provider / wallet_name for connect.
pub fn resolve_connect_wallet_metadata(
    chain_family: ChainFamily,
    wallet_type: &str,
    wallet_provider: Option<&str>,
    wallet_name: Option<&str>,
) -> Result<ResolvedWalletConnectFields, WalletConnectValidationError> {
    let wallet_name = match sanitize_wallet_name(wallet_name) {
        Some(n) => Some(n),
        None if wallet_name.is_some() => return Err(WalletConnectValidationError::InvalidWalletName),
        None => None,
    };

    let wallet_type = match chain_family {
        ChainFamily::Evm => normalize_evm_wallet_type(wallet_type)
            .ok_or(WalletConnectValidationError::InvalidWalletType)?
            .to_string(),
        ChainFamily::Solana => {
            let wt = wallet_type.trim().to_lowercase();
            if !ALLOWED_SOLANA_WALLET_TYPES.contains(&wt.as_str()) {
                return Err(WalletConnectValidationError::InvalidWalletType);
            }
            wt
        }
    };

    let wallet_provider = match wallet_provider.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            let slug = slugify_wallet_provider(raw);
            if !is_valid_wallet_provider_slug(&slug) {
                return Err(WalletConnectValidationError::InvalidWalletProvider);
            }
            Some(slug)
        }
        None if wallet_type == "walletconnect" => None,
        None => Some(wallet_type.clone()),
    };

    Ok(ResolvedWalletConnectFields {
        wallet_type,
        wallet_provider,
        wallet_name,
    })
}

/// UI label for a connected wallet (prefers wallet_name, then provider, then wallet_type).
pub fn wallet_display_name(
    wallet_type: &str,
    wallet_provider: Option<&str>,
    wallet_name: Option<&str>,
) -> String {
    if let Some(name) = wallet_name.map(str::trim).filter(|s| !s.is_empty()) {
        return name.to_string();
    }
    if let Some(provider) = wallet_provider.map(str::trim).filter(|s| !s.is_empty()) {
        return known_wallet_slug_display(provider);
    }
    known_wallet_slug_display(wallet_type)
}

fn known_wallet_slug_display(slug: &str) -> String {
    match slug.to_ascii_lowercase().as_str() {
        "metamask" => "MetaMask".to_string(),
        "coinbase" => "Coinbase Wallet".to_string(),
        "trustwallet" | "trust" => "Trust Wallet".to_string(),
        "walletconnect" => "WalletConnect".to_string(),
        "binance" | "binancewallet" => "Binance Wallet".to_string(),
        "phantom" => "Phantom".to_string(),
        "solflare" => "Solflare".to_string(),
        "backpack" => "Backpack".to_string(),
        "rainbow" => "Rainbow".to_string(),
        "rabby" => "Rabby".to_string(),
        "zerion" => "Zerion".to_string(),
        "safe" => "Safe".to_string(),
        "ledger" => "Ledger".to_string(),
        "okx" | "okxwallet" => "OKX Wallet".to_string(),
        other if !other.is_empty() => title_case_slug(other),
        _ => "Wallet".to_string(),
    }
}

fn title_case_slug(slug: &str) -> String {
    slug.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Allowed Solana wallet types for popup connect.
pub const ALLOWED_SOLANA_WALLET_TYPES: &[&str] = &["phantom", "solflare", "backpack"];

/// Backward-compatible alias.
pub const ALLOWED_WALLET_TYPES: &[&str] = ALLOWED_EVM_WALLET_TYPES;

/// Solana mainnet chain_id convention (EIP-155-style label used in dashboard).
pub const SOLANA_MAINNET_CHAIN_ID: i64 = 101;

/// Sentinel `contract_address` for native SOL rows in `wallet_assets`.
pub const SOLANA_NATIVE_CONTRACT: &str = "native";

/// EVM or Solana address accepted on asset dashboard routes.
pub fn is_valid_dashboard_wallet_address(address: &str) -> bool {
    is_valid_eth_address(address) || is_valid_solana_address(address)
}

/// EVM contract or Solana program ID accepted by the contract scanner.
pub fn is_valid_scan_contract_address(address: &str) -> bool {
    is_valid_eth_address(address) || is_valid_solana_address(address)
}

/// Alias: wallet pubkey on dashboard + protection routes (EVM or Solana).
pub fn is_valid_security_wallet_address(address: &str) -> bool {
    is_valid_dashboard_wallet_address(address)
}

/// Contract, token mint, or program ID on block/watchlist/report routes.
pub fn is_valid_security_contract_address(address: &str) -> bool {
    is_valid_scan_contract_address(address)
}

/// Infer scan target family from explicit request field or address format.
pub fn resolve_scan_chain_family(chain_family: Option<&str>, address: &str) -> ChainFamily {
    if chain_family.is_some() {
        return parse_chain_family(chain_family);
    }
    if is_valid_solana_address(address) {
        ChainFamily::Solana
    } else {
        ChainFamily::Evm
    }
}

/// Normalize Solana cluster from connect payload or env default.
pub fn normalize_solana_network(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim().to_lowercase();
    match s.as_str() {
        "mainnet" | "mainnet-beta" => Some("mainnet".to_string()),
        "devnet" => Some("devnet".to_string()),
        _ => None,
    }
}

/// Default Solana network when wallet row has no cluster stored.
pub fn default_solana_network() -> String {
    std::env::var("SOLANA_NETWORK")
        .ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .and_then(|s| normalize_solana_network(Some(&s)))
        .unwrap_or_else(|| "mainnet".to_string())
}

/// Resolve Moralis Solana network param for a wallet row.
pub fn solana_network_for_wallet(wallet: &Wallet) -> String {
    wallet
        .network
        .as_deref()
        .and_then(|n| normalize_solana_network(Some(n)))
        .unwrap_or_else(default_solana_network)
}

/// Whether a stored wallet row is Solana (by chain_id or address format).
pub fn is_solana_wallet(wallet: &Wallet) -> bool {
    is_solana_wallet_row(wallet.chain_id, &wallet.address)
}

/// Chain family inferred from a stored wallet row.
pub fn wallet_chain_family(wallet: &Wallet) -> ChainFamily {
    if is_solana_wallet(wallet) {
        ChainFamily::Solana
    } else {
        ChainFamily::Evm
    }
}

/// Chain ID range (EIP-155 style). Reject obviously invalid values.
pub const CHAIN_ID_MIN: i64 = 1;
pub const CHAIN_ID_MAX: i64 = 999_999;

#[derive(Debug, Serialize)]
pub struct WalletResponse {
    pub id: Uuid,
    pub address: String,
    pub chain_id: i64,
    pub chain_family: String,
    pub wallet_type: String,
    pub wallet_provider: Option<String>,
    pub wallet_name: Option<String>,
    pub provider_display: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub network_label: String,
    pub connected_at: DateTime<Utc>,
    pub is_active: bool,
}

impl From<Wallet> for WalletResponse {
    fn from(wallet: Wallet) -> Self {
        let provider_display = wallet_display_name(
            &wallet.wallet_type,
            wallet.wallet_provider.as_deref(),
            wallet.wallet_name.as_deref(),
        );
        let chain_family = wallet_chain_family(&wallet);
        WalletResponse {
            id: wallet.id,
            address: wallet.address.clone(),
            chain_id: if chain_family == ChainFamily::Solana {
                SOLANA_MAINNET_CHAIN_ID
            } else {
                wallet.chain_id
            },
            chain_family: chain_family.as_str().to_string(),
            wallet_type: wallet.wallet_type,
            wallet_provider: wallet.wallet_provider,
            wallet_name: wallet.wallet_name,
            provider_display,
            network: wallet.network.clone(),
            network_label: wallet_network_label(
                wallet.chain_id,
                &wallet.address,
                wallet.network.as_deref(),
            ),
            connected_at: wallet.connected_at,
            is_active: wallet.is_active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_wallet_provider_normalizes_names() {
        assert_eq!(slugify_wallet_provider("Trust Wallet"), "trustwallet");
        assert_eq!(slugify_wallet_provider("rainbow"), "rainbow");
    }

    #[test]
    fn resolve_walletconnect_with_provider() {
        let resolved = resolve_connect_wallet_metadata(
            ChainFamily::Evm,
            "walletconnect",
            Some("Trust Wallet"),
            Some("Trust Wallet"),
        )
        .expect("valid");
        assert_eq!(resolved.wallet_type, "walletconnect");
        assert_eq!(resolved.wallet_provider.as_deref(), Some("trustwallet"));
        assert_eq!(resolved.wallet_name.as_deref(), Some("Trust Wallet"));
    }

    #[test]
    fn resolve_direct_metamask_defaults_provider() {
        let resolved =
            resolve_connect_wallet_metadata(ChainFamily::Evm, "metamask", None, None).expect("valid");
        assert_eq!(resolved.wallet_type, "metamask");
        assert_eq!(resolved.wallet_provider.as_deref(), Some("metamask"));
    }

    #[test]
    fn normalize_solana_network_values() {
        assert_eq!(
            normalize_solana_network(Some("mainnet-beta")).as_deref(),
            Some("mainnet")
        );
        assert_eq!(normalize_solana_network(Some("devnet")).as_deref(), Some("devnet"));
        assert!(normalize_solana_network(Some("testnet")).is_none());
    }

    #[test]
    fn is_valid_dashboard_wallet_address_accepts_solana() {
        assert!(is_valid_dashboard_wallet_address(
            "kXB7FfzdrfZpAZEW3TZcp8a8CwQbsowa6BdfAHZ4gVs"
        ));
    }

    #[test]
    fn resolve_connect_chain_family_from_solana_address() {
        assert_eq!(
            resolve_connect_chain_family(None, "kXB7FfzdrfZpAZEW3TZcp8a8CwQbsowa6BdfAHZ4gVs"),
            ChainFamily::Solana
        );
    }

    #[test]
    fn wallet_network_label_solana_despite_wrong_chain_id() {
        assert_eq!(
            wallet_network_label(
                1,
                "kXB7FfzdrfZpAZEW3TZcp8a8CwQbsowa6BdfAHZ4gVs",
                Some("mainnet")
            ),
            "Solana"
        );
    }

    #[test]
    fn connect_chain_id_solana_ignores_evm_chain_id() {
        assert_eq!(
            connect_chain_id(ChainFamily::Solana, 1).expect("solana"),
            SOLANA_MAINNET_CHAIN_ID
        );
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
    pub chain_family: String,
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
