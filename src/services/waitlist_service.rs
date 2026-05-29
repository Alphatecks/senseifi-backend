//! Waitlist XP: compute referral XP and bind claims to dashboard user_id + wallet.

use crate::db::DbPool;
use crate::models::wallet::{canonical_eth_address, is_valid_eth_address};
use crate::models::waitlist::{ClaimXpResult, UserXpClaim, WaitlistXpBreakdown};
use crate::repositories::waitlist_repository::WaitlistRepository;
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::dashboard_user_service;
use sqlx::Error;

#[derive(Debug)]
pub enum WaitlistXpError {
    InvalidEmail,
    InvalidWalletAddress,
    WalletNotConnected,
    EmailNotOnWaitlist,
    EmailAlreadyClaimed { claimed_by_user_id: String },
    Database(Error),
}

impl From<Error> for WaitlistXpError {
    fn from(e: Error) -> Self {
        WaitlistXpError::Database(e)
    }
}

impl WaitlistXpError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidEmail => "Invalid email address",
            Self::InvalidWalletAddress => "Invalid wallet address format",
            Self::WalletNotConnected => "Wallet must be connected before claiming XP",
            Self::EmailNotOnWaitlist => "Email not found on the SenseiFi waitlist",
            Self::EmailAlreadyClaimed { .. } => {
                "This waitlist email has already been claimed by another account"
            }
            Self::Database(_) => "Database error",
        }
    }
}

fn normalize_email(email: &str) -> Option<String> {
    let trimmed = email.trim().trim_start_matches('\n').trim_start_matches('\r');
    if trimmed.is_empty() || !trimmed.contains('@') {
        return None;
    }
    Some(trimmed.to_lowercase())
}

fn xp_per_referral() -> i32 {
    std::env::var("XP_PER_REFERRAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
}

fn xp_per_level2_referral() -> i32 {
    std::env::var("XP_PER_LEVEL2_REFERRAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
}

pub async fn preview_xp_by_email(
    pool: &DbPool,
    email: &str,
) -> Result<WaitlistXpBreakdown, WaitlistXpError> {
    let email = normalize_email(email).ok_or(WaitlistXpError::InvalidEmail)?;
    let entry = WaitlistRepository::find_entry_by_email(pool, &email)
        .await?
        .ok_or(WaitlistXpError::EmailNotOnWaitlist)?;

    WaitlistRepository::compute_xp_breakdown(
        pool,
        entry.id,
        &entry.email,
        xp_per_referral(),
        xp_per_level2_referral(),
    )
    .await
    .map_err(WaitlistXpError::from)
}

fn existing_claim_result(claim: UserXpClaim, requested_email: &str) -> ClaimXpResult {
    ClaimXpResult {
        email_mismatch: claim.email.to_lowercase() != requested_email,
        already_claimed: true,
        claim,
    }
}

pub async fn claim_xp(
    pool: &DbPool,
    email: &str,
    wallet_address: &str,
) -> Result<ClaimXpResult, WaitlistXpError> {
    let email = normalize_email(email).ok_or(WaitlistXpError::InvalidEmail)?;
    if !is_valid_eth_address(wallet_address) {
        return Err(WaitlistXpError::InvalidWalletAddress);
    }
    let wallet_address = canonical_eth_address(wallet_address);

    let wallet = WalletRepository::get_wallet_by_address(pool, &wallet_address)
        .await?
        .ok_or(WaitlistXpError::WalletNotConnected)?;
    if !wallet.is_active {
        return Err(WaitlistXpError::WalletNotConnected);
    }

    let dashboard_user =
        dashboard_user_service::get_or_create_for_wallet(pool, &wallet_address).await?;

    // Wallet already claimed: return stored XP (idempotent), even if a different email is submitted.
    if let Some(existing) = WaitlistRepository::get_claim_by_wallet(pool, &wallet_address).await? {
        return Ok(existing_claim_result(existing, &email));
    }

    if let Some(existing) =
        WaitlistRepository::get_claim_by_user_id(pool, &dashboard_user.user_id).await?
    {
        return Ok(existing_claim_result(existing, &email));
    }

    let entry = WaitlistRepository::find_entry_by_email(pool, &email)
        .await?
        .ok_or(WaitlistXpError::EmailNotOnWaitlist)?;

    if let Some(existing) = WaitlistRepository::get_claim_by_email(pool, &email).await? {
        if existing.user_id == dashboard_user.user_id {
            return Ok(existing_claim_result(existing, &email));
        }
        return Err(WaitlistXpError::EmailAlreadyClaimed {
            claimed_by_user_id: existing.user_id,
        });
    }

    let breakdown = WaitlistRepository::compute_xp_breakdown(
        pool,
        entry.id,
        &entry.email,
        xp_per_referral(),
        xp_per_level2_referral(),
    )
    .await?;

    let claim = WaitlistRepository::insert_claim(
        pool,
        &dashboard_user.user_id,
        &wallet_address,
        entry.id,
        &entry.email,
        breakdown.xp,
        breakdown.direct_referrals,
        breakdown.level2_referrals,
    )
    .await?;

    let _ = WalletRepository::update_wallet_user_id(
        pool,
        &wallet_address,
        &dashboard_user.user_id,
    )
    .await;

    Ok(ClaimXpResult {
        claim,
        already_claimed: false,
        email_mismatch: false,
    })
}

pub async fn get_claim_for_wallet(
    pool: &DbPool,
    wallet_address: &str,
) -> Result<Option<UserXpClaim>, WaitlistXpError> {
    if !is_valid_eth_address(wallet_address) {
        return Err(WaitlistXpError::InvalidWalletAddress);
    }
    let wallet_address = canonical_eth_address(wallet_address);
    WaitlistRepository::get_claim_by_wallet(pool, &wallet_address)
        .await
        .map_err(WaitlistXpError::from)
}

pub async fn get_claim_for_user_id(
    pool: &DbPool,
    user_id: &str,
) -> Result<Option<UserXpClaim>, WaitlistXpError> {
    WaitlistRepository::get_claim_by_user_id(pool, user_id)
        .await
        .map_err(WaitlistXpError::from)
}
