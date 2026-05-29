use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize)]
pub struct WaitlistXpBreakdown {
    pub email: String,
    pub waitlist_entry_id: i32,
    pub direct_referrals: i32,
    pub level2_referrals: i32,
    pub xp: i32,
    pub xp_per_referral: i32,
    pub xp_per_level2_referral: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserXpClaim {
    pub user_id: String,
    pub wallet_address: String,
    pub email: String,
    pub waitlist_entry_id: i32,
    pub xp: i32,
    pub direct_referrals: i32,
    pub level2_referrals: i32,
    pub claimed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ClaimWaitlistXpRequest {
    pub email: String,
    pub wallet_address: String,
}

#[derive(Debug, Clone)]
pub struct ClaimXpResult {
    pub claim: UserXpClaim,
    pub already_claimed: bool,
    pub email_mismatch: bool,
}

/// JSON shape compatible with the legacy waitlist API (`successfulCount`, `level2Count`).
pub fn xp_breakdown_json(b: &WaitlistXpBreakdown) -> Value {
    json!({
        "email": b.email,
        "waitlist_entry_id": b.waitlist_entry_id,
        "direct_referrals": b.direct_referrals,
        "successfulCount": b.direct_referrals,
        "level2_referrals": b.level2_referrals,
        "level2Count": b.level2_referrals,
        "xp": b.xp,
        "xp_per_referral": b.xp_per_referral,
        "xp_per_level2_referral": b.xp_per_level2_referral,
    })
}

pub fn xp_claim_json(c: &UserXpClaim) -> Value {
    json!({
        "user_id": c.user_id,
        "wallet_address": c.wallet_address,
        "email": c.email,
        "waitlist_entry_id": c.waitlist_entry_id,
        "direct_referrals": c.direct_referrals,
        "successfulCount": c.direct_referrals,
        "level2_referrals": c.level2_referrals,
        "level2Count": c.level2_referrals,
        "xp": c.xp,
        "claimed_at": c.claimed_at,
    })
}
