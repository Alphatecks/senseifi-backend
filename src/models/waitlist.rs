use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
