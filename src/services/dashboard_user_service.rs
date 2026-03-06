//! Creates or returns dashboard identity (user_id, display_name, user_number) when user connects wallet.

use crate::db::DbPool;
use crate::models::wallet::DashboardUser;
use crate::repositories::dashboard_user_repository::DashboardUserRepository;
use rand::Rng;
use sqlx::Error;

const DISPLAY_NAMES: &[&str] = &[
    "Stealth bag",
    "Megatron",
    "Alpha",
    "Shadow",
    "Phantom",
    "Vault",
    "Sentinel",
    "Nexus",
    "Apex",
    "Cipher",
];

/// Generate a random user_id string (lowercase alphanumeric, ~14 chars) like "fetrtwgebejhssns".
fn random_user_id() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..14)
        .map(|_| {
            let i = rng.gen_range(0..CHARS.len());
            CHARS[i] as char
        })
        .collect()
}

fn random_display_name() -> &'static str {
    let i = rand::thread_rng().gen_range(0..DISPLAY_NAMES.len());
    DISPLAY_NAMES[i]
}

fn random_user_number() -> i32 {
    rand::thread_rng().gen_range(1000..=9999)
}

/// Get existing dashboard user for wallet, or create one with random user_id, display_name, user_number.
pub async fn get_or_create_for_wallet(
    pool: &DbPool,
    wallet_address: &str,
) -> Result<DashboardUser, Error> {
    if let Some(du) = DashboardUserRepository::get_by_wallet(pool, wallet_address).await? {
        return Ok(du);
    }
    let user_id = random_user_id();
    let display_name = random_display_name().to_string();
    let user_number = random_user_number();
    DashboardUserRepository::create(pool, wallet_address, &user_id, &display_name, user_number)
        .await
}
