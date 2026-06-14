//! Deduct claimed waitlist XP when users consume app features.

use crate::db::DbPool;
use crate::models::waitlist::XpChargeResult;
use crate::models::wallet::normalize_wallet_address_for_lookup;
use crate::repositories::waitlist_repository::WaitlistRepository;
use serde_json::{json, Value};
use sqlx::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpUsageAction {
    TxAnalysis,
    ContractScan,
    DappCheck,
    DashboardAnalyze,
}

impl XpUsageAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TxAnalysis => "tx_analysis",
            Self::ContractScan => "contract_scan",
            Self::DappCheck => "dapp_check",
            Self::DashboardAnalyze => "dashboard_analyze",
        }
    }

    pub fn cost(self) -> i32 {
        let key = match self {
            Self::TxAnalysis => "XP_COST_TX_ANALYSIS",
            Self::ContractScan => "XP_COST_CONTRACT_SCAN",
            Self::DappCheck => "XP_COST_DAPP_CHECK",
            Self::DashboardAnalyze => "XP_COST_DASHBOARD_ANALYZE",
        };
        env_i32(key).unwrap_or_else(|| env_i32("XP_COST_PER_USAGE").unwrap_or(1))
    }
}

#[derive(Debug)]
pub enum XpUsageError {
    InsufficientXp {
        xp_balance: i32,
        xp_cost: i32,
        action_type: String,
    },
    Database(Error),
}

impl From<Error> for XpUsageError {
    fn from(e: Error) -> Self {
        XpUsageError::Database(e)
    }
}

impl XpUsageError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::InsufficientXp { .. } => "Insufficient XP balance for this action",
            Self::Database(_) => "Database error",
        }
    }
}

fn env_i32(key: &str) -> Option<i32> {
    std::env::var(key).ok()?.parse().ok().filter(|v| *v > 0)
}

pub fn xp_usage_billing_enabled() -> bool {
    std::env::var("XP_USAGE_BILLING_ENABLED")
        .map(|s| s != "false" && s != "0")
        .unwrap_or(true)
}

/// Charge XP for a wallet-scoped app action. Skips silently if the wallet has no XP claim.
pub async fn charge_wallet_usage(
    pool: &DbPool,
    wallet_address: &str,
    action: XpUsageAction,
    metadata: Option<Value>,
) -> Result<Option<XpChargeResult>, XpUsageError> {
    if !xp_usage_billing_enabled() {
        return Ok(None);
    }

    let wallet_address = normalize_wallet_address_for_lookup(wallet_address);
    let Some(claim) = WaitlistRepository::get_claim_by_wallet(pool, &wallet_address).await? else {
        return Ok(None);
    };

    charge_user_usage(pool, &claim.user_id, &wallet_address, action, metadata).await
}

pub async fn charge_user_usage(
    pool: &DbPool,
    user_id: &str,
    wallet_address: &str,
    action: XpUsageAction,
    metadata: Option<Value>,
) -> Result<Option<XpChargeResult>, XpUsageError> {
    if !xp_usage_billing_enabled() {
        return Ok(None);
    }

    let action_type = action.as_str();
    let xp_cost = action.cost();

    let updated = WaitlistRepository::deduct_xp_for_usage(
        pool,
        user_id,
        wallet_address,
        action_type,
        xp_cost,
        metadata,
    )
    .await?;

    match updated {
        Some((xp_earned, xp_spent, xp_balance)) => Ok(Some(XpChargeResult {
            action_type: action_type.to_string(),
            xp_cost,
            xp_spent,
            xp_balance,
            xp_earned,
        })),
        None => {
            let claim = WaitlistRepository::get_claim_by_user_id(pool, user_id)
                .await?
                .ok_or_else(|| XpUsageError::InsufficientXp {
                    xp_balance: 0,
                    xp_cost,
                    action_type: action_type.to_string(),
                })?;
            Err(XpUsageError::InsufficientXp {
                xp_balance: claim.xp_balance(),
                xp_cost,
                action_type: action_type.to_string(),
            })
        }
    }
}

pub fn insufficient_xp_json(xp_balance: i32, xp_cost: i32, action_type: &str) -> Value {
    json!({
        "success": false,
        "error": "Insufficient XP balance for this action",
        "xp_balance": xp_balance,
        "xp_cost": xp_cost,
        "action_type": action_type,
    })
}

pub fn parse_insufficient_xp_error(message: &str) -> Option<(i32, i32)> {
    let rest = message.strip_prefix("insufficient_xp:")?;
    let mut parts = rest.split(':');
    let balance = parts.next()?.parse().ok()?;
    let cost = parts.next()?.parse().ok()?;
    Some((balance, cost))
}

pub async fn list_recent_usage(
    pool: &DbPool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<crate::models::waitlist::XpUsageEvent>, XpUsageError> {
    WaitlistRepository::list_usage_events(pool, user_id, limit)
        .await
        .map_err(XpUsageError::from)
}

pub async fn list_usage_for_account(
    pool: &DbPool,
    wallet_address: Option<&str>,
    user_id: Option<&str>,
    limit: Option<i64>,
) -> Result<Value, XpUsageError> {
    let limit = limit.unwrap_or(50).clamp(1, 100);

    if wallet_address.is_none() && user_id.is_none() {
        return Ok(json!({
            "success": false,
            "error": "wallet_address or user_id is required"
        }));
    }

    let resolved_user_id = if let Some(uid) = user_id {
        uid.to_string()
    } else {
        let addr = normalize_wallet_address_for_lookup(wallet_address.unwrap_or_default());
        match WaitlistRepository::get_claim_by_wallet(pool, &addr).await? {
            Some(claim) => claim.user_id,
            None => {
                return Ok(json!({
                    "success": true,
                    "claimed": false,
                    "data": []
                }));
            }
        }
    };

    let claim = WaitlistRepository::get_claim_by_user_id(pool, &resolved_user_id).await?;
    let Some(claim) = claim else {
        return Ok(json!({
            "success": true,
            "claimed": false,
            "data": []
        }));
    };

    let events = list_recent_usage(pool, &resolved_user_id, limit).await?;

    Ok(json!({
        "success": true,
        "claimed": true,
        "data": events,
        "xp": claim.xp_balance(),
        "xp_earned": claim.xp,
        "xp_spent": claim.xp_spent,
    }))
}
