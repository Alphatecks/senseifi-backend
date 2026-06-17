use crate::db::DbPool;
use crate::models::onchain_payment::{OnchainSubscribeRequest, OnchainSubscribeResponse};
use crate::models::wallet::{
    canonical_eth_address, is_valid_eth_address, onchain_billing_chain_id,
    onchain_billing_network_label, wallet_eligible_for_onchain_billing,
};
use crate::repositories::dashboard_user_repository::DashboardUserRepository;
use crate::repositories::subscription_repository::{
    SubscriptionRepository, UpsertSubscriptionInput,
};
use crate::repositories::wallet_repository::WalletRepository;
use crate::services::onchain_payment_webhook_service::OnchainPaymentWebhookService;
use crate::services::plan_catalog::{
    normalize_billing_cycle, normalize_plan, subscription_id_bytes32_hex, OnchainPriceTable,
};
use rust_decimal::Decimal;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BillingContextResponse {
    pub onchain_enabled: bool,
    pub chain_id: i32,
    pub network_label: String,
    pub requires_evm_wallet: bool,
    pub payer_address: Option<String>,
    pub can_subscribe: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub struct OnchainSubscribeService;

impl OnchainSubscribeService {
    /// Tells the client which wallet to use for USDC billing (may differ from the active Solana wallet).
    pub async fn billing_context(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<BillingContextResponse, String> {
        let chain_id = onchain_billing_chain_id();
        let network_label = onchain_billing_network_label(chain_id).to_string();
        let onchain_enabled = OnchainPaymentWebhookService::is_onchain_enabled();

        if !onchain_enabled {
            return Ok(BillingContextResponse {
                onchain_enabled: false,
                chain_id,
                network_label,
                requires_evm_wallet: true,
                payer_address: None,
                can_subscribe: false,
                message: Some("Onchain payments are disabled".to_string()),
            });
        }

        let wallets = WalletRepository::get_all_active_wallets_by_user(pool, user_id)
            .await
            .map_err(|e| format!("Failed to load wallets: {e}"))?;

        let payer_address = wallets
            .iter()
            .find(|w| wallet_eligible_for_onchain_billing(w.chain_id, &w.address))
            .map(|w| canonical_eth_address(&w.address));

        let can_subscribe = payer_address.is_some();
        let message = if can_subscribe {
            None
        } else {
            Some(format!(
                "Billing currently supports EVM wallets (0x…) on {network_label}. Connect an EVM wallet to continue."
            ))
        };

        Ok(BillingContextResponse {
            onchain_enabled: true,
            chain_id,
            network_label,
            requires_evm_wallet: true,
            payer_address,
            can_subscribe,
            message,
        })
    }

    pub async fn subscribe(
        pool: &DbPool,
        req: OnchainSubscribeRequest,
    ) -> Result<OnchainSubscribeResponse, String> {
        if !OnchainPaymentWebhookService::is_onchain_enabled() {
            return Err("Onchain payments are disabled".to_string());
        }

        let user_id = req.user_id.trim();
        if user_id.is_empty() {
            return Err("user_id is required".to_string());
        }

        if DashboardUserRepository::get_by_user_id(pool, user_id)
            .await
            .map_err(|e| format!("Failed to validate user_id: {e}"))?
            .is_none()
        {
            return Err("Unknown user_id. Connect wallet first.".to_string());
        }

        let normalized_plan = normalize_plan(&req.plan)
            .ok_or_else(|| "Invalid plan. Use pro, pro+, or premium.".to_string())?;
        let normalized_cycle = normalize_billing_cycle(req.billing_cycle.as_deref())
            .ok_or_else(|| "Invalid billing_cycle. Use monthly or annual.".to_string())?;

        let payer = req.payer_address.trim();
        if payer.is_empty() || !is_valid_eth_address(payer) {
            return Err("Invalid payer_address".to_string());
        }

        let prices = OnchainPriceTable::from_env_or_default();
        let amount_usdc = prices
            .price_usd(&normalized_plan, &normalized_cycle)
            .ok_or_else(|| "Plan is missing onchain price mapping.".to_string())?;

        let chain_id = req.chain_id.unwrap_or_else(onchain_billing_chain_id);

        let token_contract = req
            .token_contract
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| {
                std::env::var("ONCHAIN_USDC_CONTRACT")
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
            })
            .ok_or_else(|| {
                "token_contract is required (or set ONCHAIN_USDC_CONTRACT)".to_string()
            })?;

        let payment_contract = req
            .payment_contract
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| {
                std::env::var("ONCHAIN_PAYMENT_CONTRACT")
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
            })
            .ok_or_else(|| {
                "payment_contract is required (or set ONCHAIN_PAYMENT_CONTRACT)".to_string()
            })?;

        if !is_valid_eth_address(&token_contract) || !is_valid_eth_address(&payment_contract) {
            return Err("Invalid token_contract or payment_contract address".to_string());
        }

        let amount_dec = Decimal::from_f64_retain(amount_usdc)
            .ok_or_else(|| "Internal error: invalid configured price amount".to_string())?;
        let max_charge_f = req.max_charge_usdc.unwrap_or(amount_usdc);
        let max_dec = Decimal::from_f64_retain(max_charge_f)
            .ok_or_else(|| "max_charge_usdc is not a valid amount".to_string())?;
        if max_dec < amount_dec {
            return Err(format!(
                "max_charge_usdc ({max_charge_f}) must be >= amount for one billing period ({amount_usdc})"
            ));
        }

        let sub = SubscriptionRepository::upsert(
            pool,
            UpsertSubscriptionInput {
                user_id,
                plan: &normalized_plan,
                billing_cycle: &normalized_cycle,
                status: "inactive",
                stripe_customer_id: None,
                stripe_subscription_id: None,
                stripe_price_id: None,
                checkout_session_id: None,
                current_period_end_unix: None,
                cancel_at_period_end: false,
            },
        )
        .await
        .map_err(|e| format!("Failed to save subscription: {e}"))?;

        OnchainPaymentWebhookService::upsert_payment_profile(
            pool,
            user_id,
            payer,
            chain_id,
            &token_contract,
            &payment_contract,
            Some(max_dec),
        )
        .await?;

        let amount_base = usdc_decimal_to_base_units_string(amount_dec);
        let max_base = usdc_decimal_to_base_units_string(max_dec);

        Ok(OnchainSubscribeResponse {
            subscription_id: sub.id,
            subscription_id_bytes32: subscription_id_bytes32_hex(&sub.id),
            plan: normalized_plan,
            billing_cycle: normalized_cycle,
            chain_id,
            token_contract,
            payment_contract,
            amount_usdc_per_period: amount_usdc,
            max_charge_usdc: max_charge_f,
            amount_usdc_per_period_base_units: amount_base,
            max_charge_usdc_base_units: max_base,
            currency: "USD".to_string(),
        })
    }
}

/// USDC uses 6 decimals on Base. Integer string avoids float/JSON issues in the frontend.
fn usdc_decimal_to_base_units_string(d: Decimal) -> String {
    let factor = Decimal::from(1_000_000u32);
    let scaled = (d * factor).trunc();
    scaled
        .to_string()
        .split('.')
        .next()
        .unwrap_or("0")
        .to_string()
}
