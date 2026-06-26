-- Replace Stripe + on-chain billing columns/tables with BoomFi-only billing.
-- Idempotent: safe if on-chain tables were already dropped or Stripe columns already renamed.

DROP TABLE IF EXISTS subscription_cycles;
DROP TABLE IF EXISTS subscription_charge_attempts;
DROP TABLE IF EXISTS onchain_event_log;
DROP TABLE IF EXISTS onchain_payment_profiles;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_subscriptions'
          AND column_name = 'stripe_customer_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_subscriptions'
          AND column_name = 'boomfi_customer_id'
    ) THEN
        ALTER TABLE user_subscriptions
            RENAME COLUMN stripe_customer_id TO boomfi_customer_id;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_subscriptions'
          AND column_name = 'stripe_subscription_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_subscriptions'
          AND column_name = 'boomfi_subscription_id'
    ) THEN
        ALTER TABLE user_subscriptions
            RENAME COLUMN stripe_subscription_id TO boomfi_subscription_id;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_subscriptions'
          AND column_name = 'stripe_price_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_subscriptions'
          AND column_name = 'boomfi_plan_id'
    ) THEN
        ALTER TABLE user_subscriptions
            RENAME COLUMN stripe_price_id TO boomfi_plan_id;
    END IF;
END $$;

DROP INDEX IF EXISTS idx_user_subscriptions_customer_id;
DROP INDEX IF EXISTS idx_user_subscriptions_subscription_id;

CREATE INDEX IF NOT EXISTS idx_user_subscriptions_boomfi_customer_id
    ON user_subscriptions(boomfi_customer_id);

CREATE INDEX IF NOT EXISTS idx_user_subscriptions_boomfi_subscription_id
    ON user_subscriptions(boomfi_subscription_id);

COMMENT ON TABLE user_subscriptions IS 'Billing state synced from BoomFi for each dashboard user.';
