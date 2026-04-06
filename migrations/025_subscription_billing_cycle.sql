ALTER TABLE user_subscriptions
ADD COLUMN IF NOT EXISTS billing_cycle VARCHAR(16) NOT NULL DEFAULT 'monthly';

CREATE INDEX IF NOT EXISTS idx_user_subscriptions_plan_cycle
ON user_subscriptions(plan, billing_cycle);

COMMENT ON COLUMN user_subscriptions.billing_cycle IS 'Billing cycle for the selected plan (monthly or annual).';
