-- Non-custodial onchain subscription billing primitives (Base USDC focused).

CREATE TABLE IF NOT EXISTS onchain_payment_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(64) NOT NULL UNIQUE REFERENCES dashboard_users(user_id) ON DELETE CASCADE,
    payer_address VARCHAR(64) NOT NULL,
    chain_id INTEGER NOT NULL DEFAULT 8453,
    token_contract VARCHAR(64) NOT NULL,
    payment_contract VARCHAR(64) NOT NULL,
    allowance_status VARCHAR(16) NOT NULL DEFAULT 'none'
        CHECK (allowance_status IN ('none', 'active', 'revoked')),
    max_charge_usdc NUMERIC(20, 6),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_onchain_payment_profiles_chain CHECK (chain_id > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_onchain_payment_profiles_chain_payer
ON onchain_payment_profiles(chain_id, payer_address);

CREATE INDEX IF NOT EXISTS idx_onchain_payment_profiles_user
ON onchain_payment_profiles(user_id);

CREATE TABLE IF NOT EXISTS subscription_charge_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(64) NOT NULL REFERENCES dashboard_users(user_id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES user_subscriptions(id) ON DELETE CASCADE,
    chain_id INTEGER NOT NULL DEFAULT 8453,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    amount_usdc NUMERIC(20, 6) NOT NULL,
    status VARCHAR(32) NOT NULL
        CHECK (status IN ('created', 'submitted', 'pending_confirmation', 'confirmed', 'failed', 'cancelled')),
    onchain_tx_hash VARCHAR(80),
    onchain_nonce BIGINT,
    failure_code VARCHAR(64),
    failure_reason TEXT,
    idempotency_key VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_subscription_charge_attempts_chain CHECK (chain_id > 0),
    CONSTRAINT chk_subscription_charge_attempts_period CHECK (period_end > period_start)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_subscription_charge_attempts_chain_tx
ON subscription_charge_attempts(chain_id, onchain_tx_hash)
WHERE onchain_tx_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_subscription_charge_attempts_subscription
ON subscription_charge_attempts(subscription_id);

CREATE INDEX IF NOT EXISTS idx_subscription_charge_attempts_status
ON subscription_charge_attempts(status);

CREATE TABLE IF NOT EXISTS onchain_event_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(64) NOT NULL,
    event_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(120) NOT NULL,
    chain_id INTEGER NOT NULL DEFAULT 8453,
    tx_hash VARCHAR(80),
    payload JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    processing_status VARCHAR(16) NOT NULL DEFAULT 'received'
        CHECK (processing_status IN ('received', 'processed', 'failed', 'ignored')),
    error TEXT,
    CONSTRAINT chk_onchain_event_log_chain CHECK (chain_id > 0),
    CONSTRAINT ux_onchain_event_log_provider_event UNIQUE (provider, event_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_onchain_event_log_chain_tx_type
ON onchain_event_log(chain_id, tx_hash, event_type)
WHERE tx_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_onchain_event_log_status
ON onchain_event_log(processing_status);

CREATE TABLE IF NOT EXISTS subscription_cycles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(64) NOT NULL REFERENCES dashboard_users(user_id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES user_subscriptions(id) ON DELETE CASCADE,
    plan VARCHAR(32) NOT NULL,
    billing_cycle VARCHAR(16) NOT NULL,
    amount_due_usdc NUMERIC(20, 6) NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    charge_attempt_id UUID REFERENCES subscription_charge_attempts(id) ON DELETE SET NULL,
    status VARCHAR(16) NOT NULL
        CHECK (status IN ('scheduled', 'charging', 'paid', 'failed', 'grace', 'cancelled')),
    grace_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_subscription_cycles_grace_window
        CHECK (grace_expires_at IS NULL OR grace_expires_at > due_at)
);

CREATE INDEX IF NOT EXISTS idx_subscription_cycles_due_status
ON subscription_cycles(due_at, status);

CREATE INDEX IF NOT EXISTS idx_subscription_cycles_subscription
ON subscription_cycles(subscription_id);

CREATE INDEX IF NOT EXISTS idx_subscription_cycles_user
ON subscription_cycles(user_id);

COMMENT ON TABLE onchain_payment_profiles IS 'Per-user non-custodial Base USDC payment configuration.';
COMMENT ON TABLE subscription_charge_attempts IS 'Each onchain charge attempt for a subscription cycle.';
COMMENT ON TABLE onchain_event_log IS 'Idempotent log of contract/indexer webhook events.';
COMMENT ON TABLE subscription_cycles IS 'Renewal schedule and lifecycle state per subscription period.';
