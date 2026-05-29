-- Track XP spent on app usage; xp balance = xp - xp_spent.

ALTER TABLE user_xp_claims
    ADD COLUMN IF NOT EXISTS xp_spent INT NOT NULL DEFAULT 0 CHECK (xp_spent >= 0);

ALTER TABLE user_xp_claims
    ADD CONSTRAINT user_xp_claims_spent_not_exceed_earned
    CHECK (xp_spent <= xp);

CREATE TABLE IF NOT EXISTS xp_usage_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(64) NOT NULL REFERENCES dashboard_users(user_id) ON DELETE CASCADE,
    wallet_address VARCHAR(42) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    xp_cost INT NOT NULL CHECK (xp_cost > 0),
    xp_balance_after INT NOT NULL CHECK (xp_balance_after >= 0),
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_xp_usage_events_user_id
    ON xp_usage_events (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_xp_usage_events_wallet
    ON xp_usage_events (LOWER(wallet_address), created_at DESC);

COMMENT ON COLUMN user_xp_claims.xp_spent IS 'Total XP consumed by in-app usage.';
COMMENT ON TABLE xp_usage_events IS 'Ledger of XP deductions for app usage (tx analysis, scans, etc.).';
