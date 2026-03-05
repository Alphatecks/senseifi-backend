-- New Approval Alerts: risky approvals detected and stored for alerting.
CREATE TABLE IF NOT EXISTS wallet_approval_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(42) NOT NULL,
    token_address VARCHAR(42),
    spender_address VARCHAR(42) NOT NULL,
    amount_raw VARCHAR(78),
    risk_score INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wallet_approval_alerts_wallet ON wallet_approval_alerts(wallet_address);
CREATE INDEX IF NOT EXISTS idx_wallet_approval_alerts_created ON wallet_approval_alerts(created_at DESC);
COMMENT ON TABLE wallet_approval_alerts IS 'Risky approvals detected when New Approval Alerts toggle is on.';
