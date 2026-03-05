-- Transaction monitoring: per-wallet list of monitored tx/activity types with risk level.
CREATE TABLE IF NOT EXISTS transaction_monitoring (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_transaction_monitoring_wallet_id ON transaction_monitoring(wallet_id);
CREATE INDEX IF NOT EXISTS idx_transaction_monitoring_detected_at ON transaction_monitoring(detected_at DESC);

COMMENT ON TABLE transaction_monitoring IS 'Monitored transaction/activity types per wallet for Transaction monitoring UI; title + risk level.';
