-- Approval & Permission: store contract approvals for wallet security UI (Surface 1).
CREATE TABLE IF NOT EXISTS wallet_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    contract_address VARCHAR(42) NOT NULL,
    approval_type VARCHAR(20) NOT NULL CHECK (approval_type IN ('unlimited', 'limited')),
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wallet_approvals_wallet_id ON wallet_approvals(wallet_id);
CREATE INDEX IF NOT EXISTS idx_wallet_approvals_detected_at ON wallet_approvals(detected_at DESC);

COMMENT ON TABLE wallet_approvals IS 'ERC20/721 approvals per wallet for Approval & Permission UI; populated by scan or indexer.';
