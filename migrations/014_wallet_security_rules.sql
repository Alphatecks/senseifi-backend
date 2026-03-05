-- Add New Control: custom rules (block tx >$5k, block contracts <24h, etc.).
CREATE TABLE IF NOT EXISTS wallet_security_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(42) NOT NULL,
    rule_type VARCHAR(64) NOT NULL,
    condition_json JSONB NOT NULL DEFAULT '{}',
    action VARCHAR(32) NOT NULL DEFAULT 'block',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wallet_security_rules_wallet ON wallet_security_rules(wallet_address);
COMMENT ON TABLE wallet_security_rules IS 'Custom rules: block_tx_above_usd, block_contract_younger_than_hours, block_unlimited_approval, etc.';
