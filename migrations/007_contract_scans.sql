-- Smart Wallet Scanner: store scan results per contract (trust score, risk flags, tokens, owner count).
CREATE TABLE IF NOT EXISTS contract_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_address VARCHAR(42) NOT NULL,
    trust_score INT NOT NULL CHECK (trust_score >= 0 AND trust_score <= 100),
    critical_risk_flags INT NOT NULL DEFAULT 0,
    token_controlled TEXT NOT NULL DEFAULT '',
    owner_admin_count INT NOT NULL DEFAULT 0,
    details JSONB DEFAULT '{}',
    scanned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_contract_scans_contract_address ON contract_scans(contract_address);
CREATE INDEX IF NOT EXISTS idx_contract_scans_scanned_at ON contract_scans(scanned_at DESC);

COMMENT ON TABLE contract_scans IS 'Smart Wallet Scanner results: trust score, risk flags, tokens controlled, owner/admin count.';
