-- Actionable protection: block contract, watchlist, report scam.
-- Requires wallet_id (user context). We use wallet address as key for simplicity if no wallet row.
CREATE TABLE IF NOT EXISTS user_blocked_contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(42) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(wallet_address, contract_address)
);
CREATE INDEX IF NOT EXISTS idx_user_blocked_contracts_wallet ON user_blocked_contracts(wallet_address);

CREATE TABLE IF NOT EXISTS user_contract_watchlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(42) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(wallet_address, contract_address)
);
CREATE INDEX IF NOT EXISTS idx_user_contract_watchlist_wallet ON user_contract_watchlist(wallet_address);

CREATE TABLE IF NOT EXISTS scam_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_address VARCHAR(42) NOT NULL,
    reporter_wallet_address VARCHAR(42),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scam_reports_contract ON scam_reports(contract_address);

COMMENT ON TABLE user_blocked_contracts IS 'User chose to block this contract.';
COMMENT ON TABLE user_contract_watchlist IS 'User watchlist for contracts.';
COMMENT ON TABLE scam_reports IS 'User-reported scam; used for reputation and community_flags.';
