-- Optional wallet context per scan: for behavioral anomaly and trend (wallets_affected).
ALTER TABLE contract_scans ADD COLUMN IF NOT EXISTS scanned_for_address VARCHAR(42);
CREATE INDEX IF NOT EXISTS idx_contract_scans_scanned_for ON contract_scans(scanned_for_address);
CREATE INDEX IF NOT EXISTS idx_contract_scans_contract_scanned_at ON contract_scans(contract_address, scanned_at DESC);

COMMENT ON COLUMN contract_scans.scanned_for_address IS 'Wallet address that requested scan; for user-aware risk and trend.';
