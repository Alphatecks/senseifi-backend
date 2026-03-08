-- Auto Security Scan run history (one row per run). GET /api/protection/scan-history.
CREATE TABLE IF NOT EXISTS wallet_scan_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(42) NOT NULL,
    scan_type VARCHAR(64) NOT NULL DEFAULT 'full',
    risk_score INT NOT NULL DEFAULT 0,
    issues_found INT NOT NULL DEFAULT 0,
    details JSONB DEFAULT '{}',
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wallet_scan_history_wallet ON wallet_scan_history(wallet_address);
CREATE INDEX IF NOT EXISTS idx_wallet_scan_history_scanned_at ON wallet_scan_history(scanned_at DESC);

COMMENT ON TABLE wallet_scan_history IS 'One row per auto security scan run; for GET /api/protection/scan-history.';
