-- Auto Security Scan: which wallet addresses have monitoring on (by address; separate from wallet_monitoring which uses wallet_id).
CREATE TABLE IF NOT EXISTS protection_auto_scan (
    wallet_address VARCHAR(42) PRIMARY KEY,
    auto_scan_enabled BOOLEAN NOT NULL DEFAULT false,
    last_scan_at TIMESTAMP WITH TIME ZONE,
    scan_interval_seconds INT NOT NULL DEFAULT 60,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE protection_auto_scan IS 'Per-address Auto Security Scan toggle; worker runs cycle when auto_scan_enabled = true.';
