-- Toggle state for Protection Control UI (5 switches per wallet).
CREATE TABLE IF NOT EXISTS user_protection_settings (
    wallet_address VARCHAR(42) PRIMARY KEY,
    auto_security_scan BOOLEAN NOT NULL DEFAULT true,
    high_risk_tx_warnings BOOLEAN NOT NULL DEFAULT true,
    new_approval_alerts BOOLEAN NOT NULL DEFAULT true,
    new_dapp_connection_alerts BOOLEAN NOT NULL DEFAULT true,
    auto_block_high_risk BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE user_protection_settings IS 'Protection Control UI: toggle state for 5 switches (auto scan, tx warnings, approval alerts, dApp alerts, autoblock malicious).';
