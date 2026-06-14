-- Solana wallet addresses for XP billing and protection scan history.
ALTER TABLE user_xp_claims
    ALTER COLUMN wallet_address TYPE VARCHAR(64);

ALTER TABLE xp_usage_events
    ALTER COLUMN wallet_address TYPE VARCHAR(64);

ALTER TABLE wallet_scan_history
    ALTER COLUMN wallet_address TYPE VARCHAR(64);
