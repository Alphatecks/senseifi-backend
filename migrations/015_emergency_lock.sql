-- Emergency Wallet Lock: block approvals/transfers except to whitelist.
ALTER TABLE user_protection_settings ADD COLUMN IF NOT EXISTS emergency_lock BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE user_protection_settings ADD COLUMN IF NOT EXISTS whitelisted_addresses JSONB DEFAULT '[]';
COMMENT ON COLUMN user_protection_settings.emergency_lock IS 'When true, block approvals and non-whitelisted transfers.';
COMMENT ON COLUMN user_protection_settings.whitelisted_addresses IS 'Array of 0x addresses allowed when emergency_lock is on.';
