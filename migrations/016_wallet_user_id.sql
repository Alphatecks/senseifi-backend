-- Scope wallets to a user so dashboard overview shows only that user's connected wallets.
ALTER TABLE wallets ADD COLUMN IF NOT EXISTS user_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);
COMMENT ON COLUMN wallets.user_id IS 'Identifier of the user who connected this wallet (e.g. auth provider sub). NULL = legacy/unscoped.';
