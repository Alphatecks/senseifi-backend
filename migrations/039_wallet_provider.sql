-- WalletConnect and multi-provider connect: store which wallet app the user picked.
ALTER TABLE wallets
    ADD COLUMN IF NOT EXISTS wallet_provider VARCHAR(32);

ALTER TABLE wallets
    ADD COLUMN IF NOT EXISTS wallet_name VARCHAR(64);

COMMENT ON COLUMN wallets.wallet_provider IS
    'Slug for the wallet app (e.g. trustwallet, rainbow). Set from WalletConnect session metadata or direct connect.';

COMMENT ON COLUMN wallets.wallet_name IS
    'Human-readable wallet label from the client (e.g. Trust Wallet). Preferred for UI display when set.';
