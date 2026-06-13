-- Solana asset sync: persist cluster network and support SPL mint addresses (base58, up to 44 chars).
ALTER TABLE wallets
    ADD COLUMN IF NOT EXISTS network VARCHAR(32);

ALTER TABLE wallet_assets
    ALTER COLUMN contract_address TYPE VARCHAR(64);

COMMENT ON COLUMN wallets.network IS
    'Solana cluster: mainnet or devnet. NULL for EVM wallets.';
