-- Solana pubkeys are base58, up to 44 chars, and case-sensitive.
ALTER TABLE dashboard_users
    ALTER COLUMN wallet_address TYPE VARCHAR(64);
