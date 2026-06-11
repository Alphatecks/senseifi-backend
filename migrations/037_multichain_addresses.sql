-- Widen address columns for Solana base58 pubkeys (32–44 chars).
ALTER TABLE scam_reports
    ALTER COLUMN contract_address TYPE VARCHAR(64);

ALTER TABLE scam_reports
    ALTER COLUMN reporter_wallet_address TYPE VARCHAR(64);

ALTER TABLE wallets
    ALTER COLUMN address TYPE VARCHAR(64);
