-- Support Solana program IDs (base58, up to 44 chars) in contract scanner tables.
ALTER TABLE contract_scans
    ALTER COLUMN contract_address TYPE VARCHAR(64);

ALTER TABLE contract_scans
    ALTER COLUMN scanned_for_address TYPE VARCHAR(64);

COMMENT ON COLUMN contract_scans.contract_address IS
    'EVM contract (0x…) or Solana program ID (base58).';
