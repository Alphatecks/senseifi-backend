-- Indexed ERC-20 rows: chain_id + contract_address for Moralis sync.
-- Legacy rows (contract_address NULL) keep unique (wallet_id, symbol).

ALTER TABLE wallet_assets DROP CONSTRAINT IF EXISTS wallet_assets_wallet_id_symbol_key;

ALTER TABLE wallet_assets ADD COLUMN IF NOT EXISTS chain_id INTEGER;
ALTER TABLE wallet_assets ADD COLUMN IF NOT EXISTS contract_address VARCHAR(42);

-- Normalize legacy symbols so partial unique is stable (best-effort).
UPDATE wallet_assets SET symbol = lower(symbol) WHERE contract_address IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS wallet_assets_wallet_chain_contract_uidx
  ON wallet_assets (wallet_id, chain_id, contract_address)
  WHERE contract_address IS NOT NULL AND chain_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS wallet_assets_wallet_symbol_legacy_uidx
  ON wallet_assets (wallet_id, symbol)
  WHERE contract_address IS NULL;
