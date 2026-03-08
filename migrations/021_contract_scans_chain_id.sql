-- Store chain_id per scan so scan result and GET by id show the correct network (BSC, Polygon, etc.), not a default.
ALTER TABLE contract_scans ADD COLUMN IF NOT EXISTS chain_id BIGINT;
COMMENT ON COLUMN contract_scans.chain_id IS 'Chain ID used for this scan (1=ETH, 56=BSC, 137=Polygon, etc.).';
