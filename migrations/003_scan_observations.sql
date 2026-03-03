-- Store scan report (observations) per scan
ALTER TABLE security_scans
  ADD COLUMN IF NOT EXISTS observations JSONB NOT NULL DEFAULT '[]';

COMMENT ON COLUMN security_scans.observations IS 'Array of { type, title, description?, severity?, detail? } observed during scan';
