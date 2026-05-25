-- Threat lifecycle status for remediation flow (Phase 1)
-- Backward-compatible: existing rows default to open.

ALTER TABLE threats
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS dismissed_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS resolution_note TEXT,
  ADD COLUMN IF NOT EXISTS dismiss_reason TEXT;

UPDATE threats
SET status = 'open'
WHERE status IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'threats_status_check'
  ) THEN
    ALTER TABLE threats
      ADD CONSTRAINT threats_status_check
      CHECK (status IN ('open', 'resolved', 'dismissed'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_threats_wallet_status_detected
  ON threats(wallet_id, status, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_threats_open_detected
  ON threats(wallet_id, detected_at DESC)
  WHERE status = 'open';
