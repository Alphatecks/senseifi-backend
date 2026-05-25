-- Phase 2: threat verification metadata + remediation action log

ALTER TABLE threats
  ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS verification_method TEXT,
  ADD COLUMN IF NOT EXISTS verification_message TEXT;

UPDATE threats
SET verification_status = 'pending'
WHERE verification_status IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'threats_verification_status_check'
  ) THEN
    ALTER TABLE threats
      ADD CONSTRAINT threats_verification_status_check
      CHECK (verification_status IN ('pending', 'verified', 'failed', 'not_applicable'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_threats_verification_status
  ON threats(verification_status, detected_at DESC);

CREATE TABLE IF NOT EXISTS threat_remediation_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  threat_id UUID NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_remediation_actions_threat_id_created_at
  ON threat_remediation_actions(threat_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_remediation_actions_wallet_id_created_at
  ON threat_remediation_actions(wallet_id, created_at DESC);
