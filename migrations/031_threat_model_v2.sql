-- Threat Model v2: kill-chain stage and campaign linkage on threats/events.

ALTER TABLE threats
  ADD COLUMN IF NOT EXISTS kill_chain_stage TEXT,
  ADD COLUMN IF NOT EXISTS campaign_id UUID REFERENCES threat_campaigns(id) ON DELETE SET NULL;

ALTER TABLE threat_events
  ADD COLUMN IF NOT EXISTS kill_chain_stage TEXT;

CREATE INDEX IF NOT EXISTS idx_threats_campaign_id ON threats(campaign_id);
CREATE INDEX IF NOT EXISTS idx_threats_kill_chain_stage ON threats(kill_chain_stage);
CREATE INDEX IF NOT EXISTS idx_threat_events_kill_chain_stage ON threat_events(kill_chain_stage);
