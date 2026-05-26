-- Threat Correlation Engine V1: normalized events, relationship edges, correlated campaigns.

CREATE TABLE IF NOT EXISTS threat_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  threat_id UUID REFERENCES threats(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  signal_category TEXT NOT NULL,
  threat_type TEXT,
  surface TEXT,
  risk_score INT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  confidence_score INT NOT NULL DEFAULT 0 CHECK (confidence_score BETWEEN 0 AND 100),
  source_contract TEXT,
  domain TEXT,
  metadata JSONB NOT NULL DEFAULT '{}',
  event_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_events_wallet_time
  ON threat_events(wallet_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_threat_events_event_type_time
  ON threat_events(event_type, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_threat_events_contract_time
  ON threat_events(source_contract, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_threat_events_domain_time
  ON threat_events(domain, event_time DESC);

CREATE TABLE IF NOT EXISTS threat_entity_edges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  from_entity_type TEXT NOT NULL,
  from_entity_id TEXT NOT NULL,
  edge_type TEXT NOT NULL,
  to_entity_type TEXT NOT NULL,
  to_entity_id TEXT NOT NULL,
  weight INT NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 100),
  metadata JSONB NOT NULL DEFAULT '{}',
  observed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_entity_edges_wallet_observed
  ON threat_entity_edges(wallet_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_entity_edges_to
  ON threat_entity_edges(to_entity_id, edge_type, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_entity_edges_from
  ON threat_entity_edges(from_entity_id, edge_type, observed_at DESC);

CREATE TABLE IF NOT EXISTS threat_campaigns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  campaign_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  risk_score INT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  confidence_score INT NOT NULL DEFAULT 0 CHECK (confidence_score BETWEEN 0 AND 100),
  narrative TEXT NOT NULL,
  signal_categories JSONB NOT NULL DEFAULT '[]',
  first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'threat_campaigns_status_check'
  ) THEN
    ALTER TABLE threat_campaigns
      ADD CONSTRAINT threat_campaigns_status_check
      CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'dismissed'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_threat_campaigns_wallet_status_last_seen
  ON threat_campaigns(wallet_id, status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_campaigns_confidence_last_seen
  ON threat_campaigns(confidence_score DESC, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS threat_campaign_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id UUID NOT NULL REFERENCES threat_campaigns(id) ON DELETE CASCADE,
  event_id UUID REFERENCES threat_events(id) ON DELETE SET NULL,
  edge_id UUID REFERENCES threat_entity_edges(id) ON DELETE SET NULL,
  evidence_type TEXT NOT NULL,
  evidence_rank INT NOT NULL DEFAULT 0,
  detail TEXT,
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'threat_campaign_evidence_type_check'
  ) THEN
    ALTER TABLE threat_campaign_evidence
      ADD CONSTRAINT threat_campaign_evidence_type_check
      CHECK (evidence_type IN ('event', 'edge', 'sequence', 'cooccurrence'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_threat_campaign_evidence_campaign_created
  ON threat_campaign_evidence(campaign_id, created_at DESC);
