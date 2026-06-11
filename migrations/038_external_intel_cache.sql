-- Cached positive hits from external threat intel APIs (GoPlus, etc.).
CREATE TABLE IF NOT EXISTS external_intel_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    chain_family TEXT,
    source TEXT NOT NULL DEFAULT 'goplus',
    is_malicious BOOLEAN NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}',
    checked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE (entity_type, entity_id, source)
);

CREATE INDEX IF NOT EXISTS idx_external_intel_cache_malicious
    ON external_intel_cache (is_malicious, expires_at);

CREATE INDEX IF NOT EXISTS idx_external_intel_cache_entity
    ON external_intel_cache (entity_type, entity_id);

COMMENT ON TABLE external_intel_cache IS 'Positive external intel hits (domains, contracts, programs) for threat-feed and fast lookups.';
