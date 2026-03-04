-- SenseiGuard: align threats with 4 surfaces and risk engine
-- See docs/SENSEIGUARD_ARCHITECTURE.md

-- Threat type: malicious_transaction, phishing_indicator, risky_token, unlimited_approval,
-- signature_phishing, drainer_pattern, behavioral_anomaly, frontend_phishing
ALTER TABLE threats
  ADD COLUMN IF NOT EXISTS threat_type VARCHAR(50),
  ADD COLUMN IF NOT EXISTS surface VARCHAR(30),
  ADD COLUMN IF NOT EXISTS explanation TEXT,
  ADD COLUMN IF NOT EXISTS risk_breakdown JSONB DEFAULT '{}';

COMMENT ON COLUMN threats.threat_type IS 'One of: malicious_transaction, phishing_indicator, risky_token, unlimited_approval, signature_phishing, drainer_pattern, behavioral_anomaly, frontend_phishing';
COMMENT ON COLUMN threats.surface IS 'Where detected: wallet_state, tx_intent, contract, off_chain';
COMMENT ON COLUMN threats.explanation IS 'Human-readable reason, e.g. Unlimited approval to contract deployed 3h ago with owner mint';
COMMENT ON COLUMN threats.risk_breakdown IS 'Component scores: approval_risk, contract_risk, simulation_drain, behavioral_anomaly, phishing_risk (0-100 each)';

CREATE INDEX IF NOT EXISTS idx_threats_threat_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_surface ON threats(surface);
