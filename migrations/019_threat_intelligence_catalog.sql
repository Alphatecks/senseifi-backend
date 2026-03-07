-- Threat intelligence catalog for "View threat" modal. Real data from DB; no hardcoded list in code.
CREATE TABLE IF NOT EXISTS threat_intelligence_catalog (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    threat_type VARCHAR(64) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    display_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_intelligence_catalog_order ON threat_intelligence_catalog(display_order);

INSERT INTO threat_intelligence_catalog (threat_type, title, description, severity, display_order) VALUES
    ('phishing_dapp', 'Phishing DApp', 'Fake Uniswap interface prompting wallet connect', 'High', 1),
    ('crypto_scam_website', 'Crypto Scam Website', 'Imitation of a popular exchange to steal credentials', 'Critical', 2),
    ('malicious_transaction', 'Malicious Transaction', 'Transaction that drains funds or grants unlimited approvals', 'High', 3),
    ('risky_token', 'Risky Token', 'Token with hidden mint, blacklist, or drainer logic', 'Medium', 4),
    ('unlimited_approval', 'Unlimited Approval', 'Token approval that allows unlimited spend without user consent', 'High', 5),
    ('signature_phishing', 'Signature Phishing', 'Request for a signature that could authorize asset transfer or permissions', 'Critical', 6),
    ('drainer_pattern', 'Drainer Pattern', 'Contract or flow designed to drain wallet assets', 'Critical', 7),
    ('frontend_phishing', 'Frontend Phishing', 'Phishing via malicious frontend or redirect', 'High', 8),
    ('behavioral_anomaly', 'Behavioral Anomaly', 'Unusual interaction pattern or first-time risk', 'Medium', 9)
ON CONFLICT (threat_type) DO NOTHING;

COMMENT ON TABLE threat_intelligence_catalog IS 'Threat types and descriptions for View threat modal; editable in DB.';
