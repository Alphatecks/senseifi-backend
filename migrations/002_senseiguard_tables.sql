-- SenseiGuard: extend wallet_monitoring for security score and last scan
ALTER TABLE wallet_monitoring
  ADD COLUMN IF NOT EXISTS security_score INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS issues_this_month INT NOT NULL DEFAULT 0;

-- Security scans (run full scan → insert row, dashboard uses latest)
CREATE TABLE IF NOT EXISTS security_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    score INT NOT NULL CHECK (score >= 0 AND score <= 100),
    status VARCHAR(20) NOT NULL DEFAULT 'strong',
    scanned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_security_scans_wallet_id ON security_scans(wallet_id);
CREATE INDEX IF NOT EXISTS idx_security_scans_scanned_at ON security_scans(scanned_at DESC);

-- Threats (detected risks; count "this month" for dashboard)
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    title VARCHAR(255) NOT NULL,
    source_contract VARCHAR(42),
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threats_wallet_id ON threats(wallet_id);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at DESC);

-- Alerts (unread alerts, high-risk count for dashboard)
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    threat_id UUID REFERENCES threats(id) ON DELETE SET NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    title VARCHAR(255) NOT NULL,
    body TEXT,
    read_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_wallet_id ON alerts(wallet_id);
CREATE INDEX IF NOT EXISTS idx_alerts_read_at ON alerts(read_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);

-- Live activity feed (outgoing tx, suspicious approval, blocked interaction)
CREATE TABLE IF NOT EXISTS activity_feed (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    activity_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_activity_feed_wallet_id ON activity_feed(wallet_id);
CREATE INDEX IF NOT EXISTS idx_activity_feed_created_at ON activity_feed(created_at DESC);

-- Wallet assets snapshot (for Connected Wallet cards: symbol, value, change %)
CREATE TABLE IF NOT EXISTS wallet_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    symbol VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    balance VARCHAR(100) NOT NULL DEFAULT '0',
    usd_value DOUBLE PRECISION NOT NULL DEFAULT 0,
    change_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(wallet_id, symbol)
);
CREATE INDEX IF NOT EXISTS idx_wallet_assets_wallet_id ON wallet_assets(wallet_id);
