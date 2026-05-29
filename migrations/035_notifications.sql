-- In-app notifications: broadcasts + read receipts for unified notification center.

CREATE TABLE IF NOT EXISTS broadcast_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    body TEXT,
    category VARCHAR(50) NOT NULL DEFAULT 'community',
    icon_type VARCHAR(50) NOT NULL DEFAULT 'community',
    action_label VARCHAR(100),
    action_url VARCHAR(500),
    action_type VARCHAR(50),
    active BOOLEAN NOT NULL DEFAULT true,
    starts_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_broadcast_notifications_active
    ON broadcast_notifications (active, starts_at DESC);

CREATE TABLE IF NOT EXISTS notification_read_receipts (
    wallet_address VARCHAR(42) NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    source_id UUID NOT NULL,
    read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (wallet_address, source_type, source_id)
);

CREATE INDEX IF NOT EXISTS idx_notification_read_receipts_wallet
    ON notification_read_receipts (LOWER(wallet_address), read_at DESC);

COMMENT ON TABLE broadcast_notifications IS 'Global product/community announcements shown in the notification center.';
COMMENT ON TABLE notification_read_receipts IS 'Per-wallet read state for broadcasts, activity, approval alerts, and threats.';
