-- Dashboard identity per wallet: random user_id (API), display name, and "User N" number.
-- Created when user connects wallet so frontend can show "User 2314" and "fetrtwgebejhssns..." without external auth.
CREATE TABLE IF NOT EXISTS dashboard_users (
    wallet_address VARCHAR(42) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL UNIQUE,
    display_name VARCHAR(128) NOT NULL,
    user_number INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dashboard_users_user_id ON dashboard_users(user_id);
COMMENT ON TABLE dashboard_users IS 'One row per connected wallet: random user_id (for API), display_name (e.g. Stealth bag), user_number (for "User 2314").';
