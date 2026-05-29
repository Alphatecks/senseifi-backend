-- Waitlist import tables and persistent XP claims bound to dashboard user_id.

CREATE TABLE IF NOT EXISTS waitlist_entries (
    id INT PRIMARY KEY,
    email TEXT NOT NULL,
    referral_code VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_waitlist_entries_email_lower
    ON waitlist_entries (LOWER(TRIM(email)));

CREATE TABLE IF NOT EXISTS waitlist_referrals (
    id UUID PRIMARY KEY,
    referrer_id INT NOT NULL REFERENCES waitlist_entries(id),
    referred_id INT NOT NULL REFERENCES waitlist_entries(id),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (referred_id)
);

CREATE INDEX IF NOT EXISTS idx_waitlist_referrals_referrer_id
    ON waitlist_referrals (referrer_id);

CREATE TABLE IF NOT EXISTS user_xp_claims (
    user_id VARCHAR(64) PRIMARY KEY REFERENCES dashboard_users(user_id) ON DELETE CASCADE,
    wallet_address VARCHAR(42) NOT NULL,
    waitlist_entry_id INT NOT NULL REFERENCES waitlist_entries(id),
    email TEXT NOT NULL,
    xp INT NOT NULL DEFAULT 0 CHECK (xp >= 0),
    direct_referrals INT NOT NULL DEFAULT 0 CHECK (direct_referrals >= 0),
    level2_referrals INT NOT NULL DEFAULT 0 CHECK (level2_referrals >= 0),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_xp_claims_email_lower
    ON user_xp_claims (LOWER(TRIM(email)));

CREATE INDEX IF NOT EXISTS idx_user_xp_claims_wallet
    ON user_xp_claims (LOWER(wallet_address));

COMMENT ON TABLE waitlist_entries IS 'Imported SenseiFi waitlist signups (email + referral code).';
COMMENT ON TABLE waitlist_referrals IS 'Imported referral edges: referrer_id referred referred_id.';
COMMENT ON TABLE user_xp_claims IS 'Waitlist XP claimed once per email, bound to dashboard user_id + wallet.';
