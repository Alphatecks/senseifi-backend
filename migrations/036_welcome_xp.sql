-- System waitlist row for welcome XP grants (not a real signup).

INSERT INTO waitlist_entries (id, email, referral_code, created_at)
VALUES (-1, 'welcome-bonus@senseifi.internal', 'WELCOME0000', NOW())
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE waitlist_entries IS 'Imported SenseiFi waitlist signups; id -1 is reserved for wallet welcome XP.';
