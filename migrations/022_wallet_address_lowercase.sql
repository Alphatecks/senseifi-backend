-- Canonical lowercase addresses: avoids checksum vs lowercase mismatches.
-- If two rows differ only by casing (same address), lowering one hits UNIQUE(address).
-- Step 1: remove duplicate wallets (keep earliest connected_at, then smallest id).
DELETE FROM wallets w
USING (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY LOWER(address)
            ORDER BY connected_at ASC, id ASC
        ) AS rn
    FROM wallets
) ranked
WHERE w.id = ranked.id
  AND ranked.rn > 1;

-- Step 2: lowercase all wallet addresses (now unique per LOWER).
UPDATE wallets SET address = LOWER(address) WHERE address <> LOWER(address);

-- Step 3: dedupe dashboard_users by case-insensitive wallet_address (keep oldest created_at).
DELETE FROM dashboard_users d
USING (
    SELECT
        wallet_address,
        ROW_NUMBER() OVER (
            PARTITION BY LOWER(wallet_address)
            ORDER BY created_at ASC, wallet_address ASC
        ) AS rn
    FROM dashboard_users
) ranked
WHERE d.wallet_address = ranked.wallet_address
  AND ranked.rn > 1;

-- Step 4: lowercase dashboard_users keys.
UPDATE dashboard_users
SET wallet_address = LOWER(wallet_address)
WHERE wallet_address <> LOWER(wallet_address);
