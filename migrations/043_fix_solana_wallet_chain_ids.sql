-- Correct wallets stored with EVM chain_id but Solana base58 addresses.
UPDATE wallets
SET chain_id = 101,
    updated_at = NOW()
WHERE chain_id <> 101
  AND address NOT LIKE '0x%'
  AND length(address) BETWEEN 32 AND 44;
