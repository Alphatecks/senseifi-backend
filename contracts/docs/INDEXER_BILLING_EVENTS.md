# Indexer: SenseiFiBilling webhook spec

Chain watcher implementation guide for Base Sepolia onchain subscription billing.

**Audience:** Indexer / chain-watcher team (not the Rust backend).  
**Backend consumer:** `POST /api/payments/webhooks/base-indexer` (header `x-webhook-token: {ONCHAIN_BASE_INDEXER_WEBHOOK_TOKEN}`).

See also: [ONCHAIN_BILLING_INTEGRATION.md](../../docs/ONCHAIN_BILLING_INTEGRATION.md) for backend + relayer deployment.

## Contract (Base Sepolia)

| Item | Value |
|------|-------|
| Chain ID | `84532` |
| SenseiFiBilling | `0xf4F1cB3668Eb8D35897031623761C982c5A8D9B2` |
| USDC | `0x036cbd53842c686983057b837BbAF642Ea437901` |

`subscriptionId` on-chain is `bytes32 = keccak256(UTF-8 hyphenated UUID)` (same as backend `subscription_id_bytes32` from `POST /api/payments/onchain-subscribe`).

## Events to watch

### `BillingUpserted` — send as `billing_upserted`

**Do not** decode data word 1 as a boolean `active` flag.

| Log part | Field | Type | Notes |
|----------|-------|------|-------|
| topic0 | event sig | bytes32 | `0xfc9e90ff10f03805a915deee8b20f37a2f9177f132e6705b397f328343a770f7` |
| topic1 | `subscriptionId` | bytes32 | indexed |
| topic2 | `payer` | address | indexed |
| data word 0 | `maxChargeUsdcRaw` | uint256 | USDC base units (6 decimals), e.g. `30000000` = 30 USDC cap |
| data word 1 | `chargedUsdcRaw` | uint256 | USDC already charged; `0` on fresh setup |

**Required webhook body:**

```json
{
  "event_id": "84532:0x<tx_hash>:<log_index>",
  "event_type": "billing_upserted",
  "chain_id": 84532,
  "tx_hash": "0x...",
  "subscription_id": "<hyphenated-uuid-if-known>",
  "payer_address": "0x...",
  "max_charge_usdc_raw": 30000000,
  "charged_usdc_raw": 0,
  "payload": {
    "subscription_id_bytes32": "0x..."
  }
}
```

- `event_id` must be stable and unique (used for idempotency).
- Include `subscription_id` (UUID) when your indexer can map bytes32 → UUID; otherwise backend can resolve via DB if UUID is in payload.
- `user_id` is optional if `subscription_id` is present.

**Wrong (legacy mis-decode — do not send):**

```json
{
  "event_type": "allowance_updated",
  "allowance_status": "active"
}
```

or treating data word 1 as `active: true`.

### Charge lifecycle

Emit after relayer `charge(subscriptionId, amount)` txs (and any contract charge events your deployment emits):

| `event_type` | When |
|--------------|------|
| `charge_submitted` | Tx hash known, not yet confirmed |
| `charge_pending_confirmation` | In mempool / waiting |
| `charge_confirmed` | Success — include `tx_hash`, `charge_attempt_id` if known |
| `charge_failed` | Revert or failure — include `failure_code`, `failure_reason` |

### `billing_cancelled`

When on-chain billing is cancelled/revoked for a subscription:

```json
{
  "event_id": "...",
  "event_type": "billing_cancelled",
  "chain_id": 84532,
  "subscription_id": "<uuid>",
  "tx_hash": "0x..."
}
```

## Endpoints

| URL | Token env var |
|-----|----------------|
| `{BACKEND}/api/payments/webhooks/base-indexer` | `ONCHAIN_BASE_INDEXER_WEBHOOK_TOKEN` |
| `{BACKEND}/api/payments/webhooks/payment-contract` | `ONCHAIN_PAYMENT_CONTRACT_WEBHOOK_TOKEN` |

Both accept the same JSON shape. Prefer `base-indexer` for chain log ingestion.

## Verification checklist

After a user completes approve + `upsertBilling`:

1. Indexer POSTs `billing_upserted` with correct `payer_address`, `max_charge_usdc_raw`, `charged_usdc_raw: 0`.
2. Backend returns `{ "success": true }`.
3. `onchain_payment_profiles.allowance_status` = `active` for that user.
4. A `subscription_cycles` row exists (status `scheduled`).

## Security

Anyone can call `upsertBilling` for a known `subscriptionId` hash and overwrite the payer. Do not fire test webhooks against production subscription UUIDs.
