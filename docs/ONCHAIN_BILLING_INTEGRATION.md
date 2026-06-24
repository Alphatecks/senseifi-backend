# Onchain billing integration (SenseiFiBilling)

Production Base Sepolia uses the **SenseiFiBilling** contract (biller model), not the in-repo `SenseifiSubscriptionPayments.sol`.

| Deployed SenseiFiBilling | In-repo SenseifiSubscriptionPayments |
|--------------------------|--------------------------------------|
| `billers(address)` | `relayers(address)` |
| `charge(bytes32 subscriptionId, uint256 amount)` | `chargeSubscription(ChargeRequest)` |
| `getBilling(bytes32)` | `billingBySubscription(bytes32)` |
| `upsertBilling(bytes32, uint256)` | same name, different layout |

## Base Sepolia (testnet)

| Item | Value |
|------|-------|
| Payment contract | `0xf4F1cB3668Eb8D35897031623761C982c5A8D9B2` |
| USDC | `0x036cbd53842c686983057b837BbAF642Ea437901` |
| Biller / owner / treasury | `0x63D7c32BA6f82A82aF67f8AAbF96Cd26fb1330EA` |
| Chain ID | `84532` |

## Two-step billing flow

1. **Setup (user wallet):** `POST /api/payments/onchain-subscribe` → USDC `approve` + `upsertBilling(subscriptionId, maxChargeUsdcRaw)`
2. **Charge (backend + relayer):** `POST /api/payments/jobs/trigger-due` → relayer calls `charge(subscriptionId, amount)` → webhooks update cycles/history

Setup only authorizes billing; no USDC is transferred until the relayer charges.

## Relayer

Deploy `relayer/` as a separate service. Required env:

```
RELAYER_API_KEY=<same as backend ONCHAIN_RELAYER_API_KEY>
RELAYER_PRIVATE_KEY=<private key for biller wallet 0x63D7...>
PAYMENT_CONTRACT=0xf4F1cB3668Eb8D35897031623761C982c5A8D9B2
PAYMENT_CONTRACT_STYLE=biller
CHAIN_ID=84532
RPC_URL=https://sepolia.base.org
```

Backend:

```
PAYMENTS_ONCHAIN_ENABLED=true
PAYMENTS_ONCHAIN_SHADOW_MODE=false
ONCHAIN_RELAYER_URL=https://<relayer-host>
ONCHAIN_RELAYER_API_KEY=...
ONCHAIN_PAYMENT_CONTRACT=0xf4F1cB3668Eb8D35897031623761C982c5A8D9B2
ONCHAIN_USDC_CONTRACT=0x036cbd53842c686983057b837BbAF642Ea437901
ONCHAIN_BASE_CHAIN_ID=84532
ONCHAIN_PAYMENT_CONTRACT_STYLE=biller
```

## Indexer webhook payloads

POST `/api/payments/webhooks/base-indexer` or `/api/payments/webhooks/payment-contract` with header `x-webhook-token`.

### `billing_upserted` (from `BillingUpserted` event)

**Critical:** the second uint in event data is `chargedUsdcRaw` (USDC base units, 6 decimals) — **not** a boolean `active` flag.

```json
{
  "event_id": "84532:0xabc...:logIndex",
  "event_type": "billing_upserted",
  "chain_id": 84532,
  "tx_hash": "0x...",
  "subscription_id": "fbdd6f48-b88d-447f-a42b-cc7872f02112",
  "user_id": "optional-if-subscription_id-present",
  "payer_address": "0xD7d29FC8Bc1831CA35ec6903c8AcDC751f333C1A",
  "charged_usdc_raw": 30000000,
  "payload": {
    "subscription_id_bytes32": "0x6dac..."
  }
}
```

Backend updates `onchain_payment_profiles` (payer, max charge, `allowance_status=active`) and ensures the first `subscription_cycles` row exists.

### Legacy mis-decode

If the indexer still sends `event_type: "allowance_updated"` with a numeric `allowance_status` (e.g. `"30000000"`), the backend re-routes to `billing_upserted` handling when `charged_usdc_raw` or `payer_address` is present, or when `allowance_status` looks like USDC raw units.

### Charge lifecycle

| event_type | Purpose |
|------------|---------|
| `charge_submitted` | Relayer tx broadcast |
| `charge_pending_confirmation` | Awaiting block confirmation |
| `charge_confirmed` | Mark cycle paid, extend subscription |
| `charge_failed` | Mark attempt/cycle failed |

### `billing_cancelled`

Sets profile `allowance_status` to `cancelled`.

## Security note

Anyone can call `upsertBilling` for a known `subscriptionId` hash and overwrite the payer. Do not run test upserts against real user subscription UUIDs.
