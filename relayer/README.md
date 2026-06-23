# Senseifi subscription relayer

Small HTTP service that submits `chargeSubscription` on `SenseifiSubscriptionPayments` when the Senseifi backend runs the due-charge job.

The Rust backend calls:

```http
POST {ONCHAIN_RELAYER_URL}/charge
Authorization: Bearer {ONCHAIN_RELAYER_API_KEY}
Content-Type: application/json

{
  "idempotency_key": "uuid:period_start_unix:period_end_unix",
  "user_id": "...",
  "subscription_id": "fbdd6f48-b88d-447f-a42b-cc7872f02112",
  "amount_usdc": 30,
  "chain_id": 84532
}
```

Response:

```json
{ "tx_hash": "0x..." }
```

`ONCHAIN_RELAYER_URL` must be the **base URL only** (no `/charge` suffix). Example: `https://senseifi-relayer.onrender.com`.

## Prerequisites

1. Payment contract deployed with `RELAYER_ADDRESS` = address of `RELAYER_PRIVATE_KEY`
2. Relayer wallet funded with ETH on Base Sepolia (or Base mainnet)
3. User completed wallet setup: USDC `approve` + `upsertBilling`
4. Backend: `PAYMENTS_ONCHAIN_SHADOW_MODE=false`, relayer URL + API key configured

## Local run

```bash
cd relayer
cp .env.example .env
# Edit .env — set RELAYER_PRIVATE_KEY, RELAYER_API_KEY, PAYMENT_CONTRACT
npm install
npm start
```

Health check:

```bash
curl http://localhost:8080/health
```

## Deploy on Render (second web service)

1. **New → Web Service** → same GitHub repo as the backend
2. **Root Directory:** `relayer`
3. **Runtime:** Node
4. **Build command:** `npm install`
5. **Start command:** `npm start`
6. **Health check path:** `/health`
7. Environment variables:

| Variable | Example |
|----------|---------|
| `RELAYER_API_KEY` | Same value as backend `ONCHAIN_RELAYER_API_KEY` |
| `RELAYER_PRIVATE_KEY` | `0x...` (relayer EOA; must match contract `RELAYER_ADDRESS`) |
| `CHAIN_ID` | `84532` (Sepolia) or `8453` (mainnet) |
| `RPC_URL` | `https://sepolia.base.org` |
| `PAYMENT_CONTRACT` | `0xf4F1cB3668Eb8D35897031623761C982c5A8D9B2` |

8. After deploy, on **senseifi-backend**:

```bash
ONCHAIN_RELAYER_URL=https://your-relayer.onrender.com
ONCHAIN_RELAYER_API_KEY=<same as RELAYER_API_KEY>
PAYMENTS_ONCHAIN_SHADOW_MODE=false
PAYMENTS_ONCHAIN_ENABLED=true
```

Redeploy the backend.

## Trigger a charge

After a user completes billing setup and a `subscription_cycles` row exists:

```bash
curl -X POST "https://senseifi-backend.onrender.com/api/payments/jobs/trigger-due" \
  -H "Content-Type: application/json" \
  -H "x-internal-token: YOUR_ONCHAIN_INTERNAL_JOB_TOKEN" \
  -d '{"limit": 10}'
```

## Security

- Never commit `.env` or private keys
- Use a long random `RELAYER_API_KEY`
- Restrict who can call the backend `trigger-due` job (`ONCHAIN_INTERNAL_JOB_TOKEN`)
