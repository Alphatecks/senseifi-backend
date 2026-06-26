# BoomFi billing integration

Senseifi uses **BoomFi only** for paid subscriptions (crypto, monthly/annual lump charges).

## Setup

1. Create a BoomFi merchant account and recurring paylinks for each SKU (Pro / Pro+ / Premium × monthly / annual).
2. Register webhook URL: `POST https://<your-api>/api/subscriptions/webhook`
3. Copy your org ID, webhook public key (PEM), and paylink URLs into backend env.

## Required env

```
BOOMFI_ORG_ID=
BOOMFI_WEBHOOK_PUBLIC_KEY=
BOOMFI_PAYLINK_BASIC_MONTHLY=
BOOMFI_PAYLINK_BASIC_ANNUAL=
BOOMFI_PAYLINK_PRO_MONTHLY=
BOOMFI_PAYLINK_PRO_ANNUAL=
BOOMFI_PAYLINK_PREMIUM_MONTHLY=
BOOMFI_PAYLINK_PREMIUM_ANNUAL=
BOOMFI_SUCCESS_URL=
BOOMFI_CANCEL_URL=
BOOMFI_SUBSCRIPTION_PORTAL_URL=
```

Optional: `BOOMFI_PLAN_*` plan IDs so webhooks map to the correct Senseifi plan tier.

## Flow

1. **Checkout:** `POST /api/subscriptions/checkout` with `user_id`, `plan`, `billing_cycle` → returns `checkout_url` (BoomFi paylink + `customer_ident=user_id`).
2. **User pays** on BoomFi hosted checkout (wallet USDC/etc.).
3. **Webhook:** BoomFi sends `Subscription.Updated` (Active/Canceled) → backend updates `user_subscriptions`.
4. **Status:** `GET /api/subscriptions/status?user_id=` for plan gating.
5. **Manage:** `POST /api/subscriptions/portal` → BoomFi subscription management URL.

## Webhook security

Verify headers on every request:

- `X-BoomFi-Timestamp`
- `X-BoomFi-Signature` (RSA-SHA256 over `{timestamp}.{raw_body}`)

Also verify `org_id` in the payload matches `BOOMFI_ORG_ID`.

## Customer linking

Paylinks must include `customer_ident=<dashboard user_id>` (backend adds this automatically). BoomFi echoes it as `customer.reference` in webhooks — that is how we tie payment to the Senseifi user.

See [BoomFi webhooks docs](https://docs.boomfi.xyz/docs/webhooks).
