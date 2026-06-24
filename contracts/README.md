# Senseifi Onchain Subscription Billing

This folder contains **SenseifiSubscriptionPayments** — a relayer-model reference contract. **Production Base Sepolia** uses the separately deployed **SenseiFiBilling** contract (biller model). See `../docs/ONCHAIN_BILLING_INTEGRATION.md` for live addresses, webhook specs, and relayer config.

## Deployed vs in-repo

| SenseiFiBilling (live) | SenseifiSubscriptionPayments (this repo) |
|------------------------|--------------------------------------------|
| `billers(address)` | `relayers(address)` |
| `charge(bytes32, uint256)` | `chargeSubscription(ChargeRequest)` |
| `getBilling(bytes32)` | `billingBySubscription(bytes32)` |

The HTTP relayer in `../relayer/` supports both via `PAYMENT_CONTRACT_STYLE=biller|relayer|auto`.

## What the in-repo contract does

- Users register billing settings with `upsertBilling(subscriptionId, maxChargeAmount)`.
- Users approve USDC spending for this contract (standard ERC20 approve).
- A trusted relayer calls `chargeSubscription(...)` per billing cycle.
- Contract emits charge lifecycle events (`ChargeSubmitted`, `ChargeConfirmed`, `ChargeFailed`, etc.).

`ChargeFailed` codes match backend expectations:
- `insufficient_allowance`
- `insufficient_balance`
- `transfer_failed`
- `user_revoked`

## Folder structure

- `src/SenseifiSubscriptionPayments.sol` - reference relayer-model contract
- `script/DeploySenseifiSubscriptionPayments.s.sol` - Foundry deploy script
- `foundry.toml` - Foundry config

## Prerequisites

- Install [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Set environment variables:

```bash
export PRIVATE_KEY=0x...
export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
export BASE_RPC_URL=https://mainnet.base.org
export USDC_ADDRESS=0x...          # Base or Base Sepolia USDC
export TREASURY_ADDRESS=0x...      # Senseifi treasury wallet
export RELAYER_ADDRESS=0x...       # Relayer EOA address
```

## Deploy (Base Sepolia first)

```bash
cd contracts
forge script script/DeploySenseifiSubscriptionPayments.s.sol:DeploySenseifiSubscriptionPayments \
  --rpc-url base_sepolia \
  --broadcast \
  -vvvv
```

For Base mainnet:

```bash
forge script script/DeploySenseifiSubscriptionPayments.s.sol:DeploySenseifiSubscriptionPayments \
  --rpc-url base \
  --broadcast \
  -vvvv
```

After deploy, copy deployed address into backend env:

```bash
ONCHAIN_PAYMENT_CONTRACT=0xYourDeployedContractAddress
```

## Relayer service

Charges after wallet setup are submitted by the HTTP relayer in `../relayer/` (Node + ethers). Deploy it as a separate web service and set `ONCHAIN_RELAYER_URL` on the backend to its public base URL. See `relayer/README.md`.

## Backend env mapping

Set these in backend `.env`:

- `ONCHAIN_PAYMENT_CONTRACT` = deployed contract address
- `ONCHAIN_USDC_CONTRACT` = same USDC token address used in deployment
- `PAYMENTS_ONCHAIN_ENABLED=true`
- `PAYMENTS_ONCHAIN_SHADOW_MODE=false` (set true for dry-run mode)

## Notes

- Amounts are token-native decimals (USDC = 6).
- `subscriptionId` in contract is `bytes32`; backend should hash its subscription identifier before passing to relayer.
- `chargeId` is the idempotency key (bytes32) to block duplicate charge execution.

