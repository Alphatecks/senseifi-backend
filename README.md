# Axum Layered/Modular Rust Backend

## Structure

- `src/main.rs`: Entry point, Axum server setup
- `src/routes/`: Route definitions
- `src/services/`: Business logic
- `src/repositories/`: Data access
- `src/models/`: Data models

## Running

1. Set environment variable (optional):
   ```sh
   export BIND_ADDRESS=127.0.0.1:3000
   ```
2. Run the server:
   ```sh
   cargo run
   ```
3. Test endpoint:
   - GET http://127.0.0.1:3000/api/hello

## Dependencies
- axum
- tokio (full)
- serde
- serde_json
- dotenv

## Example Endpoints
- `GET /api/hello` — Returns a message from the repository layer.
- Wallet: `POST /api/wallets/connect`, `GET/DELETE /api/wallets/:address`, `GET /api/wallets/:address/status`.

## SenseiGuard dashboard API (per wallet address)

All dashboard routes require a valid Ethereum address in the path (`0x` + 40 hex chars).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard/:address/summary` | Full dashboard summary (security status, threat/scan/alert counts, total asset, issues). |
| GET | `/api/dashboard/:address/security-status` | Security score, status (strong/moderate/weak), last scan, message. |
| POST | `/api/dashboard/:address/scan` | Run full security scan; returns new score and status. |
| GET | `/api/dashboard/:address/threats?limit=20` | List threats for the wallet. |
| GET | `/api/dashboard/:address/scans?limit=20` | List recent security scans. |
| GET | `/api/dashboard/:address/alerts?limit=20` | List alerts (unread and high-risk counts from summary). |
| GET | `/api/dashboard/:address/activity?limit=20` | Live activity feed (e.g. outgoing tx, suspicious approval, blocked interaction). |
| GET | `/api/dashboard/:address/assets` | Connected wallet assets: `wallet_assets` (DB) + live native per scanned chain. |
| POST | `/api/dashboard/:address/assets/sync` | Moralis → refresh indexed ERC-20 rows in `wallet_assets` (needs `MORALIS_API_KEY`). |

After running migrations, `wallet_monitoring` is extended with `security_score`, `last_scan_at`, `issues_this_month`. New tables: `security_scans`, `threats`, `alerts`, `activity_feed`, `wallet_assets`.

**`total_asset_usd` (dashboard summary)** = portfolio USD with **per-chain deduping**: all **`wallet_assets`** token rows, plus RPC **native** per scanned chain, but on each chain if both **native** and the **wrapped gas token** (WBNB, WETH, …) have USD, only **`max(native, wrapped)`** counts for that gas position (avoids ~2× vs MetaMask). **`wallet_assets_usd`** and **`native_usd`** in the JSON are **raw** and can overlap — use **`total_asset_usd`** as the single headline number (do not add the two). RPC env per chain: **DEPLOYMENT.md**, **`NATIVE_BALANCE_SCAN_CHAIN_IDS`**.

**`native_balance_eth`** = native balance on the **DB `chain_id` only** (e.g. 0 ETH when `chain_id` is 1). Use **`native_per_chain`** for the full breakdown.

USD spot: CoinGecko (optional Pro key), CoinCap, Binance USDT, Coinbase spot; **120s in-memory cache** per asset to limit rate limits when scanning many chains.

The JSON body includes **`total_asset_usd`**, **`native_per_chain`**, **`wallet_assets_usd`**, **`native_usd`**, **`native_price_source`**, and on failure **`rpc_error`** / **`native_pricing_error`**.

ERC-20/BEP-20 balances: call **`POST /api/dashboard/:address/assets/sync`** (Moralis) to populate **`wallet_assets`**; then **`GET .../assets`** and **`GET .../summary`** include them. Native gas tokens remain live from RPC.

**Addresses** are stored and matched case-insensitively (canonical lowercase); migration `022_wallet_address_lowercase.sql` normalizes existing rows.
