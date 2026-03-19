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
| GET | `/api/dashboard/:address/assets` | Connected wallet assets (symbol, balance, USD value, change %). |

After running migrations, `wallet_monitoring` is extended with `security_score`, `last_scan_at`, `issues_this_month`. New tables: `security_scans`, `threats`, `alerts`, `activity_feed`, `wallet_assets`.

**`total_asset_usd` (dashboard summary)** = sum of `wallet_assets.usd_value` **plus** live **native** (gas token) balance from your chain RPC × USD spot (CoinGecko). Set `ETHEREUM_RPC_URL` (or `BSC_RPC_URL`, `POLYGON_RPC_URL`, etc. for that chain). Pure ERC-20 balances are not read from chain unless rows exist in `wallet_assets` (e.g. future ingest/sync).
