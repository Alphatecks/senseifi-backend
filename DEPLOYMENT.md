# Deployment Options for Senseifi Backend

This project includes three deployment options for Render. Choose the one that works best for you.

## Option 1: cargo-chef Dockerfile (RECOMMENDED - Fastest) ⚡

**File:** `Dockerfile` (already set as default)

**Why use it:**
- Fastest build times (2-3x faster than manual caching)
- Best Docker layer caching
- Dependencies cached separately from source code

**How to use:**
1. Make sure `Dockerfile` is in your repo (it already is)
2. In Render dashboard:
   - Service Type: Web Service
   - Build Command: (leave empty - uses Dockerfile automatically)
   - Start Command: (leave empty - uses Dockerfile CMD)
3. Deploy!

## Option 2: Native Rust Build (No Docker) 🚀

**File:** `render.yaml`

**Why use it:**
- Simpler setup
- No Docker overhead
- Faster for small projects
- Render handles Rust natively

**How to use:**
1. In Render dashboard, connect your GitHub repo
2. Render will detect `render.yaml` automatically
3. Or manually set:
   - Environment: Rust
   - Build Command: `cargo build --release`
   - Start Command: `./target/release/backend`
   - Environment Variables:
     - `PORT`: (auto-set by Render)
     - `HOST`: `0.0.0.0`
     - `RUST_LOG`: `info`

## Option 3: Manual Dockerfile (Backup)

**File:** `Dockerfile.manual`

**Why use it:**
- If cargo-chef has issues
- More straightforward caching approach

**How to use:**
1. Rename `Dockerfile.manual` to `Dockerfile`
2. Deploy normally

## Environment Variables

All options support these environment variables:

- `PORT`: Port to bind to (Render sets this automatically)
- `HOST`: Host to bind to (default: `0.0.0.0`)
- `RUST_LOG`: Logging level (default: `info`)
- `BIND_ADDRESS`: Legacy option (format: `host:port`)
- `DATABASE_URL`: PostgreSQL connection string (required)

### RPC URLs (required for correct `total_asset_usd` / native balance)

The backend calls `eth_getBalance` on the **same chain** as the wallet’s `chain_id`. **Do not** point every chain at Ethereum mainnet.

| `chain_id` | Environment variable |
|------------|----------------------|
| 1 | `ETHEREUM_RPC_URL` |
| 56 | `BSC_RPC_URL` |
| 137 | `POLYGON_RPC_URL` |
| 8453 | `BASE_RPC_URL` |
| 42161 | `ARBITRUM_RPC_URL` |
| 10 | `OPTIMISM_RPC_URL` |
| 324 | `ZKSYNC_ERA_RPC_URL` or `ZKSYNC_RPC_URL` |
| 59144 | `LINEA_RPC_URL` |
| 534352 | `SCROLL_RPC_URL` |
| 43114 | `AVALANCHE_RPC_URL` |
| 250 | `FANTOM_RPC_URL` |
| *other* | `RPC_URL_<chain_id>` (e.g. `RPC_URL_81457` for Blast) |

If the URL for a chain is missing, balance calls for that chain fail (see `rpc_error` on `/api/dashboard/:address/summary`).

### Multi-chain native total (dashboard)

`GET /api/dashboard/:address/summary` sums **native** (gas token) balance × USD across several EVM chains for the **same address**, so a row with `chain_id = 1` can still pick up **BNB on BSC** if `BSC_RPC_URL` is set.

- **`NATIVE_BALANCE_SCAN_CHAIN_IDS`** (optional): comma-separated chain IDs, e.g. `1,56,137,8453,42161,10`.  
  If unset, defaults to: `1,56,137,8453,42161,10,324,59144,534352,43114,250` plus the wallet’s stored `chain_id` if missing from the list.

Only chains with a configured RPC URL are queried. Response includes **`native_per_chain`** breakdown.

### ERC-20 / BEP-20 token balances (Moralis)

Indexed token balances are stored in **`wallet_assets`** and included in **`GET /api/dashboard/:address/summary`** (`wallet_assets_usd`) and **`GET /api/dashboard/:address/assets`** (merged with live native balances).

- **`MORALIS_API_KEY`** (required for sync): [Moralis](https://moralis.io/) Web3 Data API key. Without it, **`POST /api/dashboard/:address/assets/sync`** returns **503**.
- **`MORALIS_API_BASE_URL`** (optional): default `https://deep-index.moralis.io`.
- **`TOKEN_BALANCE_SCAN_CHAIN_IDS`** (optional): comma-separated chain IDs to sync (e.g. `1,56,137`). If unset, defaults to the same list as **`NATIVE_BALANCE_SCAN_CHAIN_IDS`** (or its built-in default). Chains **not supported** by Moralis’ wallet token endpoint (e.g. **zkSync 324**, **Scroll 534352**) are reported as **`skipped`** — omit them from this env if you want fewer noise rows.
- **`MORALIS_EXCLUDE_SPAM`** (optional): set to `true` to add Moralis `exclude_spam=true`. Default in this backend is **false** so balances match the Moralis docs default and fewer holdings are hidden.

**On-demand sync:** `POST /api/dashboard/:address/assets/sync` — uses Moralis `chain` as **hex** (e.g. `0x38` for BSC), **`exclude_native=true`**, and skips `native_token` rows so **gas-token USD is not double-counted** (native remains from RPC in `native_usd` / `total_asset_usd`). Paginates with `cursor` until exhausted. Respect Moralis rate limits; add a cron or debounce on the client if needed.

### Native token USD price (optional)

- Order: **CoinGecko** public (or **Pro** if `COINGECKO_API_KEY`), then **CoinCap**, **Binance** `ticker/price` (USDT), **Coinbase** `v2/prices/{PAIR}/spot`.
- Successful quotes are **cached 120s** per asset (e.g. one `ethereum` price reused for chains 1, 10, 8453…), which avoids **CoinGecko rate limits** when scanning many chains.
- Optional: `COINGECKO_API_KEY` — uses CoinGecko Pro (`pro-api.coingecko.com`) with header `x-cg-pro-api-key`.

## Troubleshooting

### Build Timeout
- Use Option 1 (cargo-chef) - it's the fastest
- Or use Option 2 (native build) - often faster than Docker

### Port Issues
- Make sure your app binds to `0.0.0.0`, not `127.0.0.1`
- The code now automatically uses Render's `PORT` variable

### Build Fails
- Check that `Cargo.lock` is committed
- Ensure all dependencies are in `Cargo.toml`
- Try Option 2 (native build) if Docker is problematic
