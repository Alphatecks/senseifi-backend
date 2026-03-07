# Scanner & external services configuration

To make the contract scanner **real** (ABI + bytecode analysis instead of stubs), set the following. If they are missing, the scanner falls back to stub behavior.

---

## 1. Etherscan (ABI + verification)

Used to fetch contract ABI and whether the contract is verified. **Uses Etherscan API V2** (V1 deprecated Aug 2025).

- **Get an API key**: [Etherscan API dashboard](https://etherscan.io/apidashboard). One key works for all [supported chains](https://docs.etherscan.io/supported-chains) with V2.
- **Set**:
  - `ETHERSCAN_API_KEY` — your key (required).
  - `ETHERSCAN_BASE_URL` — optional. Default: `https://api.etherscan.io/v2/api`.
  - `ETHERSCAN_CHAIN_ID` — optional. Default: `1` (Ethereum). Use the chain ID for the network you scan, e.g. `56` BSC, `137` Polygon, `8453` Base, `42161` Arbitrum.

Example `.env`:

```bash
ETHERSCAN_API_KEY=YourEtherscanKeyHere
# ETHERSCAN_CHAIN_ID=1
```

---

## 2. Ethereum RPC (bytecode)

Used to fetch contract bytecode via `eth_getCode` (e.g. for DELEGATECALL detection).

- **Options**:
  - **Alchemy**: [alchemy.com](https://www.alchemy.com/) → Create app → copy “HTTPS” URL. Free tier is enough.
  - **Infura**: [infura.io](https://www.infura.io/) → Create project → copy “Project URL” (HTTPS).
  - **QuickNode**: [quicknode.com](https://www.quicknode.com/) → Create endpoint → copy HTTP URL.
  - **Public RPC** (rate-limited, not for production): e.g. `https://eth.llamarpc.com` or chain-specific public RPCs.
- **Set**:
  - `ETHEREUM_RPC_URL` — full JSON-RPC URL, e.g. `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY` or `https://mainnet.infura.io/v3/YOUR_KEY`.

Example `.env`:

```bash
ETHEREUM_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/your_alchemy_key
```

For other chains, use the RPC URL of that chain (e.g. Arbitrum, Base) so `eth_getCode` runs on the correct network.

---

## 3. Scanning contracts on other chains (BSC, Polygon, Base, etc.)

**Per-request chain:** The scan API accepts an optional `chain_id` in the request body. No need to change env vars when switching chains.

**Request body** (e.g. `POST /api/scan-contract`):

```json
{
  "contract_address": "0x...",
  "for_address": "0x...",
  "chain_id": 56
}
```

- **`chain_id`** optional. `1` = Ethereum, `56` = BSC, `137` = Polygon, `8453` = Base, `42161` = Arbitrum. If omitted, uses `ETHERSCAN_CHAIN_ID` env or `1`.

**Set RPC URLs once per chain** (so the backend can fetch bytecode on that chain). You can set all you need; the request’s `chain_id` picks which one to use:

| Env var               | Chain    | Chain ID |
|-----------------------|----------|----------|
| `ETHEREUM_RPC_URL`    | Ethereum | 1        |
| `BSC_RPC_URL`         | BSC      | 56       |
| `POLYGON_RPC_URL`     | Polygon  | 137      |
| `BASE_RPC_URL`        | Base     | 8453     |
| `ARBITRUM_RPC_URL`    | Arbitrum | 42161    |

- **Same** `ETHERSCAN_API_KEY` works for all chains (V2).
- If a chain’s RPC isn’t set (e.g. no `BSC_RPC_URL`), the backend falls back to `ETHEREUM_RPC_URL` for bytecode (may fail for that chain). Set the RPC for each chain you want to support.

Example: support both Ethereum and BSC without ever editing env again:

```bash
ETHERSCAN_API_KEY=YourEtherscanKeyHere
ETHEREUM_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
BSC_RPC_URL=https://bsc-dataseed.binance.org/
```

Frontend: send `chain_id: 1` for Ethereum contracts, `chain_id: 56` for BSC.

---

## 4. Behavior summary

| Variable               | Used for                         | If unset / error |
|------------------------|-----------------------------------|-------------------|
| `ETHERSCAN_API_KEY`    | Etherscan getabi / getsourcecode  | Stub privileges & dangerous fns |
| `ETHERSCAN_BASE_URL`   | API base (optional)              | Default: V2 API   |
| `ETHERSCAN_CHAIN_ID`   | Default chain when request has no `chain_id` | Default: 1 (Ethereum) |
| `ETHEREUM_RPC_URL`     | Bytecode for chain 1 (and fallback) | No bytecode for that chain |
| `BSC_RPC_URL`          | Bytecode for chain 56            | Falls back to ETHEREUM_RPC_URL |
| `POLYGON_RPC_URL`      | Bytecode for chain 137           | Falls back to ETHEREUM_RPC_URL |
| `BASE_RPC_URL`         | Bytecode for chain 8453          | Falls back to ETHEREUM_RPC_URL |
| `ARBITRUM_RPC_URL`     | Bytecode for chain 42161         | Falls back to ETHEREUM_RPC_URL |

The analyzer:

1. Tries to fetch ABI from Etherscan (with optional key and base URL).
2. Tries to fetch bytecode from RPC.
3. Fetches contract creation (Etherscan getcontractcreation) for **contract age** and **owner/admin count**.
4. Parses ABI for privilege-like functions (mint, pause, upgrade, withdraw, blacklist) and dangerous ones (approve, setApprovalForAll, etc.).
5. Derives **tokens controlled** from ABI (ETH + ERC20 when approve/transferFrom present).
6. **User anomaly** uses your DB (how often this wallet has scanned this contract).
7. If any step fails or config is missing, uses stub values so the API still responds.

**What is real now:** Owner privileges, dangerous functions, contract age risk, owner/admin count (from creation), tokens controlled (from ABI), reputation (DB), trend (DB), user anomaly (DB scan count), and **simulation** when your RPC URL is Alchemy.

**Simulation:** When `ETHEREUM_RPC_URL` (or the chain’s RPC) is an Alchemy URL (`alchemy.com`), the backend calls `alchemy_simulateAssetChanges` to get real **drains_full_balance** and **hidden_internal_calls**; **approval_scope** is derived from the contract’s dangerous functions (approve/setApprovalForAll → "unlimited"). If the RPC is not Alchemy or the call fails, simulation falls back to stub values.

---

## 5. Render / production

In Render (or any host), set the same variables in the **Environment** tab:

- `ETHERSCAN_API_KEY`
- `ETHEREUM_RPC_URL`
- Optionally `ETHERSCAN_BASE_URL` for non-mainnet.

Do **not** commit `.env` or keys to git.

---

## 6. Dashboard APIs — real data only

Dashboard endpoints return **only real data** from your database (and, where configured, from Etherscan/RPC). No simulations or hardcoded fake values.

| Endpoint | Data source | Notes |
|----------|-------------|--------|
| `GET /api/dashboard/overview` | DB only | Accepts **`user_id`** or **`wallet_address`** (optional). When provided, wallet status (active count, last scan, status), alerts, activity timeline, recent activity, and connected risk are **scoped to that user's connected wallets only**. When **both** are omitted, the single-wallet fallback runs by default: if there is exactly one active wallet, that user is used so "1 active wallet" shows (set **`OVERVIEW_SINGLE_WALLET_FALLBACK=false`** to disable). |
| `GET /api/dashboard/{address}/summary` | DB only | Per-wallet summary; trend % are computed from previous period (no hardcoded -2.3 / 2.3). |
| `GET /api/dashboard/{address}/metrics` | DB only | Threat counts by type and security score. |
| `GET /api/dashboard/threat-intelligence` | Actual detections | Recent threat detections from the `threats` table (title, description/explanation, severity, threat_type, detected_at, wallet_address, source_contract). Query: `user_id` (optional, scope to user's wallets), `limit` (optional, default 50, max 200). |
| `GET /api/dashboard/activity-monitor/wallets` | DB only | Activity Monitor "Connected wallet" tab: list of wallets with `wallet_type_display` (e.g. MetaMask), `chain_name`, `status` (Active/Inactive), `security_level` (Safe/Moderate/High), `last_activity` (e.g. "2 minutes ago"). Query: `user_id` or `wallet_address` (optional; same resolution as overview). |
| `GET /api/dashboard/activity-monitor/dapps` | DB only | Activity Monitor "Connected dApps" tab: list of dApp connections (`dapp_name`, `description`, `tokens`, `status`, `connected_wallet_address`, `last_activity`). Query: `user_id` or `wallet_address` (optional). Data from `dapp_connections` table (populate via extension/client ingest). |
| `GET /api/dashboard/{address}/alerts/unread` | DB only | Unread alerts for the "Unread Alert" modal: `data.alerts[]` (id, severity, title, body, created_at), plus `data.wallet_address` and `data.wallet_type` (e.g. MetaMask) for display. Query: `limit` (default 20, max 100). |
| `GET /api/dashboard/{address}/threats` | DB only | Stored threats detected for that wallet. |
| `GET /api/dashboard/{address}/alerts` | DB only | Stored alerts. |
| `GET /api/dashboard/{address}/activity` | DB only | Activity feed (ingest via `POST .../activity` or workers). |
| `GET /api/dashboard/{address}/transaction-monitoring` | DB only | Monitored transactions / risk items. |

**Fields that are 0 until you add data or an external source**

- **`recent_activity.contract_calls_24h`** — Not derived from DB today. To get real values: ingest contract-call events into `activity_feed` (e.g. with `activity_type = 'contract_call'`) or use an external API (e.g. Alchemy `alchemy_getAssetTransfers` or similar) and either store results or aggregate in your backend.
- **`connected_risk.active_dapps`** — No dApp table in DB. To get real values: add a `dapp_connections` (or similar) table and ingest when the user connects to a dApp, or use an external provider that tracks dApp usage.

**User-scoped dashboard**

- **`user_id`** — When connecting a wallet (`POST /api/wallets/connect`), send `user_id` in the body (e.g. your auth provider's user/sub id). That links the wallet to the user. `GET /api/dashboard/overview?user_id=<id>` then shows only that user's wallets and their alerts/activity/risk. Wallets connected without `user_id` (legacy) are not included in any user's overview.
- **Overview identity** — Overview accepts either **`user_id`** or **`wallet_address`** as query params. If you send **`wallet_address`**, the backend resolves the linked `user_id` (or creates a dashboard user for that wallet) and returns data for that user. If you send neither, the overview uses the **single-wallet fallback** (on by default): if there is exactly one active wallet, that wallet's user is used so the dashboard shows "1 active wallet".
- **`OVERVIEW_SINGLE_WALLET_FALLBACK`** — Optional env var. **Default: enabled** (fallback runs when there is exactly one active wallet). Set to **`false`** to disable: then overview with no `user_id`/`wallet_address` shows 0 active wallets. Disable for **multi-tenant** deployments so one user's wallet is not shown to everyone.

**Dashboard identity (no external auth)**

- If the frontend does **not** send `user_id` on connect, the backend creates or reuses a **dashboard user** for that wallet: a random `user_id` (e.g. `fetrtwgebejhssns`), a random **display name** (e.g. "Stealth bag", "Megatron", "Alpha"), and a **user number** (e.g. 2314 for "User 2314"). The connect response then includes `dashboard_user: { user_id, display_name, user_number, user_label }`. Use `user_id` for `GET /api/dashboard/overview?user_id=...`.
- **`GET /api/wallets/{address}/dashboard-user`** — Returns the dashboard user for that wallet (404 if never connected).
- **`GET /api/wallets/{address}/balance?chain_id=1`** — Fetches native balance from RPC (`eth_getBalance`). Requires `ETHEREUM_RPC_URL` (or chain-specific RPC). Response: `{ balance_wei, balance_eth, chain_id }`.
- **`GET /api/wallets/{address}/modal`** — **Real data only** for the connected-wallet modal (Details, Balance, Security, Activity). One response: `details` (provider, address, network, connected_at, security_status), `balance` (total_usd from DB assets, native_balance_eth from RPC, `assets[]` from `wallet_assets`), `security` (active_approvals, last_scan_at, last_scan_ago, threat_level, risk_exposure_percent from DB), `activity` (from `activity_feed`). No stubs; 2FA is `null` (not tracked).
- **`GET /api/dashboard/activity/feed`** — **Live activity feed** for the table UI. Query: `user_id` (optional), `page` (default 1), `per_page` (default 10, max 50). Returns `data[]` with: `time` (created_at), `wallet` (display name from wallet_type), `wallet_address`, `type` (Incoming/Outgoing/Contract/Approval from activity_type), `asset`, `amount`, `counterparty`, `risk_level`, `status`, `title`, `description`. Asset/amount/counterparty/risk_level/status come from **metadata** when ingesting: `POST /api/dashboard/{address}/activity` with body `metadata: { "asset": "0.42 ETH", "amount": "0.42", "counterparty": "0x9f3...a21", "risk_level": "low", "status": "completed" }`. Real data from `activity_feed` + wallets join.

**External APIs used by the backend (for reference)**

- **Etherscan V2** — Contract scan (ABI, source, contract creation). See §1 above.
- **Ethereum/chain RPC** — Bytecode, and when the RPC URL is Alchemy, **simulation** (`alchemy_simulateAssetChanges`) for scan results. See §2 and §5.
- **Dashboard overview/summary** — No external API; all from your DB. If you later add Alchemy (or another provider) for transaction/history, that would be documented here.

---

## 7. Deployments and migrations

To avoid **`Migrate(VersionMissing(N))`** on deploy (e.g. on Render):

- **Include the full `migrations/` directory in every build.** The backend embeds migrations at compile time (`sqlx::migrate!("./migrations")`). The commit/branch used for the build must contain all migration files (`001_*` through the latest). If the binary is built without a migration that the database expects, the app will panic at startup with `VersionMissing(N)`.
- **Do not remove or renumber** existing migration files after they have been applied. Do not change the contents of applied migrations (checksum changes cause version mismatch).
- If you see `VersionMissing(N)` again: redeploy from a commit that includes `migrations/NNN_*.sql` and ensure your build step does not exclude the `migrations/` folder (e.g. no `.dockerignore` or similar that drops it).
