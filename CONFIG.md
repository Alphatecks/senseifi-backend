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

**What is real now:** Owner privileges, dangerous functions, contract age risk, owner/admin count (from creation), tokens controlled (from ABI), reputation (DB), trend (DB), user anomaly (DB scan count).

**Still stub:** **Simulation** (drains_full_balance, hidden_internal_calls, approval_scope). To make it real, integrate Tenderly or Alchemy simulation below.

---

## 5. Optional: simulation (to make risk 100% real)

The **simulation** block (drains_full_balance, approval_scope, hidden_internal_calls) is currently a fixed placeholder. To make it real:

- **Tenderly**: [tenderly.co](https://tenderly.co) — simulate transactions and inspect internal calls. Env: `TENDERLY_ACCESS_KEY`, `TENDERLY_PROJECT`, `TENDERLY_USER`. Wire `SimulationService::simulate_contract` to call Tenderly Simulation API.
- **Alchemy**: If you use Alchemy RPC, their [simulation APIs](https://docs.alchemy.com/reference/simulate-asset-changes) (e.g. `alchemy_simulateAssetChanges`) can show what a call would do. Wire `SimulationService` to use that when `ETHEREUM_RPC_URL` (or chain RPC) is Alchemy.

Until then, simulation stays stub and trust score is partly estimated.

---

## 6. Render / production

In Render (or any host), set the same variables in the **Environment** tab:

- `ETHERSCAN_API_KEY`
- `ETHEREUM_RPC_URL`
- Optionally `ETHERSCAN_BASE_URL` for non-mainnet.

Do **not** commit `.env` or keys to git.
