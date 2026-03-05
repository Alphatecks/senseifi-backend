# Scanner & external services configuration

To make the contract scanner **real** (ABI + bytecode analysis instead of stubs), set the following. If they are missing, the scanner falls back to stub behavior.

---

## 1. Etherscan (ABI + verification)

Used to fetch contract ABI and whether the contract is verified.

- **Get an API key**: [Etherscan → API-KEYs](https://etherscan.io/myapikey). Create an account, then add a key. Free tier: 3–5 calls/sec, 100k calls/day.
- **Set**:
  - `ETHERSCAN_API_KEY` — your key (required for getabi; recommended for rate limits).
  - `ETHERSCAN_BASE_URL` — optional. Default: `https://api.etherscan.io/api`. For other chains use:
    - Arbitrum: `https://api.arbiscan.io/api`
    - Base: `https://api.basescan.org/api`
    - Polygon: `https://api.polygonscan.com/api`
    - BSC: `https://api.bscscan.com/api`

Example `.env`:

```bash
ETHERSCAN_API_KEY=YourEtherscanKeyHere
# ETHERSCAN_BASE_URL=https://api.etherscan.io/api
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

## 3. Behavior summary

| Variable               | Used for                         | If unset / error |
|------------------------|-----------------------------------|-------------------|
| `ETHERSCAN_API_KEY`    | Etherscan getabi / getsourcecode  | Stub privileges & dangerous fns |
| `ETHERSCAN_BASE_URL`   | Chain (Ethereum vs Arbitrum etc.) | Default: Etherscan mainnet API  |
| `ETHEREUM_RPC_URL`     | Bytecode (`eth_getCode`)          | No bytecode; no DELEGATECALL from bytecode |

The analyzer:

1. Tries to fetch ABI from Etherscan (with optional key and base URL).
2. Tries to fetch bytecode from RPC.
3. Parses ABI for privilege-like functions (mint, pause, upgrade, withdraw, blacklist) and dangerous ones (approve, setApprovalForAll, etc.).
4. Scans bytecode for DELEGATECALL (0xF4).
5. If any step fails or config is missing, uses stub values so the API still responds.

---

## 4. Optional: simulation & reputation (future)

Not wired yet; when you add them, typical env vars would be:

- **Tenderly** (simulation): `TENDERLY_ACCESS_KEY`, `TENDERLY_PROJECT`, `TENDERLY_USER` (or similar from [Tenderly](https://tenderly.co)).
- **Alchemy** (simulate): same as `ETHEREUM_RPC_URL` if using Alchemy; their `alchemy_simulateAssetChanges` or similar.
- **GoPlus / others** (reputation): `GOPLUS_API_KEY` etc., then call their token/address security APIs and map into `details.reputation`.

---

## 5. Render / production

In Render (or any host), set the same variables in the **Environment** tab:

- `ETHERSCAN_API_KEY`
- `ETHEREUM_RPC_URL`
- Optionally `ETHERSCAN_BASE_URL` for non-mainnet.

Do **not** commit `.env` or keys to git.
