# SenseiGuard™ — Technical Architecture (Open the Hood)

This document describes **how SenseiGuard actually operates**: the exact tools and services it uses, the step-by-step paths for transactions and contract scans, and the security models in place. Use it for internal alignment and for **go-to-market (GTM) content** to build user trust by being transparent about the plumbing.

---

## 1. Stack — Tools & Services We Use

### 1.1 Blockchain data & RPC

| Tool / Service | Role | Env / Config | Notes |
|----------------|------|--------------|--------|
| **Etherscan API (V2)** | Contract ABI, verification status, contract creation (deploy time, creator) | `ETHERSCAN_API_KEY`, `ETHERSCAN_BASE_URL`, `ETHERSCAN_CHAIN_ID` | Single key works across Etherscan-supported chains (Ethereum, BSC, Polygon, Base, Arbitrum). Default base: `https://api.etherscan.io/v2/api`. |
| **JSON-RPC (generic)** | Bytecode (`eth_getCode`), native balance (`eth_getBalance`) | `ETHEREUM_RPC_URL`, `BSC_RPC_URL`, `POLYGON_RPC_URL`, `BASE_RPC_URL`, `ARBITRUM_RPC_URL` | Provider-agnostic; we support **Alchemy**, **Infura**, **QuickNode**, or any HTTPS JSON-RPC endpoint. |
| **Alchemy (when RPC is Alchemy)** | Pre-execution simulation | Same as RPC URL | Only when `*_RPC_URL` is an Alchemy URL. Uses **`alchemy_simulateAssetChanges`** to detect drain risk and hidden internal calls. |

**What we do *not* use today:** Chainlink oracles, The Graph for indexing, or any third-party threat-oracle API in the critical path. Reputation is currently our own DB + future hooks for GoPlus/Chainabuse/ScamSniffer (see Security models).

### 1.2 Backend & data

| Component | Technology | Role |
|-----------|------------|------|
| Runtime | **Rust** | Backend services, APIs, security engine. |
| Web framework | **Axum** | HTTP API, routing, middleware. |
| Async runtime | **Tokio** | Async I/O for RPC, Etherscan, DB. |
| Database | **PostgreSQL** | Wallets, scans, threats, alerts, protection settings, blocklists, scam reports, security rules. |
| DB access | **SQLx** | Type-safe queries, migrations. |
| HTTP client | **reqwest** | Calls to Etherscan and RPC (including Alchemy simulation). |

### 1.3 Security & middleware

| Layer | Tool / Approach | Role |
|-------|-----------------|------|
| CORS | **tower-http** | Allow configured frontend origins (`ALLOWED_ORIGINS` + localhost). |
| Rate limiting | **tower_governor** | Per-IP rate limit (configurable `RATE_LIMIT_PER_SEC`). |
| Request body limit | **tower_http** | Cap request size. |
| Security headers | **tower_http** | e.g. `X-Content-Type-Options`, `X-Frame-Options`. |

### 1.4 Algorithms & libraries (in-process)

| Name | Role |
|------|------|
| **strsim (Levenshtein)** | Domain typosquat detection (distance ≤2 vs known brands: Uniswap, MetaMask, OpenSea, etc.). |
| **Template-based AI** | Risk explanation from scan factors (simulation, owner privileges, reputation). LLM not wired yet. |

### 1.5 External references (no direct integration)

- **Revoke.cash** — We do not perform on-chain revokes. The protection API returns a **revoke.cash** URL so users can revoke approvals themselves on-chain.
- **GoPlus / Chainabuse / TokenSniffer / ScamSniffer** — Mentioned in code/roadmap for future reputation enrichment; not integrated today. Current reputation = our **scam_reports** table + contract scan results.

---

## 2. Logic flow — How data moves

### 2.1 Pre-sign transaction path (Safe / Warning / Dangerous / Block)

Used when a user is about to sign a transaction (e.g. from a wallet or Chrome extension). The extension/app sends the pending tx payload to SenseiGuard; we return a risk band and recommendation.

```
User transaction (to, value, data)
        │
        ▼
POST /api/protection/transaction/analyze  or  POST /api/dashboard/:address/analyze-tx
        │
        ▼
SenseiGuard filter (protection_engine)
        │
        ├─ 1. Load user protection settings (PostgreSQL: user_protection_settings)
        ├─ 2. Emergency lock? → If ON, allow only whitelisted addresses → else continue
        ├─ 3. high_risk_tx_warnings OFF? → Return "Safe", recommend "Proceed" (no further checks)
        ├─ 4. Is destination contract in user blocklist? (PostgreSQL: user_blocked_contracts) → If yes → Block
        ├─ 5. Threat analysis (sync, no external API):
        │      • Decode calldata: approval selectors (0x095ea7b3 approve, 0xa22cb465 setApprovalForAll)
        │      • Unlimited approval (0xff...ff in amount) → +35 risk, threat_type: unlimited_approval
        │      • risk_breakdown: approval_risk, simulation_drain (0 in this path)
        ├─ 6. Custom security rules (PostgreSQL: wallet_security_rules):
        │      • block_unlimited_approval, block_tx_above_usd
        ├─ 7. Auto-block if auto_block_high_risk ON and risk_score ≥ 80
        └─ 8. Map score to band: ≥80 Block, 50–79 Dangerous, 30–49 Warning, <30 Safe
        │
        ▼
Response: band, risk_score, recommended_action, threat_types, risk_breakdown
        │
        ▼
Execution decision stays with user / wallet (SenseiGuard does not sign or block on-chain)
```

**Important:** In this path we **do not** call Etherscan, Alchemy, or any RPC. Validation is based on user settings, blocklist, calldata rules, and custom rules — all with **PostgreSQL** and in-process logic. This keeps pre-sign latency low and avoids external rate limits on every tx.

### 2.2 Contract scan path (Trust score, risk breakdown, AI summary)

Used when a user or the dashboard requests a security scan of a **contract** (e.g. before connecting to a dApp or approving a token). This is where we pull in Etherscan and (optionally) Alchemy.

```
User / Dashboard requests scan for contract address (optional: chain_id, for_address)
        │
        ▼
POST /api/scan-contract  or  (dashboard) POST /api/dashboard/:address/scan (wallet-level scan)
        │
        ▼
Scan pipeline (scan_service)
        │
        ├─ 1. Analyzer (analyzer_service)
        │      • Etherscan: getabi / getsourcecode → ABI, verified flag, contract name
        │      • RPC: eth_getCode (bytecode) → DELEGATECALL / opcode checks
        │      • Output: owner_privileges (mint, pause, upgradeable, withdraw_liquidity, blacklist),
        │                dangerous_functions (e.g. setApprovalForAll, approve, delegatecall),
        │                tokens_controlled, abi_source (etherscan | stub)
        │
        ├─ 2. Contract creation (etherscan client)
        │      • getcontractcreation → deploy timestamp, creator
        │      • contract_age_risk (e.g. <7 days → 80, <30 → 50, <365 → 30, else 10)
        │
        ├─ 3. Simulation (simulation_service)
        │      • If RPC URL is Alchemy → alchemy_simulateAssetChanges (zero-value call to contract)
        │      • Output: drains_full_balance, hidden_internal_calls; approval_scope from dangerous_functions
        │      • If not Alchemy or call fails → stub (conservative: drains_full_balance=true, hidden_internal_calls=3)
        │
        ├─ 4. Reputation (reputation_service)
        │      • PostgreSQL: scam_reports count for this contract → reported_scam, community_flags
        │      • (Future: GoPlus, Chainabuse, TokenSniffer, etc.)
        │
        ├─ 5. Trend (senseiguard_repository)
        │      • PostgreSQL: scans_today, wallets_affected for this contract → risk_trend (increasing | stable | low_concern)
        │
        ├─ 6. User anomaly (optional for_address)
        │      • How often this wallet has scanned this contract → user_anomaly_score
        │
        ├─ 7. Scoring (scoring_engine)
        │      • Weights: Simulation 30%, Owner privileges 20%, Reputation 15%, Contract age 15%, Anomaly 10%, Token scope 10%
        │      • trust_score 0–100 (higher = safer), risk_breakdown (percent contribution per factor)
        │      • rug_pull_probability from owner_privileges (High / Medium / Low)
        │
        ├─ 8. AI summary (ai_insight_service)
        │      • Template-based explanation from simulation, owner_privileges, reputation, tokens_controlled
        │      • (Future: LLM for natural-language explanation)
        │
        └─ 9. Persist (contract_scans, wallet_monitoring, security_scans, etc.) and return
        │
        ▼
Response: trust_score, risk_breakdown, rug_pull_probability, ai_summary, scan details
```

So: **Contract scan** = Etherscan (ABI + creation) + RPC (bytecode) + **Alchemy simulation** (when RPC is Alchemy) + **PostgreSQL** (reputation, trend, persistence). **Pre-sign tx** = **PostgreSQL** + in-process calldata and rules only.

### 2.3 dApp connection check (Phishing / typosquat)

When a user connects a dApp (e.g. wallet connect from a website), the client can call:

```
User connects to dApp (domain)
        │
        ▼
POST /api/protection/dapp/connection-check  (wallet_address, domain)
        │
        ▼
SenseiGuard (protection_engine)
        │
        ├─ 1. Load protection settings → if new_dapp_connection_alerts OFF → skip (allow)
        ├─ 2. Domain checks (no external API):
        │      • Typosquat: Levenshtein distance vs known brands (uniswap, metamask, opensea, etc.) + canonical domain check
        │      • Homograph: non-ASCII characters in domain (e.g. Cyrillic lookalikes)
        ├─ 3. risk_score, phishing_risk → response
        │
        ▼
Response: safe_to_connect, risk_level, (optional) warning
```

No Etherscan, RPC, or Alchemy in this path; only **PostgreSQL** (settings) and in-process **Levenshtein** (strsim) + homograph check.

---

## 3. Security models — Frameworks & approaches

We do **not** use zk proofs, multi-sig execution, or on-chain automated auditing bots. Our security is based on the following.

### 3.1 Risk scoring model (additive signals)

- **Bands:** Safe (&lt;30), Warning (30–49), Dangerous (50–79), Block (≥80). Same bands for transactions and dApp connection.
- **Transaction path:** Approval risk (unlimited approval +35), blocklist, custom rules (block_unlimited_approval, block_tx_above_usd), emergency lock.
- **Contract scan path:** Weighted mix of simulation (30%), owner privileges (20%), reputation (15%), contract age (15%), anomaly (10%), token scope (10%) → **trust_score** and **risk_breakdown**.
- **Reference:** Phishing detection roadmap (`docs/PHISHING_DETECTION_ROADMAP.md`) aligns with production patterns (MetaMask/Coinbase-style layered flow and additive risk).

### 3.2 User-controlled protection (no custodial keys)

- **Keys:** Users keep full control of keys; SenseiGuard never signs or holds assets.
- **Toggles:** Auto security scan, high-risk tx warnings, new approval alerts, new dApp connection alerts, auto-block high risk, emergency lock.
- **Blocklist / watchlist:** User-level blocked contracts and watchlist (PostgreSQL).
- **Custom rules:** e.g. block unlimited approval, block tx above USD threshold (rule engine in **protection_engine** + **wallet_security_rules**).
- **Emergency lock:** Only whitelisted addresses allowed when ON.

### 3.3 Data sources we use today

- **Etherscan (V2):** Contract ABI, verification, creation time. No Chainlink or The Graph.
- **RPC (Alchemy / Infura / QuickNode):** Bytecode, balance; **Alchemy-only:** `alchemy_simulateAssetChanges` for drain detection.
- **Our database:** Scam reports, scan history, threats, alerts, protection settings, blocklists, security rules. No automated on-chain audit bots; scans are triggered by user/dashboard or auto-scan interval.

### 3.4 What we do not use (for clarity in GTM)

| Category | Not used | What we use instead |
|----------|----------|----------------------|
| Oracles | Chainlink | Etherscan API, RPC, our DB |
| Indexing | The Graph | PostgreSQL, on-demand RPC/Etherscan |
| Execution / consensus | ZK proofs, multi-sig | User keeps keys; we advise only |
| Auditing | Automated on-chain audit bots | On-demand contract scan (Etherscan + RPC + Alchemy simulation) + pre-sign rule engine |
| Threat intel APIs | GoPlus, Chainabuse, ScamSniffer (planned) | Today: scam_reports table + scan-derived reputation |

### 3.5 Operational security

- **Rate limiting:** Per-IP (tower_governor) to reduce abuse.
- **CORS and headers:** Restrict origins and harden response headers (tower_http).
- **Config:** Secrets (API keys, RPC URLs) via env; no keys in code.

---

## 4. One-page summary for GTM

- **Stack:** **Etherscan API V2** (ABI, verification, contract creation), **generic JSON-RPC** (Alchemy / Infura / QuickNode) for bytecode and balance, **Alchemy** for pre-execution simulation when RPC is Alchemy, **PostgreSQL** for all persistent state, **Rust/Axum/Tokio/SQLx** for the backend.
- **Transaction path:** User tx → **SenseiGuard** (settings + blocklist + calldata rules + custom rules) → **Safe / Warning / Dangerous / Block**. No external chain calls in this path; validation is **PostgreSQL + in-process logic**.
- **Contract scan path:** Contract → **Etherscan** (ABI, creation) + **RPC** (bytecode) + **Alchemy simulation** (drain risk) + **PostgreSQL** (reputation, trend) → **ScoringEngine** (weighted) → **trust_score** + **risk_breakdown** + AI summary.
- **Security model:** Additive risk bands, user-controlled toggles and blocklists, custom rules, emergency lock. **No custodial keys**, **no zk proofs**, **no multi-sig**; we advise, we don’t sign. Optional future: threat intel APIs (GoPlus, Chainabuse, etc.) and LLM for explanations.

Use this doc to say exactly **how** SenseiGuard decides “safe” vs “not safe” and which **named tools** (Etherscan, Alchemy, PostgreSQL, etc.) are in the loop — so users can open the hood and build trust.
