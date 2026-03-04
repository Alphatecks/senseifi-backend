# SenseiGuard™ Architecture: Transaction Lie Detector

SenseiGuard is not a "wallet scanner." It is a **transaction lie detector** that sits between intention and signature. The backend observes four surfaces and produces a risk score plus a clear, human explanation.

---

## 1. Four Threat Surfaces

| Surface | When observed | What we check |
|--------|----------------|----------------|
| **1. Wallet state** | On connect / periodic | Approvals (ERC20/721), unlimited approvals, approvals to flagged contracts (phishing, exploit, honeypot). Contract age & verified source. |
| **2. Transaction intent** | Pre-sign (user clicked Confirm) | Decoded calldata, simulation (`eth_call` / Tenderly / Alchemy). Dangerous function signatures, drain patterns, internal transfers. |
| **3. Smart contract behavior** | When user interacts with a contract | Contract age, liquidity lock, LP ownership, owner privileges (mint, blacklist, pause, withdraw LP). |
| **4. Off-chain context** | Extension / frontend | Domain age, typosquatting (e.g. unlswap.org), SSL, URL blacklist, entropy. |

All four feed into a single **risk scoring engine** and a single **explanation** (e.g. "Unlimited approval to a contract deployed 3 hours ago with owner mint privileges").

---

## 2. Threat Types We Detect (and store)

These map to `threats.threat_type` and drive dashboard metrics.

| Type | Surface | Definition |
|------|--------|------------|
| **malicious_transaction** | Tx intent | Simulated tx drains >X% of balance, or calls dangerous function (setApprovalForAll, approve(max), transferOwnership, delegatecall, etc.) to unknown/high-risk contract. |
| **phishing_indicator** | Wallet state / Off-chain | Approval or interaction with contract/domain in phishing/exploit/honeypot DB; or domain typosquatting / blacklist. |
| **risky_token** | Contract / Wallet state | Token contract: no liquidity lock, owner mint/blacklist/pause, or on honeypot/rug list. |
| **unlimited_approval** | Wallet state / Tx intent | ERC20/721 unlimited (or max uint) approval to unknown or high-risk contract. |
| **signature_phishing** | Tx intent | EIP-712 / permit with malicious spender or drainer pattern. |
| **drainer_pattern** | Tx intent | Multicall/hidden secondary calls, proxy drain, batch transfer of full balance. |
| **behavioral_anomaly** | Behavioral | Deviation from wallet baseline (unusual value, new dApp, fresh contract). |
| **frontend_phishing** | Off-chain | Domain risk (age, similarity, blacklist). |

---

## 3. Wallet State (Surface 1)

**Trigger:** Wallet connect (and optional periodic refresh).

**Checks:**

- Fetch active approvals (Etherscan/GoPlus/Alchemy): ERC20 `approve`, ERC721 `setApprovalForAll`.
- Flag: unlimited approval to contract that is (a) unknown, (b) in phishing/exploit/honeypot list, (c) created &lt; 24h ago, (d) no verified source.
- Data sources: Etherscan API, GoPlus Security, Honeypot.is, Chainabuse, ScamSniffer (or equivalent feeds).

**Output:** Risk profile (approval risk component), list of threats (e.g. `phishing_indicator`, `unlimited_approval`), and cache for dashboard.

---

## 4. Transaction Intent (Surface 2) — Pre-Sign Simulation

**Trigger:** User clicks Confirm; backend receives `{ to, value, data, gas, chainId }` (and optional `from`).

**Pipeline:**

1. Decode calldata (ABI): identify function (e.g. `approve`, `setApprovalForAll`, `multicall`).
2. Simulate: `eth_call` or Tenderly / Alchemy / Blocknative simulation.
3. Inspect: internal txs, delegate calls, event logs; detect full-balance transfer, batch drains, proxy patterns.
4. Classify: dangerous function to unknown contract → threat; drain &gt; X% → high risk.
5. Return: **risk_score** (0–100), **threat_types**[], **explanation** (one clear sentence), **recommendation** (e.g. Block / Warn / Safe).

**Dangerous function list (examples):**  
`setApprovalForAll`, `approve` (max uint), `transferOwnership`, `delegatecall`, `upgradeTo`, `selfdestruct`, `permit` (unknown spender).

**Drain patterns:**  
Whole balance transfer, approval of max uint, batch transfers, hidden multicall, proxy call draining assets.

---

## 5. Smart Contract (Surface 3)

**Trigger:** When user interacts with a contract (we have `to` or `source_contract`).

**Checks:**

- Contract age: deployed &lt; 48h → higher risk weight.
- Token contracts: liquidity lock duration, LP ownership; unlocked LP → rug risk.
- Owner privileges: mint, blacklist, pause, change fees, withdraw LP → "god-mode" increases rug probability.

**Output:** Contract risk component; threats like `risky_token` when criteria match.

---

## 6. Off-Chain / Phishing (Surface 4)

**Trigger:** Extension or frontend (e.g. when wallet connects to a site).

**Checks:**  
Domain age, similarity (e.g. Levenshtein vs uniswap.org), SSL, blacklist, URL entropy.

**Output:** Phishing risk component; threat type `frontend_phishing` or `phishing_indicator` when applicable.

---

## 7. Risk Scoring Engine

Weighted model (tunable):

```
risk_score = 
  (approval_risk      * 0.25) +
  (contract_risk      * 0.25) +
  (simulation_drain   * 0.30) +
  (behavioral_anomaly * 0.10) +
  (phishing_risk      * 0.10)
```

Each component is 0–100. Final score 0–100:

- **0–30**  = Safe  
- **30–60** = Warning  
- **60–85** = Dangerous  
- **85–100** = Block  

Premium: optional auto-block above threshold.

---

## 8. Backend API Shape (Rust/Axum)

**Wallet connect flow:**

- `GET /api/dashboard/{address}/risk-profile`  
  Returns: wallet state risk, approval summary, cached contract risks, last score.  
  (Triggers or uses cached: fetch approvals, scan risky contracts.)

**Pre-sign flow (transaction lie detector):**

- `POST /api/dashboard/{address}/analyze-tx`  
  Body: `{ "to", "value", "data", "gas", "chainId" }`  
  Returns:  
  `{ "risk_score", "band": "Safe"|"Warning"|"Dangerous"|"Block", "threat_types": [], "explanation": "...", "recommendation": "..." }`  
  (Backend decodes, simulates, classifies, scores.)

**Threat storage:**

- Every detected threat is stored in `threats` with:  
  `threat_type`, `surface` (wallet_state | tx_intent | contract | off_chain), `explanation`, `risk_breakdown` (JSONB), `source_contract`, `severity`.

**Explanation rule:**  
AI/rules must not only say "High risk." They must say e.g.  
"This transaction grants unlimited approval to a contract deployed 3 hours ago with owner mint privileges."

---

## 9. Advanced Threat Types (handled in rules + simulation)

- Signature phishing (EIP-712 malicious permit)
- Blind signing
- NFT airdrop drain traps
- Gasless approval traps
- Social engineering batch approvals
- Cross-chain bridge fake contracts
- Proxy upgrade rug switches

These are implemented as threat types and rules on top of the same four surfaces and the same scoring pipeline.

---

## 10. Stack Principle

- **Rules** = shield (deterministic, list + pattern).
- **Simulation** = radar (pre-sign outcome and internals).
- **Scoring** = judge (weighted combination).
- **Explanation** = interpreter (one clear sentence per decision).

The backend owns: ingestion of events, rules, simulation orchestration, scoring, storage of threats and risk profile, and the APIs above. The AI explanation layer can be a separate service or model called by the same pipeline.

---

*This document is the single source of truth for what SenseiGuard detects and how the backend is structured. Implementations (Rust services, migrations, external integrations) follow this architecture.*
