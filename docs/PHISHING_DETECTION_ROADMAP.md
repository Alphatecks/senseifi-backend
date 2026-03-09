# Phishing detection intelligence roadmap

This document captures a phased plan to make SenseiGuard’s phishing detection more intelligent: moving from **rule-based only** to **reputation, behavior, similarity, and (later) graph/ML**. It aligns with **production-grade patterns** used by MetaMask, Coinbase Wallet, Blockaid, Chainalysis, and TRM Labs.

---

## Production-grade architecture (target)

MetaMask/Coinbase-style layered flow:

```
User action (connect site / sign tx)
        │
        ▼
Domain security layer
        │  Phishing blocklist, domain similarity, homograph, (later: DNS, domain age, reputation feeds)
        ▼
Transaction / contract layer
        │  Simulation (drain/approval detection), contract behavior, approval patterns
        ▼
Threat intelligence layer
        │  Malicious address DB, scam contract DB, (later: victim reports, on-chain analysis)
        ▼
Risk scoring engine (weighted signals)
        │
        ▼
Wallet warning UI (Safe / Medium / High / Block)
```

**Ideal full pipeline (longer term):** Domain analyzer → Contract analyzer → Transaction simulation → Address intelligence → Graph threat engine → Risk score → Warning.

---

## Production risk scoring model

Risk is **additive** over signals (not a single fixed score):

```
risk_score =
  domain_risk +
  address_reputation +
  contract_behavior +
  approval_risk +
  transaction_pattern +
  (later) graph_cluster_score
```

### Signal weights (reference)

| Signal | Weight | When available |
|--------|--------|----------------|
| Domain typosquat / similarity | +25 | Now (Levenshtein) |
| Domain homograph | +25 | Now |
| Domain age &lt; 3 days | +20 | When WHOIS/API |
| Domain on phishing list | +70 | When feed integrated |
| Address in scam cluster | +40 | Phase 2+ |
| Unlimited token approval | +35 | Now |
| Contract unverified | +10 | When verification check |
| Known drain wallet | +80 | Phase 2+ / blocklist |

### Decision bands

| Score | Band | Action |
|-------|------|--------|
| ≥ 80 | Block | Reject / block |
| 50–79 | High warning | Strong warning, recommend reject |
| 30–49 | Medium warning | Review before signing |
| &lt; 30 | Safe | Proceed |

Backend uses these bands for both **dApp connection** and **transaction** risk (see `score_to_band` and weighted scoring in `protection_engine`).

---

## Attacker bypass techniques (to defend against)

Design and future phases should account for:

| Technique | Description | Mitigation |
|-----------|-------------|------------|
| **Approval-only** | Approve now, drain later (no immediate tx). | Approval alerts, reputation, behavioral patterns. |
| **Proxy / delegatecall** | User sees “safe” contract; logic in other contract. | Bytecode analysis, proxy detection. |
| **Delayed execution** | `if block.timestamp > X: drain()`. | Simulation can miss; need heuristics or monitoring. |
| **Signature phishing** | EIP-2612 `permit()` etc. No on-chain tx to simulate. | Message signing warnings, domain + reputation. |
| **Domain rotation** | New domains (e.g. uniswap-airdrop.xyz) faster than blocklists. | Similarity + domain age + feeds. |
| **Homograph domains** | Unicode lookalikes (e.g. Cyrillic `а`). | Unicode normalization, non-ASCII check (done). |
| **Self-destruct swap** | Safe at analysis, then contract replaced. | Reputation, re-scan, victim reports. |
| **Approval + multicall** | approve + transferFrom in one multicall. | Simulation, calldata parsing. |

---

## Current state (rule-based)

- **Tx analyze:** `phishing_indicator` only when destination is on the **block list**.
- **DApp connection:** Typo patterns only: `unlswap`, `unisvvap`, `metamask` ≠ `metamask.io`.

Limitation: unknown campaigns and subtle impersonation are missed.

---

## Phase 1 — High impact, minimal new infra

### 1.1 Domain intelligence (stronger than typos only)

| Feature | Description | Status / note |
|--------|-------------|----------------|
| **Levenshtein similarity** | Compare domain to known brands (uniswap, metamask, etc.). If `levenshtein(domain, brand) <= 2` → phishing_risk. | Implement in `evaluate_dapp_connection`. |
| **Homograph attacks** | Detect non-ASCII (e.g. Cyrillic `а` in “metamаsk”). Normalize to NFC and flag if any char is outside ASCII/Latin. | Implement in `evaluate_dapp_connection`. |
| **Domain age** | `domain_age < 7 days` → risk boost. | Requires WHOIS or external API; defer or use optional service. |

### 1.2 Approval phishing (clearer threat type)

- Already detect unlimited `approve` / `setApprovalForAll` (calldata) and add `unlimited_approval`.
- Add **`approval_phishing`** (or use existing `unlimited_approval` with higher score) when:
  - `approve` value = `MAX_UINT256` **and**
  - Contract is unknown / low reputation (when we have reputation).
- Optional: “approval to contract with no verified code” as a signal (needs Etherscan/verification).

### 1.3 Threat type taxonomy (doc + code constants)

Extend beyond single `phishing_indicator` where useful:

- `phishing_domain` — domain typosquat / homograph / suspicious domain.
- `approval_phishing` — high-risk approval (unlimited to unknown/low-rep contract).
- `phishing_indicator` — block list or combined signals.
- (Later) `drain_wallet`, `scam_cluster`, `malicious_contract`, `impersonation_domain` when we have graph/reputation.

---

## Phase 2 — Address and contract reputation

### 2.1 Address reputation scoring

Signals (when data available):

- Address age (first seen).
- Transaction velocity.
- Number of unique “victims” (wallets that approved or transferred to it).
- Token approvals requested (count, unlimited count).
- Known scam cluster membership.

Scoring:

```
address_risk =
    address_age_score +
    tx_velocity_score +
    approval_pattern_score +
    victim_overlap_score
```

If `address_risk > threshold` → treat as phishing / malicious (e.g. set `phishing_indicator` or new type).

Requires: chain indexer, or external API (e.g. Chainalysis, TRM), or our own DB of “first seen” and approval events.

### 2.2 Contract behavior (beyond current ABI checks)

- Already: `approve` / `setApprovalForAll` and max-uint in calldata.
- Add: bytecode-level or ABI-level signals where feasible:
  - `delegatecall` usage.
  - `selfdestruct`.
  - Suspicious fallback.
  - Hidden mint / privileged functions.

Can be implemented incrementally in analyzer/scan service.

---

## Phase 3 — Graph and behavioral signals

### 3.1 Graph-based scam detection

- **Nodes:** wallet, contract, domain, token.
- **Edges:** transfer, approval, deploy, interaction.
- Detect: shared drain wallets, repeated contract patterns, scam clusters (e.g. connected components, cluster labels).
- Techniques: connected components, graph embeddings, GNN (longer term).
- Requires: indexed chain + graph DB or analytics pipeline.

### 3.2 Behavioral drain patterns

- Pattern: `approve` → `transferFrom` from same contract within short window (e.g. 5 min).
- Rule: if approval detected and transferFrom from same spender within N minutes → `phishing_indicator` or `drain_wallet`.
- Requires: approval ingest + tx history (indexer or external).

### 3.3 Victim pattern (multi-victim)

- Signal: same contract received approvals from many wallets in a short time (e.g. >10 in 1 hour).
- Mark contract as suspicious; use in reputation or block list.
- Requires: global approval/tx data (indexer or feed).

---

## Phase 4 — External feeds and ML

### 4.1 External threat intelligence

- Integrate: scam domain lists, phishing wallet lists, malicious contract lists.
- Examples: CryptoScamDB, PhishTank, Chainalysis, TRM, etc.
- Use as: block list + reputation input (e.g. “in known scam list” → high score).

### 4.2 Machine learning risk model

- Features: domain_age, domain_similarity, wallet_age, tx_velocity, approval_pattern, contract_complexity, graph_cluster_score.
- Model: Gradient Boosting / Random Forest / NN.
- Output: `phishing_probability` 0–1; threshold for alert/block.
- Requires: labeled data, training pipeline, model serving.

### 4.3 Frontend / wallet simulation

- Simulate tx before sign (e.g. Alchemy `alchemy_simulateAssetChanges` or similar).
- Detect: token drain, NFT transfer, approval abuse.
- We already use simulation in scan; extend to pre-sign in extension/dashboard where applicable.

---

## Implementation order (recommended)

1. **Phase 1.1** — Domain: Levenshtein + homograph in `evaluate_dapp_connection` (no new services).
2. **Phase 1.2 / 1.3** — Approval phishing threat type and taxonomy constants.
3. **Phase 2.1** — Address reputation when we have first-seen or external API.
4. **Phase 2.2** — Contract behavior (bytecode/ABI) in analyzer.
5. **Phase 3** — Graph and behavioral patterns when we have indexer/approval history.
6. **Phase 4** — Feeds and ML when we have data and labels.

---

## Risk pipeline (target)

```
User action
   │
   ▼
Transaction analyzer
   │
   ├ Address reputation (Phase 2)
   ├ Contract behavior (Phase 2)
   ├ Approval patterns (Phase 1–2)
   └ (Later) Graph intelligence (Phase 3)
   │
   ▼
Domain analyzer
   │
   ├ Typosquat (Levenshtein) (Phase 1)
   ├ Homograph (Phase 1)
   ├ Domain age (Phase 1, when API available)
   └ Threat feeds (Phase 4)
   │
   ▼
Combined risk score + threat types
   │
   ▼
Alert / block / explain
```

---

## AI-powered upgrades (practical path)

Three upgrades that make SenseiGuard genuinely AI-powered while staying practical (weeks, not months).

### 1. AI-generated threat explanations (contextual) — **Implemented**

**Before:** Fixed static string.  
**After:** Explanations built from **actual risk signals** that triggered the risk.

- **Signals** (from risk engine + dashboard aggregates): e.g. `active_threats`, `multiple_scam_patterns`, `elevated_risk_score`, `community_reports`, `critical_risk_score`.
- **Template-based today:** each signal maps to a reason sentence; description is a short summary + optional bullet list. See `build_ai_threat_explanation` in `senseiguard_service` and `ai_threat_explanation.reasons` / `ai_threat_explanation.signals` in `GET /api/dashboard/security-overview`.
- **Later:** Feed signals (and optionally reasons) into a lightweight LLM (OpenAI, Anthropic, or local) for one natural-language paragraph. Architecture: Risk engine → Threat signals → Explanation generator (templates + optional LLM) → AI Threat Explanation.

Users trust **specific reasons** far more than generic copy.

### 2. AI phishing domain detection (beyond typos) — **Planned**

**Current:** Rule-based (Levenshtein, homograph, hardcoded typos).  
**Target:** ML-based domain similarity so new phishing sites are caught without new rules.

- **Features:** domain_length, character_entropy, brand_similarity, homograph patterns, subdomain structure, domain_age.
- **Model:** Simple classifier (e.g. Logistic Regression, Random Forest, Gradient Boosted Trees). Training data: PhishTank, OpenPhish.
- **Output:** `phishing_probability` (0–1); e.g. &gt; 0.7 → `phishing_risk = true`.
- **Benefit:** Detects variants like `uniswap-airdrop.claim`, `metamask-auth.io`, `app-uniswap.org` automatically.

### 3. Scam cluster detection (graph intelligence) — **Planned**

Phishing wallets usually belong to **scam clusters**. Detecting one scam address can surface many more.

- **Graph model:** Nodes = wallet, contract, domain, token. Edges = transfer, approval, contract interaction.
- **Algorithm:** Connected components or community detection (e.g. NetworkX, Neo4j). Same approach as Chainalysis, TRM Labs.
- **Example:** Address A = known scam; B sends funds to A; C shares contract deployer with A → A, B, C = scam cluster; engine flags all.
- **Requires:** Indexed chain data (transfers, approvals, deployers) and/or external graph API.

### Resulting system (after all three)

```
User action
     │
     ▼
Domain AI detector (2)
     │
     ▼
Transaction analyzer
     │
     ▼
Graph scam detection (3)
     │
     ▼
Risk scoring engine
     │
     ▼
AI explanation generator (1)
```

| Capability           | Before        | After                    |
|----------------------|---------------|--------------------------|
| Phishing detection   | Manual rules  | ML classifier (2)        |
| Threat explanations  | Static text   | Signal-based / LLM (1) ✓ |
| Address detection    | Blocklist     | Scam cluster (3)        |

---

## References

- **MetaMask / Ethereum Phishing Detection** — blocklist, domain similarity, homograph, simulation.
- **Coinbase Wallet** — domain reputation, contract analyzer, on-chain intelligence, risk scoring.
- **Blockaid** — transaction simulation before sign (drain/approval detection).
- **Chainalysis, TRM Labs** — graph and scam cluster detection.
- **CryptoScamDB, PhishTank** — external threat feeds.
- Levenshtein for domain similarity; Unicode normalization / non-ASCII check for homographs.
