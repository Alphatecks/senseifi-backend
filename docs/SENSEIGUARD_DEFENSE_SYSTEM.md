# SenseiGuard™ Defense System

This document extends the [SenseiGuard Architecture](SENSEIGUARD_ARCHITECTURE.md) with the **missing layers** that separate good detection from great detection: reputation intelligence, contract fingerprinting, and network-level attack awareness. It also defines the **modular engine structure**, additional threat types, **explainable scoring**, and the path from detection to **prevention** (the guardian vision).

---

## 1. Engine Architecture (Modular)

The engine is structured as a pipeline: **Collectors → Processors → Risk Engine → Explanation → API**.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     SenseiGuard Engine                                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Signal Collectors                                                       │
│     ├── Wallet Scanner        (approvals, state, history)                │
│     ├── Transaction Decoder   (calldata, ABI, function id)              │
│     ├── Contract Analyzer     (bytecode, age, LP, owner)                │
│     ├── Domain Analyzer       (URL, SSL, typosquat)                     │
│     └── (Future: Reputation & Fingerprint fetchers)                      │
├─────────────────────────────────────────────────────────────────────────┤
│  Signal Processors                                                       │
│     ├── Simulation Engine     (eth_call, internal txs, drain check)     │
│     ├── Reputation Engine     (deployer, bytecode hash, associations)   │
│     ├── Fingerprint Matcher   (bytecode/opcode/storage vs known fams)   │
│     └── Behavior Analyzer     (rules + patterns per surface)            │
├─────────────────────────────────────────────────────────────────────────┤
│  Risk Engine                                                             │
│     ├── Weighted scoring      (approval_risk, contract_risk, …)         │
│     ├── Threat classification (threat_type, surface, severity)         │
│     └── Network layer         (clustered attacks, shared infrastructure)│
├─────────────────────────────────────────────────────────────────────────┤
│  Explanation Engine                                                      │
│     └── Human-readable output (one sentence + risk_breakdown)             │
├─────────────────────────────────────────────────────────────────────────┤
│  SenseiGuard API Response  (score, band, threat_types, explanation,     │
│                             risk_breakdown, recommendation)              │
└─────────────────────────────────────────────────────────────────────────┘
```

This modular layout keeps collectors, processors, and scoring separate so you can add or replace components (e.g. a new reputation provider) without rewriting the whole pipeline.

---

## 2. What Is Missing (and How to Add It)

Your current system is strong on **rules and simulation**. Three major layers are still absent; adding them moves the system toward **threat intelligence network** quality.

---

### 2.1 Reputation Intelligence Layer

**Problem:** Today the system is mostly rule-based. Attackers reuse:

- **Bytecode** (same logic, new address)
- **Deployer wallets** (one EOA deploys many drainers)
- **Proxy factories** (same factory, new instance)
- **Drainer infrastructure** (same backend, new front contract)

Without reputation, a slightly modified or redeployed contract can bypass rules.

**Reputation signals to track:**

| Signal | Description | Use |
|--------|--------------|-----|
| `contract_deployer` | EOA or factory that deployed this contract | Same deployer as known drainers → boost risk |
| `contract_bytecode_hash` | Hash of runtime bytecode (or creation code) | Match to known malicious bytecode |
| `first_seen_timestamp` | When we first saw this contract/deployer | Fresh deployer + recent malicious deploys → campaign |
| `wallet_association_graph` | Links: wallet ↔ contract ↔ other wallets (e.g. funding, CEX) | Cluster and label attack infrastructure |

**Example detection:**

> This contract was deployed by the same wallet that deployed **3 known drainer contracts** in the last 24 hours.

**Implementation direction:**

- Store `contract_deployer`, `bytecode_hash`, `first_seen` in contract/deployer tables.
- Join with `threats` / incident data: “deployer X deployed contracts A, B, C; A and B are confirmed drainers.”
- Reputation Engine consumes this and outputs a **reputation_risk** component (0–100) and a short reason for the explanation engine.

---

### 2.2 Contract Fingerprinting

**Problem:** Malicious contracts often share **structural** similarities (not just behavior). Rule-only analysis can miss new variants.

**Idea:** Treat contracts like malware: fingerprint and match to **families** and **attack patterns**.

**Fingerprint dimensions:**

| Dimension | Description | Example |
|-----------|-------------|---------|
| `bytecode_hash` | Hash of runtime or creation bytecode | Exact clone detection |
| `opcode_frequency` | Histogram or signature of opcodes | Same “DNA” as known drainer |
| `proxy_structure` | Proxy pattern, delegatecall targets, upgrade slot | wallet_drainer_v2 pattern |
| `storage_layout_patterns` | Slot usage, proxy storage layout | Matches known scam layout |

**Storage (signature-like):**

```
contract_fingerprint
  - fingerprint_id (hash or composite)
  - family: "wallet_drainer_v2"
  - attack_pattern: "multicall_drain"
  - first_seen_at
  - risk_level: high
```

**When a similar contract appears:**

- Fingerprint Matcher finds a hit (exact or fuzzy).
- **risk_score += high** (or set a minimum floor).
- Explanation: “This contract matches a known drainer family (wallet_drainer_v2).”

This enables **zero-day-style** detection when new contracts share structure with known bad families.

---

### 2.3 Network-Level Attack Detection

**Problem:** Detection is currently **single-wallet / single-transaction** focused. Many attacks are **campaigns**: one contract or one infrastructure drains many wallets in a short window.

**What to detect:**

| Pattern | Description | Example |
|--------|-------------|---------|
| **Clustered attacks** | Many wallets drained by the same contract or same deployer in a time window | “Contract X drained 40 wallets in 2 hours” |
| **Repeated drain patterns** | Same bytecode/fingerprint or same flow across multiple victims | Same multicall sequence on 20 wallets |
| **Shared drainer infrastructure** | Same funding source, same CEX withdrawal, same proxy factory | Cluster of contracts linked to one EOA |

**Example output:**

> This contract has drained **27 wallets** in the past 6 hours.

**Implementation direction:**

- Aggregate by `source_contract` and/or `deployer` and time: count distinct victim wallets, count events.
- Store or cache: `contract_id` / `deployer` → `victim_count_24h`, `victim_count_6h`, `first_drain_at`, `last_drain_at`.
- Network layer in the Risk Engine consumes these counts and:
  - Pushes **risk_score** up (e.g. +20 if victim_count_6h &gt; 10).
  - Adds a **threat_type** (e.g. `network_drain_campaign` or reuse `drainer_pattern` with explanation).
  - Feeds the Explanation Engine: “This contract has drained N wallets in the past X hours.”

---

## 3. Explainable Scoring (Risk Breakdown)

Scoring must be **explainable**. Return not only a single number but **why** the score is what it is.

**Instead of only:**

```json
{ "risk_score": 72 }
```

**Return:**

```json
{
  "risk_score": 72,
  "risk_breakdown": {
    "approval_risk": 30,
    "contract_age": 10,
    "owner_privileges": 20,
    "phishing_signal": 12,
    "simulation_drain": 0,
    "reputation_risk": 0,
    "fingerprint_risk": 0,
    "network_campaign_risk": 0
  }
}
```

- Each component is 0–100; the **Risk Engine** combines them with weights (as in the main architecture).
- **Explanation Engine** turns `risk_breakdown` + threat_types into one human sentence (e.g. “High risk: unlimited approval to a contract deployed 3 hours ago with owner mint and no liquidity lock.”).
- Storing `risk_breakdown` in `threats.risk_breakdown` (JSONB) supports auditing and trust: users and auditors see **why**.

---

## 4. Threat Types (Extended)

In addition to the types in the [main architecture](SENSEIGUARD_ARCHITECTURE.md), add these for common DeFi attack vectors:

| Type | Surface | Definition |
|------|--------|------------|
| **honeypot_token** | Contract / Wallet state | Token that cannot be sold (e.g. transfer restrictions, hidden trap). |
| **proxy_upgrade_risk** | Contract / Tx intent | Proxy or upgradeable contract; risk of malicious upgrade or delegatecall to unknown impl. |
| **fake_liquidity_lock** | Contract | Claims locked LP but lock is fake, short, or bypassable. |
| **scam_airdrop_token** | Contract / Off-chain | Airdrop that requires approval or signature and leads to drain. |
| **gasless_signature_trap** | Tx intent | Gasless (meta-tx) or permit flow that signs away approvals or ownership. |

These integrate into the same pipeline: **Signal Collectors** and **Behavior Analyzer** (and later **Fingerprint Matcher**) set threat types; **Risk Engine** uses them for scoring and classification.

---

## 5. From Detection to Prevention (Guardian Vision)

The design today focuses on **detecting** threats. The most valuable Web3 security systems **prevent** them. SenseiGuard should evolve into a **guardian** that can act, not only warn.

**Prevention capabilities to target:**

| Capability | Description |
|------------|--------------|
| **Approval firewall** | Block or warn on new approvals that exceed risk threshold or match dangerous patterns. |
| **Automatic approval revocation** | Revoke or reduce approval to a contract when it is later flagged (drainer, phishing, campaign). |
| **Malicious contract blocking** | Persist “blocked” contracts per user or global; block txs and approvals to them. |
| **Transaction veto** | Before sign: recommend “Reject” and (where possible) block signing of high-risk txs (e.g. via extension or wallet integration). |

**Flow:**

1. **Detection** (current + reputation + fingerprint + network) produces risk_score, threat_types, explanation, risk_breakdown.
2. **Policy** (user or org settings) defines thresholds and actions: e.g. “block if risk_score ≥ 85”, “revoke approvals to any contract in campaign”.
3. **Prevention** executes: block tx, revoke approval, add to blocklist, show veto UI.

When detection turns into prevention, the system becomes a real **guardian**—which fits the name SenseiGuard.

---

## 6. Summary: Before vs After

| Dimension | Current (strong base) | After (defense system) |
|-----------|------------------------|-------------------------|
| **Intelligence** | Rule-based + simulation | + Reputation (deployer, bytecode, associations) |
| **Contract risk** | Behavior + age + LP + owner | + Fingerprinting (families, attack patterns) |
| **Scope** | Single wallet / single tx | + Network (clustered attacks, campaign, victim counts) |
| **Engine** | Described as rules/surfaces | Modular: Collectors → Processors → Risk → Explanation → API |
| **Scoring** | risk_score (single number) | + risk_breakdown (per-component, explainable) |
| **Threat types** | 8 core types | + honeypot_token, proxy_upgrade_risk, fake_liquidity_lock, scam_airdrop_token, gasless_signature_trap |
| **Role** | Detection | Detection + **Prevention** (firewall, revocation, blocking, veto) |

---

## 7. References

- [SenseiGuard Architecture](SENSEIGUARD_ARCHITECTURE.md) — Four surfaces, threat types, scoring, API.
- [Threat Detection Architecture](THREAT_DETECTION_ARCHITECTURE.md) — Flow from triggers to threats/alerts.

*This document is the roadmap for the SenseiGuard defense system: reputation, fingerprinting, network awareness, modular engine, explainability, and prevention.*
