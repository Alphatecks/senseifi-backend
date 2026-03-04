# SenseiGuard™ — Full Threat Detection Architecture

End-to-end flow from user actions to risk score and stored threats. Render this file in any Mermaid-supported viewer (GitHub, VS Code, Notion, etc.).

---

## High-level: Triggers → 4 Surfaces → Risk Engine → Outputs

```mermaid
flowchart TB
    subgraph TRIGGERS["🟦 Triggers"]
        T1["Wallet connect"]
        T2["User clicks Confirm (pre-sign)"]
        T3["Contract interaction (to address)"]
        T4["Extension / Frontend (domain)"]
    end

    subgraph SURFACES["🟨 Four Threat Surfaces"]
        S1["1. Wallet state"]
        S2["2. Transaction intent"]
        S3["3. Smart contract"]
        S4["4. Off-chain context"]
    end

    subgraph ENGINE["🟩 Risk scoring engine"]
        W["Weighted combination"]
        B["Band: Safe / Warning / Dangerous / Block"]
    end

    subgraph OUT["🟧 Outputs"]
        O1["threats table"]
        O2["alerts"]
        O3["API: score + explanation + recommendation"]
    end

    T1 --> S1
    T2 --> S2
    T3 --> S3
    T4 --> S4

    S1 --> W
    S2 --> W
    S3 --> W
    S4 --> W

    W --> B
    W --> O1
    W --> O2
    B --> O3
    W --> O3
```

---

## Detailed: Data flow per surface

```mermaid
flowchart LR
    subgraph TRIGGERS
        A1["Wallet connect"]
        A2["Pre-sign: to, value, data, gas, chainId"]
        A3["Contract address (to)"]
        A4["Domain / URL"]
    end

    subgraph S1["Surface 1: Wallet state"]
        B1["Fetch approvals (ERC20/721)"]
        B2["Check: unlimited? unknown? &lt;24h? no source?"]
        B3["Match vs blocklists"]
        B1 --> B2 --> B3
    end

    subgraph S2["Surface 2: Tx intent"]
        C1["Decode calldata (ABI)"]
        C2["Simulate (eth_call / Tenderly)"]
        C3["Inspect internals, delegatecall, logs"]
        C4["Classify: dangerous fn? drain pattern?"]
        C1 --> C2 --> C3 --> C4
    end

    subgraph S3["Surface 3: Contract"]
        D1["Contract age (&lt;48h?)"]
        D2["Liquidity lock / LP"]
        D3["Owner privileges (mint, pause, rug)"]
        D1 --> D2 --> D3
    end

    subgraph S4["Surface 4: Off-chain"]
        E1["Domain age, SSL"]
        E2["Typosquat (Levenshtein)"]
        E3["URL blacklist, entropy"]
        E1 --> E2 --> E3
    end

    A1 --> S1
    A2 --> S2
    A3 --> S3
    A4 --> S4

    S1 --> SCORE
    S2 --> SCORE
    S3 --> SCORE
    S4 --> SCORE

    subgraph SCORE["Risk engine"]
        SCORE["approval×0.25 + contract×0.25 + simulation×0.30 + behavioral×0.10 + phishing×0.10"]
    end

    SCORE --> THREAT
    SCORE --> API

    subgraph THREAT["Persistence"]
        THREAT["threats (type, surface, explanation, risk_breakdown)"]
        THREAT --> ALERT["alerts (optional)"]
    end

    subgraph API["API response"]
        API["risk_score, band, threat_types[], explanation, recommendation"]
    end
```

---

## External data sources and where they plug in

```mermaid
flowchart TB
    subgraph SENSEIGUARD["SenseiGuard backend"]
        S1["Wallet state pipeline"]
        S2["Tx intent pipeline"]
        S3["Contract pipeline"]
        S4["Off-chain pipeline"]
    end

    subgraph EXTERNAL["External data sources"]
        E1["Etherscan API"]
        E2["GoPlus Security API"]
        E3["Honeypot.is"]
        E4["Chainabuse / ScamSniffer"]
        E5["Tenderly / Alchemy / Blocknative (simulation)"]
        E6["RPC (eth_call)"]
    end

    E1 --> S1
    E2 --> S1
    E3 --> S1
    E4 --> S1
    E1 --> S3
    E2 --> S3
    E3 --> S3
    E5 --> S2
    E6 --> S2
    E4 --> S4
```

---

## Pre-sign (transaction lie detector) pipeline — step by step

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend / Extension
    participant API as Backend API
    participant Decode as Calldata decoder
    participant Sim as Simulator
    participant Rules as Rule engine
    participant Score as Risk scorer
    participant DB as threats / alerts

    U->>FE: Clicks Confirm
    FE->>API: POST /analyze-tx { to, value, data, gas, chainId }
    API->>Decode: Decode ABI
    Decode->>API: function, args (e.g. approve, spender)
    API->>Sim: Simulate tx
    Sim->>API: internal txs, logs, state diff
    API->>Rules: event + decoded + simulation result
    Rules->>API: threat_types[], component scores
    API->>Score: component scores
    Score->>API: risk_score 0–100, band
    API->>DB: create_threat (if any), create_alert (if high)
    API->>FE: { risk_score, band, explanation, recommendation }
    FE->>U: Show: Safe / Warn / Block + explanation
```

---

## Threat types and which surface produces them

```mermaid
flowchart LR
    subgraph SURFACES
        S1["Wallet state"]
        S2["Tx intent"]
        S3["Contract"]
        S4["Off-chain"]
    end

    subgraph TYPES["Threat types (stored in threats.threat_type)"]
        T1["malicious_transaction"]
        T2["phishing_indicator"]
        T3["risky_token"]
        T4["unlimited_approval"]
        T5["signature_phishing"]
        T6["drainer_pattern"]
        T7["behavioral_anomaly"]
        T8["frontend_phishing"]
    end

    S1 --> T2
    S1 --> T4
    S2 --> T1
    S2 --> T4
    S2 --> T5
    S2 --> T6
    S3 --> T3
    S4 --> T2
    S4 --> T8
    S1 -.-> T7
    S2 -.-> T7
```

---

## Risk score bands and actions

```mermaid
flowchart LR
    subgraph INPUT["Weighted components (0–100 each)"]
        A["approval_risk × 0.25"]
        B["contract_risk × 0.25"]
        C["simulation_drain × 0.30"]
        D["behavioral_anomaly × 0.10"]
        E["phishing_risk × 0.10"]
    end

    INPUT --> SUM["risk_score 0–100"]

    SUM --> BANDS

    subgraph BANDS["Bands"]
        R1["0–30: Safe"]
        R2["30–60: Warning"]
        R3["60–85: Dangerous"]
        R4["85–100: Block"]
    end

    R1 --> ACT1["Allow"]
    R2 --> ACT2["Warn user"]
    R3 --> ACT3["Strong warn / optional block"]
    R4 --> ACT4["Block (Premium: auto-block)"]
```

---

## Stack roles (from architecture doc)

```mermaid
flowchart TB
    R["Rules (deterministic lists + patterns)"]
    Sim["Simulation (eth_call / Tenderly)"]
    Score["Scoring (weighted formula)"]
    Expl["Explanation (one clear sentence)"]

    R --> Shield["🛡️ Shield"]
    Sim --> Radar["📡 Radar"]
    Score --> Judge["⚖️ Judge"]
    Expl --> Interpreter["🗣️ Interpreter"]

    Shield --> Out["Threat + explanation"]
    Radar --> Out
    Judge --> Out
    Interpreter --> Out
```

---

*For implementation details and API shape, see [SENSEIGUARD_ARCHITECTURE.md](./SENSEIGUARD_ARCHITECTURE.md).*
