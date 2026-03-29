# Senseifi Technical White Paper

Version: 1.0  
Date: 2026-03-29  
Scope: `backend` Rust service

## 1) Executive Overview

Senseifi is a Rust/Axum security backend for wallet protection, contract scanning, and wallet risk intelligence dashboards.  
It combines:

- In-process transaction and domain-risk heuristics.
- User-level policy enforcement (rules, emergency lock, blocklists).
- Contract intelligence from Etherscan + chain RPC + optional Alchemy simulation.
- PostgreSQL persistence for threats, scans, alerts, approvals, activity, and configuration.

The system is designed as an advisory and control plane for wallet security workflows. It does not custody keys and does not execute transactions on behalf of users.

## 2) Technical Stack

### Core Runtime

- Language: Rust 2021
- Web framework: Axum
- Async runtime: Tokio
- DB access: SQLx
- Database: PostgreSQL
- HTTP client: reqwest
- Middleware: tower-http, tower_governor

### Security-Related Middleware

- CORS allowlist (`ALLOWED_ORIGINS` plus localhost defaults).
- Per-IP rate limiting (`RATE_LIMIT_PER_SEC`, `RATE_LIMIT_BURST`).
- Request body size cap (256 KiB).
- Security headers:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`

## 3) Service Architecture

Senseifi follows a layered architecture:

1. **Routes**: HTTP parsing, basic validation, response shaping.
2. **Services**: orchestration, risk logic, score computation.
3. **Repositories**: SQL persistence and query abstraction.
4. **Clients**: external integrations (Etherscan, RPC, Moralis, pricing, Alchemy simulation).
5. **Models**: typed request/response and domain payloads.

### Main API Domains

- `/api/wallets`: wallet connect/status/balance/age/modal data.
- `/api/dashboard`: overview, metrics, scans, alerts, threats, assets, activity.
- `/api/scan-contract`: contract scan pipeline and scan details.
- `/api/protection`: transaction analysis, dApp checks, rules, lock/freeze, watchlist, reports.

## 4) Risk and Protection Flows

### 4.1 Pre-sign Transaction Analysis

Endpoint family:

- `POST /api/protection/transaction/analyze`
- `POST /api/dashboard/{address}/analyze-tx`

Decision sequence:

1. Load wallet protection settings.
2. If emergency lock is enabled, only whitelisted destinations are allowed.
3. If high-risk transaction warnings are disabled, response is skipped/safe.
4. Check user blocklist for destination contract.
5. Analyze transaction calldata for approval risk.
6. Apply custom rules (for example unlimited approval or max USD cap).
7. Auto-block if enabled and score is high.
8. Persist threat/alert records when thresholds are crossed.

Band thresholds:

- `>= 80`: Block
- `50 - 79`: Dangerous
- `30 - 49`: Warning
- `< 30`: Safe

Current notable signal:

- Unlimited approval selector/amount pattern contributes significant risk (`+35`).

### 4.2 dApp Connection Phishing Check

Endpoint:

- `POST /api/protection/dapp/connection-check`

Signals:

- Typosquat similarity (Levenshtein) against known brands.
- Homograph detection through non-ASCII domain characters.

Weights:

- Domain typosquat: `+25`
- Homograph: `+25`

### 4.3 Contract Intelligence Scan

Endpoint:

- `POST /api/scan-contract`

Pipeline:

1. ABI/source analysis (Etherscan) and static risk extraction.
2. Bytecode fetch (RPC `eth_getCode`).
3. Contract creation metadata for age risk.
4. Simulation (Alchemy when RPC host is Alchemy, otherwise stub fallback).
5. Reputation from internal scam reports.
6. Trend and anomaly from historical scan data.
7. Weighted scoring and explainable `risk_breakdown`.
8. Persistence into `contract_scans`.

## 5) Scoring Methodology

### 5.1 Contract Trust Score (0-100, higher is safer)

Weighted factors:

- Simulation: 30%
- Owner privileges: 20%
- Reputation: 15%
- Contract age: 15%
- User anomaly: 10%
- Token control scope: 10%

Computation:

- Compute risk contribution for each factor (`0-100` each).
- Weighted aggregate forms total risk.
- `trust_score = 100 - weighted_risk` (clamped to `0-100`).

### 5.2 Wallet Full Scan Score

Wallet scan score uses a simpler formula based on persisted telemetry:

- `score = 100 - 5*(threats_this_month) - 10*(high_risk_alerts)` (clamped).

Status mapping:

- `0 - 39`: weak
- `40 - 69`: moderate
- `70 - 100`: strong

## 6) Data Model and Persistence

The backend applies SQL migrations at startup and stores both operational and intelligence data.

### Core Entities

- `wallets`: connected wallet identity, chain, type, active state, optional `user_id`.
- `wallet_monitoring`: wallet-level security score and scan timing.
- `dashboard_users`: generated/linked dashboard identity.
- `security_scans`: wallet scan history and observations.
- `contract_scans`: contract trust/intelligence results and details JSON.
- `threats`, `alerts`, `activity_feed`: security event streams.
- `wallet_assets`: token holdings (with chain/contract uniqueness evolution).
- `wallet_approvals`, `transaction_monitoring`: approval and risk monitoring artifacts.
- `user_protection_settings`, `wallet_security_rules`: enforcement controls.
- `user_blocked_contracts`, `user_contract_watchlist`, `scam_reports`: policy and reputation inputs.
- `dapp_connections`: dashboard-connected dApp metadata.

### Address Canonicalization

Wallet addresses are normalized to lowercase for consistent matching and indexing semantics.

## 7) External Integrations

### Implemented

- **Etherscan API V2**: ABI/source/creation and wallet age-related lookups.
- **Chain JSON-RPC**: bytecode and balance (`eth_getCode`, `eth_getBalance`).
- **Alchemy simulation**: asset-change simulation when RPC endpoint is Alchemy.
- **Moralis wallet tokens**: indexed token sync into `wallet_assets`.
- **Native asset pricing**: multiple market data providers with short-term cache.

### Fallback Strategy

- Missing Etherscan or analysis errors can degrade to stub-based analyzer behavior.
- Missing chain RPC for target chain yields explicit configuration errors.
- Non-Alchemy RPC uses simulation stubs.
- Moralis sync endpoint returns service-unavailable semantics when not configured.

## 8) Security and Operational Posture

### Defensive Controls

- Input validation for wallet addresses at route boundaries.
- DB pool hardening details:
  - statement cache disabled to avoid cached-plan mismatch after schema changes.
  - connection cap and acquire timeout configured.
- Secrets are expected from environment variables.
- Migrations are embedded/required at startup.

### Deployment Behavior

- Service startup fails without `DATABASE_URL`.
- Migrations execute on boot (`sqlx::migrate!("./migrations")`).
- Host/port configurable through environment (`HOST`, `PORT`).

## 9) Current Limitations and Engineering Gaps

This section is intentionally explicit for technical credibility.

1. **Authentication model**: many API behaviors rely on caller-provided `user_id` scoping rather than enforced end-user auth in this service boundary.
2. **Stub paths still present** in selected flows (simulation, analyzer degradation, placeholder endpoints).
3. **Some dashboard cards are partially placeholder-backed** when underlying ingest/index data is not populated.
4. **Contract fingerprint table exists** but appears underused in active service flows.
5. **Documentation and code parity risk** should be managed continuously (for example, chain-RPC fallback expectations should follow code truth).

## 10) Reliability and Trust Recommendations

For production-grade assurance:

- Add formal authn/authz guardrails for user-scoped routes.
- Separate clearly in API responses which fields are measured vs inferred vs stubbed.
- Introduce signed audit events for security decisions (transaction analysis outcomes).
- Add integration tests around chain-ID routing and fallback behavior.
- Add quality gates for docs-to-code consistency before release.

## 11) Conclusion

Senseifi already implements a meaningful security architecture: deterministic pre-sign controls, explainable contract scoring, wallet-level risk telemetry, and multi-source data enrichment.  
The strongest next milestone is tightening trust boundaries (authentication and provenance), while preserving the current strengths of transparency, explainability, and modular design.

With those upgrades, the platform can move from a strong engineering prototype into a more formally assured security backend for wallet protection products.
