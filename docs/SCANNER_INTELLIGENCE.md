# SenseiGuard Scanner: Intelligence Layer & Protection

## Philosophy

The scanner answers three questions:

1. **Why is it risky?** — Simulation, owner privileges, reputation, AI summary.
2. **What will happen if I interact?** — Simulation result (drains, hidden calls, approval scope).
3. **How dangerous for THIS user?** — User anomaly score when `for_address` is provided.

---

## Scan pipeline

```
scan_contract(contract_address, for_address?)
  → AnalyzerService (owner privileges, dangerous functions)
  → SimulationService (drains, hidden calls, approval scope) [stub: Tenderly/Alchemy later]
  → ReputationService (scam reports, verified source) [stub: GoPlus/Chainabuse later]
  → Trend (from DB: scans_today, wallets_affected, risk_trend)
  → User anomaly (stub: 0.78 if for_address set)
  → ScoringEngine (weighted trust score + risk_breakdown)
  → AiInsightService (plain-language summary)
  → Persist contract_scan with full details
```

## Trust score formula (explainable)

| Factor              | Weight |
|---------------------|--------|
| Simulation result   | 30%    |
| Owner privileges     | 20%    |
| Reputation          | 15%    |
| Contract age        | 15%    |
| Behavioral anomaly  | 10%    |
| Token control scope | 10%    |

Response includes `details.risk_breakdown` with each factor’s contribution (percent of total risk).

## Details JSONB shape

- **simulation**: `drains_full_balance`, `hidden_internal_calls`, `approval_scope`, `dangerous_functions`
- **owner_privileges**: `mint`, `pause`, `upgradeable`, `withdraw_liquidity`, `blacklist`
- **reputation**: `reported_scam`, `community_flags`, `verified_source`
- **trend**: `scans_today`, `wallets_affected`, `risk_trend` ("increasing" | "stable" | "low_concern")
- **risk_breakdown**: per-factor contribution to risk
- **ai_summary**: human-readable explanation (also at top level in response)
- **user_anomaly_score**: 0–1 when scan is for a specific wallet
- **rug_pull_probability**: "Low" | "Medium" | "High" from owner privileges

## APIs

### Scan

- **POST /api/scan-contract**  
  Body: `{ "contract_address": "0x...", "for_address": "0x..."? }`  
  Returns full scan with `details` and `ai_summary`.
- **GET /api/scan-contract/:scan_id**  
  Returns full scan (for “View Details”).

### Protection

- **POST /api/protection/block-contract** — `{ wallet_address, contract_address }`
- **DELETE /api/protection/block-contract** — same body (unblock)
- **GET /api/protection/blocked?wallet_address=0x...**
- **POST /api/protection/watchlist** — `{ wallet_address, contract_address }`
- **DELETE /api/protection/watchlist** — same body
- **GET /api/protection/watchlist?wallet_address=0x...**
- **POST /api/protection/report** — `{ contract_address, reporter_wallet_address? }`
- **POST /api/protection/revoke-approval** — `{ wallet_address, contract_address, chain_id? }` → returns `revoke_url` (e.g. revoke.cash).

## Migrations

- **008** — `contract_fingerprints` (bytecode_hash, family, known_attack_type) for DNA/fingerprinting (ready for integration).
- **009** — `user_blocked_contracts`, `user_contract_watchlist`, `scam_reports`.
- **010** — `contract_scans.scanned_for_address` for user-aware scans and trend.

## Next integrations (stubs in place)

- **Simulation**: Tenderly or Alchemy `simulateTransaction` / `eth_call` with approve/swap/transfer/mint/stake.
- **Reputation**: GoPlus, Chainabuse, ScamSniffer, Etherscan verified, TokenSniffer, Honeypot.is.
- **Analyzer**: Fetch bytecode/ABI (Etherscan), opcode/selector analysis, privilege detection.
- **Fingerprints**: Hash bytecode/ABI, match against `contract_fingerprints` and known drainer/honeypot families.
- **AI summary**: Send `details` to an LLM with a “explain for beginner” prompt.
