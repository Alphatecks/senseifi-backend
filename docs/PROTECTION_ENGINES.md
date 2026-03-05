# Protection Control: From Toggles to Engines

Each toggle in Protection Control is intended to drive an **engine**, not just store a boolean.

---

## 1. Auto Security Scan → Watchdog Engine

**When enabled:** Run scheduled jobs (e.g. every 5–10 min transactions, 30 min approvals, 1h reputation).

**Backend support:**
- **`wallet_scan_history`** — One row per run: `wallet_address`, `scan_type`, `risk_score`, `issues_found`, `details` JSONB, `scanned_at`.
- **Repo:** `create_wallet_scan_history`, `list_wallet_scan_history(wallet, limit)`.
- **API:** **GET /api/protection/scan-history?wallet_address=0x...&limit=20** — List recent scan runs.

**To make it live:** Add a worker/cron that, when `auto_security_scan` is true, calls your scan/approval/threat logic and records rows via `create_wallet_scan_history`.

---

## 2. High-Risk Tx Warnings → Pre-Sign Simulation Engine

**Goal:** Before the user signs, simulate the tx and return risk (unlimited approvals, drains, delegatecalls, etc.).

**Backend support:**
- **Models:** `SimulateTxRequest` (wallet_address, to, data, value, chain_id), `SimulateTxResponse` (risk_level, expected_token_loss, hidden_internal_calls, dangerous_functions, should_warn).
- **API:** **POST /api/protection/simulate-tx** — Body: `SimulateTxRequest`. Returns stub response; replace with Tenderly/Alchemy/eth_call simulation.

**To make it live:** Decode calldata, run simulation (Tenderly or Alchemy `simulateTransaction`), analyze internal calls and approvals, fill `SimulateTxResponse`.

---

## 3. Approval Alerts → Smart Thresholds

**Goal:** Alert only when approval is dangerous (unlimited, unknown contract, unverified, known drainer).

**Backend support:** Existing `wallet_approvals` (risk_level, etc.). Use **`new_approval_alerts`** toggle to gate whether to push/display. Add approval-risk scoring (e.g. approval_risk_score, spender_reputation) in a future schema/API.

---

## 4. dApp Connection Alerts → Reputation Engine

**Goal:** Score domain (age, SSL, phishing similarity, contract reputation) and alert when risky.

**Backend support:** No dedicated table yet. Can store dApp risk in a future `dapp_connections` or reuse contract scan + scam_reports. Toggle **`new_dapp_connection_alerts`** gates whether to show alerts.

---

## 5. Wallet Security Score

**Backend support:**
- **`wallet_security_scores`** — `wallet_address`, `score` (0–100), `risk_breakdown` JSONB, `last_updated`.
- **Computation:** Threats this month, high-risk alerts, risky approvals → deductions → score; then upsert.
- **API:** **GET /api/dashboard/{address}/security-score** — Returns `score`, `risk_breakdown`, `last_updated`, `level` (safe | moderate | dangerous).

---

## 6. Auto-Block High Risk

**Backend support:**
- **`user_protection_settings.auto_block_high_risk`** — When true, client/worker can block or require confirmation for high-risk txs.
- **GET/PUT /api/protection/settings** — Include `auto_block_high_risk` and `emergency_freeze_at`.

---

## 7. Emergency Freeze

**Backend support:**
- **`user_protection_settings.emergency_freeze_at`** — Set when user hits “Emergency Lock”; clear when they unfreeze.
- **API:** **POST /api/protection/emergency-freeze** — Body: `{ "wallet_address": "0x...", "freeze": true | false }`. When `freeze: true`, sets `emergency_freeze_at` and turns on `auto_block_high_risk`; when `freeze: false`, clears `emergency_freeze_at`.

Client should block new approvals and unknown contracts when `emergency_freeze_at` is non-null.

---

## 8. Add New Control → Custom Rules

**Backend support:**
- **`user_protection_rules`** — `wallet_address`, `rule_type`, `rule_value` JSONB (e.g. `{"max_usd": 5000}`, `{"block_new_approvals": true}`).
- **API:**
  - **POST /api/protection/rules** — Body: `{ "wallet_address", "rule_type", "rule_value" }`.
  - **GET /api/protection/rules?wallet_address=0x...** — List rules.
  - **DELETE /api/protection/rules/{rule_id}?wallet_address=0x...** — Delete one.

**Example rule_type:** `block_tx_above_usd`, `block_new_approvals`, `allow_only_trusted_dapps`, `block_contracts_younger_than_hours`.

---

## Summary: APIs Added

| Endpoint | Purpose |
|----------|--------|
| GET /api/dashboard/{address}/security-score | Wallet health 0–100 + breakdown + level |
| GET /api/protection/settings | Toggles + auto_block_high_risk + emergency_freeze_at |
| PUT /api/protection/settings | Update toggles + auto_block_high_risk |
| POST /api/protection/emergency-freeze | Set/clear emergency lock |
| POST /api/protection/simulate-tx | Pre-sign simulation (stub) |
| GET /api/protection/scan-history | Auto-scan run history |
| POST /api/protection/rules | Create custom rule |
| GET /api/protection/rules | List rules |
| DELETE /api/protection/rules/{id} | Delete rule |

---

## Next: Threat Learning & Personal Risk

- **Threat learning:** Table/key for contracts_flagged, wallets_affected, attack_patterns; downgrade trust when many wallets flag same contract.
- **Personal risk profile:** Baseline (avg_tx_value, frequent_dapps, usual_gas); anomaly when behavior deviates (e.g. sudden $20k approval).

These can be added as new tables and services that feed into the same engines above.
