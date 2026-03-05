# Protection Control Wiring

The Protection Control toggles now drive real backend behavior. Each toggle enables or disables a specific engine or flow.

## 1. Auto Security Scan

- **Toggle:** `auto_security_scan` in `user_protection_settings`
- **When ON:** The wallet is registered in `protection_auto_scan` with `auto_scan_enabled = true`. A monitor cycle can be run for it.
- **Flow:** On PUT `/api/protection/settings` with `auto_security_scan: true`, we upsert `protection_auto_scan` for that wallet. When the toggle is OFF, we set `auto_scan_enabled = false`.
- **Worker:** Call **POST /api/protection/monitor/run** with `{ "wallet_address": "0x..." }` to run one cycle (e.g. every 30–60s from a cron or in-process loop). For “run all”, fetch wallets from `protection_auto_scan` where `auto_scan_enabled = true` (use `list_wallets_to_monitor` in code) and call the endpoint for each.
- **Cycle:** Updates `last_scan_at`; can be extended to check new approvals, contract interactions, scam tokens, rug risk.

## 2. High-Risk Transaction Warnings

- **Toggle:** `high_risk_tx_warnings`
- **When ON:** **POST /api/protection/transaction/analyze** runs the threat analyzer and applies rules + emergency lock.
- **When OFF:** The same endpoint returns `skipped: true` with reason "High-risk transaction warnings are disabled."
- **Payload:** `{ "wallet_address", "to", "value", "data", "chain_id?" }`
- **Response:** `risk_score`, `warning`, `recommended_action`; unlimited-approval and blocked-contract checks are applied. Custom rules (e.g. block unlimited approval, block tx above USD) and `auto_block_high_risk` are applied.

## 3. New Approval Alerts

- **Toggle:** `new_approval_alerts`
- **When ON:** Ingested approvals are evaluated and, if risky, stored in `wallet_approval_alerts` and returned as alert.
- **Ingest:** **POST /api/protection/approvals/ingest** with `{ "wallet_address", "token_address?", "spender_address", "amount_raw?" }`. The protection engine evaluates; if `should_alert` (risk ≥ 50 and toggle on), a row is created in `wallet_approval_alerts`.
- **When OFF:** Events can still be ingested and evaluated, but no alert is stored (engine returns `should_alert: false` when the toggle is off).

## 4. New dApp Connection Alerts

- **Toggle:** `new_dapp_connection_alerts`
- **When ON:** **POST /api/protection/dapp/connection-check** runs the domain check (typosquatting, phishing-style signals).
- **When OFF:** The endpoint returns `skipped: true`.
- **Payload:** `{ "wallet_address", "domain" }`
- **Response:** `risk_score`, `phishing_risk`.

## 5. Custom Rules (Add New Control)

- **Table:** `wallet_security_rules` (`wallet_address`, `rule_type`, `condition_json`, `action`, `enabled`)
- **CRUD:**  
  - **GET /api/protection/rules?wallet_address=0x...**  
  - **POST /api/protection/rules** (body: `wallet_address`, `rule_type`, `condition_json?`, `action?`)  
  - **PUT /api/protection/rules/{rule_id}?wallet_address=0x...**  
  - **DELETE /api/protection/rules/{rule_id}?wallet_address=0x...**
- **Rule types** evaluated in the transaction analyzer include: `block_unlimited_approval`, `block_tx_above_usd` (e.g. `condition_json: { "max_usd": 5000 }`).

## 6. Emergency Wallet Lock (Wallet Firewall Mode)

- **Toggle:** `emergency_lock` in `user_protection_settings`; **whitelisted_addresses** (JSON array of 0x addresses).
- **When ON:** The protection engine blocks transactions to non-whitelisted addresses and blocks approvals. Only whitelisted destinations are allowed.
- **API:** **POST /api/protection/emergency-lock** with `{ "wallet_address", "lock": true, "whitelisted_addresses": ["0x..."] }`. GET/PUT `/api/protection/settings` also read/write `emergency_lock` and `whitelisted_addresses`.

## 7. Protection Engine

- **Module:** `src/services/protection_engine.rs`
- **Functions:**  
  - `evaluate_transaction(...)` – pre-sign tx analysis; respects emergency lock, blocked contracts, custom rules, and `auto_block_high_risk`.  
  - `evaluate_approval(...)` – approval risk and whether to alert; respects emergency lock and `new_approval_alerts`.  
  - `evaluate_dapp_connection(...)` – domain risk and phishing signal.  
  - `run_monitor_cycle(...)` – one cycle for a wallet (updates `last_scan_at`; extend for real checks).

All of the above read `user_protection_settings` (and rules / `protection_auto_scan` where relevant) so that toggles and rules consistently control behavior.

## 8. Database Tables

- **user_protection_settings** – existing toggles + `emergency_lock`, `whitelisted_addresses` (migration 015)
- **protection_auto_scan** – which addresses have auto-scan on and `last_scan_at` (migration 012)
- **wallet_approval_alerts** – stored approval alerts when New Approval Alerts is on (migration 013)
- **wallet_security_rules** – custom rules (migration 014)

## 9. Status for UI

- **Monitoring Active:** `auto_security_scan === true` and optionally `last_scan_at` recent.
- **Partial Protection:** Some toggles on, some off.
- **Protection Disabled:** All toggles off (or no settings).
- **Emergency lock:** `emergency_lock === true` – show “Wallet Firewall Mode” and whitelist.

Use **GET /api/protection/settings?wallet_address=0x...** to drive these indicators; add optional “last run” from monitor or scan APIs if needed.
