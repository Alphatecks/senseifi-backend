use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::json;
use uuid::Uuid;

use crate::db::DbPool;
use crate::models::senseiguard::{
    CommunitySignalsResponse, ContractActivityResponse, ContractLiquidityResponse,
    ScamPatternResponse, ScanContractRequest, ScanContractResponse,
};
use crate::models::wallet::{
    is_valid_scan_contract_address, is_valid_solana_address, is_valid_wallet_address,
    normalize_solana_network, resolve_scan_chain_family,
};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::services::scan_service::ScanService;
use crate::services::xp_usage_service::{self, XpUsageAction, XpUsageError};

/// Normalize EVM contract input (0x address or Etherscan-style URL) or Solana program ID / explorer URL.
fn normalize_contract_input(input: &str) -> String {
    let s = input.trim();
    if s.is_empty() {
        return String::new();
    }
    if is_valid_solana_address(s) {
        return s.to_string();
    }
    if let Some(addr) = extract_solana_from_url(s) {
        return addr;
    }
    if s.len() >= 42 && s.starts_with("0x") && s[2..42].chars().all(|c| c.is_ascii_hexdigit()) {
        return s[..42].to_string();
    }
    if let Some(start) = s.find("0x") {
        let rest = &s[start..];
        let addr: String = rest
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == 'x')
            .collect();
        if addr.len() == 42 && addr.starts_with("0x") {
            return addr;
        }
    }
    s.to_string()
}

fn extract_solana_from_url(s: &str) -> Option<String> {
    let lower = s.to_lowercase();
    for marker in ["/account/", "/token/", "/address/"] {
        if let Some(idx) = lower.find(marker) {
            let rest = &s[idx + marker.len()..];
            let candidate: String = rest
                .chars()
                .take_while(|c| {
                    c.is_ascii_alphanumeric() && *c != '0' && *c != 'O' && *c != 'I' && *c != 'l'
                })
                .collect();
            if is_valid_solana_address(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn scan_xp_error(err: XpUsageError) -> (StatusCode, Json<serde_json::Value>) {
    match err {
        XpUsageError::InsufficientXp {
            xp_balance,
            xp_cost,
            action_type,
        } => (
            StatusCode::PAYMENT_REQUIRED,
            Json(xp_usage_service::insufficient_xp_json(
                xp_balance,
                xp_cost,
                &action_type,
            )),
        ),
        XpUsageError::Database(e) => {
            eprintln!("xp usage error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Database error" })),
            )
        }
    }
}

pub fn scan_routes() -> Router<DbPool> {
    Router::new()
        .route("/", post(scan_contract))
        .route("/{scan_id}", get(get_scan_details))
        .route(
            "/contract/{address}/scam-pattern",
            get(contract_scam_pattern),
        )
        .route("/contract/{address}/activity", get(contract_activity))
        .route("/contract/{address}/liquidity", get(contract_liquidity))
        .route(
            "/contract/{address}/community-signals",
            get(contract_community_signals),
        )
}

async fn scan_contract(
    State(pool): State<DbPool>,
    axum::Json(request): axum::Json<ScanContractRequest>,
) -> Result<Json<ScanContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let address = normalize_contract_input(&request.contract_address);
    if !is_valid_scan_contract_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid contract/program address or link. Use 0x + 40 hex chars (EVM) or a Solana base58 program ID."
            })),
        ));
    }
    let chain_family = resolve_scan_chain_family(request.chain_family.as_deref(), &address);
    let for_address = request
        .for_address
        .as_ref()
        .map(|s| normalize_contract_input(s))
        .filter(|s| is_valid_wallet_address(s, chain_family));
    let for_ref = for_address.as_deref();
    if let Some(wallet) = for_ref {
        if let Err(e) = xp_usage_service::charge_wallet_usage(
            &pool,
            wallet,
            XpUsageAction::ContractScan,
            Some(json!({ "contract_address": address, "chain_family": chain_family.as_str() })),
        )
        .await
        {
            return Err(scan_xp_error(e));
        }
    }
    let solana_network = normalize_solana_network(request.network.as_deref());
    match ScanService::scan_contract(
        &pool,
        &address,
        for_ref,
        request.chain_id,
        chain_family,
        solana_network.as_deref(),
    )
    .await {
        Ok(res) => {
            if let Some(wallet) = for_ref {
                if let Err(e) =
                    ScanService::record_wallet_scan_history(&pool, wallet, &res, chain_family).await
                {
                    eprintln!("wallet scan history: {}", e);
                }
            }
            Ok(Json(res))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": e.to_string()
            })),
        )),
    }
}

async fn get_scan_details(
    State(pool): State<DbPool>,
    Path(scan_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let id = scan_id.parse::<Uuid>().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid scan ID" })),
        )
    })?;
    match ScanService::get_scan_details(&pool, id).await {
        Ok(Some(scan)) => Ok(Json(json!({
            "success": true,
            "data": scan
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "success": false, "error": "Scan not found" })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
        )),
    }
}

/// GET /api/scan-contract/contract/:address/scam-pattern — scam checklist + similarity from latest scan.
async fn contract_scam_pattern(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let address = address.trim();
    if !is_valid_scan_contract_address(address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid contract or program address" })),
        ));
    }
    let scan =
        match SenseiguardRepository::get_latest_contract_scan_by_address(&pool, address).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return Ok(Json(json!({
                    "success": true,
                    "data": {
                        "honeypot": false,
                        "approval_drain": false,
                        "delayed_rug": false,
                        "fee_escalation": false,
                        "similarity_score_percent": 0
                    },
                    "message": "No scan found for this contract. Run a scan first."
                })));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": e.to_string() })),
                ));
            }
        };
    let details = scan.details.as_ref().and_then(|d| d.get("simulation"));
    let sim = details
        .and_then(|s| s.get("drains_full_balance"))
        .and_then(|v| v.as_bool());
    let approval_drain = sim == Some(true);
    let owner = scan
        .details
        .as_ref()
        .and_then(|d| d.get("owner_privileges"));
    let withdraw_liq = owner
        .and_then(|o| o.get("withdraw_liquidity"))
        .and_then(|v| v.as_bool());
    let delayed_rug = withdraw_liq == Some(true);
    let mint = owner.and_then(|o| o.get("mint")).and_then(|v| v.as_bool());
    let pause = owner.and_then(|o| o.get("pause")).and_then(|v| v.as_bool());
    let honeypot = (mint == Some(true) || pause == Some(true)) && (approval_drain || delayed_rug);
    let fee_escalation = false; // no set_fee in owner_privileges yet; wire when added
    let similarity_score_percent = (100i32.saturating_sub(scan.trust_score)).clamp(0, 100) as u8;
    let data = ScamPatternResponse {
        honeypot,
        approval_drain,
        delayed_rug,
        fee_escalation,
        similarity_score_percent,
    };
    Ok(Json(json!({ "success": true, "data": data })))
}

/// GET /api/scan-contract/contract/:address/activity — activity metrics (placeholder until indexer/RPC).
async fn contract_activity(
    State(_pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_scan_contract_address(address.trim()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid contract address" })),
        ));
    }
    let data = ContractActivityResponse {
        avg_tx_per_day: None,
        largest_tx_usd: None,
        abnormal_activity: false,
    };
    Ok(Json(json!({ "success": true, "data": data })))
}

/// GET /api/scan-contract/contract/:address/liquidity — liquidity metrics (placeholder until DEX/subgraph).
async fn contract_liquidity(
    State(_pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_valid_scan_contract_address(address.trim()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid contract address" })),
        ));
    }
    let data = ContractLiquidityResponse {
        initial_lp_usd: None,
        current_lp_usd: None,
        sudden_pulls: None,
    };
    Ok(Json(json!({ "success": true, "data": data })))
}

/// GET /api/scan-contract/contract/:address/community-signals — report count, exploits, users flagged.
async fn contract_community_signals(
    State(pool): State<DbPool>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let address = address.trim();
    if !is_valid_scan_contract_address(address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "error": "Invalid contract or program address" })),
        ));
    }
    let report_count = SenseiguardRepository::count_scam_reports(&pool, address)
        .await
        .unwrap_or(0);
    let confirmed_exploits = SenseiguardRepository::count_threats_for_contract(&pool, address)
        .await
        .unwrap_or(0);
    let users_flagged_count =
        SenseiguardRepository::count_distinct_reporters_for_contract(&pool, address)
            .await
            .unwrap_or(0);
    let data = CommunitySignalsResponse {
        report_count,
        confirmed_exploits,
        users_flagged_count,
    };
    Ok(Json(json!({ "success": true, "data": data })))
}
