use axum::{
    extract::Path,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};

use crate::models::wallet::is_valid_eth_address;

pub fn scamsniffer_proxy_public_routes() -> Router {
    Router::new().route("/scamsniffer/address/{address}", get(scamsniffer_address_proxy))
}

async fn scamsniffer_address_proxy(
    Path(address): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_valid_eth_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid address format (0x + 40 hex)"
            })),
        ));
    }

    let api_key = std::env::var("SCAMSNIFFER_API_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "success": false,
                    "error": "SCAMSNIFFER_API_KEY is not configured"
                })),
            )
        })?;

    let base = std::env::var("SCAMSNIFFER_LOOKUP_API_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "https://lookup-api.scamsniffer.io".to_string());
    let url = format!("{}/address/check/batch", base.trim_end_matches('/'));

    let payload = json!({
        "address": [address.to_lowercase()]
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(internal_error)?;

    let resp = client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .send()
        .await
        .map_err(internal_error)?;

    let status = resp.status();
    let body = resp.text().await.map_err(internal_error)?;
    if !status.is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "success": false,
                "error": "ScamSniffer upstream error",
                "upstream_status": status.as_u16(),
                "body": body
            })),
        ));
    }

    let parsed: Value = serde_json::from_str(&body).map_err(internal_error)?;
    let (reported_scam, report_count, status_label) = parse_scamsniffer_result(&parsed);

    Ok(Json(json!({
        "success": true,
        "provider": "scamsniffer",
        "address": address.to_lowercase(),
        "reported_scam": reported_scam,
        "report_count": report_count,
        "status": status_label,
        "raw": parsed
    })))
}

fn parse_scamsniffer_result(v: &Value) -> (bool, u32, String) {
    let mut status_label = "UNKNOWN".to_string();
    let mut blocked = false;
    let mut count = 0u32;

    let items: Vec<&Value> = match v {
        Value::Array(arr) => arr.iter().collect(),
        Value::Object(map) => {
            if let Some(Value::Array(arr)) = map.get("data") {
                arr.iter().collect()
            } else if let Some(Value::Array(arr)) = map.get("result") {
                arr.iter().collect()
            } else {
                vec![v]
            }
        }
        _ => vec![v],
    };

    for item in items {
        if let Some(label) = item
            .get("status")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
        {
            status_label = label.clone();
            if label.eq_ignore_ascii_case("BLOCKED") {
                blocked = true;
            }
        }
        if let Some(b) = item.get("is_malicious").and_then(|x| x.as_bool()) {
            blocked |= b;
        }
        if let Some(n) = item
            .get("report_count")
            .and_then(|x| x.as_u64())
            .or_else(|| item.get("count").and_then(|x| x.as_u64()))
            .or_else(|| item.get("reports").and_then(|x| x.as_u64()))
        {
            count = count.saturating_add(n.min(u32::MAX as u64) as u32);
        } else if item.get("status").and_then(|x| x.as_str()) == Some("BLOCKED") {
            count = count.saturating_add(1);
        }
    }

    (blocked, count, status_label)
}

fn internal_error<E: ToString>(err: E) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "success": false,
            "error": err.to_string()
        })),
    )
}
