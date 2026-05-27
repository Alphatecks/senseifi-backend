use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct ExternalReputationSignals {
    pub reported_scam: bool,
    pub community_flags: u32,
    pub verified_source: Option<bool>,
}

pub async fn fetch_combined_signals(
    contract_address: &str,
    chain_id: Option<u64>,
) -> ExternalReputationSignals {
    let mut out = ExternalReputationSignals::default();

    let goplus = fetch_goplus_signals(contract_address, chain_id).await;
    if let Some(s) = goplus {
        out.reported_scam |= s.reported_scam;
        out.community_flags = out.community_flags.saturating_add(s.community_flags);
        if s.verified_source == Some(true) {
            out.verified_source = Some(true);
        } else if out.verified_source.is_none() {
            out.verified_source = s.verified_source;
        }
    }

    if let Some(count) =
        fetch_custom_report_count("CHAINABUSE_ADDRESS_URL_TEMPLATE", contract_address).await
    {
        if count > 0 {
            out.reported_scam = true;
            out.community_flags = out.community_flags.saturating_add(count);
        }
    }

    if let Some(count) =
        fetch_custom_report_count("SCAMSNIFFER_ADDRESS_URL_TEMPLATE", contract_address).await
    {
        if count > 0 {
            out.reported_scam = true;
            out.community_flags = out.community_flags.saturating_add(count);
        }
    }

    out
}

async fn fetch_goplus_signals(
    contract_address: &str,
    chain_id: Option<u64>,
) -> Option<ExternalReputationSignals> {
    let base = std::env::var("GOPLUS_API_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://api.gopluslabs.io".to_string());
    let chain = chain_id.unwrap_or(1);
    let url = format!(
        "{}/api/v1/token_security/{}?contract_addresses={}",
        base.trim_end_matches('/'),
        chain,
        contract_address.to_lowercase()
    );
    let json = fetch_json(&url).await?;
    let result_map = json.get("result")?.as_object()?;

    let lookup = contract_address.to_lowercase();
    let token = result_map
        .get(&lookup)
        .or_else(|| result_map.values().next())?
        .clone();

    let verified_source = parse_bool_flag(token.get("is_open_source")).or(Some(false));

    let mut risk_flags = 0u32;
    let risky_keys = [
        "is_honeypot",
        "is_blacklisted",
        "is_proxy",
        "is_mintable",
        "owner_change_balance",
        "cannot_sell_all",
        "trading_cooldown",
        "personal_slippage_modifiable",
        "selfdestruct",
    ];
    for key in risky_keys {
        if parse_bool_flag(token.get(key)) == Some(true) {
            risk_flags = risk_flags.saturating_add(1);
        }
    }

    // Tax outliers are suspicious (common drainer/honeypot characteristic).
    let buy_tax = parse_number_flag(token.get("buy_tax")).unwrap_or(0.0);
    let sell_tax = parse_number_flag(token.get("sell_tax")).unwrap_or(0.0);
    if buy_tax >= 30.0 || sell_tax >= 30.0 {
        risk_flags = risk_flags.saturating_add(1);
    }

    Some(ExternalReputationSignals {
        reported_scam: risk_flags > 0,
        community_flags: risk_flags,
        verified_source,
    })
}

async fn fetch_custom_report_count(template_env: &str, contract_address: &str) -> Option<u32> {
    let template = std::env::var(template_env).ok().filter(|s| !s.trim().is_empty())?;
    let url = template.replace("{address}", contract_address);
    let json = fetch_json(&url).await?;

    if parse_bool_flag(json.get("is_scam")) == Some(true)
        || parse_bool_flag(json.get("reported_scam")) == Some(true)
    {
        return Some(1);
    }

    let count = extract_report_count(&json);
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

async fn fetch_json(url: &str) -> Option<Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .ok()?;
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

fn parse_bool_flag(v: Option<&Value>) -> Option<bool> {
    let v = v?;
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => {
            let l = s.trim().to_ascii_lowercase();
            if l == "1" || l == "true" || l == "yes" {
                Some(true)
            } else if l == "0" || l == "false" || l == "no" {
                Some(false)
            } else {
                None
            }
        }
        Value::Number(n) => n.as_i64().map(|x| x > 0),
        _ => None,
    }
}

fn parse_number_flag(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn extract_report_count(v: &Value) -> u32 {
    match v {
        Value::Object(map) => {
            let keys = ["count", "report_count", "reports", "total", "total_reports"];
            for k in keys {
                if let Some(n) = map.get(k).and_then(to_u32) {
                    return n;
                }
            }
            let mut best = 0u32;
            for child in map.values() {
                best = best.max(extract_report_count(child));
            }
            best
        }
        Value::Array(arr) => arr.len().min(u32::MAX as usize) as u32,
        _ => 0,
    }
}

fn to_u32(v: &Value) -> Option<u32> {
    match v {
        Value::Number(n) => n.as_u64().map(|x| x.min(u32::MAX as u64) as u32),
        Value::String(s) => s.trim().parse::<u32>().ok(),
        Value::Array(arr) => Some(arr.len().min(u32::MAX as usize) as u32),
        _ => None,
    }
}
