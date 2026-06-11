//! GoPlus Security API client: auth, phishing site, dApp security, address security, token security.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::RwLock;

const DEFAULT_BASE_URL: &str = "https://api.gopluslabs.io";
const REQUEST_TIMEOUT_SECS: u64 = 4;
const TOKEN_REFRESH_BUFFER_SECS: i64 = 60;

struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

static TOKEN_CACHE: OnceLock<RwLock<Option<CachedToken>>> = OnceLock::new();

fn token_cache() -> &'static RwLock<Option<CachedToken>> {
    TOKEN_CACHE.get_or_init(|| RwLock::new(None))
}

pub fn is_enabled() -> bool {
    if std::env::var("GOPLUS_ENABLED")
        .ok()
        .is_some_and(|v| v == "0" || v.eq_ignore_ascii_case("false"))
    {
        return false;
    }
    has_credentials()
}

fn has_credentials() -> bool {
    std::env::var("GOPLUS_APP_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
        && std::env::var("GOPLUS_APP_SECRET")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some()
}

fn api_base_url() -> String {
    std::env::var("GOPLUS_API_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
}

fn http_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .ok()
}

pub fn compute_sign(app_key: &str, time: i64, app_secret: &str) -> String {
    let payload = format!("{}{}{}", app_key, time, app_secret);
    let mut hasher = Sha1::new();
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

async fn get_access_token() -> Option<String> {
    if !is_enabled() {
        return None;
    }

    {
        let cache = token_cache().read().await;
        if let Some(cached) = cache.as_ref() {
            if cached.expires_at > Utc::now() + chrono::Duration::seconds(TOKEN_REFRESH_BUFFER_SECS)
            {
                return Some(cached.access_token.clone());
            }
        }
    }

    let app_key = std::env::var("GOPLUS_APP_KEY").ok()?;
    let app_secret = std::env::var("GOPLUS_APP_SECRET").ok()?;
    let time = Utc::now().timestamp();
    let sign = compute_sign(app_key.trim(), time, app_secret.trim());

    let client = http_client()?;
    let url = format!("{}/api/v1/token", api_base_url().trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(&json!({
            "app_key": app_key.trim(),
            "sign": sign,
            "time": time,
        }))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: Value = resp.json().await.ok()?;
    if body.get("code").and_then(|c| c.as_i64()) != Some(1) {
        return None;
    }

    let access_token = body
        .get("result")?
        .get("access_token")?
        .as_str()?
        .to_string();
    let expires_in = body
        .get("result")?
        .get("expires_in")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600);

    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in.max(60));
    {
        let mut cache = token_cache().write().await;
        *cache = Some(CachedToken {
            access_token: access_token.clone(),
            expires_at,
        });
    }

    Some(access_token)
}

async fn authorized_get(path: &str, query: &[(&str, &str)]) -> Option<Value> {
    let token = get_access_token().await?;
    let client = http_client()?;
    let url = format!("{}{}", api_base_url().trim_end_matches('/'), path);
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .query(query)
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: Value = resp.json().await.ok()?;
    if body.get("code").and_then(|c| c.as_i64()) != Some(1) {
        return None;
    }
    Some(body)
}

fn flag_is_true(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Number(n)) => n.as_i64().is_some_and(|x| x == 1),
        Some(Value::String(s)) => {
            let l = s.trim();
            l == "1" || l.eq_ignore_ascii_case("true")
        }
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct PhishingSiteResult {
    pub is_phishing: bool,
    pub malicious_contracts: Vec<String>,
    pub raw: Value,
}

pub async fn check_phishing_site(url: &str) -> Option<PhishingSiteResult> {
    if !is_enabled() || url.trim().is_empty() {
        return None;
    }

    let body = authorized_get("/api/v1/phishing_site", &[("url", url.trim())]).await?;
    let result = body.get("result")?;
    let is_phishing = flag_is_true(result.get("phishing_site"));

    let mut malicious_contracts = Vec::new();
    if let Some(arr) = result.get("website_contract_security").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(contract) = item.get("contract").and_then(|v| v.as_str()) {
                if !contract.trim().is_empty() {
                    malicious_contracts.push(contract.to_string());
                }
            }
        }
    }

    Some(PhishingSiteResult {
        is_phishing,
        malicious_contracts,
        raw: result.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct DappSecurityResult {
    pub malicious_contract: bool,
    pub malicious_creator: bool,
    pub is_trusted: bool,
    pub malicious_contract_addresses: Vec<String>,
    pub raw: Value,
}

pub async fn check_dapp_security(url: &str) -> Option<DappSecurityResult> {
    if !is_enabled() || url.trim().is_empty() {
        return None;
    }

    let body = authorized_get("/api/v1/dapp_security", &[("url", url.trim())]).await?;
    let result = body.get("result")?;

    let mut malicious_contract = false;
    let mut malicious_creator = false;
    let mut malicious_contract_addresses = Vec::new();

    if let Some(sections) = result.get("contracts_security").and_then(|v| v.as_array()) {
        for section in sections {
            if let Some(contracts) = section.get("contracts").and_then(|v| v.as_array()) {
                for c in contracts {
                    if flag_is_true(c.get("malicious_contract")) {
                        malicious_contract = true;
                        if let Some(addr) = c.get("contract_address").and_then(|v| v.as_str()) {
                            malicious_contract_addresses.push(addr.to_string());
                        }
                    }
                    if flag_is_true(c.get("malicious_creator")) {
                        malicious_creator = true;
                    }
                }
            }
        }
    }

    Some(DappSecurityResult {
        malicious_contract,
        malicious_creator,
        is_trusted: flag_is_true(result.get("trust_list")),
        malicious_contract_addresses,
        raw: result.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct AddressSecurityResult {
    pub is_malicious: bool,
    pub risk_flags: Vec<String>,
    pub raw: Value,
}

const MALICIOUS_ADDRESS_FLAGS: &[&str] = &[
    "blacklist_doubt",
    "blackmail_activities",
    "cybercrime",
    "darkweb_transactions",
    "fake_kyc",
    "fake_standard_interface",
    "fake_token",
    "financial_crime",
    "gas_abuse",
    "honeypot_related_address",
    "malicious_mining_activities",
    "mixer",
    "money_laundering",
    "phishing_activities",
    "reinit",
    "sanctioned",
    "stealing_attack",
];

pub async fn check_address_security(address: &str, chain_id: &str) -> Option<AddressSecurityResult> {
    if !is_enabled() || address.trim().is_empty() {
        return None;
    }

    let path = format!(
        "/api/v1/address_security/{}",
        urlencoding::encode(address.trim())
    );
    let body = authorized_get(&path, &[("chain_id", chain_id)]).await?;
    let result = body.get("result")?;

    let mut risk_flags = Vec::new();
    for key in MALICIOUS_ADDRESS_FLAGS {
        if flag_is_true(result.get(*key)) {
            risk_flags.push(key.to_string());
        }
    }

    let malicious_contracts_created = result
        .get("number_of_malicious_contracts_created")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if malicious_contracts_created > 0 {
        risk_flags.push("number_of_malicious_contracts_created".to_string());
    }

    let is_malicious = !risk_flags.is_empty();

    Some(AddressSecurityResult {
        is_malicious,
        risk_flags,
        raw: result.clone(),
    })
}

pub async fn fetch_token_security(
    contract_address: &str,
    chain_id: u64,
) -> Option<Value> {
    if !is_enabled() {
        return None;
    }

    let path = format!("/api/v1/token_security/{}", chain_id);
    let body = authorized_get(
        &path,
        &[("contract_addresses", contract_address.to_lowercase().as_str())],
    )
    .await?;
    body.get("result").cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_matches_goplus_spec_format() {
        let sign = compute_sign("test_key", 1647847498, "test_secret");
        assert_eq!(sign.len(), 40);
        assert!(sign.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn flag_parsing() {
        assert!(flag_is_true(Some(&json!(1))));
        assert!(flag_is_true(Some(&json!("1"))));
        assert!(!flag_is_true(Some(&json!(0))));
        assert!(!flag_is_true(Some(&json!("0"))));
    }

    #[test]
    fn address_malicious_flags_detected() {
        let result = json!({
            "phishing_activities": "1",
            "stealing_attack": "0"
        });
        let mut flags = Vec::new();
        for key in MALICIOUS_ADDRESS_FLAGS {
            if flag_is_true(result.get(*key)) {
                flags.push(key.to_string());
            }
        }
        assert_eq!(flags, vec!["phishing_activities"]);
    }
}
