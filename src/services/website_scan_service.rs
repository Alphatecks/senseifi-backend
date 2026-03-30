use reqwest::header::{CONTENT_TYPE, HeaderMap};
use scraper::{Html, Selector};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

const DEFAULT_MAX_PAGES: usize = 4;
const MAX_ALLOWED_PAGES: usize = 10;
const CACHE_TTL_SECONDS: u64 = 600;

#[derive(Debug, Clone, serde::Serialize)]
pub struct WebsiteScanIssue {
    pub code: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WebsitePageScan {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub issues: Vec<WebsiteScanIssue>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WebsiteScanResult {
    pub target: String,
    pub normalized_url: String,
    pub domain: String,
    pub safety: String,
    pub risk_score: i32,
    pub crawled_pages: usize,
    pub issues: Vec<WebsiteScanIssue>,
    pub pages: Vec<WebsitePageScan>,
}

#[derive(Clone)]
struct CachedScan {
    created_at: Instant,
    result: WebsiteScanResult,
}

static WEBSITE_SCAN_CACHE: OnceLock<RwLock<HashMap<String, CachedScan>>> = OnceLock::new();
static WEBSITE_SCAN_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<String, CachedScan>> {
    WEBSITE_SCAN_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn http_client() -> &'static reqwest::Client {
    WEBSITE_SCAN_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("SenseiGuardSecurityScanner/1.0")
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

fn normalize_target_url(target: &str) -> Result<Url, String> {
    let raw = target.trim();
    if raw.is_empty() {
        return Err("URL or domain is required".to_string());
    }
    let with_scheme = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.to_string()
    } else {
        format!("https://{}", raw)
    };
    Url::parse(&with_scheme).map_err(|_| "Invalid URL/domain format".to_string())
}

fn risk_weight(severity: &str) -> i32 {
    match severity {
        "critical" => 40,
        "high" => 25,
        "medium" => 12,
        "low" => 5,
        _ => 0,
    }
}

fn safety_from_score(score: i32) -> String {
    match score {
        s if s >= 80 => "Block".to_string(),
        s if s >= 50 => "Dangerous".to_string(),
        s if s >= 30 => "Warning".to_string(),
        _ => "Safe".to_string(),
    }
}

fn dedupe_issues(issues: Vec<WebsiteScanIssue>) -> Vec<WebsiteScanIssue> {
    let mut seen: HashSet<(String, String, Option<String>)> = HashSet::new();
    let mut out: Vec<WebsiteScanIssue> = Vec::new();
    for i in issues {
        let key = (i.code.clone(), i.message.clone(), i.evidence.clone());
        if seen.insert(key) {
            out.push(i);
        }
    }
    out
}

fn check_security_headers(headers: &HeaderMap) -> Vec<WebsiteScanIssue> {
    let mut issues = Vec::new();
    if headers.get("content-security-policy").is_none() {
        issues.push(WebsiteScanIssue {
            code: "missing_csp".to_string(),
            severity: "medium".to_string(),
            message: "Missing Content-Security-Policy header.".to_string(),
            evidence: None,
        });
    }
    if headers.get("x-frame-options").is_none() {
        issues.push(WebsiteScanIssue {
            code: "missing_x_frame_options".to_string(),
            severity: "low".to_string(),
            message: "Missing X-Frame-Options header.".to_string(),
            evidence: None,
        });
    }
    if headers.get("strict-transport-security").is_none() {
        issues.push(WebsiteScanIssue {
            code: "missing_hsts".to_string(),
            severity: "medium".to_string(),
            message: "Missing Strict-Transport-Security header.".to_string(),
            evidence: None,
        });
    }
    issues
}

fn extract_title(document: &Html) -> Option<String> {
    let selector = Selector::parse("title").ok()?;
    let title = document.select(&selector).next()?;
    let text = title.text().collect::<Vec<_>>().join(" ").trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn analyze_content(body: &str) -> Vec<WebsiteScanIssue> {
    let mut issues: Vec<WebsiteScanIssue> = Vec::new();
    let body_lower = body.to_lowercase();

    let phishing_markers = [
        "enter your seed phrase",
        "recovery phrase",
        "wallet validation required",
        "connect wallet to claim",
        "verify wallet now",
    ];
    for marker in phishing_markers {
        if body_lower.contains(marker) {
            issues.push(WebsiteScanIssue {
                code: "phishing_phrase_detected".to_string(),
                severity: "high".to_string(),
                message: "Potential phishing phrase detected in page content.".to_string(),
                evidence: Some(marker.to_string()),
            });
        }
    }

    let drainer_markers = [
        "setapprovalforall",
        "eth_sendtransaction",
        "permit(",
        "personal_sign",
        "seaport",
    ];
    let mut marker_hits: Vec<&str> = Vec::new();
    for marker in drainer_markers {
        if body_lower.contains(marker) {
            marker_hits.push(marker);
        }
    }
    if marker_hits.len() >= 3 {
        issues.push(WebsiteScanIssue {
            code: "drainer_like_script_pattern".to_string(),
            severity: "high".to_string(),
            message: "Page includes combined wallet-drainer-like script patterns.".to_string(),
            evidence: Some(marker_hits.join(", ")),
        });
    }

    let eval_count = body_lower.matches("eval(").count();
    let atob_count = body_lower.matches("atob(").count();
    if eval_count >= 2 || (eval_count >= 1 && atob_count >= 2) {
        issues.push(WebsiteScanIssue {
            code: "obfuscated_script_pattern".to_string(),
            severity: "medium".to_string(),
            message: "Potentially obfuscated JavaScript pattern detected.".to_string(),
            evidence: Some(format!("eval: {}, atob: {}", eval_count, atob_count)),
        });
    }

    issues
}

fn extract_same_host_links(base_url: &Url, body: &str) -> Vec<String> {
    let mut links: Vec<String> = Vec::new();
    let base_host = base_url.host_str().unwrap_or_default();
    let document = Html::parse_document(body);
    let selector = match Selector::parse("a[href]") {
        Ok(s) => s,
        Err(_) => return links,
    };
    for a in document.select(&selector) {
        if let Some(href) = a.value().attr("href") {
            if href.starts_with('#') || href.starts_with("mailto:") || href.starts_with("javascript:") {
                continue;
            }
            if let Ok(next) = base_url.join(href) {
                if let Some(host) = next.host_str() {
                    if host.eq_ignore_ascii_case(base_host) {
                        links.push(next.to_string());
                    }
                }
            }
        }
    }
    links
}

async fn maybe_get_cached(cache_key: &str) -> Option<WebsiteScanResult> {
    let map = cache().read().await;
    let entry = map.get(cache_key)?;
    if entry.created_at.elapsed() > Duration::from_secs(CACHE_TTL_SECONDS) {
        return None;
    }
    Some(entry.result.clone())
}

async fn set_cache(cache_key: &str, result: WebsiteScanResult) {
    let mut map = cache().write().await;
    map.insert(
        cache_key.to_string(),
        CachedScan {
            created_at: Instant::now(),
            result,
        },
    );
}

pub async fn scan_website(target: &str, max_pages: Option<u8>) -> Result<WebsiteScanResult, String> {
    let normalized = normalize_target_url(target)?;
    let host = normalized
        .host_str()
        .ok_or_else(|| "URL host is missing".to_string())?
        .to_lowercase();
    let page_limit = max_pages.unwrap_or(DEFAULT_MAX_PAGES as u8) as usize;
    let page_limit = page_limit.clamp(1, MAX_ALLOWED_PAGES);
    let cache_key = format!("{}#{}", normalized, page_limit);
    if let Some(cached) = maybe_get_cached(&cache_key).await {
        return Ok(cached);
    }

    let mut queue: VecDeque<String> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut pages: Vec<WebsitePageScan> = Vec::new();
    let mut global_issues: Vec<WebsiteScanIssue> = Vec::new();
    queue.push_back(normalized.to_string());

    while let Some(current_url) = queue.pop_front() {
        if visited.len() >= page_limit {
            break;
        }
        if !visited.insert(current_url.clone()) {
            continue;
        }
        let mut page_issues: Vec<WebsiteScanIssue> = Vec::new();
        let mut status_code: Option<u16> = None;
        let mut title: Option<String> = None;

        let url = match Url::parse(&current_url) {
            Ok(u) => u,
            Err(_) => {
                page_issues.push(WebsiteScanIssue {
                    code: "invalid_discovered_url".to_string(),
                    severity: "low".to_string(),
                    message: "Crawler discovered malformed URL.".to_string(),
                    evidence: Some(current_url.clone()),
                });
                pages.push(WebsitePageScan {
                    url: current_url,
                    status_code,
                    title,
                    issues: page_issues.clone(),
                });
                global_issues.extend(page_issues);
                continue;
            }
        };

        if url.scheme() != "https" {
            page_issues.push(WebsiteScanIssue {
                code: "non_https_page".to_string(),
                severity: "high".to_string(),
                message: "Page is not served over HTTPS.".to_string(),
                evidence: Some(url.to_string()),
            });
        }

        let response = http_client().get(url.clone()).send().await;
        match response {
            Ok(resp) => {
                status_code = Some(resp.status().as_u16());
                if !resp.status().is_success() {
                    page_issues.push(WebsiteScanIssue {
                        code: "http_error_status".to_string(),
                        severity: "medium".to_string(),
                        message: "Page returned non-success HTTP status.".to_string(),
                        evidence: Some(resp.status().to_string()),
                    });
                }

                page_issues.extend(check_security_headers(resp.headers()));
                let is_html = resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_lowercase().contains("text/html"))
                    .unwrap_or(true);
                if !is_html {
                    pages.push(WebsitePageScan {
                        url: url.to_string(),
                        status_code,
                        title,
                        issues: dedupe_issues(page_issues.clone()),
                    });
                    global_issues.extend(page_issues);
                    continue;
                }

                let body = match resp.text().await {
                    Ok(t) => t,
                    Err(_) => {
                        page_issues.push(WebsiteScanIssue {
                            code: "html_read_error".to_string(),
                            severity: "medium".to_string(),
                            message: "Failed to read page HTML content.".to_string(),
                            evidence: Some(url.to_string()),
                        });
                        pages.push(WebsitePageScan {
                            url: url.to_string(),
                            status_code,
                            title,
                            issues: dedupe_issues(page_issues.clone()),
                        });
                        global_issues.extend(page_issues);
                        continue;
                    }
                };

                let document = Html::parse_document(&body);
                title = extract_title(&document);
                page_issues.extend(analyze_content(&body));

                let links = extract_same_host_links(&url, &body);
                for link in links {
                    if !visited.contains(&link) && queue.len() + visited.len() < page_limit * 3 {
                        queue.push_back(link);
                    }
                }
            }
            Err(err) => {
                page_issues.push(WebsiteScanIssue {
                    code: "request_failed".to_string(),
                    severity: "high".to_string(),
                    message: "Failed to fetch page during scan.".to_string(),
                    evidence: Some(err.to_string()),
                });
            }
        }

        let deduped_page_issues = dedupe_issues(page_issues.clone());
        global_issues.extend(deduped_page_issues.clone());
        pages.push(WebsitePageScan {
            url: url.to_string(),
            status_code,
            title,
            issues: deduped_page_issues,
        });
    }

    let issues = dedupe_issues(global_issues);
    let mut score = 0i32;
    for i in &issues {
        score += risk_weight(&i.severity);
    }
    score = score.clamp(0, 100);
    let result = WebsiteScanResult {
        target: target.to_string(),
        normalized_url: normalized.to_string(),
        domain: host,
        safety: safety_from_score(score),
        risk_score: score,
        crawled_pages: pages.len(),
        issues,
        pages,
    };
    set_cache(&cache_key, result.clone()).await;
    Ok(result)
}
