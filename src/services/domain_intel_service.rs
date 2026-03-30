use crate::db::DbPool;
use crate::models::senseiguard::{DomainThreatFeedResponse, DomainThreatFeedSources};
use chrono::Utc;
use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

const FEED_CACHE_TTL_SECONDS: u64 = 300;
const MAX_MALICIOUS_DOMAINS: usize = 1000;

const TRUSTED_DOMAINS: &[&str] = &[
    "aave.com",
    "app.aave.com",
    "uniswap.org",
    "app.uniswap.org",
    "lido.fi",
    "curve.fi",
    "pancakeswap.finance",
    "1inch.io",
    "coingecko.com",
    "defillama.com",
    "metamask.io",
    "coinbase.com",
    "opensea.io",
];

#[derive(Debug, Clone)]
struct CachedFeed {
    created_at: Instant,
    feed: DomainThreatFeedResponse,
}

#[derive(Debug, Clone)]
pub struct DomainIntelAssessment {
    pub domain: String,
    pub is_malicious: bool,
    pub is_trusted: bool,
    pub reason: Option<String>,
    pub risk_boost: i32,
}

static FEED_CACHE: OnceLock<RwLock<Option<CachedFeed>>> = OnceLock::new();

fn feed_cache() -> &'static RwLock<Option<CachedFeed>> {
    FEED_CACHE.get_or_init(|| RwLock::new(None))
}

fn normalize_domain(input: &str) -> Option<String> {
    let raw = input.trim().to_lowercase();
    if raw.is_empty() {
        return None;
    }
    let candidate = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw
    } else {
        format!("https://{}", raw)
    };
    let parsed = Url::parse(&candidate).ok()?;
    parsed.host_str().map(|h| h.to_lowercase())
}

fn parse_env_malicious_domains() -> Vec<String> {
    std::env::var("SENSEIGUARD_MALICIOUS_DOMAINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|d| d.trim().to_lowercase())
                .filter(|d| !d.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn is_same_or_subdomain(domain: &str, base: &str) -> bool {
    domain == base || domain.ends_with(&format!(".{}", base))
}

pub async fn get_domain_threat_feed(pool: &DbPool) -> Result<DomainThreatFeedResponse, String> {
    {
        let cache = feed_cache().read().await;
        if let Some(cached) = cache.as_ref() {
            if cached.created_at.elapsed() <= Duration::from_secs(FEED_CACHE_TTL_SECONDS) {
                return Ok(cached.feed.clone());
            }
        }
    }

    let activity_domains = sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT metadata->>'domain' AS domain
        FROM activity_feed
        WHERE metadata IS NOT NULL
          AND metadata ? 'domain'
          AND (
            metadata->>'event_type' = 'domain_risk_detected'
            OR (
              metadata ? 'risk_score'
              AND (metadata->>'risk_score') ~ '^[0-9]+$'
              AND (metadata->>'risk_score')::int >= 70
            )
          )
        ORDER BY created_at DESC
        LIMIT 5000
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let env_domains = parse_env_malicious_domains();
    let mut set: HashSet<String> = HashSet::new();
    let mut activity_set: HashSet<String> = HashSet::new();
    for d in activity_domains.into_iter().flatten() {
        if let Some(norm) = normalize_domain(&d) {
            activity_set.insert(norm.clone());
            set.insert(norm);
        }
    }
    for d in &env_domains {
        if let Some(norm) = normalize_domain(d) {
            set.insert(norm);
        }
    }

    let mut malicious_domains = set.into_iter().collect::<Vec<_>>();
    malicious_domains.sort();
    malicious_domains.truncate(MAX_MALICIOUS_DOMAINS);

    let mut trusted_domains = TRUSTED_DOMAINS.iter().map(|d| d.to_string()).collect::<Vec<_>>();
    trusted_domains.sort();
    trusted_domains.dedup();

    let feed = DomainThreatFeedResponse {
        malicious_domains,
        trusted_domains,
        sources: DomainThreatFeedSources {
            from_activity_feed: activity_set.len(),
            from_env_blocklist: env_domains.len(),
            static_trusted: TRUSTED_DOMAINS.len(),
        },
        updated_at: Utc::now(),
    };

    {
        let mut cache = feed_cache().write().await;
        *cache = Some(CachedFeed {
            created_at: Instant::now(),
            feed: feed.clone(),
        });
    }

    Ok(feed)
}

pub async fn assess_domain(pool: &DbPool, target: &str) -> DomainIntelAssessment {
    let domain = normalize_domain(target).unwrap_or_else(|| target.trim().to_lowercase());
    let feed = get_domain_threat_feed(pool).await.ok();

    let malicious = feed
        .as_ref()
        .map(|f| f.malicious_domains.iter().any(|d| is_same_or_subdomain(&domain, d)))
        .unwrap_or(false);
    if malicious {
        return DomainIntelAssessment {
            domain,
            is_malicious: true,
            is_trusted: false,
            reason: Some("Domain matches malicious threat-intelligence feed.".to_string()),
            risk_boost: 60,
        };
    }

    let trusted = TRUSTED_DOMAINS
        .iter()
        .any(|d| is_same_or_subdomain(&domain, d));
    if trusted {
        return DomainIntelAssessment {
            domain,
            is_malicious: false,
            is_trusted: true,
            reason: Some("Domain matches trusted protocol allowlist.".to_string()),
            risk_boost: -10,
        };
    }

    DomainIntelAssessment {
        domain,
        is_malicious: false,
        is_trusted: false,
        reason: None,
        risk_boost: 0,
    }
}
