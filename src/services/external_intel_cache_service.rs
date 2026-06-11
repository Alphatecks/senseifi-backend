//! Persistent cache for confirmed external threat-intel hits (GoPlus, etc.).

use crate::db::DbPool;
use chrono::{Duration, Utc};
use serde_json::Value;

const DEFAULT_TTL_DAYS: i64 = 7;

fn cache_ttl_days() -> i64 {
    std::env::var("GOPLUS_INTEL_CACHE_TTL_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TTL_DAYS)
        .max(1)
}

pub async fn upsert_positive_hit(
    pool: &DbPool,
    entity_type: &str,
    entity_id: &str,
    chain_family: Option<&str>,
    source: &str,
    risk_score: i32,
    metadata: Value,
) -> Result<(), String> {
    let expires_at = Utc::now() + Duration::days(cache_ttl_days());
    sqlx::query(
        r#"
        INSERT INTO external_intel_cache (
            entity_type, entity_id, chain_family, source,
            is_malicious, risk_score, metadata, checked_at, expires_at
        )
        VALUES ($1, $2, $3, $4, true, $5, $6, NOW(), $7)
        ON CONFLICT (entity_type, entity_id, source) DO UPDATE SET
            chain_family = EXCLUDED.chain_family,
            is_malicious = true,
            risk_score = GREATEST(external_intel_cache.risk_score, EXCLUDED.risk_score),
            metadata = EXCLUDED.metadata,
            checked_at = NOW(),
            expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(entity_type)
    .bind(entity_id)
    .bind(chain_family)
    .bind(source)
    .bind(risk_score)
    .bind(metadata)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn get_cached_domain_hit(pool: &DbPool, domain: &str) -> Option<i32> {
    sqlx::query_scalar::<_, i32>(
        r#"
        SELECT risk_score
        FROM external_intel_cache
        WHERE entity_type = 'domain'
          AND entity_id = $1
          AND is_malicious = true
          AND expires_at > NOW()
        ORDER BY risk_score DESC
        LIMIT 1
        "#,
    )
    .bind(domain)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

pub async fn list_active_malicious_domains(
    pool: &DbPool,
    chain_family: Option<&str>,
) -> Result<Vec<String>, String> {
    let rows = if let Some(family) = chain_family {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT entity_id
            FROM external_intel_cache
            WHERE entity_type = 'domain'
              AND is_malicious = true
              AND expires_at > NOW()
              AND (chain_family = $1 OR chain_family IS NULL)
            ORDER BY entity_id
            LIMIT 500
            "#,
        )
        .bind(family)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT entity_id
            FROM external_intel_cache
            WHERE entity_type = 'domain'
              AND is_malicious = true
              AND expires_at > NOW()
            ORDER BY entity_id
            LIMIT 500
            "#,
        )
        .fetch_all(pool)
        .await
    }
    .map_err(|e| e.to_string())?;
    Ok(rows)
}

pub async fn list_active_malicious_addresses(
    pool: &DbPool,
    entity_type: &str,
) -> Result<Vec<String>, String> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT entity_id
        FROM external_intel_cache
        WHERE entity_type = $1
          AND is_malicious = true
          AND expires_at > NOW()
        ORDER BY entity_id
        LIMIT 500
        "#,
    )
    .bind(entity_type)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())
}

pub async fn count_active_malicious(pool: &DbPool) -> Result<usize, String> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM external_intel_cache
        WHERE is_malicious = true
          AND expires_at > NOW()
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ttl_is_seven_days() {
        assert_eq!(cache_ttl_days(), 7);
    }
}
