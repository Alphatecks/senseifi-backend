use crate::db::DbPool;
use crate::models::senseiguard::{kill_chain, ThreatCorrelationSummary, ThreatEvent};
use crate::repositories::senseiguard_repository::SenseiguardRepository;
use crate::services::threat_scoring_v2::ThreatScoringV2;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

const CORRELATION_CREATE_THRESHOLD: i32 = 65;
const CORRELATION_ESCALATION_THRESHOLD: i32 = 80;
const CORRELATION_LOOKBACK_HOURS: i64 = 24;

#[derive(Debug, Clone)]
pub struct ThreatSignalInput {
    pub wallet_id: Uuid,
    pub threat_id: Option<Uuid>,
    pub event_type: String,
    pub signal_category: String,
    pub threat_type: Option<String>,
    pub surface: Option<String>,
    pub risk_score: i32,
    pub confidence_score: i32,
    pub source_contract: Option<String>,
    pub domain: Option<String>,
    pub metadata: serde_json::Value,
    pub event_time: Option<DateTime<Utc>>,
    pub kill_chain_stage: Option<String>,
}

pub struct ThreatCorrelationService;

impl ThreatCorrelationService {
    pub fn shadow_mode() -> bool {
        if ThreatScoringV2::enabled() {
            return false;
        }
        std::env::var("THREAT_CORRELATION_SHADOW_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
    }

    pub async fn ingest_signal(
        pool: &DbPool,
        input: ThreatSignalInput,
    ) -> Result<Option<ThreatCorrelationSummary>, sqlx::Error> {
        let now = input.event_time.unwrap_or_else(Utc::now);
        let shadow_mode = Self::shadow_mode();
        let mut event_metadata = input.metadata.clone();
        if let Some(obj) = event_metadata.as_object_mut() {
            obj.insert("shadow_mode".to_string(), json!(shadow_mode));
            if let Some(ref stage) = input.kill_chain_stage {
                obj.insert("kill_chain_stage".to_string(), json!(stage));
            }
        }
        let event = SenseiguardRepository::create_threat_event(
            pool,
            input.wallet_id,
            input.threat_id,
            &input.event_type,
            &input.signal_category,
            input.threat_type.as_deref(),
            input.surface.as_deref(),
            input.risk_score,
            input.confidence_score,
            input.source_contract.as_deref(),
            input.domain.as_deref(),
            Some(event_metadata),
            Some(now),
            input.kill_chain_stage.as_deref(),
        )
        .await?;

        let mut edge_ids: Vec<Uuid> = Vec::new();
        if let Some(contract) = input
            .source_contract
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            let edge = SenseiguardRepository::create_threat_entity_edge(
                pool,
                input.wallet_id,
                "wallet",
                &input.wallet_id.to_string(),
                "interacts_with",
                "contract",
                contract,
                input.risk_score.max(1),
                Some(json!({"event_type": input.event_type, "signal_category": input.signal_category})),
            )
            .await?;
            edge_ids.push(edge.id);
        }
        if let Some(domain) = input.domain.as_deref().filter(|s| !s.trim().is_empty()) {
            let edge = SenseiguardRepository::create_threat_entity_edge(
                pool,
                input.wallet_id,
                "wallet",
                &input.wallet_id.to_string(),
                "connected_domain",
                "domain",
                domain,
                input.risk_score.max(1),
                Some(json!({"event_type": input.event_type, "signal_category": input.signal_category})),
            )
            .await?;
            edge_ids.push(edge.id);
        }

        let since = now - Duration::hours(CORRELATION_LOOKBACK_HOURS);
        let mut events =
            SenseiguardRepository::list_recent_threat_events(pool, input.wallet_id, since, 200)
                .await?;
        if !events.iter().any(|e| e.id == event.id) {
            events.push(event.clone());
        }
        let correlation = Self::build_correlation(&events, &event, now);
        let Some(result) = correlation else {
            return Ok(None);
        };

        // Shadow mode still persists campaigns/evidence for offline validation.
        let campaign = match SenseiguardRepository::find_recent_open_campaign_by_type(
            pool,
            input.wallet_id,
            &result.campaign_type,
            now - Duration::days(7),
        )
        .await?
        {
            Some(existing) => {
                SenseiguardRepository::update_threat_campaign_scores(
                    pool,
                    existing.id,
                    result.risk_score,
                    result.confidence_score,
                    &result.narrative,
                    &json!(result.categories),
                    Some(now),
                )
                .await?
            }
            None => {
                if result.confidence_score < CORRELATION_CREATE_THRESHOLD
                    && result.categories.len() < 2
                {
                    return Ok(None);
                }
                SenseiguardRepository::create_threat_campaign(
                    pool,
                    input.wallet_id,
                    &result.campaign_type,
                    result.risk_score,
                    result.confidence_score,
                    &result.narrative,
                    &json!(result.categories),
                    Some(now),
                    Some(now),
                )
                .await?
            }
        };

        SenseiguardRepository::create_threat_campaign_evidence(
            pool,
            campaign.id,
            Some(event.id),
            None,
            "event",
            1,
            Some("Primary event that updated campaign state."),
            Some(json!({"event_type": event.event_type, "signal_category": event.signal_category})),
        )
        .await?;
        for (idx, edge_id) in edge_ids.into_iter().enumerate() {
            let _ = SenseiguardRepository::create_threat_campaign_evidence(
                pool,
                campaign.id,
                None,
                Some(edge_id),
                "edge",
                (idx + 1) as i32,
                Some("Entity edge linked to correlated event."),
                None,
            )
            .await;
        }
        if result.sequence_detected {
            let _ = SenseiguardRepository::create_threat_campaign_evidence(
                pool,
                campaign.id,
                Some(event.id),
                None,
                "sequence",
                1,
                Some("Kill-chain progression detected inside sliding window."),
                Some(json!({
                    "window_hours": CORRELATION_LOOKBACK_HOURS,
                    "kill_chain_stages": result.kill_chain_stages,
                })),
            )
            .await;
        }
        if result.categories.len() >= 2 {
            let _ = SenseiguardRepository::create_threat_campaign_evidence(
                pool,
                campaign.id,
                Some(event.id),
                None,
                "cooccurrence",
                1,
                Some("Independent signal categories aligned on the same entity cluster."),
                Some(json!({"categories": result.categories})),
            )
            .await;
        }

        let evidence_count =
            SenseiguardRepository::count_campaign_evidence(pool, campaign.id).await?;
        Ok(Some(ThreatCorrelationSummary {
            campaign_id: campaign.id.to_string(),
            campaign_type: campaign.campaign_type,
            confidence_score: campaign.confidence_score,
            risk_score: campaign.risk_score,
            narrative: campaign.narrative,
            evidence_count,
            last_seen_at: campaign.last_seen_at,
            kill_chain_stages: if result.kill_chain_stages.is_empty() {
                None
            } else {
                Some(result.kill_chain_stages.clone())
            },
        }))
    }

    fn build_correlation(
        events: &[ThreatEvent],
        current_event: &ThreatEvent,
        now: DateTime<Utc>,
    ) -> Option<CorrelationComputation> {
        if events.is_empty() {
            return None;
        }

        let mut categories: HashSet<String> = HashSet::new();
        let mut max_risk = current_event.risk_score;
        let mut max_confidence = current_event.confidence_score;
        let mut contract_hits: HashMap<String, i32> = HashMap::new();
        let mut domain_hits: HashMap<String, i32> = HashMap::new();
        for event in events {
            categories.insert(event.signal_category.clone());
            max_risk = max_risk.max(event.risk_score);
            max_confidence = max_confidence.max(event.confidence_score);
            if let Some(contract) = event
                .source_contract
                .as_ref()
                .map(|s| s.to_lowercase())
                .filter(|s| !s.is_empty())
            {
                *contract_hits.entry(contract).or_insert(0) += 1;
            }
            if let Some(domain) = event
                .domain
                .as_ref()
                .map(|s| s.to_lowercase())
                .filter(|s| !s.is_empty())
            {
                *domain_hits.entry(domain).or_insert(0) += 1;
            }
        }
        let categories_vec = categories.into_iter().collect::<Vec<String>>();

        let kill_chain_stages = Self::collect_kill_chain_stages(events);
        let sequence_detected = Self::detect_sequence(events);
        let repeated_contract = contract_hits.values().any(|count| *count >= 2);
        let repeated_domain = domain_hits.values().any(|count| *count >= 2);

        let mut confidence = max_confidence.max(max_risk);
        if categories_vec.len() >= 2 {
            confidence += 10;
        }
        if sequence_detected {
            confidence += 10;
        }
        if repeated_contract || repeated_domain {
            confidence += 8;
        }
        let confidence = confidence.clamp(0, 100);

        if confidence < CORRELATION_CREATE_THRESHOLD && categories_vec.len() < 2 {
            return None;
        }

        let mut risk_score = max_risk;
        if sequence_detected {
            risk_score += 8;
        }
        if categories_vec.len() >= 3 {
            risk_score += 6;
        }
        risk_score = risk_score.clamp(0, 100);

        let campaign_type = Self::campaign_type(events, repeated_contract, repeated_domain);
        let narrative = Self::build_narrative(
            &campaign_type,
            &categories_vec,
            &kill_chain_stages,
            current_event,
            sequence_detected,
            repeated_contract || repeated_domain,
            confidence,
            now,
        );

        Some(CorrelationComputation {
            campaign_type,
            confidence_score: confidence,
            risk_score,
            narrative,
            categories: categories_vec,
            sequence_detected,
            kill_chain_stages,
        })
    }

    fn collect_kill_chain_stages(events: &[ThreatEvent]) -> Vec<String> {
        let order = [
            kill_chain::LURE,
            kill_chain::HOOK,
            kill_chain::EXECUTE,
            kill_chain::EXFILTRATE,
        ];
        let mut seen = HashSet::new();
        let mut stages = Vec::new();
        for stage in order {
            let present = events.iter().any(|e| {
                e.kill_chain_stage
                    .as_deref()
                    .map(|s| s == stage)
                    .unwrap_or_else(|| Self::infer_kill_chain_stage(e) == stage)
            });
            if present && seen.insert(stage) {
                stages.push(stage.to_string());
            }
        }
        stages
    }

    fn infer_kill_chain_stage(event: &ThreatEvent) -> &'static str {
        let cat = event.signal_category.to_lowercase();
        let et = event.event_type.to_lowercase();
        if cat.contains("domain") || cat.contains("phishing") || cat.contains("temporal") {
            kill_chain::LURE
        } else if cat.contains("signature") {
            kill_chain::HOOK
        } else if cat.contains("liquidity") || et.contains("liquidity") || et.contains("exfil") {
            kill_chain::EXFILTRATE
        } else {
            kill_chain::EXECUTE
        }
    }

    fn campaign_type(
        events: &[ThreatEvent],
        repeated_contract: bool,
        repeated_domain: bool,
    ) -> String {
        let stages = Self::collect_kill_chain_stages(events);
        if stages.contains(&kill_chain::LURE.to_string())
            && (stages.contains(&kill_chain::HOOK.to_string())
                || stages.contains(&kill_chain::EXECUTE.to_string()))
        {
            return "phishing_kill_chain".to_string();
        }

        let mut has_domain = false;
        let mut has_approval = false;
        let mut has_reputation = false;
        let mut has_behavior = false;
        let mut has_tx = false;

        for e in events {
            let cat = e.signal_category.to_lowercase();
            has_domain |= cat.contains("domain") || cat.contains("phishing");
            has_approval |= cat.contains("approval");
            has_reputation |= cat.contains("reputation") || cat.contains("graph");
            has_behavior |= cat.contains("behavior") || cat.contains("temporal");
            has_tx |= cat.contains("transaction") || cat.contains("tx");
        }

        if has_domain && (has_approval || has_tx) {
            "phishing_execution_chain".to_string()
        } else if has_reputation && repeated_contract {
            "malicious_contract_cluster".to_string()
        } else if has_behavior && (repeated_contract || repeated_domain) {
            "coordinated_behavior_pattern".to_string()
        } else {
            "suspicious_activity_cluster".to_string()
        }
    }

    /// Kill-chain progression: Lure → Hook → Execute → Exfiltrate (strict order, no skipping).
    fn detect_sequence(events: &[ThreatEvent]) -> bool {
        let mut ordered = events.iter().collect::<Vec<&ThreatEvent>>();
        ordered.sort_by_key(|e| e.event_time);
        let mut stage = 0u8;
        for ev in ordered {
            let kcs = ev
                .kill_chain_stage
                .as_deref()
                .unwrap_or_else(|| Self::infer_kill_chain_stage(ev));
            stage = match (stage, kcs) {
                (0, kill_chain::LURE) => 1,
                (1, kill_chain::HOOK) => 2,
                (2, kill_chain::EXECUTE) => 3,
                (3, kill_chain::EXFILTRATE) => 4,
                _ => stage,
            };
        }
        stage >= 3
    }

    fn build_narrative(
        campaign_type: &str,
        categories: &[String],
        kill_chain_stages: &[String],
        current_event: &ThreatEvent,
        sequence_detected: bool,
        linked_entities: bool,
        confidence: i32,
        now: DateTime<Utc>,
    ) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push(format!(
            "Correlated {} detected with {} signal categories.",
            campaign_type.replace('_', " "),
            categories.len()
        ));
        if !kill_chain_stages.is_empty() {
            parts.push(format!(
                "Kill-chain stages observed: {}.",
                kill_chain_stages.join(" → ")
            ));
        }
        if sequence_detected {
            parts.push(
                "Event timeline matches Lure → Hook → Execute kill-chain progression.".to_string(),
            );
        }
        if linked_entities {
            parts.push(
                "Shared contract/domain entities indicate campaign-level linkage.".to_string(),
            );
        }
        if let Some(threat_type) = current_event.threat_type.as_ref() {
            parts.push(format!("Latest event type: {}.", threat_type));
        } else {
            parts.push(format!("Latest event: {}.", current_event.event_type));
        }
        if confidence >= CORRELATION_ESCALATION_THRESHOLD {
            parts.push("Confidence is high enough to prioritize analyst review.".to_string());
        }
        parts.push(format!("Updated at {}.", now.to_rfc3339()));
        parts.join(" ")
    }
}

struct CorrelationComputation {
    campaign_type: String,
    confidence_score: i32,
    risk_score: i32,
    narrative: String,
    categories: Vec<String>,
    sequence_detected: bool,
    kill_chain_stages: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::senseiguard::{kill_chain, ThreatEvent};
    use chrono::Utc;
    use uuid::Uuid;

    fn event(stage: &str, category: &str, minutes_ago: i64) -> ThreatEvent {
        ThreatEvent {
            id: Uuid::new_v4(),
            wallet_id: Uuid::new_v4(),
            threat_id: None,
            event_type: "test".to_string(),
            signal_category: category.to_string(),
            threat_type: None,
            surface: None,
            risk_score: 50,
            confidence_score: 60,
            source_contract: None,
            domain: None,
            metadata: json!({}),
            event_time: Utc::now() - Duration::minutes(minutes_ago),
            created_at: Utc::now(),
            kill_chain_stage: Some(stage.to_string()),
        }
    }

    #[test]
    fn detect_sequence_follows_kill_chain_order() {
        let events = vec![
            event(kill_chain::LURE, "domain", 30),
            event(kill_chain::HOOK, "signature", 20),
            event(kill_chain::EXECUTE, "approval", 10),
        ];
        assert!(ThreatCorrelationService::detect_sequence(&events));
    }

    #[test]
    fn detect_sequence_false_for_execute_only() {
        let events = vec![event(kill_chain::EXECUTE, "transaction", 5)];
        assert!(!ThreatCorrelationService::detect_sequence(&events));
    }
}
