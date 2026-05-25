-- Cleanup: reclassify emergency-lock policy events and remove from active threat queue.

UPDATE threats
SET threat_type = COALESCE(threat_type, 'policy_enforcement'),
    surface = COALESCE(surface, 'wallet_state'),
    verification_status = 'not_applicable',
    verification_method = COALESCE(verification_method, 'policy_enforcement_event'),
    verification_message = COALESCE(
      verification_message,
      'Policy enforcement event (emergency lock), not a malware/security incident.'
    ),
    status = CASE WHEN status = 'open' THEN 'dismissed' ELSE status END,
    dismissed_at = CASE WHEN status = 'open' THEN COALESCE(dismissed_at, NOW()) ELSE dismissed_at END,
    dismiss_reason = CASE
      WHEN status = 'open' THEN COALESCE(dismiss_reason, 'system_policy_event_cleanup')
      ELSE dismiss_reason
    END
WHERE (
    LOWER(title) LIKE '%emergency lock is on%'
    OR LOWER(COALESCE(explanation, '')) LIKE '%emergency lock is on%'
    OR LOWER(title) LIKE '%whitelisted addresses are allowed%'
    OR LOWER(COALESCE(explanation, '')) LIKE '%whitelisted addresses are allowed%'
  )
  AND (threat_type IS NULL OR LOWER(threat_type) <> 'policy_enforcement');
