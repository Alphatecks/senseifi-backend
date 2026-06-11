//! Solana transaction and signing analysis for SenseiGuard extension protection.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use solana_sdk::{
    instruction::CompiledInstruction,
    message::{Message, VersionedMessage},
    transaction::{Transaction, VersionedTransaction},
};
use std::collections::{HashMap, HashSet};

use crate::services::protection_engine::score_to_band;

pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

const SPL_APPROVE: u8 = 4;
const SPL_SET_AUTHORITY: u8 = 6;
const SPL_CLOSE_ACCOUNT: u8 = 9;

const KNOWN_MALICIOUS_PROGRAMS: &[&str] = &[];

pub const SOLANA_SIGN_METHODS: &[&str] = &[
    "connect",
    "signTransaction",
    "signAllTransactions",
    "signMessage",
    "signAndSendTransaction",
    "wallet_standard_connect",
    "wallet_standard_signTransaction",
    "wallet_standard_signMessage",
];

#[derive(Debug, Clone)]
pub struct SolanaAnalysisResult {
    pub risk_score: i32,
    pub findings: Vec<String>,
    pub breakdown: HashMap<String, i32>,
    pub threat_types: Vec<String>,
    pub malicious_program_detected: bool,
    pub program_ids: Vec<String>,
    pub recommendation: String,
}

pub fn parse_env_malicious_programs() -> Vec<String> {
    std::env::var("SENSEIGUARD_MALICIOUS_PROGRAMS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub fn static_malicious_programs() -> Vec<String> {
    KNOWN_MALICIOUS_PROGRAMS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

pub fn merge_malicious_programs(db_programs: &[String], env_programs: &[String]) -> HashSet<String> {
    let mut set = HashSet::new();
    for p in db_programs {
        set.insert(p.clone());
    }
    for p in env_programs {
        set.insert(p.clone());
    }
    for p in static_malicious_programs() {
        set.insert(p);
    }
    set
}

pub fn is_solana_sign_method(method: &str) -> bool {
    SOLANA_SIGN_METHODS.contains(&method)
}

pub fn analyze_solana_request(
    method: &str,
    params: Option<&[Value]>,
    malicious_programs: &HashSet<String>,
    domain_risk_score: i32,
) -> SolanaAnalysisResult {
    let mut findings: Vec<String> = Vec::new();
    let mut breakdown: HashMap<String, i32> = HashMap::new();
    let mut threat_types: Vec<String> = Vec::new();
    let mut program_reputation_risk = 0i32;
    let mut authority_change_risk = 0i32;
    let mut drainer_pattern_risk = 0i32;
    let mut bulk_operation_risk = 0i32;
    let mut malicious_program_detected = false;
    let mut program_ids: Vec<String> = Vec::new();

    if method == "signMessage" || method == "wallet_standard_signMessage" {
        findings.push("[medium] Off-chain message signing request".to_string());
        if domain_risk_score >= 50 {
            findings.push("[high] Message sign on high-risk domain".to_string());
            threat_types.push("blind_signing".to_string());
        }
    }

    if method == "signAllTransactions" {
        findings.push("[high] Batch transaction signing requested".to_string());
        bulk_operation_risk = bulk_operation_risk.max(35);
        threat_types.push("batch_sign".to_string());
    }

    let tx_bytes_list = extract_all_serialized_txs(params);
    let mut close_count = 0usize;
    let mut approve_count = 0usize;
    let mut set_authority_count = 0usize;
    let mut unique_programs: HashSet<String> = HashSet::new();

    for tx_bytes in &tx_bytes_list {
        if let Some(parsed) = parse_transaction_bytes(tx_bytes) {
            for program in &parsed.program_ids {
                unique_programs.insert(program.clone());
                if !program_ids.contains(program) {
                    program_ids.push(program.clone());
                }
                if malicious_programs.contains(program) {
                    malicious_program_detected = true;
                    program_reputation_risk = program_reputation_risk.max(95);
                    findings.push(format!(
                        "[critical] Transaction invokes known malicious program {}",
                        truncate_program(program)
                    ));
                    threat_types.push("drainer".to_string());
                }
            }
            close_count += parsed.close_account_count;
            approve_count += parsed.approve_count;
            set_authority_count += parsed.set_authority_count;

            if parsed.set_authority_count > 0 {
                authority_change_risk = authority_change_risk.max(70);
                findings.push("[high] SetAuthority on token account detected".to_string());
                threat_types.push("authority_hijack".to_string());
            }
            if parsed.approve_count > 0 {
                authority_change_risk = authority_change_risk.max(55);
                findings.push("[high] Token delegation (Approve) detected".to_string());
                threat_types.push("delegation".to_string());
            }
            if parsed.close_account_count > 0 && parsed.transfer_count > 0 {
                drainer_pattern_risk = drainer_pattern_risk.max(80);
                findings.push(
                    "[critical] CloseAccount combined with transfer (drainer pattern)".to_string(),
                );
                threat_types.push("drainer".to_string());
            }
            if parsed.account_count >= 8 {
                bulk_operation_risk = bulk_operation_risk.max(45);
                findings.push(format!(
                    "[medium] Transaction touches {} accounts",
                    parsed.account_count
                ));
            }
        } else if !tx_bytes.is_empty() {
            findings.push("[medium] Unable to fully decode serialized transaction".to_string());
        }
    }

    if close_count >= 3 {
        drainer_pattern_risk = drainer_pattern_risk.max(75);
        findings.push("[critical] Bulk account closures detected".to_string());
        threat_types.push("bulk_close".to_string());
    }

    for program in &unique_programs {
        if is_unknown_program(program) {
            program_reputation_risk = program_reputation_risk.max(40);
            if !findings.iter().any(|f| f.contains(program)) {
                findings.push(format!(
                    "[medium] Unknown program invoked: {}",
                    truncate_program(program)
                ));
            }
        }
    }

    let domain_context_risk = domain_risk_score.clamp(0, 50);
    if domain_risk_score >= 50 {
        findings.push("[high] Transaction origin domain has elevated phishing risk".to_string());
        threat_types.push("frontend_phishing".to_string());
    } else if domain_risk_score >= 30 {
        findings.push("[medium] Transaction origin domain has moderate risk".to_string());
    }

    breakdown.insert("program_reputation_risk".to_string(), program_reputation_risk);
    breakdown.insert("authority_change_risk".to_string(), authority_change_risk);
    breakdown.insert("drainer_pattern_risk".to_string(), drainer_pattern_risk);
    breakdown.insert("bulk_operation_risk".to_string(), bulk_operation_risk);
    breakdown.insert("domain_context_risk".to_string(), domain_context_risk);

    let mut risk_score = program_reputation_risk
        .max(authority_change_risk)
        .max(drainer_pattern_risk)
        .max(bulk_operation_risk)
        .max(domain_context_risk);

    if approve_count > 1 || set_authority_count > 1 {
        risk_score = (risk_score + 10).min(100);
    }

    if findings.is_empty() {
        findings.push("[low] No significant Solana transaction risks detected".to_string());
    }

    threat_types.sort();
    threat_types.dedup();

    let band = score_to_band(risk_score);
    let recommendation = match band {
        "Block" => "Reject transaction",
        "Dangerous" => "Review carefully before signing",
        "Warning" => "Proceed with caution",
        _ => "Proceed",
    }
    .to_string();

    SolanaAnalysisResult {
        risk_score,
        findings,
        breakdown,
        threat_types,
        malicious_program_detected,
        program_ids,
        recommendation,
    }
}

struct ParsedTxSignals {
    program_ids: Vec<String>,
    close_account_count: usize,
    approve_count: usize,
    set_authority_count: usize,
    transfer_count: usize,
    account_count: usize,
}

fn parse_transaction_bytes(bytes: &[u8]) -> Option<ParsedTxSignals> {
    if bytes.is_empty() {
        return None;
    }
    if let Ok(vtx) = bincode::deserialize::<VersionedTransaction>(bytes) {
        return Some(analyze_versioned_message(&vtx.message));
    }
    if let Ok(ltx) = bincode::deserialize::<Transaction>(bytes) {
        return Some(analyze_legacy_message(&ltx.message));
    }
    None
}

fn analyze_legacy_message(message: &Message) -> ParsedTxSignals {
    let account_keys: Vec<String> = message
        .account_keys
        .iter()
        .map(|k| k.to_string())
        .collect();
    analyze_instructions(&account_keys, &message.instructions)
}

fn analyze_versioned_message(message: &VersionedMessage) -> ParsedTxSignals {
    let account_keys: Vec<String> = message
        .static_account_keys()
        .iter()
        .map(|k| k.to_string())
        .collect();
    analyze_instructions(&account_keys, message.instructions())
}

fn analyze_instructions(
    account_keys: &[String],
    instructions: &[CompiledInstruction],
) -> ParsedTxSignals {
    let mut program_ids = Vec::new();
    let mut close_account_count = 0usize;
    let mut approve_count = 0usize;
    let mut set_authority_count = 0usize;
    let mut transfer_count = 0usize;

    for ix in instructions {
        let program_id = account_keys
            .get(ix.program_id_index as usize)
            .cloned()
            .unwrap_or_default();
        if !program_id.is_empty() && !program_ids.contains(&program_id) {
            program_ids.push(program_id.clone());
        }

        if program_id == TOKEN_PROGRAM_ID || program_id == TOKEN_2022_PROGRAM_ID {
            if let Some(&disc) = ix.data.first() {
                match disc {
                    SPL_APPROVE => approve_count += 1,
                    SPL_SET_AUTHORITY => set_authority_count += 1,
                    SPL_CLOSE_ACCOUNT => close_account_count += 1,
                    _ => {}
                }
            }
        }
        if program_id == SYSTEM_PROGRAM_ID && ix.data.len() >= 4 {
            let disc = u32::from_le_bytes(ix.data[0..4].try_into().unwrap_or([0; 4]));
            if disc == 2 {
                transfer_count += 1;
            }
        }
    }

    ParsedTxSignals {
        program_ids,
        close_account_count,
        approve_count,
        set_authority_count,
        transfer_count,
        account_count: account_keys.len(),
    }
}

fn extract_all_serialized_txs(params: Option<&[Value]>) -> Vec<Vec<u8>> {
    let Some(params) = params else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in params {
        if let Some(obj) = p.as_object() {
            if obj.get("kind").and_then(|k| k.as_str()) == Some("serialized_tx") {
                if let Some(data) = obj.get("data").and_then(|d| d.as_str()) {
                    if let Ok(bytes) = STANDARD.decode(data.trim()) {
                        out.push(bytes);
                    }
                }
            }
        }
    }
    out
}

fn is_unknown_program(program_id: &str) -> bool {
    !matches!(
        program_id,
        SYSTEM_PROGRAM_ID
            | TOKEN_PROGRAM_ID
            | TOKEN_2022_PROGRAM_ID
            | "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
            | "ComputeBudget111111111111111111111111111111"
            | "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
            | "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
            | "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
            | "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"
            | "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"
    )
}

fn truncate_program(program: &str) -> String {
    if program.len() <= 12 {
        return program.to_string();
    }
    format!("{}…{}", &program[..6], &program[program.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solana_methods_recognized() {
        assert!(is_solana_sign_method("signTransaction"));
        assert!(!is_solana_sign_method("eth_sendTransaction"));
    }

    #[test]
    fn empty_params_safe_message_sign() {
        let result = analyze_solana_request("signMessage", None, &HashSet::new(), 0);
        assert!(result.risk_score < 50);
        assert!(result.findings.iter().any(|f| f.contains("message")));
    }
}
