//! Contract analyzer: ABI decoding, opcode scanning, privilege extraction.
//! Uses Etherscan (ABI) and ETH RPC (bytecode) when ETHERSCAN_API_KEY and ETHEREUM_RPC_URL are set.

use crate::clients::{etherscan, rpc};
use crate::models::senseiguard::OwnerPrivileges;
use serde::Deserialize;

/// Known function names that imply owner privileges (case-insensitive match on ABI function names).
const MINT_NAMES: &[&str] = &["mint", "mintto", "mint_token"];
const PAUSE_NAMES: &[&str] = &["pause", "unpause", "pausable"];
const UPGRADE_NAMES: &[&str] = &["upgradeto", "upgradetoandcall", "upgrade", "initialize"];
const WITHDRAW_NAMES: &[&str] = &["withdraw", "withdrawliquidity", "withdrawfunds", "sweep", "rescue"];
const BLACKLIST_NAMES: &[&str] = &["blacklist", "addblacklist", "setblacklist"];
/// Dangerous for user approvals / proxy.
const DANGEROUS_NAMES: &[&str] = &[
    "setapprovalforall",
    "approve",
    "increaseallowance",
    "delegatecall",
    "multicall",
];

fn abi_has_function(abi_json: &str, names: &[&str]) -> bool {
    #[derive(Debug, Deserialize)]
    struct AbiItem {
        #[serde(rename = "type")]
        typ: Option<String>,
        name: Option<String>,
    }
    let items: Vec<AbiItem> = match serde_json::from_str(abi_json) {
        Ok(x) => x,
        Err(_) => return false,
    };
    for item in items {
        if item.typ.as_deref() != Some("function") {
            continue;
        }
        let name = item.name.as_deref().unwrap_or("").to_lowercase();
        let name = name.replace('_', "");
        for n in names {
            if name.contains(n) || name == *n {
                return true;
            }
        }
    }
    false
}

fn bytecode_has_delegatecall(code: &[u8]) -> bool {
    // DELEGATECALL opcode = 0xF4
    code.iter().any(|&b| b == 0xF4)
}

pub struct AnalyzerService;

impl AnalyzerService {
    /// Extract owner/admin privileges from ABI (and optionally bytecode). Uses Etherscan + RPC when configured.
    pub async fn extract_owner_privileges(contract_address: &str) -> OwnerPrivileges {
        let (abi, _verified) = match etherscan::fetch_abi_and_verified(contract_address).await {
            Ok((a, v)) if !a.is_empty() => (a, v),
            Ok((_, _)) => {
                tracing::info!("Analyzer: empty ABI for {}; using stub owner privileges", contract_address);
                return Self::stub_owner_privileges();
            }
            Err(e) => {
                tracing::warn!("Analyzer: Etherscan fetch failed for {}: {}; using stub owner privileges", contract_address, e);
                return Self::stub_owner_privileges();
            }
        };

        OwnerPrivileges {
            mint: Some(abi_has_function(&abi, MINT_NAMES)),
            pause: Some(abi_has_function(&abi, PAUSE_NAMES)),
            upgradeable: Some(abi_has_function(&abi, UPGRADE_NAMES)),
            withdraw_liquidity: Some(abi_has_function(&abi, WITHDRAW_NAMES)),
            blacklist: Some(abi_has_function(&abi, BLACKLIST_NAMES)),
        }
    }

    /// Dangerous function names from ABI; plus "delegatecall" if bytecode contains DELEGATECALL.
    pub async fn dangerous_functions(contract_address: &str) -> Vec<String> {
        let mut out = Vec::new();
        let abi = match etherscan::fetch_abi_and_verified(contract_address).await {
            Ok((a, _)) if !a.is_empty() => a,
            _ => {
                tracing::info!("Analyzer: empty ABI or fetch failed for {}; using fallback dangerous_functions list", contract_address);
                return vec!["delegatecall".to_string(), "setApprovalForAll".to_string()];
            }
        };

        #[derive(Debug, Deserialize)]
        struct AbiItem {
            name: Option<String>,
            #[serde(rename = "type")]
            typ: Option<String>,
        }
        let items: Vec<AbiItem> = if let Ok(x) = serde_json::from_str(&abi) {
            x
        } else {
            return out;
        };
        let abi_lower = abi.to_lowercase();
        for n in DANGEROUS_NAMES {
            if abi_lower.contains(n) {
                let name = n
                    .replace("setapprovalforall", "setApprovalForAll")
                    .replace("increaseallowance", "increaseAllowance")
                    .replace("delegatecall", "delegatecall")
                    .replace("multicall", "multicall")
                    .replace("approve", "approve");
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        for item in items {
            if item.typ.as_deref() != Some("function") {
                continue;
            }
            if let Some(name) = item.name {
                let lower = name.to_lowercase().replace('_', "");
                for n in DANGEROUS_NAMES {
                    if lower.contains(n) && !out.contains(&name) {
                        out.push(name);
                        break;
                    }
                }
            }
        }
        if let Ok(code) = rpc::fetch_bytecode(contract_address).await {
            if bytecode_has_delegatecall(&code) && !out.iter().any(|s| s.eq_ignore_ascii_case("delegatecall")) {
                out.push("delegatecall".to_string());
            }
        }
        if out.is_empty() {
            out.push("setApprovalForAll".to_string());
        }
        out
    }

    fn stub_owner_privileges() -> OwnerPrivileges {
        OwnerPrivileges {
            mint: Some(true),
            pause: Some(true),
            upgradeable: Some(true),
            withdraw_liquidity: Some(true),
            blacklist: Some(false),
        }
    }
}
