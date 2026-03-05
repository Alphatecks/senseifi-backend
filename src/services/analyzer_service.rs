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

/// Result of one contract analysis (single Etherscan fetch).
pub struct AnalysisResult {
    pub owner_privileges: OwnerPrivileges,
    pub dangerous_functions: Vec<String>,
    /// True when ABI was fetched from Etherscan; false when using stub/fallback.
    pub abi_from_etherscan: bool,
}

impl AnalyzerService {
    /// Run analyzer with a single Etherscan fetch. Returns privileges, dangerous functions, and whether ABI was from Etherscan.
    pub async fn analyze_contract(contract_address: &str) -> AnalysisResult {
        let (abi, _verified) = match etherscan::fetch_abi_and_verified(contract_address).await {
            Ok((a, v)) if !a.is_empty() => (a, v),
            Ok((_, _)) => {
                tracing::info!("Analyzer: empty ABI for {} (contract not verified?); using stub", contract_address);
                return AnalysisResult {
                    owner_privileges: Self::stub_owner_privileges(),
                    dangerous_functions: vec!["delegatecall".to_string(), "setApprovalForAll".to_string()],
                    abi_from_etherscan: false,
                };
            }
            Err(e) => {
                tracing::warn!("Analyzer: Etherscan fetch failed for {}: {}; using stub", contract_address, e);
                return AnalysisResult {
                    owner_privileges: Self::stub_owner_privileges(),
                    dangerous_functions: vec!["delegatecall".to_string(), "setApprovalForAll".to_string()],
                    abi_from_etherscan: false,
                };
            }
        };

        let owner_privileges = OwnerPrivileges {
            mint: Some(abi_has_function(&abi, MINT_NAMES)),
            pause: Some(abi_has_function(&abi, PAUSE_NAMES)),
            upgradeable: Some(abi_has_function(&abi, UPGRADE_NAMES)),
            withdraw_liquidity: Some(abi_has_function(&abi, WITHDRAW_NAMES)),
            blacklist: Some(abi_has_function(&abi, BLACKLIST_NAMES)),
        };
        let dangerous_functions = Self::dangerous_functions_from_abi_impl(abi.clone(), contract_address.to_string()).await;
        AnalysisResult {
            owner_privileges,
            dangerous_functions,
            abi_from_etherscan: true,
        }
    }

    async fn dangerous_functions_from_abi_impl(abi: String, contract_address: String) -> Vec<String> {
        let mut out = Vec::new();
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
        let contract_address = contract_address.as_str();
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

    /// Extract owner/admin privileges from ABI (and optionally bytecode). Uses Etherscan + RPC when configured.
    pub async fn extract_owner_privileges(contract_address: &str) -> OwnerPrivileges {
        Self::analyze_contract(contract_address).await.owner_privileges
    }

    /// Dangerous function names from ABI; plus "delegatecall" if bytecode contains DELEGATECALL.
    pub async fn dangerous_functions(contract_address: &str) -> Vec<String> {
        Self::analyze_contract(contract_address).await.dangerous_functions
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
