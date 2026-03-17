use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingKind {
    AddressReuse,
    Cioh,
    Dust,
    DustSpending,
    ChangeDetection,
    Consolidation,
    ScriptTypeMixing,
    ClusterMerge,
    UtxoAgeSpread,
    ExchangeOrigin,
    TaintedUtxoMerge,
    BehavioralFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WarningKind {
    DormantUtxos,
    DirectTaint,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FindingDetails {
    Generic(Value),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WarningDetails {
    Generic(Value),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    #[serde(rename = "type")]
    pub kind: FindingKind,
    pub severity: Severity,
    pub description: String,
    pub details: FindingDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Warning {
    #[serde(rename = "type")]
    pub kind: WarningKind,
    pub severity: Severity,
    pub description: String,
    pub details: WarningDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub transactions_analyzed: usize,
    pub addresses_derived: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub findings: usize,
    pub warnings: usize,
    pub clean: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub stats: AnalysisStats,
    pub findings: Vec<Finding>,
    pub warnings: Vec<Warning>,
    pub summary: AnalysisSummary,
}

impl AnalysisReport {
    pub fn new(
        transactions_analyzed: usize,
        addresses_derived: usize,
        findings: Vec<Finding>,
        warnings: Vec<Warning>,
    ) -> Self {
        let summary = AnalysisSummary {
            findings: findings.len(),
            warnings: warnings.len(),
            clean: findings.is_empty() && warnings.is_empty(),
        };

        Self {
            stats: AnalysisStats {
                transactions_analyzed,
                addresses_derived,
            },
            findings,
            warnings,
            summary,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorChainRole {
    External,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorType {
    P2wpkh,
    P2tr,
    P2shP2wpkh,
    P2pkh,
    Unknown,
}

impl DescriptorType {
    pub fn from_descriptor(descriptor: &str) -> Self {
        if descriptor.starts_with("wpkh(") {
            Self::P2wpkh
        } else if descriptor.starts_with("tr(") {
            Self::P2tr
        } else if descriptor.starts_with("sh(wpkh(") {
            Self::P2shP2wpkh
        } else if descriptor.starts_with("pkh(") {
            Self::P2pkh
        } else {
            Self::Unknown
        }
    }

    pub fn infer_from_address(address: &str) -> Self {
        if address.starts_with("bc1q")
            || address.starts_with("tb1q")
            || address.starts_with("bcrt1q")
        {
            Self::P2wpkh
        } else if address.starts_with("bc1p")
            || address.starts_with("tb1p")
            || address.starts_with("bcrt1p")
        {
            Self::P2tr
        } else if address.starts_with('2') || address.starts_with('3') {
            Self::P2shP2wpkh
        } else if address.starts_with('1') || address.starts_with('m') || address.starts_with('n') {
            Self::P2pkh
        } else {
            Self::Unknown
        }
    }

    pub fn as_script_name(self) -> &'static str {
        match self {
            Self::P2wpkh => "witness_v0_keyhash",
            Self::P2tr => "witness_v1_taproot",
            Self::P2shP2wpkh => "scripthash",
            Self::P2pkh => "pubkeyhash",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedAddress {
    pub address: String,
    pub descriptor_type: DescriptorType,
    pub chain_role: DescriptorChainRole,
    pub derivation_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDescriptor {
    pub desc: String,
    pub internal: bool,
    pub active: bool,
    pub range_end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletTxCategory {
    Send,
    Receive,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletTxEntry {
    pub txid: String,
    pub address: String,
    pub category: WalletTxCategory,
    pub amount_btc: f64,
    pub confirmations: u32,
    pub blockheight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInputRef {
    #[serde(rename = "txid")]
    pub previous_txid: String,
    #[serde(rename = "vout")]
    pub previous_vout: u32,
    pub sequence: u32,
    pub coinbase: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxOutput {
    pub n: u32,
    pub address: String,
    pub value_btc: f64,
    pub script_type: DescriptorType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedTransaction {
    pub txid: String,
    pub vin: Vec<TxInputRef>,
    pub vout: Vec<TxOutput>,
    pub version: i32,
    pub locktime: u32,
    pub vsize: u32,
    pub confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount_btc: f64,
    pub confirmations: u32,
    pub script_type: DescriptorType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletHistory {
    pub wallet_txs: Vec<WalletTxEntry>,
    pub utxos: Vec<Utxo>,
    pub transactions: std::collections::HashMap<String, DecodedTransaction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionParticipant {
    pub address: String,
    pub value_btc: f64,
    pub value_sats: u64,
    pub script_type: DescriptorType,
    pub is_ours: bool,
    pub funding_txid: Option<String>,
    pub funding_vout: Option<u32>,
}
