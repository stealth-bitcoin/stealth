use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Txid};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::gateway::WalletTxCategory;

/// Serde helper: serialize an [`Address<NetworkUnchecked>`] via its checked
/// display representation. Deserialization delegates to the standard
/// `Address<NetworkUnchecked>` deserializer.
pub mod serde_addr {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::Address;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(addr: &Address<NetworkUnchecked>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.collect_str(addr.assume_checked_ref())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Address<NetworkUnchecked>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Address::<NetworkUnchecked>::deserialize(d)
    }
}

/// Serde helper for `Option<Address<NetworkUnchecked>>`.
pub mod serde_addr_opt {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::Address;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(addr: &Option<Address<NetworkUnchecked>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match addr {
            Some(a) => s.collect_str(a.assume_checked_ref()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Address<NetworkUnchecked>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Address<NetworkUnchecked>>::deserialize(d)
    }
}

/// Serde helper for `HashSet<Address<NetworkUnchecked>>`.
pub mod serde_addr_set {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::Address;
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::collections::HashSet;

    pub fn serialize<S>(addrs: &HashSet<Address<NetworkUnchecked>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(addrs.len()))?;
        for addr in addrs {
            seq.serialize_element(&addr.assume_checked_ref().to_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(d: D) -> Result<HashSet<Address<NetworkUnchecked>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(d)?;
        strings
            .into_iter()
            .map(|s| {
                s.parse::<Address<NetworkUnchecked>>()
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

/// Severity levels for privacy vulnerability findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl core::fmt::Display for Severity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// The category of privacy vulnerability detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VulnerabilityType {
    AddressReuse,
    Cioh,
    Dust,
    DustSpending,
    ChangeDetection,
    Consolidation,
    ScriptTypeMixing,
    ClusterMerge,
    UtxoAgeSpread,
    DormantUtxos,
    ExchangeOrigin,
    TaintedUtxoMerge,
    DirectTaint,
    BehavioralFingerprint,
}

impl core::fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AddressReuse => write!(f, "ADDRESS_REUSE"),
            Self::Cioh => write!(f, "CIOH"),
            Self::Dust => write!(f, "DUST"),
            Self::DustSpending => write!(f, "DUST_SPENDING"),
            Self::ChangeDetection => write!(f, "CHANGE_DETECTION"),
            Self::Consolidation => write!(f, "CONSOLIDATION"),
            Self::ScriptTypeMixing => write!(f, "SCRIPT_TYPE_MIXING"),
            Self::ClusterMerge => write!(f, "CLUSTER_MERGE"),
            Self::UtxoAgeSpread => write!(f, "UTXO_AGE_SPREAD"),
            Self::DormantUtxos => write!(f, "DORMANT_UTXOS"),
            Self::ExchangeOrigin => write!(f, "EXCHANGE_ORIGIN"),
            Self::TaintedUtxoMerge => write!(f, "TAINTED_UTXO_MERGE"),
            Self::DirectTaint => write!(f, "DIRECT_TAINT"),
            Self::BehavioralFingerprint => write!(f, "BEHAVIORAL_FINGERPRINT"),
        }
    }
}

/// A single privacy vulnerability finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    #[serde(rename = "type")]
    pub vulnerability_type: VulnerabilityType,
    pub severity: Severity,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correction: Option<String>,
}

/// Aggregate statistics about the scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub transactions_analyzed: usize,
    pub addresses_seen: usize,
    pub utxos_current: usize,
}

/// Summary of the scan results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub findings: usize,
    pub warnings: usize,
    pub clean: bool,
}

/// The complete vulnerability scan report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub stats: Stats,
    pub findings: Vec<Finding>,
    pub warnings: Vec<Finding>,
    pub summary: Summary,
}

impl Report {
    /// Construct a report from collected findings and warnings.
    pub fn new(stats: Stats, findings: Vec<Finding>, warnings: Vec<Finding>) -> Self {
        let summary = Summary {
            findings: findings.len(),
            warnings: warnings.len(),
            clean: findings.is_empty() && warnings.is_empty(),
        };
        Report {
            stats,
            findings,
            warnings,
            summary,
        }
    }
}

/// Convert a BTC f64 value to an [`Amount`].
pub fn btc_to_amount(btc: f64) -> Amount {
    Amount::from_sat((btc * 1e8).round() as u64)
}

/// Metadata about a derived address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInfo {
    /// The script type (e.g. "p2wpkh", "p2tr", "p2sh", "p2wsh", "p2pkh").
    pub script_type: String,
    /// Whether this is a change (internal) address.
    pub internal: bool,
    /// The derivation index.
    pub index: usize,
}

/// Information about a transaction input, resolved from the parent transaction.
#[derive(Debug, Clone)]
pub struct InputInfo {
    pub address: Address<NetworkUnchecked>,
    pub value: Amount,
    pub funding_txid: Txid,
    pub funding_vout: u32,
}

/// Information about a transaction output.
#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub address: Address<NetworkUnchecked>,
    pub value: Amount,
    pub index: u32,
    pub script_type: String,
}

/// A wallet transaction entry (from `listtransactions`).
#[derive(Debug, Clone)]
pub struct WalletTx {
    pub txid: Txid,
    pub address: Address<NetworkUnchecked>,
    pub category: WalletTxCategory,
    pub amount: Amount,
    pub confirmations: u32,
}
