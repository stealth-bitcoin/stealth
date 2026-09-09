use std::collections::HashSet;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Txid};
use serde::{Deserialize, Serialize};

use crate::config::AnalysisConfig;
use crate::progress::ScanProgress;

/// What to scan.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    Descriptor(String),
    Descriptors(Vec<String>),
    Utxos(Vec<UtxoInput>),
}

/// A raw UTXO to analyse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInput {
    pub txid: Txid,
    pub vout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Amount>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::types::serde_addr_opt"
    )]
    pub address: Option<Address<NetworkUnchecked>>,
}

/// Top-level settings for the analysis engine, combining detector config
/// with optional known-wallet hooks used by taint and exchange detectors.
#[derive(Debug, Clone, Default)]
pub struct EngineSettings {
    pub config: AnalysisConfig,
    pub known_risky_txids: Option<HashSet<Txid>>,
    pub known_exchange_txids: Option<HashSet<Txid>>,
    pub rescan_since: Option<u64>,
    pub ownership_descriptors: Vec<String>,
    /// Reuse a deterministic watch-only wallet across scans of the same
    /// descriptors. When set, the first descriptor scan imports and keeps
    /// the wallet so later scans only pay Core's incremental catch-up.
    /// Defaults to `false`: a throwaway wallet is created and discarded.
    pub persist_scan_wallet: bool,
    /// Optional sink that receives phase transitions and rescan progress.
    pub progress: Option<ScanProgress>,
}
