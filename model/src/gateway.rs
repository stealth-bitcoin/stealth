use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Txid};
use serde::{Deserialize, Serialize};

use crate::descriptor::DescriptorNormalizer;
use crate::error::AnalysisError;
use crate::types::{serde_addr, serde_addr_opt, serde_addr_set};

/// Abstraction over a blockchain data source (e.g. Bitcoin Core RPC).
///
/// Implementations provide descriptor normalization, address derivation,
/// wallet scanning, and transaction history retrieval. This trait decouples
/// domain logic from the concrete RPC transport, making it possible to
/// test with mocks.
pub trait BlockchainGateway {
    fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError>;
    fn derive_addresses(
        &self,
        descriptor: &ResolvedDescriptor,
    ) -> Result<Vec<Address<NetworkUnchecked>>, AnalysisError>;
    fn scan_descriptors(
        &self,
        descriptors: &[ResolvedDescriptor],
    ) -> Result<WalletHistory, AnalysisError>;
    fn list_wallet_descriptors(
        &self,
        wallet_name: &str,
    ) -> Result<Vec<ResolvedDescriptor>, AnalysisError>;
    fn scan_wallet(&self, wallet_name: &str) -> Result<WalletHistory, AnalysisError>;
    fn known_wallet_txids(&self, wallet_names: &[String]) -> Result<HashSet<Txid>, AnalysisError>;
    fn get_transaction(&self, txid: Txid) -> Result<DecodedTransaction, AnalysisError>;
}

/// Blanket implementation: any `BlockchainGateway` is also a
/// `DescriptorNormalizer`.
impl<T> DescriptorNormalizer for T
where
    T: BlockchainGateway + ?Sized,
{
    fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError> {
        self.normalize_descriptor(descriptor)
    }
}

// ── Gateway model types ─────────────────────────────────────────────────────

/// A descriptor that has been normalized and resolved for import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDescriptor {
    pub desc: String,
    pub internal: bool,
    pub active: bool,
    pub range_end: u32,
}

/// Role of a descriptor chain (external receive vs internal change).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorChainRole {
    External,
    Internal,
}

/// Script/address type derived from a descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorType {
    P2wpkh,
    P2tr,
    P2shP2wpkh,
    P2sh,
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

    pub fn infer_from_address(address: &Address<NetworkUnchecked>) -> Self {
        let script = address.clone().assume_checked().script_pubkey();
        if script.is_p2wpkh() {
            Self::P2wpkh
        } else if script.is_p2tr() {
            Self::P2tr
        } else if script.is_p2sh() {
            Self::P2sh
        } else if script.is_p2pkh() {
            Self::P2pkh
        } else {
            Self::Unknown
        }
    }

    pub fn as_script_name(self) -> &'static str {
        match self {
            Self::P2wpkh => "witness_v0_keyhash",
            Self::P2tr => "witness_v1_taproot",
            Self::P2shP2wpkh | Self::P2sh => "scripthash",
            Self::P2pkh => "pubkeyhash",
            Self::Unknown => "unknown",
        }
    }
}

/// A derived address with metadata about its origin descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedAddress {
    #[serde(with = "serde_addr")]
    pub address: Address<NetworkUnchecked>,
    pub descriptor_type: DescriptorType,
    pub chain_role: DescriptorChainRole,
    pub derivation_index: u32,
}

/// Wallet transaction category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletTxCategory {
    Send,
    Receive,
    Unknown,
}

/// A wallet transaction entry (from `listtransactions`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletTxEntry {
    pub txid: Txid,
    #[serde(with = "serde_addr_opt")]
    pub address: Option<Address<NetworkUnchecked>>,
    pub category: WalletTxCategory,
    pub amount: Amount,
    pub confirmations: u32,
    pub blockheight: u32,
}

/// An input reference within a decoded transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInputRef {
    #[serde(rename = "txid")]
    pub previous_txid: Txid,
    #[serde(rename = "vout")]
    pub previous_vout: u32,
    pub sequence: u32,
    pub coinbase: bool,
}

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxOutput {
    pub n: u32,
    #[serde(with = "serde_addr_opt")]
    pub address: Option<Address<NetworkUnchecked>>,
    pub value: Amount,
    pub script_type: DescriptorType,
}

/// A fully decoded transaction with inputs and outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedTransaction {
    pub txid: Txid,
    pub vin: Vec<TxInputRef>,
    pub vout: Vec<TxOutput>,
    pub version: i32,
    pub locktime: u32,
    pub vsize: u32,
    pub confirmations: u32,
}

/// A current unspent transaction output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    #[serde(with = "serde_addr_opt")]
    pub address: Option<Address<NetworkUnchecked>>,
    pub amount: Amount,
    pub confirmations: u32,
    pub script_type: DescriptorType,
}

/// Complete wallet history with transactions and UTXOs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletHistory {
    pub wallet_txs: Vec<WalletTxEntry>,
    pub utxos: Vec<Utxo>,
    pub transactions: HashMap<Txid, DecodedTransaction>,
    /// Addresses known to belong to internal (change) descriptor chains.
    /// Populated by the descriptor scan path; may be empty for wallet scans.
    #[serde(default, with = "serde_addr_set")]
    pub internal_addresses: HashSet<Address<NetworkUnchecked>>,
}

/// A participant (input or output) in a transaction, enriched with
/// ownership information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionParticipant {
    #[serde(with = "serde_addr")]
    pub address: Address<NetworkUnchecked>,
    pub value: Amount,
    pub script_type: DescriptorType,
    pub is_ours: bool,
    pub funding_txid: Option<Txid>,
    pub funding_vout: Option<u32>,
}
