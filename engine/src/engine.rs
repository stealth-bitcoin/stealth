//! Canonical analysis pipeline.
//!
//! [`AnalysisEngine`] is the primary entry point for running a privacy
//! scan.  It accepts a [`BlockchainGateway`] for data access and routes
//! every scan request through the shared gateway abstraction, ensuring a
//! single execution path for HTTP, CLI, and library consumers.

use std::collections::{HashMap, HashSet};

use bitcoin::{Amount, Txid};

use crate::descriptor::normalize_descriptors;
use crate::error::AnalysisError;
use crate::gateway::{
    BlockchainGateway, DecodedTransaction, DescriptorType, Utxo, WalletHistory, WalletTxCategory,
    WalletTxEntry,
};
use crate::graph::TxGraph;
use crate::types::Report;

pub use stealth_model::scan::{EngineSettings, ScanTarget, UtxoInput};

// ── Engine ──────────────────────────────────────────────────────────────────

/// Runs a privacy analysis through a [`BlockchainGateway`].
///
/// Construct one per request (or per CLI invocation) and call
/// [`analyze`](Self::analyze).
pub struct AnalysisEngine<'a, G: BlockchainGateway> {
    gateway: &'a G,
    settings: EngineSettings,
}

impl<G: BlockchainGateway> std::fmt::Debug for AnalysisEngine<'_, G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisEngine")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl<'a, G: BlockchainGateway> AnalysisEngine<'a, G> {
    pub fn new(gateway: &'a G, settings: EngineSettings) -> Self {
        Self { gateway, settings }
    }

    /// Run a full privacy scan for the given target.
    pub fn analyze(&self, target: ScanTarget) -> Result<Report, AnalysisError> {
        match target {
            ScanTarget::Descriptor(d) => self.analyze_descriptors(vec![d]),
            ScanTarget::Descriptors(ds) => self.analyze_descriptors(ds),
            ScanTarget::Utxos(utxos) => self.analyze_utxos(utxos),
        }
    }

    // ── descriptor path ─────────────────────────────────────────────────

    fn analyze_descriptors(&self, raw_descriptors: Vec<String>) -> Result<Report, AnalysisError> {
        let resolved = normalize_descriptors(
            &raw_descriptors,
            self.settings.config.derivation_range_end,
            self.gateway,
        )?;
        let history = self.gateway.scan_descriptors(&resolved)?;
        let graph = TxGraph::from_wallet_history(history);
        Ok(graph.detect_all(
            &self.settings.config.thresholds,
            self.settings.known_risky_txids.as_ref(),
            self.settings.known_exchange_txids.as_ref(),
        ))
    }

    // ── UTXO path ───────────────────────────────────────────────────────

    fn analyze_utxos(&self, utxos: Vec<UtxoInput>) -> Result<Report, AnalysisError> {
        let history = self.resolve_utxo_history(&utxos)?;
        let graph = TxGraph::from_wallet_history(history);
        Ok(graph.detect_all(
            &self.settings.config.thresholds,
            self.settings.known_risky_txids.as_ref(),
            self.settings.known_exchange_txids.as_ref(),
        ))
    }

    /// Build a [`WalletHistory`] from raw UTXO inputs by fetching the
    /// referenced transactions (and their parents) through the gateway.
    fn resolve_utxo_history(&self, utxos: &[UtxoInput]) -> Result<WalletHistory, AnalysisError> {
        let mut wallet_txs = Vec::new();
        let mut utxo_entries = Vec::new();
        let mut transactions: HashMap<Txid, DecodedTransaction> = HashMap::new();
        let mut fetch_queue: Vec<Txid> = Vec::new();

        for utxo in utxos {
            // Fetch the UTXO's parent transaction.
            if let std::collections::hash_map::Entry::Vacant(e) = transactions.entry(utxo.txid) {
                let tx = self.gateway.get_transaction(utxo.txid)?;
                fetch_queue.extend(
                    tx.vin
                        .iter()
                        .filter(|i| !i.coinbase)
                        .map(|i| i.previous_txid),
                );
                e.insert(tx);
            }

            let tx = &transactions[&utxo.txid];

            let address = utxo.address.clone().or_else(|| {
                tx.vout
                    .iter()
                    .find(|o| o.n == utxo.vout)
                    .and_then(|o| o.address.clone())
            });

            let value = utxo.value.unwrap_or_else(|| {
                tx.vout
                    .iter()
                    .find(|o| o.n == utxo.vout)
                    .map(|o| o.value)
                    .unwrap_or(Amount::ZERO)
            });

            if address.is_some() {
                wallet_txs.push(WalletTxEntry {
                    txid: utxo.txid,
                    address: address.clone(),
                    category: WalletTxCategory::Receive,
                    amount: value,
                    confirmations: 0,
                    blockheight: 0,
                });
            }

            utxo_entries.push(Utxo {
                txid: utxo.txid,
                vout: utxo.vout,
                address,
                amount: value,
                confirmations: 0,
                script_type: DescriptorType::Unknown,
            });
        }

        // Fetch ancestor transactions for input resolution, bounded by
        // max_ancestor_depth to prevent unbounded graph traversal.
        // A depth of 0 means we only keep the UTXO's own transaction.
        let max_depth = self.settings.config.max_ancestor_depth;
        if max_depth > 0 {
            let mut depth_queue: Vec<(Txid, u32)> =
                fetch_queue.into_iter().map(|txid| (txid, 1)).collect();
            while let Some((txid, depth)) = depth_queue.pop() {
                if transactions.contains_key(&txid) {
                    continue;
                }
                if let Ok(tx) = self.gateway.get_transaction(txid) {
                    if depth < max_depth {
                        depth_queue.extend(
                            tx.vin
                                .iter()
                                .filter(|i| !i.coinbase)
                                .map(|i| (i.previous_txid, depth + 1)),
                        );
                    }
                    transactions.insert(txid, tx);
                }
            }
        }

        Ok(WalletHistory {
            wallet_txs,
            utxos: utxo_entries,
            transactions,
            internal_addresses: HashSet::new(),
        })
    }
}
