//! Canonical analysis pipeline.
//!
//! [`AnalysisEngine`] is the primary entry point for running a privacy
//! scan.  It accepts a [`BlockchainGateway`] for data access and routes
//! every scan request through the shared gateway abstraction, ensuring a
//! single execution path for HTTP, CLI, and library consumers.

use std::collections::{HashMap, HashSet};

use bitcoin::{Amount, Txid};

use crate::descriptor::{expand_input, normalize_descriptors};
use crate::error::AnalysisError;
use crate::gateway::{
    BlockchainGateway, DecodedTransaction, DescriptorType, Utxo, WalletHistory, WalletTxCategory,
    WalletTxEntry,
};
use crate::graph::TxGraph;
use crate::types::Report;

pub use stealth_model::progress::{ScanPhase, ScanProgress};
pub use stealth_model::scan::{EngineSettings, ScanTarget, UtxoInput};

type AddressSet = HashSet<bitcoin::Address<bitcoin::address::NetworkUnchecked>>;

// ── Engine ──────────────────────────────────────────────────────────────────

/// Runs a privacy analysis through a [`BlockchainGateway`].
///
/// Construct one per request (or per CLI invocation) and call
/// [`analyze`](Self::analyze).
pub struct AnalysisEngine<'a, G: BlockchainGateway + ?Sized> {
    gateway: &'a G,
    settings: EngineSettings,
}

impl<G: BlockchainGateway + ?Sized> std::fmt::Debug for AnalysisEngine<'_, G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisEngine")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl<'a, G: BlockchainGateway + ?Sized> AnalysisEngine<'a, G> {
    pub fn new(gateway: &'a G, settings: EngineSettings) -> Self {
        Self { gateway, settings }
    }

    /// Run a full privacy scan for the given target.
    pub fn analyze(&self, target: ScanTarget) -> Result<Report, AnalysisError> {
        if let Some(sink) = &self.settings.progress {
            self.gateway.set_progress_sink(sink.clone());
        }
        match target {
            ScanTarget::Descriptor(d) => self.analyze_descriptors(vec![d]),
            ScanTarget::Descriptors(ds) => self.analyze_descriptors(ds),
            ScanTarget::Utxos(utxos) => self.analyze_utxos(utxos),
        }
    }

    fn mark_phase(&self, phase: ScanPhase) {
        if let Some(sink) = &self.settings.progress {
            sink.set_phase(phase);
        }
    }

    // ── descriptor path ─────────────────────────────────────────────────

    fn analyze_descriptors(&self, raw_descriptors: Vec<String>) -> Result<Report, AnalysisError> {
        let mut expanded = Vec::new();
        for raw in &raw_descriptors {
            expanded.extend(expand_input(raw)?);
        }
        let resolved = normalize_descriptors(
            &expanded,
            self.settings.config.derivation_range_end,
            self.settings.rescan_since,
            self.gateway,
        )?;
        let history = self.gateway.scan_descriptors(&resolved)?;
        self.mark_phase(ScanPhase::Analyzing);
        let graph = TxGraph::from_wallet_history(history);
        Ok(graph.detect_all(
            &self.settings.config.thresholds,
            self.settings.known_risky_txids.as_ref(),
            self.settings.known_exchange_txids.as_ref(),
        ))
    }

    // ── UTXO path ───────────────────────────────────────────────────────

    fn analyze_utxos(&self, utxos: Vec<UtxoInput>) -> Result<Report, AnalysisError> {
        self.mark_phase(ScanPhase::LoadingHistory);
        let history = self.resolve_utxo_history(&utxos)?;
        self.mark_phase(ScanPhase::Analyzing);
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
            let confirmations = tx.confirmations;

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
                    confirmations,
                    blockheight: 0,
                });
            }

            utxo_entries.push(Utxo {
                txid: utxo.txid,
                vout: utxo.vout,
                address,
                amount: value,
                confirmations,
                script_type: DescriptorType::Unknown,
            });
        }

        // Fetch ancestor transactions for input resolution, bounded by
        // max_ancestor_depth to prevent unbounded graph traversal.
        // A depth of 0 means we only keep the UTXO's own transaction.
        // Level-order so the gateway can batch each frontier; failed
        // ancestor fetches are skipped, transport errors propagate.
        let max_depth = self.settings.config.max_ancestor_depth;
        let mut frontier: Vec<Txid> = fetch_queue
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|txid| !transactions.contains_key(txid))
            .collect();
        let mut depth = 1;
        while depth <= max_depth && !frontier.is_empty() {
            let mut next = HashSet::new();
            for (txid, fetched) in self.gateway.get_transactions(&frontier)? {
                if let Ok(tx) = fetched {
                    for input in tx.vin.iter().filter(|i| !i.coinbase) {
                        if !transactions.contains_key(&input.previous_txid) {
                            next.insert(input.previous_txid);
                        }
                    }
                    transactions.insert(txid, tx);
                }
            }
            frontier = next
                .into_iter()
                .filter(|txid| !transactions.contains_key(txid))
                .collect();
            depth += 1;
        }

        let (internal_addresses, derived_addresses) = self.derive_ownership_addresses()?;

        Ok(WalletHistory {
            wallet_txs,
            utxos: utxo_entries,
            transactions,
            internal_addresses,
            derived_addresses,
        })
    }

    /// Derive the addresses of `ownership_descriptors` so `is_ours()` can
    /// recognise the user's own inputs in UTXO scans.
    fn derive_ownership_addresses(&self) -> Result<(AddressSet, AddressSet), AnalysisError> {
        let mut internal = HashSet::new();
        let mut derived = HashSet::new();
        if self.settings.ownership_descriptors.is_empty() {
            return Ok((internal, derived));
        }

        let mut expanded = Vec::new();
        for raw in &self.settings.ownership_descriptors {
            expanded.extend(expand_input(raw)?);
        }
        let resolved = normalize_descriptors(
            &expanded,
            self.settings.config.derivation_range_end,
            self.settings.rescan_since,
            self.gateway,
        )?;
        for descriptor in &resolved {
            let addrs = self.gateway.derive_addresses(descriptor)?;
            if descriptor.internal {
                internal.extend(addrs.iter().cloned());
            }
            derived.extend(addrs);
        }
        Ok((internal, derived))
    }
}
