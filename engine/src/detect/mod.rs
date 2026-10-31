//! Privacy detectors, one module per family, run together by `detect_all`.

use std::collections::HashSet;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};

use crate::config::DetectorThresholds;
use crate::graph::TxGraph;
use crate::types::*;

mod address_reuse;
mod behavior;
mod change;
mod dust;
mod linkage;
mod origins;

/// Most addresses a description names before "and N more"; details keep them all.
const MAX_LISTED_ADDRESSES: usize = 5;

/// `addresses` joined for a description, the ones past the cap counted instead of named.
fn list_addresses(addresses: &[String]) -> String {
    let shown = addresses[..addresses.len().min(MAX_LISTED_ADDRESSES)].join(", ");
    match addresses.len().saturating_sub(MAX_LISTED_ADDRESSES) {
        0 => shown,
        more => format!("{shown} and {more} more"),
    }
}

impl TxGraph {
    /// Run all vulnerability detectors and produce a [`Report`].
    ///
    /// Optionally pass sets of known-risky and known-exchange transaction IDs
    /// to enable taint analysis (detector 11) and exchange-origin detection
    /// (detector 10).
    pub fn detect_all(
        &self,
        thresholds: &DetectorThresholds,
        known_risky_txids: Option<&HashSet<Txid>>,
        known_exchange_txids: Option<&HashSet<Txid>>,
    ) -> Report {
        let mut findings = Vec::new();
        let mut warnings = Vec::new();

        self.detect_address_reuse(&mut findings);
        self.detect_cioh(&mut findings);
        self.detect_dust(thresholds, &mut findings);
        self.detect_dust_spending(thresholds, &mut findings);
        self.detect_change_detection(&mut findings);
        self.detect_consolidation_origin(thresholds, &mut findings, &mut warnings);
        self.detect_script_type_mixing(&mut findings);
        self.detect_cluster_merge(&mut findings);
        self.detect_lookback_depth(thresholds, &mut findings, &mut warnings);
        self.detect_exchange_origin(thresholds, &mut findings, known_exchange_txids);
        self.detect_tainted_utxos(&mut findings, &mut warnings, known_risky_txids);
        self.detect_behavioral_fingerprint(&mut findings);
        // Dust-attack detection is folded into `detect_dust`, which
        // escalates Dust findings whose parent tx matches the attack
        // pattern (see commit 2 of PR #19 review).
        self.detect_peel_chain(thresholds, &mut findings);
        self.detect_deterministic_links(thresholds, &mut findings, &mut warnings);
        self.detect_unnecessary_input(&mut findings);
        self.detect_toxic_change(thresholds, &mut findings);

        for list in [&mut findings, &mut warnings] {
            list.sort_by(|a, b| {
                (a.vulnerability_type as u8, a.description.as_str())
                    .cmp(&(b.vulnerability_type as u8, b.description.as_str()))
            });
        }

        // In the order they are printed, which reverses the bytes a Txid sorts by.
        let mut conflicted_txids: Vec<Txid> = self.left_out.conflicted.iter().copied().collect();
        conflicted_txids.sort_by_cached_key(Txid::to_string);
        let mut mempool_conflicted_txids: Vec<MempoolConflict> = self
            .left_out
            .mempool_conflicted
            .iter()
            .map(|(&txid, &conflicts_with)| MempoolConflict {
                txid,
                conflicts_with,
            })
            .collect();
        mempool_conflicted_txids.sort_by_cached_key(|r| r.txid.to_string());
        let mut abandoned_txids: Vec<Txid> = self.left_out.abandoned.iter().copied().collect();
        abandoned_txids.sort_by_cached_key(Txid::to_string);
        let mut unavailable_txids: Vec<Txid> = self.left_out.unavailable.iter().copied().collect();
        unavailable_txids.sort_by_cached_key(Txid::to_string);
        let mut orphaned_txids: Vec<Txid> = self.left_out.orphaned.iter().copied().collect();
        orphaned_txids.sort_by_cached_key(Txid::to_string);

        let stats = Stats {
            transactions_analyzed: self.our_txids.len(),
            addresses_seen: self.addr_map.len(),
            utxos_current: self.utxos.len(),
            addresses_without_history: 0,
            conflicted_txids,
            mempool_conflicted_txids,
            abandoned_txids,
            unavailable_txids,
            orphaned_txids,
        };

        Report::new(stats, findings, warnings)
    }

    /// The spend looks like a CoinJoin round: two or more outputs of exactly the same value
    /// and more than two input addresses the scan cannot attribute. Full CoinJoin detection
    /// is separate work; this only keeps a round's participants from being called the user's.
    fn coinjoin_shaped(&self, txid: &Txid) -> bool {
        let Some(tx) = self.tx_cache.get(txid) else {
            return false;
        };
        let equal_outputs = tx
            .vout
            .iter()
            .enumerate()
            .any(|(i, o)| tx.vout[i + 1..].iter().any(|p| p.value == o.value));
        let mut strangers: Vec<&Address<NetworkUnchecked>> = Vec::new();
        for input in self.input_cache.get(txid).into_iter().flatten() {
            if !self.is_ours(&input.address) && !strangers.contains(&&input.address) {
                strangers.push(&input.address);
            }
        }
        equal_outputs && strangers.len() > 2
    }

    /// In a partial scan, an input address of `txid` the scan cannot tell apart from one of
    /// the user's, unless the spend is shaped like a CoinJoin round.
    fn unattributed(&self, txid: &Txid, address: &Address<NetworkUnchecked>) -> bool {
        self.partial_scan && !self.is_ours(address) && !self.coinjoin_shaped(txid)
    }

    /// Addresses of `txid`'s inputs, other than `address`, that the spend ties to it: the
    /// wallet's own, then, in a partial scan, those it cannot attribute.
    fn joined_addresses(
        &self,
        txid: &Txid,
        address: &Address<NetworkUnchecked>,
    ) -> (Vec<String>, Vec<String>) {
        let (mut own, mut unattributed) = (Vec::new(), Vec::new());
        for input in self.get_input_addresses(txid) {
            if input.address == *address {
                continue;
            }
            let list = if self.is_ours(&input.address) {
                &mut own
            } else if self.unattributed(txid, &input.address) {
                &mut unattributed
            } else {
                continue;
            };
            let text = input.address.assume_checked_ref().to_string();
            if !list.contains(&text) {
                list.push(text);
            }
        }
        (own, unattributed)
    }

    /// Our transaction IDs in a stable order, so detector output never
    /// depends on `HashSet` iteration order.
    fn ordered_txids(&self) -> Vec<Txid> {
        let mut txids: Vec<Txid> = self.our_txids.iter().copied().collect();
        txids.sort_unstable();
        txids
    }
}
