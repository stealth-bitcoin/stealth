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

        let stats = Stats {
            transactions_analyzed: self.our_txids.len(),
            addresses_seen: self.addr_map.len(),
            utxos_current: self.utxos.len(),
            addresses_without_history: 0,
        };

        Report::new(stats, findings, warnings)
    }

    /// The scan was given no ranged descriptor (a UTXO scan without ownership descriptors, or
    /// a single-address scan), so it knows only some of the wallet's addresses.
    fn partial_scan(&self) -> bool {
        self.ranged_addrs.is_empty()
    }

    /// In a partial scan, an input address the scan cannot tell apart from one of the user's.
    fn unattributed(&self, address: &Address<NetworkUnchecked>) -> bool {
        self.partial_scan() && !self.is_ours(address)
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
            } else if self.unattributed(&input.address) {
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
