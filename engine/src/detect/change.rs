//! Change identification and toxic change detectors.

use std::collections::HashSet;

use serde_json::json;

use crate::config::DetectorThresholds;
use crate::graph::TxGraph;
use crate::types::*;

impl TxGraph {
    // ── 5. Change Detection ────────────────────────────────────────────────

    pub(super) fn detect_change_detection(&self, findings: &mut Vec<Finding>) {
        let txids = self.ordered_txids();
        for txid in &txids {
            let outputs = self.get_output_addresses(txid);
            if outputs.len() < 2 {
                continue;
            }
            let input_addrs = self.get_input_addresses(txid);
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.is_empty() {
                continue;
            }

            let our_outs: Vec<_> = outputs
                .iter()
                .filter(|o| self.is_ours(&o.address))
                .collect();
            let ext_outs: Vec<_> = outputs
                .iter()
                .filter(|o| !self.is_ours(&o.address))
                .collect();
            if our_outs.is_empty() || ext_outs.is_empty() {
                continue;
            }

            let mut problems = Vec::new();
            for change in &our_outs {
                let ch_sats = change.value.to_sat();
                let ch_round = ch_sats % 100_000 == 0 || ch_sats % 1_000_000 == 0;

                for payment in &ext_outs {
                    let pay_sats = payment.value.to_sat();
                    let pay_round = pay_sats % 100_000 == 0 || pay_sats % 1_000_000 == 0;

                    if pay_round && !ch_round {
                        problems.push(format!(
                            "Round payment ({} sats) vs non-round change ({} sats)",
                            pay_sats, ch_sats
                        ));
                    }

                    let in_types: HashSet<String> = our_in
                        .iter()
                        .map(|ia| self.script_type(&ia.address))
                        .collect();
                    let ch_type = self.script_type(&change.address);
                    if in_types.contains(&ch_type) && change.script_type != payment.script_type {
                        problems.push(format!(
                            "Change script type ({}) matches input type — different from payment ({})",
                            change.script_type, payment.script_type
                        ));
                    }

                    if let Some(meta) = self.addr_map.get(&change.address) {
                        if meta.internal {
                            problems.push(
                                "Change uses an internal (BIP-44 /1/*) derivation path".into(),
                            );
                        }
                    }
                }
            }

            if !problems.is_empty() {
                problems.truncate(6);
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ChangeDetection,
                    severity: Severity::Medium,
                    description: format!(
                        "TX {} has identifiable change output(s) ({} heuristic(s) matched)",
                        txid,
                        problems.len()
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "reasons": problems,
                    })),
                    correction: Some(
                        "Use PayJoin (BIP-78) so the receiver also contributes an input. \
                         Avoid sending round amounts so the change amount is not the obvious leftover."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 17. Toxic Change Detection ─────────────────────────────────────────
    //
    // Port of: am-i-exposed/src/lib/analysis/chain/forward.ts
    //
    // Detects when a small change output (< 10 000 sats) is later spent
    // alongside a larger UTXO, linking the two. "Toxic" change is the
    // non-round leftover from a payment that, when later consolidated,
    // reveals the connection between the payment transaction and the
    // user's larger holdings.

    pub(super) fn detect_toxic_change(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
    ) {
        let toxic_lower = thresholds.toxic_change_lower;
        let toxic_upper = thresholds.toxic_change_upper;

        let txids = self.ordered_txids();
        for txid in txids {
            let input_addrs = self.get_input_addresses(&txid);
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.is_empty() {
                continue;
            }

            let outputs = self.get_output_addresses(&txid);
            // Look for our outputs that are small "toxic change"
            for out in &outputs {
                if !self.is_ours(&out.address) {
                    continue;
                }
                if !(toxic_lower..=toxic_upper).contains(&out.value) {
                    continue;
                }
                let sats = out.value.to_sat();

                // Check if this toxic change was later spent alongside
                // a larger UTXO (the dangerous consolidation).
                let Some(child_txid) = self.spending_index.get(&(txid, out.index)).copied() else {
                    continue;
                };
                let child_inputs = self.get_input_addresses(&child_txid);
                if child_inputs.len() < 2 {
                    continue;
                }
                let has_larger = child_inputs
                    .iter()
                    .any(|ci| ci.value > toxic_upper && self.is_ours(&ci.address));
                if !has_larger {
                    continue;
                }

                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ToxicChange,
                    severity: Severity::High,
                    description: format!(
                        "Toxic change ({} sats) from TX {} was later merged with a larger \
                         UTXO in TX {}, linking both transactions",
                        sats, txid, child_txid
                    ),
                    details: Some(json!({
                        "source_txid": txid.to_string(),
                        "change_address": out.address.assume_checked_ref().to_string(),
                        "change_sats": sats,
                        "spending_txid": child_txid.to_string(),
                        "total_inputs_in_child": child_inputs.len(),
                    })),
                    correction: Some(
                        "Absorb tiny change into the miner fee (bump fee to consume it) \
                         or freeze small change outputs. Never consolidate small change \
                         with unrelated UTXOs."
                            .into(),
                    ),
                });
            }
        }
    }
}
