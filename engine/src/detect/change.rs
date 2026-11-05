//! Change identification and toxic change detectors.

use std::collections::HashSet;

use serde_json::json;

use crate::config::DetectorThresholds;
use crate::graph::TxGraph;
use crate::types::*;

const MAX_CHANGE_REASONS: usize = 6;

/// Keeps at most `cap` reasons, the first of each heuristic before any other, in first-found order.
fn cap_reasons(problems: Vec<(&'static str, String)>, cap: usize) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let firsts: Vec<bool> = problems.iter().map(|(h, _)| seen.insert(h)).collect();
    let mut keep: Vec<bool> = firsts.iter().map(|_| false).collect();
    let mut room = cap;
    for pass_firsts in [true, false] {
        for (i, first) in firsts.iter().enumerate() {
            if room > 0 && *first == pass_firsts && !keep[i] {
                keep[i] = true;
                room -= 1;
            }
        }
    }
    problems
        .into_iter()
        .zip(keep)
        .filter_map(|((_, reason), kept)| kept.then_some(reason))
        .collect()
}

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

            let in_types: HashSet<String> = our_in
                .iter()
                .map(|ia| self.script_type(&ia.address))
                .collect();
            let mut problems: Vec<(&'static str, String)> = Vec::new();
            let mut matched: HashSet<&str> = HashSet::new();
            // Each heuristic counts once per transaction, and each reason is listed once.
            let mut note = |heuristic: &'static str, reason: String| {
                matched.insert(heuristic);
                if !problems.iter().any(|(_, r)| *r == reason) {
                    problems.push((heuristic, reason));
                }
            };
            for change in &our_outs {
                let ch_sats = change.value.to_sat();
                let ch_round = ch_sats % 100_000 == 0 || ch_sats % 1_000_000 == 0;
                let ch_type = self.script_type(&change.address);

                for payment in &ext_outs {
                    let pay_sats = payment.value.to_sat();
                    let pay_round = pay_sats % 100_000 == 0 || pay_sats % 1_000_000 == 0;

                    if pay_round && !ch_round {
                        note(
                            "round_amount",
                            format!(
                                "Round payment ({} sats) vs non-round change ({} sats)",
                                pay_sats, ch_sats
                            ),
                        );
                    }

                    if in_types.contains(&ch_type) && change.script_type != payment.script_type {
                        note(
                            "script_type",
                            format!(
                                "Change script type ({}) matches input type — different from payment ({})",
                                change.script_type, payment.script_type
                            ),
                        );
                    }

                    if let Some(meta) = self.addr_map.get(&change.address) {
                        if meta.internal {
                            note(
                                "derivation_path",
                                "Change uses an internal (BIP-44 /1/*) derivation path".into(),
                            );
                        }
                    }
                }
            }

            if !problems.is_empty() {
                let problems = cap_reasons(problems, MAX_CHANGE_REASONS);
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ChangeDetection,
                    severity: Severity::Medium,
                    description: format!(
                        "TX {} has identifiable change output(s) ({} heuristic(s) matched)",
                        txid,
                        matched.len()
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

#[cfg(test)]
mod tests;
