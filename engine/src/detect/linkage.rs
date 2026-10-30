//! Input-ownership and input/output linkage detectors.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::json;

use crate::config::DetectorThresholds;
use crate::graph::TxGraph;
use crate::types::*;

impl TxGraph {
    // ── 2. Common Input Ownership Heuristic (CIOH) ─────────────────────────

    pub(super) fn detect_cioh(&self, findings: &mut Vec<Finding>) {
        let txids = self.ordered_txids();
        for txid in &txids {
            let tx = match self.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };
            if tx.vin.len() < 2 {
                continue;
            }

            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.len() < 2 {
                continue;
            }

            let our_inputs: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_inputs.len() < 2 {
                continue;
            }

            let total_inputs = input_addrs.len();
            let n_ours = our_inputs.len();
            let ownership_pct = (n_ours as f64 / total_inputs as f64 * 100.0).round() as u32;

            let severity = if n_ours == total_inputs {
                Severity::Critical
            } else {
                Severity::High
            };

            findings.push(Finding {
                vulnerability_type: VulnerabilityType::Cioh,
                severity,
                description: format!(
                    "TX {} merges {}/{} of your inputs ({}% ownership)",
                    txid, n_ours, total_inputs, ownership_pct
                ),
                details: Some(json!({
                    "txid": txid,
                    "total_inputs": total_inputs,
                    "our_inputs": n_ours,
                    "ownership_pct": ownership_pct,
                })),
                correction: Some(
                    "Use coin control to select only one UTXO per transaction. \
                     If you are paying someone, prefer a Payjoin (BIP-78) payment: \
                     it merges inputs without revealing common ownership. \
                     If consolidation is unavoidable, do it privately via a CoinJoin round."
                        .into(),
                ),
            });
        }
    }

    // ── 8. Cluster Merge ───────────────────────────────────────────────────

    pub(super) fn detect_cluster_merge(&self, findings: &mut Vec<Finding>) {
        let txids = self.ordered_txids();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.len() < 2 {
                continue;
            }
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.len() < 2 {
                continue;
            }

            // Trace each input one hop back to find funding sources.
            let mut funding_sources: HashMap<String, HashSet<String>> = HashMap::new();
            for ia in &our_in {
                let parent_tx = match self.fetch_tx(&ia.funding_txid) {
                    Some(t) => t,
                    None => continue,
                };
                let mut gp_sources = HashSet::new();
                for p_vin in &parent_tx.vin {
                    if p_vin.coinbase {
                        gp_sources.insert("coinbase".into());
                    } else {
                        let ptxid = p_vin.previous_txid.to_string();
                        gp_sources.insert(ptxid[..16].to_string());
                    }
                }
                let ftxid = ia.funding_txid.to_string();
                let key = format!("{}:{}", &ftxid[..16], ia.funding_vout);
                funding_sources.insert(key, gp_sources);
            }

            let all_sources: Vec<&HashSet<String>> = funding_sources.values().collect();
            if all_sources.len() >= 2 {
                let mut merged = false;
                'outer: for i in 0..all_sources.len() {
                    for j in (i + 1)..all_sources.len() {
                        if all_sources[i].is_disjoint(all_sources[j]) {
                            merged = true;
                            break 'outer;
                        }
                    }
                }

                if merged {
                    findings.push(Finding {
                        vulnerability_type: VulnerabilityType::ClusterMerge,
                        severity: Severity::High,
                        description: format!(
                            "TX {} merges UTXOs from {} different funding chains",
                            txid,
                            funding_sources.len()
                        ),
                        details: Some(json!({
                            "txid": txid,
                            "funding_sources": funding_sources.iter()
                                .map(|(k, v)| {
                                    let mut sources: Vec<String> = v.iter().cloned().collect();
                                    sources.sort_unstable();
                                    (k.clone(), sources)
                                })
                                .collect::<BTreeMap<_, _>>(),
                        })),
                        correction: Some(
                            "Use coin control to spend UTXOs from only one funding source \
                             per transaction. Keep UTXOs received from different counterparties \
                             in separate wallets."
                                .into(),
                        ),
                    });
                }
            }
        }
    }

    // ── 15. Deterministic Link Detection ───────────────────────────────────
    //
    // Port of: am-i-exposed/src/lib/analysis/chain/linkability.ts
    //
    // For small transactions (≤4 inputs, ≤4 outputs) we enumerate all
    // valid input→output assignments to find deterministic links — cases
    // where a specific input can only map to one specific output (or
    // vice versa). This indicates zero ambiguity for that link.

    pub(super) fn detect_deterministic_links(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
        warnings: &mut Vec<Finding>,
    ) {
        let low_ambiguity_cutoff = thresholds.low_ambiguity_cutoff;
        let txids = self.ordered_txids();
        for txid in txids {
            let inputs = self.get_input_addresses(&txid);
            let outputs = self.get_output_addresses(&txid);

            if inputs.is_empty() || outputs.is_empty() || inputs.len() < 2 || outputs.len() < 2 {
                continue;
            }

            // Only our sends
            if !inputs.iter().any(|ia| self.is_ours(&ia.address)) {
                continue;
            }

            let n_in = inputs.len();
            let n_out = outputs.len();

            // Skip large transactions (too expensive to enumerate)
            if n_in > 4 || n_out > 4 {
                continue;
            }

            let in_sats: Vec<u64> = inputs.iter().map(|i| i.value.to_sat()).collect();
            let out_sats: Vec<u64> = outputs.iter().map(|o| o.value.to_sat()).collect();

            // Count how many times each input→output pair appears in valid
            // assignments (a valid assignment maps each input to one output
            // such that the assigned inputs can fund each output).
            let mut pair_count = vec![vec![0u64; n_out]; n_in];
            let mut total_valid: u64 = 0;

            // Enumerate all n_out^n_in assignments (≤ 4^4 = 256)
            let total_combos = (n_out as u64).pow(n_in as u32);
            for combo in 0..total_combos {
                let mut assignment = vec![0usize; n_in];
                let mut c = combo;
                for slot in assignment.iter_mut().take(n_in) {
                    *slot = (c % n_out as u64) as usize;
                    c /= n_out as u64;
                }

                // Check validity: each output must receive at least its value
                let mut output_funding = vec![0u64; n_out];
                for (i, &out_idx) in assignment.iter().enumerate() {
                    output_funding[out_idx] += in_sats[i];
                }
                let valid = output_funding
                    .iter()
                    .zip(out_sats.iter())
                    .all(|(&funded, &needed)| funded >= needed);
                if valid {
                    total_valid += 1;
                    for (i, &out_idx) in assignment.iter().enumerate() {
                        pair_count[i][out_idx] += 1;
                    }
                }
            }

            if total_valid == 0 {
                continue;
            }

            // A deterministic link exists when an input maps to the same
            // output in 100% of valid assignments (probability = 1.0).
            let mut det_links = Vec::new();
            for (i, row) in pair_count.iter().enumerate() {
                for (j, count) in row.iter().enumerate() {
                    if *count == total_valid {
                        det_links.push(json!({
                            "input_index": i,
                            "output_index": j,
                            "input_address": inputs[i].address.assume_checked_ref().to_string(),
                            "output_address": outputs[j].address.assume_checked_ref().to_string(),
                            "input_sats": in_sats[i],
                            "output_sats": out_sats[j],
                        }));
                    }
                }
            }

            // Compute average ambiguity
            let mut max_probs = Vec::new();
            for row in pair_count.iter().take(n_in) {
                let max_p = (0..n_out)
                    .map(|j| row[j] as f64 / total_valid as f64)
                    .fold(0.0f64, f64::max);
                max_probs.push(max_p);
            }
            let avg_max_prob: f64 = max_probs.iter().sum::<f64>() / max_probs.len() as f64;
            let ambiguity = 1.0 - avg_max_prob;

            if !det_links.is_empty() {
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::DeterministicLink,
                    severity: Severity::High,
                    description: format!(
                        "TX {} has {} deterministic input→output link(s) out of {} valid interpretations",
                        txid,
                        det_links.len(),
                        total_valid
                    ),
                    details: Some(json!({
                        "txid": txid.to_string(),
                        "deterministic_links": det_links,
                        "total_valid_interpretations": total_valid,
                        "ambiguity_pct": (ambiguity * 100.0).round() as u32,
                    })),
                    correction: Some(
                        "Create transactions where multiple valid input→output mappings exist. \
                         Use CoinJoin or PayJoin to increase ambiguity."
                            .into(),
                    ),
                });
            } else if ambiguity > 0.0 && ambiguity < low_ambiguity_cutoff {
                // No fully deterministic link, but ambiguity is low —
                // an analyst can guess the input→output mapping with
                // high confidence. Surface this as a warning (warnings
                // flag risks, not good privacy). High-ambiguity
                // transactions emit nothing.
                warnings.push(Finding {
                    vulnerability_type: VulnerabilityType::DeterministicLink,
                    severity: Severity::Low,
                    description: format!(
                        "TX {} has low ambiguity ({:.0}%, {} valid interpretations) — \
                         input→output mapping is largely guessable",
                        txid,
                        ambiguity * 100.0,
                        total_valid
                    ),
                    details: Some(json!({
                        "txid": txid.to_string(),
                        "total_valid_interpretations": total_valid,
                        "ambiguity_pct": (ambiguity * 100.0).round() as u32,
                    })),
                    correction: Some(
                        "Use CoinJoin or PayJoin to add valid alternative \
                         input→output assignments and raise the ambiguity."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 16. Unnecessary Input Detection ────────────────────────────────────
    //
    // Port of: am-i-exposed/src/lib/analysis/chain/spending-patterns.ts
    //
    // A transaction has an unnecessary input when any single input is
    // larger than the total output value (excluding change). This means
    // a smaller UTXO selection was possible — including extra inputs
    // needlessly links more addresses via CIOH.

    pub(super) fn detect_unnecessary_input(&self, findings: &mut Vec<Finding>) {
        let txids = self.ordered_txids();
        for txid in txids {
            let input_addrs = self.get_input_addresses(&txid);
            if input_addrs.len() < 2 {
                continue;
            }
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.len() < 2 {
                continue;
            }

            let outputs = self.get_output_addresses(&txid);
            let ext_total_sats: u64 = outputs
                .iter()
                .filter(|o| !self.is_ours(&o.address))
                .map(|o| o.value.to_sat())
                .sum();
            if ext_total_sats == 0 {
                continue;
            }

            let in_total_sats: u64 = input_addrs.iter().map(|i| i.value.to_sat()).sum();
            let out_total_sats: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
            let fee_sats = in_total_sats.saturating_sub(out_total_sats);
            let needed_sats = ext_total_sats + fee_sats;

            // Check if any single input could have funded the payment + fee
            let mut oversized_inputs = Vec::new();
            for ia in &our_in {
                if ia.value.to_sat() >= needed_sats {
                    oversized_inputs.push(ia);
                }
            }

            if !oversized_inputs.is_empty() && our_in.len() > 1 {
                let extra_count = our_in.len() - 1;
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::UnnecessaryInput,
                    severity: Severity::Medium,
                    description: format!(
                        "TX {} has {} unnecessary input(s): a single UTXO of {:.8} BTC \
                         could cover the {:.8} BTC payment + fee",
                        txid,
                        extra_count,
                        oversized_inputs[0].value.to_sat() as f64 / 1e8,
                        ext_total_sats as f64 / 1e8,
                    ),
                    details: Some(json!({
                        "txid": txid.to_string(),
                        "sufficient_input": {
                            "address": oversized_inputs[0].address.assume_checked_ref().to_string(),
                            "sats": oversized_inputs[0].value.to_sat(),
                        },
                        "total_inputs_used": input_addrs.len(),
                        "unnecessary_count": extra_count,
                        "payment_sats": ext_total_sats,
                        "fee_sats": fee_sats,
                    })),
                    correction: Some(
                        "Use coin control to select only the single sufficient UTXO. \
                         Adding extra inputs needlessly links more of your addresses \
                         via common-input-ownership."
                            .into(),
                    ),
                });
            }
        }
    }
}
