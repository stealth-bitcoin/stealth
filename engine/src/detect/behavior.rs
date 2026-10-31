//! Wallet behaviour detectors: script mixing, UTXO age, fingerprint, peel chain.

use std::collections::{HashMap, HashSet};

use bitcoin::{Amount, Txid};
use serde_json::json;

use crate::config::DetectorThresholds;
use crate::gateway::WalletTxCategory;
use crate::graph::TxGraph;
use crate::types::*;

impl TxGraph {
    // ── 7. Script Type Mixing ──────────────────────────────────────────────

    pub(super) fn detect_script_type_mixing(&self, findings: &mut Vec<Finding>) {
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

            let mut types: HashSet<String> = HashSet::new();
            for ia in &input_addrs {
                let t = self.script_type(&ia.address);
                if t != "unknown" {
                    types.insert(t);
                }
            }

            if types.len() >= 2 {
                let mut sorted: Vec<String> = types.into_iter().collect();
                sorted.sort();
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ScriptTypeMixing,
                    severity: Severity::High,
                    description: format!("TX {} mixes input script types: {:?}", txid, sorted),
                    details: Some(json!({
                        "txid": txid,
                        "script_types": sorted,
                    })),
                    correction: Some(
                        "Migrate all funds to a single address type — preferably Taproot (P2TR). \
                         Never mix P2PKH, P2SH, P2WPKH, P2WSH, and P2TR inputs in the same transaction. \
                         Taproot is also a prerequisite for receiving via Silent Payments."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 9. Lookback Depth / UTXO Age ───────────────────────────────────────

    pub(super) fn detect_lookback_depth(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
        warnings: &mut Vec<Finding>,
    ) {
        let our_utxos: Vec<_> = self
            .utxos
            .iter()
            .filter(|u| self.is_ours(&u.address))
            .cloned()
            .collect();
        if our_utxos.len() < 2 {
            return;
        }

        let mut aged: Vec<_> = our_utxos.iter().map(|u| (u, u.confirmations)).collect();
        aged.sort_by_key(|b| std::cmp::Reverse(b.1));

        let (Some(oldest), Some(newest)) = (aged.first(), aged.last()) else {
            return;
        };
        let spread = oldest.1 - newest.1;

        if spread < thresholds.utxo_age_spread_blocks {
            return;
        }

        findings.push(Finding {
            vulnerability_type: VulnerabilityType::UtxoAgeSpread,
            severity: Severity::Low,
            description: format!(
                "UTXO age spread of {} blocks between oldest and newest",
                spread
            ),
            details: Some(json!({
                "spread_blocks": spread,
                "oldest": {
                    "txid": oldest.0.txid,
                    "confirmations": oldest.1,
                    "amount_sats": oldest.0.amount.to_sat(),
                },
                "newest": {
                    "txid": newest.0.txid,
                    "confirmations": newest.1,
                    "amount_sats": newest.0.amount.to_sat(),
                },
            })),
            correction: Some(
                "Prefer spending older UTXOs first (FIFO coin selection) to normalize \
                 the age distribution of your UTXO set."
                    .into(),
            ),
        });

        let dormant_threshold = thresholds.dormant_utxo_blocks;
        let old_count = aged.iter().filter(|(_, c)| *c >= dormant_threshold).count();
        if old_count > 0 {
            warnings.push(Finding {
                vulnerability_type: VulnerabilityType::DormantUtxos,
                severity: Severity::Low,
                description: format!(
                    "{} UTXO(s) have ≥{} confirmations (dormant/hoarded coins pattern)",
                    old_count, dormant_threshold
                ),
                details: Some(json!({
                    "count": old_count,
                    "threshold_blocks": dormant_threshold,
                })),
                correction: None,
            });
        }
    }

    // ── 12. Behavioral Fingerprint ─────────────────────────────────────────

    pub(super) fn detect_behavioral_fingerprint(&self, findings: &mut Vec<Finding>) {
        // Collect send transactions. Prefer explicit wallet-side `send`
        // labels and fall back to ownership inferred from inputs.
        let txids = self.ordered_txids();
        let send_labeled_txids: HashSet<Txid> = self
            .addr_txs
            .values()
            .flatten()
            .filter(|entry| entry.category == WalletTxCategory::Send)
            .map(|entry| entry.txid)
            .collect();
        let mut send_txids = Vec::new();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            let has_our_input = input_addrs.iter().any(|ia| self.is_ours(&ia.address));
            if has_our_input || send_labeled_txids.contains(txid) {
                send_txids.push(*txid);
            }
        }

        if send_txids.len() < 3 {
            return;
        }

        let mut output_counts = Vec::new();
        let mut input_script_types = Vec::new();
        let mut rbf_signals = Vec::new();
        let mut locktime_values = Vec::new();
        let mut fee_rates: Vec<f64> = Vec::new();
        let mut uses_round_amounts: usize = 0;
        let mut total_payments: usize = 0;

        for txid in &send_txids {
            let tx = match self.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };

            output_counts.push(tx.vout.len());

            locktime_values.push(tx.locktime as u64);

            for vin in &tx.vin {
                rbf_signals.push(vin.sequence < 0xffff_fffe);
            }

            let input_addrs = self.get_input_addresses(txid);
            for ia in &input_addrs {
                if self.is_ours(&ia.address) {
                    input_script_types.push(self.script_type(&ia.address));
                }
            }

            let outputs = self.get_output_addresses(txid);
            for out in &outputs {
                if !self.is_ours(&out.address) {
                    let sats = out.value.to_sat();
                    total_payments += 1;
                    if sats > 0 && (sats % 100_000 == 0 || sats % 1_000_000 == 0) {
                        uses_round_amounts += 1;
                    }
                }
            }

            // Fee rate
            let vsize = tx.vsize as u64;
            if vsize > 0 {
                let in_total: Amount = input_addrs.iter().map(|ia| ia.value).sum();
                let out_total: Amount = tx.vout.iter().map(|o| o.value).sum();
                let fee_sats = in_total.to_sat().saturating_sub(out_total.to_sat());
                if fee_sats > 0 {
                    fee_rates.push(fee_sats as f64 / vsize as f64);
                }
            }
        }

        let mut problems = Vec::new();

        // Round amount pattern
        if total_payments > 0 {
            let round_pct = uses_round_amounts as f64 / total_payments as f64 * 100.0;
            if round_pct > 60.0 {
                problems.push(format!(
                    "Round payment amounts: {:.0}% of payments are round numbers.",
                    round_pct
                ));
            }
        }

        // Uniform output count
        if output_counts.len() >= 3 && output_counts.iter().all(|&c| c == output_counts[0]) {
            problems.push(format!(
                "Uniform output count: all {} send TXs have exactly {} outputs.",
                output_counts.len(),
                output_counts[0]
            ));
        }

        // Script type consistency
        let mut input_types: Vec<&String> = input_script_types
            .iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        input_types.sort_unstable();
        if input_types.len() > 1 {
            problems.push(format!(
                "Mixed input script types used across TXs: {:?}.",
                input_types
            ));
        }

        // RBF signaling
        if !rbf_signals.is_empty() {
            let rbf_pct = rbf_signals.iter().filter(|&&b| b).count() as f64
                / rbf_signals.len() as f64
                * 100.0;
            if rbf_pct == 100.0 {
                problems.push("RBF always enabled: 100% of inputs signal replace-by-fee.".into());
            } else if rbf_pct == 0.0 {
                problems.push("RBF never enabled: 0% of inputs signal replace-by-fee.".into());
            }
        }

        // Locktime pattern
        if locktime_values.len() >= 3 {
            let all_nonzero = locktime_values.iter().all(|&lt| lt > 0);
            let all_zero = locktime_values.iter().all(|&lt| lt == 0);
            if all_nonzero {
                problems.push(
                    "Anti-fee-sniping locktime always set — consistent with Bitcoin Core.".into(),
                );
            } else if all_zero {
                problems.push("Locktime always 0 — no anti-fee-sniping.".into());
            }
        }

        // Fee rate consistency
        if fee_rates.len() >= 3 {
            let avg: f64 = fee_rates.iter().sum::<f64>() / fee_rates.len() as f64;
            if avg > 0.0 {
                let variance: f64 = fee_rates.iter().map(|f| (f - avg).powi(2)).sum::<f64>()
                    / fee_rates.len() as f64;
                let stddev = variance.sqrt();
                let cv = stddev / avg;
                if cv < 0.15 {
                    problems.push(format!(
                        "Very consistent fee rate: avg {:.1} sat/vB ± {:.1} (CV={:.2}).",
                        avg, stddev, cv
                    ));
                }
            }
        }

        if problems.is_empty() {
            return;
        }

        findings.push(Finding {
            vulnerability_type: VulnerabilityType::BehavioralFingerprint,
            severity: Severity::Medium,
            description: format!(
                "Behavioral fingerprint detected across {} send transactions ({} pattern(s))",
                send_txids.len(),
                problems.len()
            ),
            details: Some(json!({
                "send_tx_count": send_txids.len(),
                "patterns": problems,
            })),
            correction: Some(
                "Switch to wallet software that applies anti-fingerprinting defaults. \
                 Avoid sending only round amounts — add small random satoshi offsets. \
                 Standardize on a single modern script type (Taproot)."
                    .into(),
            ),
        });
    }

    // ── 14. Peel Chain Detection ───────────────────────────────────────────
    //
    // Port of: am-i-exposed/src/lib/analysis/chain/forward.ts and
    //          peel-chain-trace.ts
    //
    // Detects peel-chain patterns: a sequence of transactions where one
    // output is "peeled off" as payment and the remaining change feeds
    // the next hop. Signature: 1-2 inputs, 2 outputs with highly
    // asymmetric values (ratio < 0.3).

    pub(super) fn detect_peel_chain(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
    ) {
        let ratio_cutoff = thresholds.peel_chain_ratio;
        let max_hops = thresholds.peel_chain_max_hops as usize;
        let min_hops = thresholds.peel_chain_min_hops as usize;
        let critical_hops = thresholds.peel_chain_critical_hops;

        // One pass: each peel-shaped tx's next hop (the peel spending its large
        // output), and whether a chain can start there.
        let txids = self.ordered_txids();
        let mut next: HashMap<Txid, Option<Txid>> = HashMap::new();
        let mut starts: Vec<(Txid, f64)> = Vec::new();
        for &txid in &txids {
            let outputs = self.get_output_addresses(&txid);
            if outputs.len() != 2 {
                continue;
            }
            let (small, large) = if outputs[0].value >= outputs[1].value {
                (&outputs[1], &outputs[0])
            } else {
                (&outputs[0], &outputs[1])
            };
            if large.value.to_sat() == 0 {
                continue;
            }
            let ratio = small.value.to_sat() as f64 / large.value.to_sat() as f64;
            if ratio >= ratio_cutoff {
                continue; // Outputs are too similar for a peel
            }
            next.insert(txid, self.spending_index.get(&(txid, large.index)).copied());

            let input_addrs = self.get_input_addresses(&txid);
            if input_addrs.len() > 2 {
                continue; // Peel chains have 1-2 inputs
            }
            if input_addrs.iter().any(|ia| self.is_ours(&ia.address)) {
                starts.push((txid, ratio));
            }
        }
        // A child that is not itself peel-shaped ends the chain.
        let step = |txid: &Txid| -> Option<Txid> {
            next.get(txid)
                .copied()
                .flatten()
                .filter(|child| next.contains_key(child))
        };

        // Txs reached from some start, the start itself only if a loop leads back.
        let mut covered: HashSet<Txid> = HashSet::new();
        for (start, _) in &starts {
            let mut cur = step(start);
            while let Some(t) = cur {
                if !covered.insert(t) {
                    break;
                }
                cur = step(&t);
            }
        }
        // Starts no other start reaches head their chain; a covered start that
        // no head reaches lies on a loop with no way in.
        let mut from_heads: HashSet<Txid> = HashSet::new();
        for (start, _) in starts.iter().filter(|(t, _)| !covered.contains(t)) {
            let mut cur = step(start);
            while let Some(t) = cur {
                if !from_heads.insert(t) {
                    break;
                }
                cur = step(&t);
            }
        }

        // Walk each head, and each loop once from its smallest start.
        let mut chains: Vec<(Vec<Txid>, bool, f64)> = Vec::new();
        let mut loop_done: HashSet<Txid> = HashSet::new();
        for &(start, ratio) in &starts {
            if covered.contains(&start) {
                if from_heads.contains(&start) || !loop_done.insert(start) {
                    continue;
                }
                let mut cur = step(&start);
                while let Some(t) = cur {
                    if !loop_done.insert(t) {
                        break;
                    }
                    cur = step(&t);
                }
            }
            let mut chain = vec![start];
            let mut seen = HashSet::from([start]);
            let mut truncated = false;
            let mut cur = step(&start);
            // Spends cannot form a cycle; the revisit check stops bad data.
            while let Some(t) = cur.filter(|t| seen.insert(*t)) {
                chain.push(t);
                cur = step(&t);
                if chain.len() > max_hops {
                    truncated = cur.is_some_and(|t| !seen.contains(&t));
                    break;
                }
            }
            if chain.len() >= min_hops {
                chains.push((chain, truncated, ratio));
            }
        }

        for (chain, truncated, ratio) in chains {
            let Some(&txid) = chain.first() else {
                continue;
            };
            let hops = u32::try_from(chain.len()).unwrap_or(u32::MAX);

            let mut details = json!({
                "start_txid": txid.to_string(),
                "hops": hops,
                "txids": chain.iter().map(Txid::to_string).collect::<Vec<_>>(),
                "initial_ratio": (ratio * 100.0).round() as u32,
            });
            if truncated {
                details["truncated"] = json!(true); // Only shown when the chain was cut.
            }

            let severity = if hops >= critical_hops {
                Severity::Critical
            } else {
                Severity::High
            };

            findings.push(Finding {
                vulnerability_type: VulnerabilityType::PeelChain,
                severity,
                description: format!(
                    "Peel chain detected from TX {}: {}{} hops of asymmetric 2-output transactions",
                    txid,
                    if truncated { "at least " } else { "" },
                    hops
                ),
                details: Some(details),
                correction: Some(
                    "Avoid sending sequential transactions from the change output. \
                     Use PayJoin or CoinJoin between sends. Send the exact UTXO \
                     amount when possible to avoid leaving trackable change."
                        .into(),
                ),
            });
        }
    }
}
