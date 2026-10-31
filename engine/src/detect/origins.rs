//! Detectors for where UTXOs came from: consolidation, exchange, taint.

use std::collections::HashSet;

use bitcoin::{Amount, Txid};
use serde_json::json;

use crate::config::DetectorThresholds;
use crate::graph::TxGraph;
use crate::types::*;

impl TxGraph {
    // ── 6. Consolidation Origin ────────────────────────────────────────────
    pub(super) fn detect_consolidation_origin(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
        warnings: &mut Vec<Finding>,
    ) {
        let min_inputs = thresholds.consolidation_min_inputs;
        let max_outputs = thresholds.consolidation_max_outputs;

        for utxo in &self.utxos {
            if !self.is_ours(&utxo.address) {
                continue;
            }
            let parent = match self.fetch_tx(&utxo.txid) {
                Some(t) => t,
                None => continue,
            };
            let n_in = parent.vin.len();
            let n_out = parent.vout.len();
            if n_in < min_inputs || n_out > max_outputs {
                continue;
            }

            let resolved = self.get_input_addresses(&utxo.txid);
            let ours = resolved
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .count();
            // Only a funding tx missing from the cache is unknown; an addressless prevout is not ours.
            let spent: Vec<_> = parent.vin.iter().filter(|input| !input.coinbase).collect();
            let unresolved = spent
                .iter()
                .filter(|input| self.fetch_tx(&input.previous_txid).is_none())
                .count();
            let unrecognised = spent.len().saturating_sub(unresolved + ours);
            let details = json!({
                "txid": utxo.txid,
                "vout": utxo.vout,
                "amount_sats": utxo.amount.to_sat(),
                "consolidation_inputs": n_in,
                "consolidation_outputs": n_out,
                "our_inputs_in_consolidation": ours,
                "unrecognised_inputs": unrecognised,
                "unresolved_inputs": unresolved,
            });

            if ours >= 2 {
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::Consolidation,
                    severity: Severity::Medium,
                    description: format!(
                        "UTXO {}:{} ({:.8} BTC) born from a {}-input consolidation",
                        utxo.txid,
                        utxo.vout,
                        utxo.amount.to_btc(),
                        n_in
                    ),
                    details: Some(details),
                    correction: Some(
                        "Avoid consolidating many UTXOs into one in a single transaction. \
                         If fee savings require consolidation, do it through a CoinJoin, \
                         or consolidate opportunistically inside a Payjoin (BIP-78) payment \
                         so the merge looks like an ordinary spend."
                            .into(),
                    ),
                });
            } else {
                // Only the user's wallet pays its own change chain, so it likely built this merge.
                let on_change = self.addr_map.get(&utxo.address).is_some_and(|m| m.internal);
                if !(self.partial_ownership || unresolved > 0 || on_change) {
                    continue;
                }
                let coin = format!(
                    "UTXO {}:{} ({:.8} BTC)",
                    utxo.txid,
                    utxo.vout,
                    utxo.amount.to_btc()
                );
                let description = if on_change {
                    format!(
                        "{coin} sits on your change address, so your wallet likely built the \
                         {n_in}-input consolidation it came from; this scan recognises {ours} of \
                         its inputs as yours and cannot tell whose the others are (another \
                         account or script type?)"
                    )
                } else {
                    format!(
                        "{coin} came from a {n_in}-input consolidation; this scan recognises \
                         {ours} of its inputs as yours and cannot tell whose the others are"
                    )
                };
                warnings.push(Finding {
                    vulnerability_type: VulnerabilityType::Consolidation,
                    severity: Severity::Low,
                    description,
                    details: Some(details),
                    correction: Some(
                        "If these inputs were yours: avoid merging many coins in one \
                         transaction; consolidate through a CoinJoin, or inside a Payjoin \
                         (BIP-78) payment so the merge looks like an ordinary spend."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 10. Exchange Origin ────────────────────────────────────────────────

    pub(super) fn detect_exchange_origin(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
        known_exchange_txids: Option<&HashSet<Txid>>,
    ) {
        let batch_threshold = thresholds.exchange_batch_min_outputs;

        let txids = self.ordered_txids();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            let recipients = self.recipient_outputs(txid);
            let n_out = recipients.len();
            if n_out < batch_threshold {
                continue;
            }

            let our_inputs: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if !our_inputs.is_empty() {
                continue; // We're a sender, not a recipient.
            }

            let our_outputs: Vec<_> = self
                .get_output_addresses(txid)
                .into_iter()
                .filter(|o| self.is_ours(&o.address))
                .collect();
            if our_outputs.is_empty() {
                continue;
            }
            // Dust we received here is already reported as a dust attack.
            if our_outputs.iter().all(|o| o.value <= thresholds.dust)
                && self.dust_attack_evidence(txid, thresholds).is_some()
            {
                continue;
            }

            let mut signals = vec![format!("High output count: {}", n_out)];

            let unique_addr_count = recipients
                .iter()
                .map(|o| &o.address)
                .collect::<HashSet<_>>()
                .len();
            if unique_addr_count >= batch_threshold {
                signals.push(format!("{} unique recipient addresses", unique_addr_count));
            }

            // Input-value to median-output-value ratio heuristic.
            let total_input: Amount = input_addrs.iter().map(|ia| ia.value).sum();
            let mut output_values: Vec<u64> = recipients.iter().map(|o| o.value.to_sat()).collect();
            output_values.sort_unstable();
            if !output_values.is_empty() {
                let median = output_values[output_values.len() / 2];
                if median > 0 && total_input.to_sat() > 10 * median {
                    signals.push(format!(
                        "Input/median-output ratio: {}x (exchange-like fan-out)",
                        total_input.to_sat() / median
                    ));
                }
            }

            if let Some(exchange_txids) = known_exchange_txids {
                if exchange_txids.contains(txid) {
                    signals.push("TX matches known exchange wallet history".into());
                }
            }

            if signals.len() >= 2 {
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ExchangeOrigin,
                    severity: Severity::Medium,
                    description: format!(
                        "TX {} looks like an exchange batch withdrawal ({} signal(s))",
                        txid,
                        signals.len()
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "signals": signals,
                        "received_outputs": our_outputs.iter().map(|o| {
                            json!({"address": o.address.assume_checked_ref().to_string(), "sats": o.value.to_sat()})
                        }).collect::<Vec<_>>(),
                    })),
                    correction: Some(
                        "Withdraw via Lightning Network to avoid the exchange-origin fingerprint. \
                         After withdrawal, pass the UTXO through a CoinJoin."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 11. Tainted UTXOs ──────────────────────────────────────────────────

    pub(super) fn detect_tainted_utxos(
        &self,
        findings: &mut Vec<Finding>,
        warnings: &mut Vec<Finding>,
        known_risky_txids: Option<&HashSet<Txid>>,
    ) {
        let risky_txids = match known_risky_txids {
            Some(t) if !t.is_empty() => t,
            _ => return,
        };

        let txids = self.ordered_txids();

        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.is_empty() || input_addrs.len() < 2 {
                continue;
            }

            let tainted: Vec<_> = input_addrs
                .iter()
                .filter(|ia| risky_txids.contains(&ia.funding_txid))
                .collect();
            let clean: Vec<_> = input_addrs
                .iter()
                .filter(|ia| !risky_txids.contains(&ia.funding_txid))
                .collect();

            if !tainted.is_empty() && !clean.is_empty() {
                let taint_pct =
                    (tainted.len() as f64 / input_addrs.len() as f64 * 100.0).round() as u32;
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::TaintedUtxoMerge,
                    severity: Severity::High,
                    description: format!(
                        "TX {} merges {} tainted + {} clean inputs ({}% taint)",
                        txid,
                        tainted.len(),
                        clean.len(),
                        taint_pct
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "tainted_inputs": tainted.iter().map(|t| {
                            json!({"address": t.address.assume_checked_ref().to_string(), "sats": t.value.to_sat(), "source_txid": t.funding_txid})
                        }).collect::<Vec<_>>(),
                        "clean_inputs": clean.iter().map(|c| {
                            json!({"address": c.address.assume_checked_ref().to_string(), "sats": c.value.to_sat()})
                        }).collect::<Vec<_>>(),
                        "taint_pct": taint_pct,
                    })),
                    correction: Some(
                        "Freeze tainted UTXOs to prevent them from being spent alongside \
                         clean funds. Never merge inputs from known risky sources."
                            .into(),
                    ),
                });
            }
        }

        // Direct taint: we received directly from a risky source.
        for txid in &txids {
            if risky_txids.contains(txid) {
                let our_outs: Vec<_> = self
                    .get_output_addresses(txid)
                    .into_iter()
                    .filter(|o| self.is_ours(&o.address))
                    .collect();
                if !our_outs.is_empty() {
                    warnings.push(Finding {
                        vulnerability_type: VulnerabilityType::DirectTaint,
                        severity: Severity::High,
                        description: format!("TX {} is directly from a known risky source", txid),
                        details: Some(json!({
                            "txid": txid,
                            "received_outputs": our_outs.iter().map(|o| {
                                json!({"address": o.address.assume_checked_ref().to_string(), "sats": o.value.to_sat()})
                            }).collect::<Vec<_>>(),
                        })),
                        correction: None,
                    });
                }
            }
        }
    }
}
