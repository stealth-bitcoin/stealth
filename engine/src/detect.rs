use std::collections::{HashMap, HashSet};

use bitcoin::{Amount, Txid};
use serde_json::json;

use crate::config::DetectorThresholds;
use crate::gateway::WalletTxCategory;
use crate::graph::TxGraph;
use crate::types::*;

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
        self.detect_consolidation_origin(thresholds, &mut findings);
        self.detect_script_type_mixing(&mut findings);
        self.detect_cluster_merge(&mut findings);
        self.detect_lookback_depth(thresholds, &mut findings, &mut warnings);
        self.detect_exchange_origin(thresholds, &mut findings, known_exchange_txids);
        self.detect_tainted_utxos(&mut findings, &mut warnings, known_risky_txids);
        self.detect_behavioral_fingerprint(&mut findings);
        self.detect_dust_attack(&mut findings);
        self.detect_peel_chain(&mut findings);
        self.detect_deterministic_links(&mut findings, &mut warnings);
        self.detect_unnecessary_input(&mut findings);
        self.detect_toxic_change(&mut findings);

        let stats = Stats {
            transactions_analyzed: self.our_txids.len(),
            addresses_seen: self.addr_map.len(),
            utxos_current: self.utxos.len(),
        };

        Report::new(stats, findings, warnings)
    }

    // ── 1. Address Reuse ───────────────────────────────────────────────────

    fn detect_address_reuse(&self, findings: &mut Vec<Finding>) {
        for addr in &self.our_addrs {
            let entries = match self.addr_txs.get(addr) {
                Some(e) => e,
                None => continue,
            };
            let receive_txids: HashSet<Txid> = entries
                .iter()
                .filter(|e| e.category == WalletTxCategory::Receive)
                .map(|e| e.txid)
                .collect();

            if receive_txids.len() >= 2 {
                let meta = self.addr_map.get(addr);
                let role = if meta.is_some_and(|m: &AddressInfo| m.internal) {
                    "change"
                } else {
                    "receive"
                };
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::AddressReuse,
                    severity: Severity::High,
                    description: format!(
                        "Address {} ({}) reused across {} transactions",
                        addr.assume_checked_ref(),
                        role,
                        receive_txids.len()
                    ),
                    details: Some(json!({
                        "address": addr.assume_checked_ref().to_string(),
                        "role": role,
                        "tx_count": receive_txids.len(),
                        "txids": receive_txids.iter().collect::<Vec<_>>(),
                    })),
                    correction: Some(
                        "Generate a fresh address for every payment received. \
                         Enable HD wallet derivation (BIP-32/44/84) so your wallet \
                         produces a new address automatically."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 2. Common Input Ownership Heuristic (CIOH) ─────────────────────────

    fn detect_cioh(&self, findings: &mut Vec<Finding>) {
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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
                     If consolidation is unavoidable, do it privately via a CoinJoin round."
                        .into(),
                ),
            });
        }
    }

    // ── 3. Dust UTXO Detection ─────────────────────────────────────────────

    fn detect_dust(&self, thresholds: &DetectorThresholds, findings: &mut Vec<Finding>) {
        let dust = thresholds.dust;
        let strict_dust = thresholds.strict_dust;

        // Current UTXOs
        for utxo in &self.utxos {
            if !self.is_ours(&utxo.address) {
                continue;
            }
            let amt = utxo.amount;
            if amt <= dust {
                let label = if amt <= strict_dust {
                    "STRICT_DUST"
                } else {
                    "dust-class"
                };
                let severity = if amt <= strict_dust {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::Dust,
                    severity,
                    description: format!(
                        "Dust UTXO at {} ({} sats, {}, unspent)",
                        utxo.address.assume_checked_ref(),
                        amt.to_sat(),
                        label
                    ),
                    details: Some(json!({
                        "status": "unspent",
                        "address": utxo.address.assume_checked_ref().to_string(),
                        "sats": amt.to_sat(),
                        "label": label,
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                    })),
                    correction: Some(
                        "Do not spend this dust output — doing so links your other inputs \
                         to this address via CIOH. Use your wallet's coin freeze feature to \
                         exclude it from future transactions."
                            .into(),
                    ),
                });
            }
        }

        // Historical dust (already spent)
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
        let current_keys: HashSet<(Txid, String)> = self
            .utxos
            .iter()
            .map(|u| (u.txid, u.address.assume_checked_ref().to_string()))
            .collect();
        let mut seen = HashSet::new();
        for txid in &txids {
            let outputs = self.get_output_addresses(txid);
            for out in &outputs {
                let amt = out.value;
                if amt <= dust && self.is_ours(&out.address) {
                    let key = (*txid, out.address.assume_checked_ref().to_string());
                    if !current_keys.contains(&key) && seen.insert(key) {
                        findings.push(Finding {
                            vulnerability_type: VulnerabilityType::Dust,
                            severity: Severity::Low,
                            description: format!(
                                "Historical dust output at {} ({} sats, already spent)",
                                out.address.assume_checked_ref(),
                                amt.to_sat()
                            ),
                            details: Some(json!({
                                "status": "spent",
                                "address": out.address.assume_checked_ref().to_string(),
                                "sats": amt.to_sat(),
                                "txid": txid,
                            })),
                            correction: Some(
                                "This dust has already been spent. Going forward, reject \
                                 unsolicited dust by enabling automatic dust rejection."
                                    .into(),
                            ),
                        });
                    }
                }
            }
        }
    }

    // ── 4. Dust Spent with Normal Inputs ───────────────────────────────────

    fn detect_dust_spending(&self, thresholds: &DetectorThresholds, findings: &mut Vec<Finding>) {
        let dust = thresholds.dust;
        let normal_min = thresholds.normal_input_min;

        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.len() < 2 {
                continue;
            }

            let mut dust_inputs = Vec::new();
            let mut normal_inputs = Vec::new();
            for ia in &input_addrs {
                if !self.is_ours(&ia.address) {
                    continue;
                }
                let amt = ia.value;
                if amt <= dust {
                    dust_inputs.push(ia);
                } else if amt > normal_min {
                    normal_inputs.push(ia);
                }
            }

            if !dust_inputs.is_empty() && !normal_inputs.is_empty() {
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::DustSpending,
                    severity: Severity::High,
                    description: format!(
                        "TX {} spends {} dust input(s) alongside {} normal input(s)",
                        txid,
                        dust_inputs.len(),
                        normal_inputs.len()
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "dust_inputs": dust_inputs.iter().map(|d| {
                            json!({"address": d.address.assume_checked_ref().to_string(), "sats": d.value.to_sat()})
                        }).collect::<Vec<_>>(),
                        "normal_inputs": normal_inputs.iter().map(|n| {
                            json!({"address": n.address.assume_checked_ref().to_string(), "sats": n.value.to_sat()})
                        }).collect::<Vec<_>>(),
                    })),
                    correction: Some(
                        "Freeze dust UTXOs in your wallet to prevent them from being \
                         automatically selected as inputs."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 5. Change Detection ────────────────────────────────────────────────

    fn detect_change_detection(&self, findings: &mut Vec<Finding>) {
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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

    // ── 6. Consolidation Origin ────────────────────────────────────────────
    fn detect_consolidation_origin(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
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

            if n_in >= min_inputs && n_out <= max_outputs {
                let parent_inputs = self.get_input_addresses(&utxo.txid);
                let our_parent_in = parent_inputs
                    .iter()
                    .filter(|ia| self.is_ours(&ia.address))
                    .count();

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
                    details: Some(json!({
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                        "amount_sats": utxo.amount.to_sat(),
                        "consolidation_inputs": n_in,
                        "consolidation_outputs": n_out,
                        "our_inputs_in_consolidation": our_parent_in,
                    })),
                    correction: Some(
                        "Avoid consolidating many UTXOs into one in a single transaction. \
                         If fee savings require consolidation, do it through a CoinJoin."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 7. Script Type Mixing ──────────────────────────────────────────────

    fn detect_script_type_mixing(&self, findings: &mut Vec<Finding>) {
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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
                         Never mix P2PKH, P2SH, P2WPKH, P2WSH, and P2TR inputs in the same transaction."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 8. Cluster Merge ───────────────────────────────────────────────────

    fn detect_cluster_merge(&self, findings: &mut Vec<Finding>) {
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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
                                .map(|(k, v)| (k.clone(), v.iter().cloned().collect::<Vec<_>>()))
                                .collect::<HashMap<_, _>>(),
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

    // ── 9. Lookback Depth / UTXO Age ───────────────────────────────────────

    fn detect_lookback_depth(
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
        aged.sort_by(|a, b| b.1.cmp(&a.1));

        let oldest = aged.first().unwrap();
        let newest = aged.last().unwrap();
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

    // ── 10. Exchange Origin ────────────────────────────────────────────────

    fn detect_exchange_origin(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
        known_exchange_txids: Option<&HashSet<Txid>>,
    ) {
        let batch_threshold = thresholds.exchange_batch_min_outputs;

        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
        for txid in &txids {
            let tx = match self.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };
            let n_out = tx.vout.len();
            if n_out < batch_threshold {
                continue;
            }

            let input_addrs = self.get_input_addresses(txid);
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

            let mut signals = vec![format!("High output count: {}", n_out)];

            let unique_addr_count = tx
                .vout
                .iter()
                .filter_map(|o| o.address.as_ref())
                .collect::<HashSet<_>>()
                .len();
            if unique_addr_count >= batch_threshold {
                signals.push(format!("{} unique recipient addresses", unique_addr_count));
            }

            // Input-value to median-output-value ratio heuristic.
            let total_input: Amount = input_addrs.iter().map(|ia| ia.value).sum();
            let mut output_values: Vec<u64> = tx.vout.iter().map(|o| o.value.to_sat()).collect();
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

    fn detect_tainted_utxos(
        &self,
        findings: &mut Vec<Finding>,
        warnings: &mut Vec<Finding>,
        known_risky_txids: Option<&HashSet<Txid>>,
    ) {
        let risky_txids = match known_risky_txids {
            Some(t) if !t.is_empty() => t,
            _ => return,
        };

        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();

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

    // ── 12. Behavioral Fingerprint ─────────────────────────────────────────

    fn detect_behavioral_fingerprint(&self, findings: &mut Vec<Finding>) {
        // Collect send transactions. Prefer explicit wallet-side `send`
        // labels and fall back to ownership inferred from inputs.
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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
        let input_types_set: HashSet<&String> = input_script_types.iter().collect();
        if input_types_set.len() > 1 {
            problems.push(format!(
                "Mixed input script types used across TXs: {:?}.",
                input_types_set
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

    // ── 13. Dust Attack Detection ──────────────────────────────────────────
    //
    // Port of: am-i-exposed/src/lib/analysis/chain/backward.ts
    //
    // Detects when our wallet received a tiny UTXO from a probable dust
    // attack transaction. A dust attack parent typically has ≥10 outputs,
    // ≥5 of which are ≤ 546 sats, distributed to many distinct addresses.

    fn detect_dust_attack(&self, findings: &mut Vec<Finding>) {
        const MIN_OUTPUTS: usize = 10;
        const DUST_THRESHOLD: u64 = 546;
        const MIN_DUST_OUTPUTS: usize = 5;

        // Check receiving transactions only (we didn't create them).
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
        for txid in txids {
            let input_addrs = self.get_input_addresses(&txid);
            let has_our_inputs = input_addrs.iter().any(|ia| self.is_ours(&ia.address));
            if has_our_inputs {
                continue; // Skip our own sends
            }

            let outputs = self.get_output_addresses(&txid);
            if outputs.len() < MIN_OUTPUTS {
                continue;
            }

            let dust_outputs: Vec<_> = outputs
                .iter()
                .filter(|o| o.value.to_sat() <= DUST_THRESHOLD)
                .collect();
            if dust_outputs.len() < MIN_DUST_OUTPUTS {
                continue;
            }

            let unique_addrs: HashSet<String> = outputs
                .iter()
                .map(|o| o.address.assume_checked_ref().to_string())
                .collect();
            let diversity = unique_addrs.len() as f64 / outputs.len() as f64;
            if diversity < 0.8 {
                continue;
            }

            // Our wallet received from this dust attack tx
            let our_outs: Vec<_> = outputs
                .iter()
                .filter(|o| self.is_ours(&o.address))
                .collect();
            if our_outs.is_empty() {
                continue;
            }

            findings.push(Finding {
                vulnerability_type: VulnerabilityType::DustAttack,
                severity: Severity::Critical,
                description: format!(
                    "TX {} is a likely dust attack: {} outputs, {} of which are ≤{} sats, \
                     targeting {} unique addresses",
                    txid,
                    outputs.len(),
                    dust_outputs.len(),
                    DUST_THRESHOLD,
                    unique_addrs.len()
                ),
                details: Some(json!({
                    "txid": txid.to_string(),
                    "total_outputs": outputs.len(),
                    "dust_outputs": dust_outputs.len(),
                    "unique_addresses": unique_addrs.len(),
                    "diversity_ratio": (diversity * 100.0).round() as u32,
                    "our_received": our_outs.iter().map(|o| {
                        json!({
                            "address": o.address.assume_checked_ref().to_string(),
                            "sats": o.value.to_sat()
                        })
                    }).collect::<Vec<_>>(),
                })),
                correction: Some(
                    "Do NOT spend this dust UTXO — spending it reveals your other UTXOs \
                     via common-input-ownership. Freeze it in your wallet immediately."
                        .into(),
                ),
            });
        }
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

    fn detect_peel_chain(&self, findings: &mut Vec<Finding>) {
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
        for txid in txids {
            let input_addrs = self.get_input_addresses(&txid);
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.is_empty() {
                continue;
            }
            if input_addrs.len() > 2 {
                continue; // Peel chains have 1-2 inputs
            }

            let outputs = self.get_output_addresses(&txid);
            if outputs.len() != 2 {
                continue;
            }

            let mut values: Vec<u64> = outputs.iter().map(|o| o.value.to_sat()).collect();
            values.sort_unstable();
            let small = values[0];
            let large = values[1];
            if large == 0 {
                continue;
            }
            let ratio = small as f64 / large as f64;
            if ratio >= 0.3 {
                continue; // Outputs are too similar for a peel
            }

            // Trace forward: does the "large" output feed into another
            // 2-output transaction? If so, count the chain length.
            let mut hops = 1u32;
            let large_idx = if outputs[0].value.to_sat() >= outputs[1].value.to_sat() {
                0
            } else {
                1
            };
            let mut trace_txid = txid;
            let mut trace_vout = outputs[large_idx].index;
            let max_hops = 6;

            while hops < max_hops {
                // Find the child transaction that spends trace_txid:trace_vout
                let child_txid = self.find_spending_tx(&trace_txid, trace_vout);
                let child_txid = match child_txid {
                    Some(t) => t,
                    None => break,
                };
                let child_outs = self.get_output_addresses(&child_txid);
                if child_outs.len() != 2 {
                    break;
                }
                let mut cv: Vec<u64> = child_outs.iter().map(|o| o.value.to_sat()).collect();
                cv.sort_unstable();
                if cv[1] == 0 || cv[0] as f64 / cv[1] as f64 >= 0.3 {
                    break;
                }
                hops += 1;
                let large_child = if child_outs[0].value.to_sat() >= child_outs[1].value.to_sat() {
                    0
                } else {
                    1
                };
                trace_txid = child_txid;
                trace_vout = child_outs[large_child].index;
            }

            if hops < 2 {
                continue; // At least 2 hops to qualify
            }

            let severity = if hops >= 4 {
                Severity::Critical
            } else {
                Severity::High
            };

            findings.push(Finding {
                vulnerability_type: VulnerabilityType::PeelChain,
                severity,
                description: format!(
                    "Peel chain detected from TX {}: {} hops of asymmetric 2-output transactions",
                    txid, hops
                ),
                details: Some(json!({
                    "start_txid": txid.to_string(),
                    "hops": hops,
                    "initial_ratio": (ratio * 100.0).round() as u32,
                })),
                correction: Some(
                    "Avoid sending sequential transactions from the change output. \
                     Use PayJoin or CoinJoin between sends. Send the exact UTXO \
                     amount when possible to avoid leaving trackable change."
                        .into(),
                ),
            });
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

    fn detect_deterministic_links(&self, findings: &mut Vec<Finding>, warnings: &mut Vec<Finding>) {
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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
            } else if ambiguity >= 0.6 {
                warnings.push(Finding {
                    vulnerability_type: VulnerabilityType::DeterministicLink,
                    severity: Severity::Low,
                    description: format!(
                        "TX {} has good ambiguity ({:.0}%, {} valid interpretations)",
                        txid,
                        ambiguity * 100.0,
                        total_valid
                    ),
                    details: Some(json!({
                        "txid": txid.to_string(),
                        "total_valid_interpretations": total_valid,
                        "ambiguity_pct": (ambiguity * 100.0).round() as u32,
                    })),
                    correction: None,
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

    fn detect_unnecessary_input(&self, findings: &mut Vec<Finding>) {
        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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

    // ── 17. Toxic Change Detection ─────────────────────────────────────────
    //
    // Port of: am-i-exposed/src/lib/analysis/chain/forward.ts
    //
    // Detects when a small change output (< 10 000 sats) is later spent
    // alongside a larger UTXO, linking the two. "Toxic" change is the
    // non-round leftover from a payment that, when later consolidated,
    // reveals the connection between the payment transaction and the
    // user's larger holdings.

    fn detect_toxic_change(&self, findings: &mut Vec<Finding>) {
        const TOXIC_UPPER: u64 = 10_000;
        const DUST_LOWER: u64 = 546;

        let txids: Vec<Txid> = self.our_txids.iter().copied().collect();
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
                let sats = out.value.to_sat();
                if !(DUST_LOWER..=TOXIC_UPPER).contains(&sats) {
                    continue;
                }

                // Check if this toxic change was later spent alongside
                // a larger UTXO (the dangerous consolidation).
                let child_txid = self.find_spending_tx(&txid, out.index);
                let child_txid = match child_txid {
                    Some(t) => t,
                    None => continue,
                };
                let child_inputs = self.get_input_addresses(&child_txid);
                if child_inputs.len() < 2 {
                    continue;
                }
                let has_larger = child_inputs
                    .iter()
                    .any(|ci| ci.value.to_sat() > TOXIC_UPPER && self.is_ours(&ci.address));
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

    fn find_spending_tx(&self, source_txid: &Txid, source_vout: u32) -> Option<Txid> {
        for txid in &self.our_txids {
            if let Some(tx) = self.fetch_tx(txid) {
                let spends_outpoint = tx.vin.iter().any(|vin| {
                    vin.previous_txid == *source_txid && vin.previous_vout == source_vout
                });
                if spends_outpoint {
                    return Some(*txid);
                }
            }
        }
        None
    }
}
