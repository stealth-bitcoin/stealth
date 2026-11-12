//! Dust reception and dust spending detectors.

use std::collections::HashSet;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, OutPoint, Txid};
use serde_json::json;

use crate::config::DetectorThresholds;
use crate::graph::TxGraph;
use crate::types::*;

impl TxGraph {
    // ── 3. Dust UTXO Detection ─────────────────────────────────────────────
    //
    // Also detects the dust-attack pattern (formerly a standalone detector). Every
    // dust-attack output is by definition a dust UTXO, so the two
    // detectors fire on the same data — we collapse them by escalating
    // severity and attaching attack evidence to the existing Dust finding
    // when the parent transaction matches the attack signature.

    pub(super) fn detect_dust(&self, thresholds: &DetectorThresholds, findings: &mut Vec<Finding>) {
        let dust = thresholds.dust;

        // Current UTXOs; a pasted one is spent when a confirmed tx in the
        // history spends it or the node says so, and otherwise stays as pasted.
        for utxo in &self.utxos {
            if !self.is_ours(&utxo.address) || utxo.amount > dust {
                continue;
            }
            let key = (utxo.txid, utxo.vout);
            let finding =
                if self.confirmed_spend(&key) || self.chain_unspent.get(&key) == Some(&false) {
                    let mut finding = self.spent_dust_finding(
                        &utxo.txid,
                        utxo.vout,
                        &utxo.address,
                        utxo.amount,
                        thresholds,
                    );
                    finding.description = format!(
                    "Dust output {}:{} at {} ({} sats) was pasted as unspent but is already spent",
                    utxo.txid,
                    utxo.vout,
                    utxo.address.assume_checked_ref(),
                    utxo.amount.to_sat(),
                );
                    finding
                } else {
                    self.unspent_dust_finding(
                        &utxo.txid,
                        utxo.vout,
                        &utxo.address,
                        utxo.amount,
                        thresholds,
                    )
                };
            findings.push(finding);
        }

        // Own dust outside the UTXO list: spent when a confirmed tx in the
        // history spends it, else the node's answer, else unknown.
        for (txid, out) in self.dust_outside_utxos(dust) {
            let key = (txid, out.index);
            let unspent = if self.confirmed_spend(&key) {
                Some(false)
            } else {
                self.chain_unspent.get(&key).copied()
            };
            let finding = match unspent {
                Some(true) => Self::unspent_dust_finding,
                Some(false) => Self::spent_dust_finding,
                None => Self::unknown_dust_finding,
            };
            findings.push(finding(
                self,
                &txid,
                out.index,
                &out.address,
                out.value,
                thresholds,
            ));
        }
    }

    /// A confirmed tx in the history spends this output; an unconfirmed one
    /// may still be replaced.
    fn confirmed_spend(&self, key: &(Txid, u32)) -> bool {
        self.spending_index
            .get(key)
            .and_then(|child| self.tx_cache.get(child))
            .is_some_and(|child| child.confirmations > 0)
    }

    /// Outpoints of own dust in the UTXO list that no confirmed tx in the
    /// history spends.
    pub(crate) fn listed_dust(&self, thresholds: &DetectorThresholds) -> Vec<OutPoint> {
        self.utxos
            .iter()
            .filter(|u| self.is_ours(&u.address) && u.amount <= thresholds.dust)
            .filter(|u| !self.confirmed_spend(&(u.txid, u.vout)))
            .map(|u| OutPoint::new(u.txid, u.vout))
            .collect()
    }

    /// Own outputs at or under `dust` that are not in the UTXO list, once each.
    fn dust_outside_utxos(&self, dust: Amount) -> Vec<(Txid, OutputInfo)> {
        let current_keys: HashSet<(Txid, u32)> =
            self.utxos.iter().map(|u| (u.txid, u.vout)).collect();
        let mut seen = HashSet::new();
        let mut found = Vec::new();
        for txid in self.ordered_txids() {
            for out in self.get_output_addresses(&txid) {
                let key = (txid, out.index);
                if out.value <= dust
                    && self.is_ours(&out.address)
                    && !current_keys.contains(&key)
                    && seen.insert(key)
                {
                    found.push((txid, out));
                }
            }
        }
        found
    }

    /// Outpoints of own dust outside the UTXO list whose spend the history
    /// does not show, or shows only in an unconfirmed (replaceable) tx.
    pub(crate) fn dust_needing_chain_status(
        &self,
        thresholds: &DetectorThresholds,
    ) -> Vec<OutPoint> {
        self.dust_outside_utxos(thresholds.dust)
            .into_iter()
            .filter(|(txid, out)| !self.confirmed_spend(&(*txid, out.index)))
            .map(|(txid, out)| OutPoint::new(txid, out.index))
            .collect()
    }

    fn unspent_dust_finding(
        &self,
        txid: &Txid,
        vout: u32,
        address: &Address<NetworkUnchecked>,
        amt: Amount,
        thresholds: &DetectorThresholds,
    ) -> Finding {
        let strict_dust = thresholds.strict_dust;
        let label = if amt <= strict_dust {
            "STRICT_DUST"
        } else {
            "dust-class"
        };
        let base_severity = if amt <= strict_dust {
            Severity::High
        } else {
            Severity::Medium
        };
        let attack = self.dust_attack_evidence(txid, thresholds);
        let severity = if attack.is_some() {
            Severity::Critical
        } else {
            base_severity
        };
        let mut details = json!({
            "status": "unspent",
            "address": address.assume_checked_ref().to_string(),
            "sats": amt.to_sat(),
            "label": label,
            "txid": txid,
            "vout": vout,
        });
        if let Some(ev) = attack.as_ref() {
            details["dust_attack"] = ev.clone();
        }
        let description = if attack.is_some() {
            format!(
                "Dust UTXO {}:{} at {} ({} sats, {}, unspent) — parent TX {} matches a dust-attack pattern",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                label,
                txid,
            )
        } else {
            format!(
                "Dust UTXO {}:{} at {} ({} sats, {}, unspent)",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                label,
            )
        };
        let correction = if attack.is_some() {
            "Do NOT spend this dust UTXO — spending it links your other addresses \
             to this one via common-input-ownership. Freeze it in your wallet immediately."
        } else {
            "Do not spend this dust output — doing so links your other addresses \
             to this one via CIOH. Use your wallet's coin freeze feature to \
             exclude it from future transactions."
        };
        Finding {
            vulnerability_type: VulnerabilityType::Dust,
            severity,
            description,
            details: Some(details),
            correction: Some(correction.into()),
        }
    }

    fn spent_dust_finding(
        &self,
        txid: &Txid,
        vout: u32,
        address: &Address<NetworkUnchecked>,
        amt: Amount,
        thresholds: &DetectorThresholds,
    ) -> Finding {
        let attack = self.dust_attack_evidence(txid, thresholds);
        let severity = if attack.is_some() {
            Severity::Critical
        } else {
            Severity::Low
        };
        let mut details = json!({
            "status": "spent",
            "address": address.assume_checked_ref().to_string(),
            "sats": amt.to_sat(),
            "txid": txid,
            "vout": vout,
        });
        if let Some(ev) = attack.as_ref() {
            details["dust_attack"] = ev.clone();
        }
        let description = if attack.is_some() {
            format!(
                "Historical dust output {}:{} at {} ({} sats, already spent) — parent TX {} matches a dust-attack pattern",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                txid,
            )
        } else {
            format!(
                "Historical dust output {}:{} at {} ({} sats, already spent)",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
            )
        };
        Finding {
            vulnerability_type: VulnerabilityType::Dust,
            severity,
            description,
            details: Some(details),
            correction: Some(
                "This dust has already been spent. Going forward, reject \
                 unsolicited dust by enabling automatic dust rejection."
                    .into(),
            ),
        }
    }

    fn unknown_dust_finding(
        &self,
        txid: &Txid,
        vout: u32,
        address: &Address<NetworkUnchecked>,
        amt: Amount,
        thresholds: &DetectorThresholds,
    ) -> Finding {
        let attack = self.dust_attack_evidence(txid, thresholds);
        let severity = if attack.is_some() {
            Severity::Critical
        } else {
            Severity::Low
        };
        let mut details = json!({
            "status": "unknown",
            "address": address.assume_checked_ref().to_string(),
            "sats": amt.to_sat(),
            "txid": txid,
            "vout": vout,
        });
        if let Some(ev) = attack.as_ref() {
            details["dust_attack"] = ev.clone();
        }
        let description = if attack.is_some() {
            format!(
                "Dust output {}:{} at {} ({} sats, spend status unknown) — parent TX {} matches a dust-attack pattern",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                txid,
            )
        } else {
            format!(
                "Dust output {}:{} at {} ({} sats, spend status unknown)",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
            )
        };
        Finding {
            vulnerability_type: VulnerabilityType::Dust,
            severity,
            description,
            details: Some(details),
            correction: Some(
                "Stealth could not confirm whether this output was spent. \
                 Check it in your wallet before relying on this entry."
                    .into(),
            ),
        }
    }

    /// If `parent_txid` matches the dust-attack signature (many outputs,
    /// many dust outputs, high address diversity, and not one of our own
    /// sends), judged on its outputs that do not pay back to its own input
    /// addresses, return a JSON evidence blob suitable for attaching to a
    /// Dust finding; otherwise return `None`.
    pub(super) fn dust_attack_evidence(
        &self,
        parent_txid: &Txid,
        thresholds: &DetectorThresholds,
    ) -> Option<serde_json::Value> {
        let min_outputs = thresholds.dust_attack_min_outputs;
        let min_dust_outputs = thresholds.dust_attack_min_dust_outputs;
        let dust_threshold = thresholds.strict_dust;
        let min_diversity = thresholds.dust_attack_diversity;

        // Dust-attack txs are received, not sent — skip our own sends.
        let inputs = self.get_input_addresses(parent_txid);
        if inputs.iter().any(|ia| self.is_ours(&ia.address)) {
            return None;
        }

        let outputs = self.recipient_outputs(parent_txid);
        if outputs.len() < min_outputs {
            return None;
        }
        let dust_outputs: Vec<_> = outputs
            .iter()
            .filter(|o| o.value <= dust_threshold)
            .collect();
        if dust_outputs.len() < min_dust_outputs {
            return None;
        }
        let unique_addrs: HashSet<String> = outputs
            .iter()
            .map(|o| o.address.assume_checked_ref().to_string())
            .collect();
        let diversity = unique_addrs.len() as f64 / outputs.len() as f64;
        if diversity < min_diversity {
            return None;
        }

        Some(json!({
            "parent_txid": parent_txid.to_string(),
            "total_outputs": outputs.len(),
            "dust_outputs": dust_outputs.len(),
            "unique_addresses": unique_addrs.len(),
            "diversity_ratio": (diversity * 100.0).round() as u32,
        }))
    }

    // ── 4. Dust Spent with Normal Inputs ───────────────────────────────────

    pub(super) fn detect_dust_spending(
        &self,
        thresholds: &DetectorThresholds,
        findings: &mut Vec<Finding>,
    ) {
        let dust = thresholds.dust;
        let normal_min = thresholds.normal_input_min;

        let txids = self.ordered_txids();
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
}
