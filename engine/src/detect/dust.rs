//! Dust reception and dust spending detectors.

use std::collections::HashSet;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, OutPoint, Txid};
use serde_json::json;

use super::list_addresses;
use crate::config::DetectorThresholds;
use crate::gateway::DecodedTransaction;
use crate::graph::TxGraph;
use crate::types::*;

/// How to get rid of a live dust coin without linking it, given after "freeze it".
const FEE_ONLY_SPEND: &str = "To get rid of it, spend it alone as fee: one coin per transaction, \
     with a single input and one 0-value OP_RETURN output carrying 4 bytes of data, sent when \
     mempool fee rates are low enough for it to confirm (a 546-sat coin pays about 6 to 7 sat/vB \
     from a native segwit or taproot address, about 5 from wrapped segwit and about 3 from \
     legacy). Send each one apart from the others, at different times and not in the same \
     block, since transactions of the same shape sent together can be grouped. If the coin \
     holds an ordinals inscription or runes, spending it as fee loses them: an ordinals \
     inscription goes to the miner and runes are burned; either way they are lost.";

/// Advice for small change of the user's own spend, given after the freeze advice.
const NEXT_TIME: &str =
    "Next time, let a remainder this small go to the fee instead of becoming a change output.";

/// Whose spend made a dust coin, from the inputs of its parent tx.
enum Origin {
    /// No input of the parent is the wallet's: someone sent it.
    Received,
    /// The parent spends the wallet's coins at these addresses: it is the user's change.
    OwnChange(Vec<String>),
    /// In a partial scan, the parent spends coins at these addresses, which the scan cannot
    /// attribute: it is the user's change if they are the user's, and is otherwise reported
    /// as received dust, since a sender's inputs are never the scanned address.
    PossiblyOwnChange(Vec<String>),
}

impl Origin {
    fn label(&self) -> &'static str {
        match self {
            Origin::Received => "received",
            Origin::OwnChange(_) => "own_change",
            Origin::PossiblyOwnChange(_) => "possibly_own_change",
        }
    }

    /// What the description calls the coin.
    fn noun(&self) -> &'static str {
        match self {
            Origin::OwnChange(_) => "change",
            _ => "dust",
        }
    }

    /// Adds the origin, and the parent's input addresses for change, to `details`.
    fn describe(&self, details: &mut serde_json::Value) {
        details["origin"] = json!(self.label());
        if let Origin::OwnChange(from) | Origin::PossiblyOwnChange(from) = self {
            details["parent_input_addresses"] = json!(from);
        }
    }

    /// The description's note on whose spend made the coin, in the present or past tense.
    fn note(&self, parent: &Txid, spent: bool) -> String {
        let (spends, is) = if spent {
            ("spent", "was")
        } else {
            ("spends", "is")
        };
        match self {
            Origin::Received => String::new(),
            Origin::OwnChange(from) => format!(
                "; it {is} small change of your own spend in TX {parent}, which {spends} your \
                 coins at {}",
                list_addresses(from)
            ),
            Origin::PossiblyOwnChange(_) => format!(
                "; if the inputs of TX {parent} are yours, this {is} small change of your own \
                 spend; it {is} already linked to that chain"
            ),
        }
    }
}

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

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
            if self.disposed_alone(&key) {
                continue;
            }
            let finding =
                if self.confirmed_spend(&key) || self.chain_unspent.get(&key) == Some(&false) {
                    let mut finding = self.spent_dust_finding(
                        &utxo.txid,
                        utxo.vout,
                        &utxo.address,
                        utxo.amount,
                        thresholds,
                    );
                    let attack = self.dust_attack_evidence(&utxo.txid, thresholds).is_some();
                    let origin = self.dust_origin(&utxo.txid, attack);
                    finding.description = format!(
                    "{} output {}:{} at {} ({} sats) was pasted as unspent but is already spent{}",
                    capitalized(origin.noun()),
                    utxo.txid,
                    utxo.vout,
                    utxo.address.assume_checked_ref(),
                    utxo.amount.to_sat(),
                    origin.note(&utxo.txid, true),
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
            if self.disposed_alone(&key) {
                continue;
            }
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
        self.confirmed_child(key).is_some()
    }

    /// The confirmed tx spending this output, if any.
    fn confirmed_child(&self, key: &(Txid, u32)) -> Option<&DecodedTransaction> {
        self.spending_index
            .get(key)
            .and_then(|child| self.tx_cache.get(child))
            .filter(|child| child.confirmations > 0)
    }

    /// A confirmed tx spends this output as its only input into nothing but 0-value
    /// outputs with no address (OP_RETURN): the fee-only spend, which links nothing.
    fn disposed_alone(&self, key: &(Txid, u32)) -> bool {
        self.confirmed_child(key).is_some_and(|child| {
            child.vin.len() == 1
                && child
                    .vout
                    .iter()
                    .all(|o| o.address.is_none() && o.value == Amount::ZERO)
        })
    }

    /// Every input of the confirmed tx spending this output is at `address`, and every output
    /// stays there or is a 0-value output with no address (OP_RETURN), so the spend tied no
    /// other address to it.
    fn spent_from_its_address_only(
        &self,
        key: &(Txid, u32),
        address: &Address<NetworkUnchecked>,
    ) -> bool {
        self.confirmed_child(key).is_some_and(|child| {
            let inputs = self.get_input_addresses(&child.txid);
            inputs.len() == child.vin.len()
                && inputs.iter().all(|i| i.address == *address)
                && child.vout.iter().all(|o| match &o.address {
                    Some(a) => a == address,
                    None => o.value == Amount::ZERO,
                })
        })
    }

    /// Whose spend made a dust coin of `parent`: the wallet's own when the parent spends any
    /// of its coins, possibly the wallet's when, in a partial scan, it spends coins the scan
    /// cannot attribute, and received otherwise. An attack-shaped parent is always received.
    fn dust_origin(&self, parent: &Txid, attack: bool) -> Origin {
        if attack {
            return Origin::Received;
        }
        let (mut own, mut unattributed) = (Vec::new(), Vec::new());
        for input in self.get_input_addresses(parent) {
            let list = if self.is_ours(&input.address) {
                &mut own
            } else if self.unattributed(parent, &input.address) {
                &mut unattributed
            } else {
                continue;
            };
            let text = input.address.assume_checked_ref().to_string();
            if !list.contains(&text) {
                list.push(text);
            }
        }
        if !own.is_empty() {
            Origin::OwnChange(own)
        } else if !unattributed.is_empty() {
            Origin::PossiblyOwnChange(unattributed)
        } else {
            Origin::Received
        }
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
        let origin = self.dust_origin(txid, attack.is_some());
        let severity = match origin {
            _ if attack.is_some() => Severity::Critical,
            // Change of inputs the scan cannot attribute may still be someone else's dust.
            Origin::Received | Origin::PossiblyOwnChange(_) => base_severity,
            Origin::OwnChange(_) => Severity::Low,
        };
        let mut details = json!({
            "status": "unspent",
            "address": address.assume_checked_ref().to_string(),
            "sats": amt.to_sat(),
            "label": label,
            "txid": txid,
            "vout": vout,
        });
        origin.describe(&mut details);
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
                "{} UTXO {}:{} at {} ({} sats, {}, unspent){}",
                capitalized(origin.noun()),
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                label,
                origin.note(txid, false),
            )
        };
        let correction = match &origin {
            Origin::OwnChange(_) => format!(
                "Freeze it in your wallet: as change of your own spend, it is already linked \
                 to the coins that spend came from, and spending it with coins of another \
                 origin links those to them as well. {FEE_ONLY_SPEND} {NEXT_TIME}"
            ),
            Origin::Received | Origin::PossiblyOwnChange(_) => format!(
                "Freeze it in your wallet: spending it with your other coins links your \
                 other addresses to this one. {FEE_ONLY_SPEND}"
            ),
        };
        Finding {
            vulnerability_type: VulnerabilityType::Dust,
            severity,
            description,
            details: Some(details),
            correction: Some(correction),
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
        let origin = self.dust_origin(txid, attack.is_some());
        let alone = self.spent_from_its_address_only(&(*txid, vout), address);
        let severity = if attack.is_some() && !alone {
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
        origin.describe(&mut details);
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
                "Historical {} output {}:{} at {} ({} sats, already spent){}",
                origin.noun(),
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                origin.note(txid, true),
            )
        };
        let correction = match (&origin, alone) {
            (Origin::OwnChange(_), true) => format!(
                "This change has already been spent with no coins from your other \
                 addresses, so it linked none of them to this one. {NEXT_TIME}"
            ),
            (Origin::OwnChange(_), false) => "This change has already been spent. From now \
                 on, freeze small change like this in your wallet's coin control so it is \
                 never spent with your other coins, and let a remainder this small go to the \
                 fee instead of becoming a change output."
                .into(),
            (_, true) => "This dust has already been spent with no coins from your other \
                 addresses, so it linked none of them to this one. Keep any other dust \
                 like it frozen in your wallet's coin control."
                .into(),
            (_, false) => "This dust has already been spent. From now on, freeze dust like \
                 this in your wallet's coin control so it is never spent with your other coins."
                .into(),
        };
        Finding {
            vulnerability_type: VulnerabilityType::Dust,
            severity,
            description,
            details: Some(details),
            correction: Some(correction),
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
        let origin = self.dust_origin(txid, attack.is_some());
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
        origin.describe(&mut details);
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
                "{} output {}:{} at {} ({} sats, spend status unknown){}",
                capitalized(origin.noun()),
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                origin.note(txid, false),
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
            let mut own_normal = false;
            for ia in &input_addrs {
                if !self.is_ours(&ia.address) {
                    // In a partial scan an unattributed coin may be the user's normal coin.
                    if ia.value > normal_min && self.unattributed(txid, &ia.address) {
                        normal_inputs.push(ia);
                    }
                    continue;
                }
                own_normal |= ia.value > normal_min;
                let amt = ia.value;
                if amt <= dust {
                    dust_inputs.push(ia);
                } else if amt > normal_min {
                    normal_inputs.push(ia);
                }
            }

            // Dust is newly tied only to addresses other than its own.
            let mut certain = false;
            let mut possible: Vec<String> = Vec::new();
            dust_inputs.retain(|d| {
                let (own, unattributed) = self.joined_addresses(txid, &d.address);
                certain |= !own.is_empty();
                for address in &unattributed {
                    if !possible.contains(address) {
                        possible.push(address.clone());
                    }
                }
                !own.is_empty() || !unattributed.is_empty()
            });
            if !dust_inputs.is_empty() && !normal_inputs.is_empty() {
                let mut description = format!(
                    "TX {} spends {} dust input(s) alongside {} normal input(s)",
                    txid,
                    dust_inputs.len(),
                    normal_inputs.len()
                );
                if !possible.is_empty() {
                    description.push_str(&format!(
                        "; this ties the dust to {}, if {} yours",
                        list_addresses(&possible),
                        if possible.len() == 1 {
                            "that address is"
                        } else {
                            "those addresses are"
                        }
                    ));
                }
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::DustSpending,
                    // A tie only to addresses the scan cannot attribute may not be the user's.
                    severity: if certain && own_normal {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    description,
                    details: Some(json!({
                        "txid": txid,
                        "possibly_joined_addresses": possible,
                        "dust_inputs": dust_inputs.iter().map(|d| {
                            json!({"address": d.address.assume_checked_ref().to_string(), "sats": d.value.to_sat()})
                        }).collect::<Vec<_>>(),
                        "normal_inputs": normal_inputs.iter().map(|n| {
                            json!({"address": n.address.assume_checked_ref().to_string(), "sats": n.value.to_sat()})
                        }).collect::<Vec<_>>(),
                    })),
                    correction: Some(
                        "Freeze dust like this in your wallet from now on, so it is never \
                         spent with your other coins again."
                            .into(),
                    ),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
