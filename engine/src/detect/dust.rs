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

/// Advice for small change of the user's own spend, given after the freeze advice. The
/// output may be the one the spend meant to make, such as inscription postage.
const NEXT_TIME: &str = "If it is a remainder, next time let a remainder this small go to the \
     fee, or leave it in the payment instead of splitting it off as change; if it carries an \
     inscription or runes, or is a CoinJoin output, keep it as its own coin.";

/// Most own hops of dust alone walked back to find where moved dust came from.
const MAX_DUST_HOPS: usize = 16;

/// Whose spend made a dust coin, from the inputs of its parent tx, or of the tx the dust it
/// was moved from came out of.
enum Origin {
    /// Someone sent it: no normal coin of the wallet paid for it.
    Received,
    /// The spend spends a normal coin of the wallet: it is the user's change.
    OwnChange(Spend),
    /// In a partial scan, the spend spends coins the scan cannot attribute: it is the user's
    /// change if they are the user's, and is otherwise reported as received dust, since a
    /// sender's inputs are never the scanned address.
    PossiblyOwnChange(Spend),
}

/// The spend that made a coin the user's change, or possibly theirs.
struct Spend {
    txid: Txid,
    /// Addresses of the spend's inputs that make it the user's, or possibly theirs.
    from: Vec<String>,
    /// When the coin was moved from an output of the spend, the own input addresses of the
    /// coin's own parent.
    moved_by: Option<Vec<String>>,
}

impl Origin {
    fn label(&self) -> &'static str {
        match self {
            Origin::Received => "received",
            Origin::OwnChange(..) => "own_change",
            Origin::PossiblyOwnChange(..) => "possibly_own_change",
        }
    }

    /// What the description calls the coin.
    fn noun(&self) -> &'static str {
        match self {
            Origin::OwnChange(..) => "change",
            _ => "dust",
        }
    }

    /// Adds the origin, and the parent's input addresses for change, to `details`.
    fn describe(&self, details: &mut serde_json::Value) {
        details["origin"] = json!(self.label());
        if let Origin::OwnChange(spend) | Origin::PossiblyOwnChange(spend) = self {
            match &spend.moved_by {
                Some(parent_inputs) => {
                    details["parent_input_addresses"] = json!(parent_inputs);
                    details["source_txid"] = json!(spend.txid);
                }
                None => details["parent_input_addresses"] = json!(spend.from),
            }
        }
    }

    /// The description's note on whose spend made the coin, in the present or past tense.
    fn note(&self, spent: bool) -> String {
        let (spends, is) = if spent {
            ("spent", "was")
        } else {
            ("spends", "is")
        };
        match self {
            Origin::Received => String::new(),
            Origin::OwnChange(Spend {
                txid,
                from,
                moved_by: None,
            }) => format!(
                "; it {is} small change of your own spend in TX {txid}, which {spends} your \
                 coins at {}",
                list_addresses(from)
            ),
            Origin::OwnChange(Spend { txid, from, .. }) => format!(
                "; it was moved from change of your own spend in TX {txid}, which spent your \
                 coins at {}",
                list_addresses(from)
            ),
            Origin::PossiblyOwnChange(Spend {
                txid,
                from,
                moved_by: None,
            }) => format!(
                "; if the inputs of TX {txid} at {} are yours, this {is} small change of your \
                 own spend; it {is} already linked to that chain",
                list_addresses(from)
            ),
            Origin::PossiblyOwnChange(Spend { txid, from, .. }) => format!(
                "; it was moved from an output of TX {txid}; if the inputs of that TX at {} are \
                 yours, this {is} small change of your own spend; it {is} already linked to \
                 that chain",
                list_addresses(from)
            ),
        }
    }
}

impl Spend {
    /// The spend as seen from a coin moved from its output by a tx with these own inputs.
    fn moved_by(self, parent_inputs: Vec<String>) -> Spend {
        Spend {
            moved_by: Some(parent_inputs),
            ..self
        }
    }
}

/// The description's note on a dust-attack match: of the coin's parent `txid`, or of the tx
/// the dust it was moved from came out of.
fn attack_note(txid: &Txid, evidence: &serde_json::Value) -> String {
    match evidence["parent_txid"].as_str() {
        Some(source) if source != txid.to_string() => {
            format!(" — it was moved from dust of TX {source}, which matches a dust-attack pattern")
        }
        _ => format!(" — parent TX {txid} matches a dust-attack pattern"),
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
                    let (origin, _) = self.dust_lineage(&utxo.txid, thresholds);
                    finding.description = format!(
                    "{} output {}:{} at {} ({} sats) was pasted as unspent but is already spent{}",
                    capitalized(origin.noun()),
                    utxo.txid,
                    utxo.vout,
                    utxo.address.assume_checked_ref(),
                    utxo.amount.to_sat(),
                    origin.note(true),
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

    /// Where a dust coin of `parent` came from, with the dust-attack evidence that marks it.
    fn dust_lineage(
        &self,
        parent: &Txid,
        thresholds: &DetectorThresholds,
    ) -> (Origin, Option<serde_json::Value>) {
        self.dust_lineage_within(parent, thresholds, MAX_DUST_HOPS)
    }

    /// As [`Self::dust_lineage`], walking back at most `hops` own spends of dust alone.
    fn dust_lineage_within(
        &self,
        parent: &Txid,
        thresholds: &DetectorThresholds,
        hops: usize,
    ) -> (Origin, Option<serde_json::Value>) {
        if let Some(evidence) = self.dust_attack_evidence(parent, thresholds) {
            return (Origin::Received, Some(evidence));
        }
        // A CoinJoin round breaks the link to the coins it spent.
        if self.coinjoin_shaped(parent) {
            return (Origin::Received, None);
        }
        let (mut own, mut unattributed, mut sources) = (Vec::new(), Vec::new(), Vec::new());
        let mut own_normal = false;
        for input in self.get_input_addresses(parent) {
            let list = if self.is_ours(&input.address) {
                if input.value > thresholds.dust {
                    own_normal = true;
                } else if !sources.contains(&input.funding_txid) {
                    sources.push(input.funding_txid);
                }
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
        if own_normal {
            let spend = Spend {
                txid: *parent,
                from: own,
                moved_by: None,
            };
            return (Origin::OwnChange(spend), None);
        }
        if !own.is_empty() {
            // Dust moved with no normal coin keeps the origin of the dust it was moved from,
            // the most exposed one when there are several.
            if hops == 0 {
                return (Origin::Received, None);
            }
            let mut lineage: Option<Origin> = None;
            for source in &sources {
                let (origin, evidence) = self.dust_lineage_within(source, thresholds, hops - 1);
                if evidence.is_some() {
                    return (Origin::Received, evidence);
                }
                lineage = match (lineage, origin) {
                    (Some(Origin::Received), _) | (_, Origin::Received) => Some(Origin::Received),
                    (Some(possible @ Origin::PossiblyOwnChange(..)), _)
                    | (_, possible @ Origin::PossiblyOwnChange(..)) => Some(possible),
                    (_, own) => Some(own),
                };
            }
            let lineage = match lineage {
                Some(Origin::OwnChange(spend)) => Origin::OwnChange(spend.moved_by(own)),
                Some(Origin::PossiblyOwnChange(spend)) => {
                    Origin::PossiblyOwnChange(spend.moved_by(own))
                }
                _ => Origin::Received,
            };
            return (lineage, None);
        }
        if !unattributed.is_empty() {
            let spend = Spend {
                txid: *parent,
                from: unattributed,
                moved_by: None,
            };
            (Origin::PossiblyOwnChange(spend), None)
        } else {
            (Origin::Received, None)
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
        let (origin, attack) = self.dust_lineage(txid, thresholds);
        let severity = match origin {
            _ if attack.is_some() => Severity::Critical,
            // Change of inputs the scan cannot attribute may still be someone else's dust.
            Origin::Received | Origin::PossiblyOwnChange(..) => base_severity,
            Origin::OwnChange(..) => Severity::Low,
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
        let description = if let Some(ev) = attack.as_ref() {
            format!(
                "Dust UTXO {}:{} at {} ({} sats, {}, unspent){}",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                label,
                attack_note(txid, ev),
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
                origin.note(false),
            )
        };
        let correction = match &origin {
            Origin::OwnChange(..) => format!(
                "Freeze it in your wallet: as change of your own spend, it is already linked \
                 to the coins that spend came from, and spending it with coins of another \
                 origin links those to them as well. {FEE_ONLY_SPEND} {NEXT_TIME}"
            ),
            Origin::Received | Origin::PossiblyOwnChange(..) => format!(
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
        let (origin, attack) = self.dust_lineage(txid, thresholds);
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
        let description = if let Some(ev) = attack.as_ref() {
            format!(
                "Historical dust output {}:{} at {} ({} sats, already spent){}",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                attack_note(txid, ev),
            )
        } else {
            format!(
                "Historical {} output {}:{} at {} ({} sats, already spent){}",
                origin.noun(),
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                origin.note(true),
            )
        };
        let correction = match (&origin, alone) {
            (Origin::OwnChange(..), true) => format!(
                "This change has already been spent with no coins from your other \
                 addresses, so this spend added no new link to it. {NEXT_TIME}"
            ),
            (Origin::OwnChange(..), false) => format!(
                "This change has already been spent. From now on, freeze small change like \
                 this in your wallet's coin control so it is never spent with your other \
                 coins. {NEXT_TIME}"
            ),
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
        let (origin, attack) = self.dust_lineage(txid, thresholds);
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
        let description = if let Some(ev) = attack.as_ref() {
            format!(
                "Dust output {}:{} at {} ({} sats, spend status unknown){}",
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                attack_note(txid, ev),
            )
        } else {
            format!(
                "{} output {}:{} at {} ({} sats, spend status unknown){}",
                capitalized(origin.noun()),
                txid,
                vout,
                address.assume_checked_ref(),
                amt.to_sat(),
                origin.note(false),
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
