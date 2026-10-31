// In-memory tests for the common-input-ownership (CIOH) detector and the
// advice other detectors give about CIOH.
//
// Runs entirely in memory; no bitcoind node required.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid, WPubkeyHash};
use stealth_engine::config::DetectorThresholds;
use stealth_engine::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, Utxo, WalletHistory,
    WalletTxCategory, WalletTxEntry,
};
use stealth_engine::{Finding, Severity, TxGraph, VulnerabilityType};

// ─── builders ───────────────────────────────────────────────────────────────

fn txid(n: u64) -> Txid {
    format!("{:0<64x}", n).parse().expect("valid txid hex")
}

fn wpkh(seed: u8) -> Address<NetworkUnchecked> {
    let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20]));
    Address::from_script(&script, Network::Regtest)
        .expect("script encodes to an address")
        .to_string()
        .parse::<Address<NetworkUnchecked>>()
        .expect("valid regtest address string")
}

fn vin(prev: Txid, vout: u32) -> TxInputRef {
    TxInputRef {
        previous_txid: prev,
        previous_vout: vout,
        sequence: 0xffff_fffd,
        coinbase: false,
    }
}

fn out(n: u32, addr: &Address<NetworkUnchecked>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address: Some(addr.clone()),
        value: Amount::from_sat(sats),
        script_type: DescriptorType::P2wpkh,
    }
}

fn tx(id: Txid, vins: Vec<TxInputRef>, vouts: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: id,
        vin: vins,
        vout: vouts,
        version: 2,
        locktime: 0,
        vsize: 200,
        confirmations: 3,
    }
}

fn entry(
    id: Txid,
    addr: Option<&Address<NetworkUnchecked>>,
    cat: WalletTxCategory,
) -> WalletTxEntry {
    WalletTxEntry {
        txid: id,
        address: addr.cloned(),
        category: cat,
        amount: Amount::from_sat(0),
        confirmations: 3,
        blockheight: 100,
    }
}

/// One funding tx per entry of `funding` (paying that address), then a
/// spend `S` consuming all of them and paying `ours[0]` back.
fn spend_history(
    funding: &[&Address<NetworkUnchecked>],
    ours: &[Address<NetworkUnchecked>],
) -> (WalletHistory, Txid) {
    let spend = txid(0xF0);
    let mut txs = Vec::new();
    let mut vins = Vec::new();
    let mut wallet_txs = Vec::new();
    for (i, addr) in funding.iter().enumerate() {
        let f = txid(0x10 + i as u64);
        txs.push(tx(
            f,
            vec![vin(txid(0xA0 + i as u64), 0)],
            vec![out(0, addr, 1_000_000)],
        ));
        vins.push(vin(f, 0));
        if ours.contains(addr) {
            wallet_txs.push(entry(f, Some(addr), WalletTxCategory::Receive));
        }
    }
    let total = 1_000_000 * funding.len() as u64 - 1_000;
    txs.push(tx(spend, vins, vec![out(0, &ours[0], total)]));
    wallet_txs.push(entry(spend, None, WalletTxCategory::Send));

    let history = WalletHistory {
        wallet_txs,
        utxos: Vec::new(),
        transactions: txs
            .into_iter()
            .map(|t| (t.txid, t))
            .collect::<HashMap<_, _>>(),
        internal_addresses: HashSet::new(),
        derived_addresses: ours.iter().cloned().collect(),
        ranged_addresses: ours.iter().cloned().collect(),
    };
    (history, spend)
}

fn cioh_findings(history: WalletHistory) -> Vec<Finding> {
    TxGraph::from_wallet_history(history)
        .detect_all(&DetectorThresholds::default(), None, None)
        .findings
        .into_iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::Cioh)
        .collect()
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[test]
fn several_inputs_from_one_own_address_is_not_cioh() {
    let a = wpkh(1);
    let (history, _) = spend_history(&[&a, &a, &a], std::slice::from_ref(&a));
    let findings = cioh_findings(history);
    assert!(
        findings.is_empty(),
        "spending coins of a single address links nothing: {findings:?}"
    );
}

#[test]
fn inputs_from_two_own_addresses_is_cioh() {
    let a = wpkh(1);
    let b = wpkh(2);
    let (history, spend) = spend_history(&[&a, &b], &[a.clone(), b.clone()]);
    let findings = cioh_findings(history);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let details = findings[0]
        .details
        .as_ref()
        .expect("CIOH finding has details");
    assert_eq!(details["txid"], spend.to_string());
    assert_eq!(details["our_inputs"], 2);
    assert_eq!(details["total_inputs"], 2);
    assert_eq!(details["our_addresses"], 2);
}

#[test]
fn reused_address_plus_another_own_address_is_cioh() {
    let a = wpkh(1);
    let b = wpkh(2);
    let (history, _) = spend_history(&[&a, &a, &b], &[a.clone(), b.clone()]);
    let findings = cioh_findings(history);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    let details = f.details.as_ref().expect("CIOH finding has details");
    assert_eq!(details["our_inputs"], 3);
    assert_eq!(details["our_addresses"], 2);
    assert_eq!(details["total_inputs"], 3);
    assert!(
        f.description.contains("3 of its 3 inputs are yours"),
        "{}",
        f.description
    );
    assert!(
        f.description.contains("2 of your addresses"),
        "{}",
        f.description
    );
}

#[test]
fn description_says_how_many_of_the_inputs_are_yours() {
    let a = wpkh(1);
    let b = wpkh(2);
    let stranger = wpkh(200);
    let (history, _) = spend_history(&[&a, &b, &stranger], &[a.clone(), b.clone()]);
    let findings = cioh_findings(history);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let d = &findings[0].description;
    assert!(d.contains("2 of its 3 inputs are yours"), "{d}");
    assert!(d.contains("(67% ownership)"), "{d}");
    assert!(!d.contains("of your inputs"), "{d}");
}

#[test]
fn two_inputs_from_one_own_address_among_a_strangers_is_not_cioh() {
    let a = wpkh(1);
    let stranger = wpkh(200);
    let (history, _) = spend_history(&[&a, &a, &stranger], std::slice::from_ref(&a));
    let findings = cioh_findings(history);
    assert!(
        findings.is_empty(),
        "one own address next to a stranger's input is not CIOH: {findings:?}"
    );
}

#[test]
fn correction_allows_coins_of_one_address_together() {
    let a = wpkh(1);
    let b = wpkh(2);
    let (history, _) = spend_history(&[&a, &b], &[a.clone(), b.clone()]);
    let findings = cioh_findings(history);
    let correction = findings
        .first()
        .and_then(|f| f.correction.as_deref())
        .expect("CIOH finding has a correction");
    assert!(!correction.contains("only one UTXO"), "{correction}");
    assert!(correction.contains("different addresses"), "{correction}");
}

#[test]
fn all_inputs_yours_across_two_addresses_is_critical() {
    let a = wpkh(1);
    let b = wpkh(2);
    let (history, _) = spend_history(&[&a, &a, &b], &[a.clone(), b.clone()]);
    let findings = cioh_findings(history);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn some_inputs_from_a_stranger_is_high() {
    let a = wpkh(1);
    let b = wpkh(2);
    let stranger = wpkh(200);
    let (history, _) = spend_history(&[&a, &b, &stranger], &[a.clone(), b.clone()]);
    let findings = cioh_findings(history);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].severity, Severity::High);
}

/// Correction of the Dust finding on a 500-sat coin of `a`, received in a
/// funding tx that pays `outputs` (output 0 must be the coin of `a`).
fn dust_correction(a: &Address<NetworkUnchecked>, outputs: Vec<TxOutput>) -> String {
    let funding = txid(0x10);
    let history = WalletHistory {
        wallet_txs: vec![entry(funding, Some(a), WalletTxCategory::Receive)],
        utxos: vec![Utxo {
            txid: funding,
            vout: 0,
            address: Some(a.clone()),
            amount: Amount::from_sat(500),
            confirmations: 3,
            script_type: DescriptorType::P2wpkh,
        }],
        transactions: [(funding, tx(funding, vec![vin(txid(0xA0), 0)], outputs))]
            .into_iter()
            .collect(),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([a.clone()]),
        ranged_addresses: HashSet::from([a.clone()]),
    };
    TxGraph::from_wallet_history(history)
        .detect_all(&DetectorThresholds::default(), None, None)
        .findings
        .into_iter()
        .find(|f| f.vulnerability_type == VulnerabilityType::Dust)
        .and_then(|f| f.correction)
        .expect("dust finding has a correction")
}

#[test]
fn dust_advice_says_spending_it_links_your_other_addresses() {
    let a = wpkh(1);
    let correction = dust_correction(&a, vec![out(0, &a, 500)]);
    assert!(
        correction.contains("links your other addresses to this one"),
        "{correction}"
    );
    assert!(!correction.contains("other inputs"), "{correction}");
}

#[test]
fn dust_attack_advice_says_spending_it_links_your_other_addresses() {
    let a = wpkh(1);
    // Ten 500-sat outputs to ten distinct addresses: a dust-attack pattern.
    let mut outputs = vec![out(0, &a, 500)];
    outputs.extend((1u8..10).map(|n| out(u32::from(n), &wpkh(100 + n), 500)));
    let correction = dust_correction(&a, outputs);
    assert!(
        correction.contains("Freeze it"),
        "not the attack branch: {correction}"
    );
    assert!(
        correction.contains("links your other addresses to this one"),
        "{correction}"
    );
    assert!(!correction.contains("other UTXOs"), "{correction}");
}

#[test]
fn unresolved_input_counts_toward_the_total() {
    let a = wpkh(1);
    let b = wpkh(2);
    let (mut history, spend) = spend_history(&[&a, &b], &[a.clone(), b.clone()]);
    // A parent that is not loaded, as for a stranger's P2PK or nonstandard prevout.
    history
        .transactions
        .get_mut(&spend)
        .expect("spend tx is in the history")
        .vin
        .push(vin(txid(0xEE), 0));
    let findings = cioh_findings(history);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert!(
        f.description.contains("2 of its 3 inputs are yours"),
        "{}",
        f.description
    );
    assert!(
        f.description.contains("(67% ownership)"),
        "{}",
        f.description
    );
    assert_eq!(f.severity, Severity::High);
    let details = f.details.as_ref().expect("CIOH finding has details");
    assert_eq!(details["total_inputs"], 3);
    assert_eq!(details["ownership_pct"], 67);
}

#[test]
fn own_input_without_address_counts_as_unknown() {
    let a = wpkh(1);
    let b = wpkh(2);
    let (mut history, spend) = spend_history(&[&a, &b], &[a.clone(), b.clone()]);
    // The wallet's own P2PK-like coin: its output has no address.
    let own_p2pk = txid(0x30);
    let mut p2pk_out = out(0, &a, 1_000_000);
    p2pk_out.address = None;
    history.transactions.insert(
        own_p2pk,
        tx(own_p2pk, vec![vin(txid(0xA9), 0)], vec![p2pk_out]),
    );
    history
        .wallet_txs
        .push(entry(own_p2pk, None, WalletTxCategory::Receive));
    history
        .transactions
        .get_mut(&spend)
        .expect("spend tx is in the history")
        .vin
        .push(vin(own_p2pk, 0));
    let findings = cioh_findings(history);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert!(
        f.description.contains("2 of its 3 inputs are yours"),
        "{}",
        f.description
    );
    assert_eq!(f.severity, Severity::High);
}
