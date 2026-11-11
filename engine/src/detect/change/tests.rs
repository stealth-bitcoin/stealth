//! Unit tests for change detection, against an in-memory wallet history.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{
    Address, Amount, Network, ScriptBuf, Txid, WPubkeyHash, WitnessProgram, WitnessVersion,
};
use serde_json::Value;

use crate::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, WalletHistory, WalletTxCategory,
    WalletTxEntry,
};
use crate::graph::TxGraph;
use crate::types::{Finding, VulnerabilityType};

fn txid(n: u32) -> Txid {
    format!("{n:064x}").parse().expect("txid")
}

fn wpkh(seed: u8) -> Address<NetworkUnchecked> {
    parse(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
        [seed; 20],
    )))
}

fn tr(seed: u8) -> Address<NetworkUnchecked> {
    let program = WitnessProgram::new(WitnessVersion::V1, &[seed; 32]).expect("v1 program");
    parse(ScriptBuf::new_witness_program(&program))
}

fn parse(script: ScriptBuf) -> Address<NetworkUnchecked> {
    Address::from_script(&script, Network::Regtest)
        .expect("address")
        .to_string()
        .parse()
        .expect("unchecked address")
}

fn out(n: u32, addr: &Address<NetworkUnchecked>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address: Some(addr.clone()),
        value: Amount::from_sat(sats),
        script_type: DescriptorType::P2wpkh,
    }
}

fn tx(id: Txid, vin: Vec<TxInputRef>, vout: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: id,
        vin,
        vout,
        version: 2,
        locktime: 0,
        vsize: 200,
        confirmations: 3,
    }
}

fn entry(
    id: Txid,
    address: Option<&Address<NetworkUnchecked>>,
    category: WalletTxCategory,
) -> WalletTxEntry {
    WalletTxEntry {
        txid: id,
        address: address.cloned(),
        category,
        amount: Amount::from_sat(0),
        confirmations: 3,
        blockheight: 100,
    }
}

/// One spend paying three external outputs, with change to an internal address.
fn change_finding(payments: [u64; 3]) -> Finding {
    change_finding_with(payments, wpkh, true)
}

/// One P2WPKH spend paying three `payee` outputs, with P2WPKH change.
fn change_finding_with(
    payments: [u64; 3],
    payee: fn(u8) -> Address<NetworkUnchecked>,
    internal_change: bool,
) -> Finding {
    let payees = (101u8..).map(payee).zip(payments).collect();
    spend_finding(payees, internal_change)
}

/// One P2WPKH spend paying `payees`, with 412 345 sats of P2WPKH change.
fn spend_finding(payees: Vec<(Address<NetworkUnchecked>, u64)>, internal_change: bool) -> Finding {
    let funded = wpkh(1);
    let change = wpkh(2);
    let (fund, spend) = (txid(1), txid(2));

    let mut vout = vec![out(0, &change, 412_345)];
    for (i, (payee, sats)) in payees.iter().enumerate() {
        vout.push(out(i as u32 + 1, payee, *sats));
    }
    let input = TxInputRef {
        previous_txid: fund,
        previous_vout: 0,
        sequence: 0xffff_fffd,
        coinbase: false,
    };
    let history = WalletHistory {
        wallet_txs: vec![
            entry(fund, Some(&funded), WalletTxCategory::Receive),
            entry(spend, None, WalletTxCategory::Send),
            entry(spend, Some(&change), WalletTxCategory::Receive),
        ],
        utxos: vec![],
        transactions: HashMap::from([
            (fund, tx(fund, vec![], vec![out(0, &funded, 20_000_000)])),
            (spend, tx(spend, vec![input], vout)),
        ]),
        internal_addresses: if internal_change {
            HashSet::from([change.clone()])
        } else {
            HashSet::new()
        },
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
    };

    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history).detect_change_detection(&mut findings);
    let mut change_findings = findings
        .into_iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::ChangeDetection);
    let finding = change_findings.next().expect("a change detection finding");
    assert!(
        change_findings.next().is_none(),
        "one finding per transaction"
    );
    finding
}

fn reasons(finding: &Finding) -> Vec<String> {
    finding
        .details
        .as_ref()
        .and_then(|d| d.get("reasons"))
        .and_then(Value::as_array)
        .expect("reasons array")
        .iter()
        .filter_map(|r| r.as_str().map(String::from))
        .collect()
}

#[test]
fn the_derivation_path_heuristic_counts_once_however_many_payments() {
    let finding = change_finding([123_457, 234_567, 345_679]);
    assert!(
        finding.description.ends_with("(1 heuristic(s) matched)"),
        "{}",
        finding.description
    );
    assert_eq!(
        reasons(&finding),
        vec!["Change uses an internal (BIP-44 /1/*) derivation path"]
    );
}

#[test]
fn each_matched_heuristic_counts_once_per_transaction() {
    let finding = change_finding([100_000, 200_000, 300_000]);
    assert!(
        finding.description.ends_with("(2 heuristic(s) matched)"),
        "{}",
        finding.description
    );
    let reasons = reasons(&finding);
    let derivation = reasons
        .iter()
        .filter(|r| r.contains("derivation path"))
        .count();
    assert_eq!(derivation, 1, "{reasons:?}");
    assert_eq!(
        reasons
            .iter()
            .filter(|r| r.starts_with("Round payment"))
            .count(),
        3,
        "{reasons:?}"
    );
}

#[test]
fn the_script_type_heuristic_counts_once_alongside_round_amounts() {
    let finding = change_finding_with([100_000, 200_000, 300_000], tr, false);
    assert!(
        finding.description.ends_with("(2 heuristic(s) matched)"),
        "{}",
        finding.description
    );
    let reasons = reasons(&finding);
    assert_eq!(
        reasons
            .iter()
            .filter(|r| r.as_str()
                == "Change script type (p2wpkh) matches input type — different from payment (p2tr)")
            .count(),
        1,
        "{reasons:?}"
    );
    assert_eq!(reasons.len(), 4, "{reasons:?}");
}

#[test]
fn every_counted_heuristic_keeps_a_reason_line_under_the_cap() {
    let mut payees: Vec<_> = (101u8..=107)
        .map(|seed| (wpkh(seed), u64::from(seed) * 100_000))
        .collect();
    payees.push((tr(108), 800_000));
    let finding = spend_finding(payees, true);
    let reasons = reasons(&finding);
    let round =
        |sats: u64| format!("Round payment ({sats} sats) vs non-round change (412345 sats)");
    assert_eq!(
        reasons,
        vec![
            round(10_100_000),
            "Change uses an internal (BIP-44 /1/*) derivation path".into(),
            round(10_200_000),
            round(10_300_000),
            round(10_400_000),
            "Change script type (p2wpkh) matches input type — different from payment (p2tr)".into(),
        ]
    );
    assert!(
        reasons
            .iter()
            .any(|r| r.starts_with("Change script type (p2wpkh)")),
        "{reasons:?}"
    );
    let listed: HashSet<&str> = reasons
        .iter()
        .map(|r| r.split(" (").next().unwrap_or(r))
        .collect();
    assert!(
        finding
            .description
            .ends_with(&format!("({} heuristic(s) matched)", listed.len())),
        "{} vs {reasons:?}",
        finding.description
    );
}
