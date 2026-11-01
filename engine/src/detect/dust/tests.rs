//! Unit tests for dust and dust spending, against an in-memory wallet history.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid, WPubkeyHash};

use crate::config::DetectorThresholds;
use crate::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, Utxo, WalletHistory,
    WalletTxCategory, WalletTxEntry,
};
use crate::graph::TxGraph;
use crate::types::{Finding, Severity};
use serde_json::json;

fn txid(n: u32) -> Txid {
    format!("{n:064x}").parse().expect("txid")
}

fn wpkh(seed: u8) -> Address<NetworkUnchecked> {
    let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20]));
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

/// One spend of `coins`, each from its own funding tx, to a stranger, seen by a wallet owning `ours`.
fn spend_of(
    coins: &[(&Address<NetworkUnchecked>, u64)],
    ours: &[&Address<NetworkUnchecked>],
) -> WalletHistory {
    let spend = txid(100);
    let mut wallet_txs = vec![entry(spend, None, WalletTxCategory::Send)];
    let mut transactions = HashMap::new();
    let mut vin = Vec::new();
    for (i, (address, sats)) in coins.iter().enumerate() {
        let fund = txid(i as u32 + 1);
        vin.push(TxInputRef {
            previous_txid: fund,
            previous_vout: 0,
            sequence: 0xffff_fffd,
            coinbase: false,
        });
        transactions.insert(fund, tx(fund, vec![], vec![out(0, address, *sats)]));
        if ours.contains(address) {
            wallet_txs.push(entry(fund, Some(address), WalletTxCategory::Receive));
        }
    }
    let total: u64 = coins.iter().map(|(_, sats)| sats).sum();
    transactions.insert(
        spend,
        tx(spend, vin, vec![out(0, &wpkh(101), total - 1_000)]),
    );
    WalletHistory {
        wallet_txs,
        utxos: vec![],
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
        left_out: Default::default(),
    }
}

/// Dust spending findings from a partial scan, which knows only the given addresses.
fn dust_spending(history: WalletHistory) -> Vec<Finding> {
    dust_spending_in(history, true)
}

/// Dust spending findings from a wallet or descriptor scan, which knows the wallet.
fn dust_spending_full(history: WalletHistory) -> Vec<Finding> {
    dust_spending_in(history, false)
}

fn dust_spending_in(history: WalletHistory, partial: bool) -> Vec<Finding> {
    let mut graph = TxGraph::from_wallet_history(history);
    graph.partial_scan = partial;
    let mut findings = Vec::new();
    graph.detect_dust_spending(&DetectorThresholds::default(), &mut findings);
    findings
}

#[test]
fn dust_spent_with_a_coin_at_another_address_is_reported() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = dust_spending(spend_of(&[(&a, 600), (&b, 50_000)], &[&a, &b]));
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn dust_spent_with_a_coin_at_its_own_address_links_nothing_new() {
    let a = wpkh(1);
    let findings = dust_spending(spend_of(&[(&a, 546), (&a, 44_980)], &[&a]));
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_strangers_input_does_not_make_one_address_dust_spending_in_a_descriptor_scan() {
    let a = wpkh(1);
    let stranger = wpkh(200);
    let mut history = spend_of(&[(&a, 546), (&a, 44_980), (&stranger, 30_000)], &[&a]);
    // A ranged descriptor derived `a`, so the scan knows the wallet's other addresses.
    history.ranged_addresses = HashSet::from([a.clone()]);
    let findings = dust_spending_full(history);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_partial_scan_counts_an_unattributed_input_as_possibly_another_address() {
    let a = wpkh(1);
    let b = wpkh(200);
    let findings = dust_spending(spend_of(&[(&a, 600), (&a, 20_000), (&b, 30_000)], &[&a]));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert_eq!(f.severity, Severity::Medium, "{f:?}");
    let b_text = b.assume_checked_ref().to_string();
    assert!(
        f.description.contains(&format!(
            "this ties the dust to {b_text}, if that address is yours"
        )),
        "{}",
        f.description
    );
    let details = f.details.as_ref().expect("details");
    assert_eq!(
        details["possibly_joined_addresses"],
        serde_json::json!([b_text])
    );
    assert_eq!(details["dust_inputs"].as_array().map(Vec::len), Some(1));
}

#[test]
fn a_known_other_address_keeps_dust_spending_high_in_a_partial_scan() {
    let (a, b, c) = (wpkh(1), wpkh(2), wpkh(200));
    let findings = dust_spending(spend_of(
        &[(&a, 600), (&a, 20_000), (&b, 5_000), (&c, 30_000)],
        &[&a, &b],
    ));
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn a_mid_sized_own_coin_elsewhere_ties_its_address_to_the_dusted_one() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = dust_spending(spend_of(&[(&a, 600), (&a, 50_000), (&b, 5_000)], &[&a, &b]));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let details = findings[0].details.as_ref().expect("details");
    assert_eq!(details["dust_inputs"].as_array().map(Vec::len), Some(1));
}

#[test]
fn every_dust_input_joined_to_another_address_is_listed() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = dust_spending(spend_of(&[(&a, 600), (&b, 700), (&a, 50_000)], &[&a, &b]));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let details = findings[0].details.as_ref().expect("details");
    let dust: Vec<_> = details["dust_inputs"]
        .as_array()
        .expect("dust inputs")
        .iter()
        .map(|d| d["sats"].as_u64())
        .collect();
    assert_eq!(dust, vec![Some(600), Some(700)], "{details}");
}

#[test]
fn dust_and_a_mid_sized_coin_elsewhere_with_no_normal_coin_is_not_dust_spending() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = dust_spending(spend_of(&[(&a, 600), (&b, 5_000)], &[&a, &b]));
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn dust_spending_lists_every_normal_input() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = dust_spending(spend_of(
        &[(&a, 600), (&a, 50_000), (&b, 40_000)],
        &[&a, &b],
    ));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let details = findings[0].details.as_ref().expect("details");
    let normal = details["normal_inputs"].as_array().expect("normal inputs");
    assert_eq!(normal.len(), 2, "{details}");
    assert_eq!(details["dust_inputs"].as_array().map(Vec::len), Some(1));
    assert!(
        findings[0]
            .description
            .contains("1 dust input(s) alongside 2 normal input(s)"),
        "{}",
        findings[0].description
    );
}

#[test]
fn dust_spending_advice_is_for_next_time_and_offers_no_way_to_spend_a_spent_coin() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = dust_spending(spend_of(&[(&a, 600), (&b, 50_000)], &[&a, &b]));
    let correction = findings[0].correction.as_deref().expect("a correction");
    assert!(
        correction.starts_with("Freeze dust like this"),
        "{correction}"
    );
    assert!(correction.contains("from now on"), "{correction}");
    for absent in ["spend it alone", "OP_RETURN", "WabiSabi", "CoinJoin"] {
        assert!(!correction.contains(absent), "{absent}: {correction}");
    }
}

#[test]
fn unspent_dust_advice_freezes_first_then_offers_a_standard_fee_only_spend() {
    let a = wpkh(1);
    let fund = txid(1);
    let history = WalletHistory {
        wallet_txs: vec![entry(fund, Some(&a), WalletTxCategory::Receive)],
        utxos: vec![Utxo {
            txid: fund,
            vout: 0,
            address: Some(a.clone()),
            amount: Amount::from_sat(600),
            confirmations: 3,
            script_type: DescriptorType::P2wpkh,
        }],
        transactions: HashMap::from([(fund, tx(fund, vec![], vec![out(0, &a, 600)]))]),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
        left_out: Default::default(),
    };
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history)
        .detect_dust(&DetectorThresholds::default(), &mut findings);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let correction = findings[0].correction.as_deref().expect("a correction");
    assert!(correction.starts_with("Freeze it"), "{correction}");
    for needle in [
        "spend it alone as fee",
        "one coin per transaction",
        // A bare 0-value OP_RETURN makes a 61-byte tx, under Core's 65-byte minimum.
        "one 0-value OP_RETURN output carrying 4 bytes of data",
        "mempool fee rates are low enough for it to confirm",
        // About 83 vB taproot and 94 native segwit, 117 wrapped segwit, 173 legacy P2PKH.
        "a 546-sat coin pays about 6 to 7 sat/vB from a native segwit or taproot address, \
         about 5 from wrapped segwit and about 3 from legacy",
        // With no runestone or other output, runes are burned, not paid to the miner.
        "an ordinals inscription goes to the miner and runes are burned; either way they are lost",
        // Same-shape transactions sent together can be grouped.
        "each one apart from the others, at different times and not in the same block",
    ] {
        assert!(correction.contains(needle), "{needle}: {correction}");
    }
    // A coin of 1,000 sats or less is under any CoinJoin coordinator's minimum.
    for banned in [
        "hands them to the miner",
        "low fee rate",
        "WabiSabi",
        "CoinJoin",
        "PayJoin",
        "Payjoin",
        "Lightning",
        "tx0",
    ] {
        assert!(!correction.contains(banned), "{banned}: {correction}");
    }
}

#[test]
fn spent_dust_advice_names_a_real_wallet_feature() {
    let (a, b) = (wpkh(1), wpkh(2));
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(spend_of(&[(&a, 600), (&b, 50_000)], &[&a, &b]))
        .detect_dust(&DetectorThresholds::default(), &mut findings);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let correction = findings[0].correction.as_deref().expect("a correction");
    assert!(
        correction.starts_with("This dust has already been spent."),
        "{correction}"
    );
    assert!(
        correction.contains("freeze dust like this in your wallet's coin control"),
        "{correction}"
    );
    // Bitcoin Core has no setting that rejects incoming dust.
    assert!(!correction.contains("rejection"), "{correction}");
}

fn op_return(n: u32) -> TxOutput {
    TxOutput {
        n,
        address: None,
        value: Amount::from_sat(0),
        script_type: DescriptorType::Unknown,
    }
}

/// Dust findings for a 600-sat coin of `a`, received in a tx paying `strangers` 500 sats each
/// too, then spent in a tx with the given extra inputs (a 0-sat one has no loaded parent)
/// and outputs.
fn spent_dust(
    strangers: u8,
    extra_inputs: &[(&Address<NetworkUnchecked>, u64)],
    vout: Vec<TxOutput>,
) -> Vec<Finding> {
    spent_dust_with(strangers, extra_inputs, vout, false, true)
}

/// As [`spent_dust`], with the coin still in the UTXO list when `listed`, as a pasted coin
/// is, and the spending tx unconfirmed unless `confirmed`.
fn spent_dust_with(
    strangers: u8,
    extra_inputs: &[(&Address<NetworkUnchecked>, u64)],
    vout: Vec<TxOutput>,
    listed: bool,
    confirmed: bool,
) -> Vec<Finding> {
    let a = wpkh(1);
    let (fund, spend) = (txid(1), txid(100));
    let mut fund_vout = vec![out(0, &a, 600)];
    fund_vout.extend((1..=strangers).map(|n| out(u32::from(n), &wpkh(100 + n), 500)));
    let from_stranger = TxInputRef {
        previous_txid: txid(90),
        previous_vout: 0,
        sequence: 0xffff_fffd,
        coinbase: false,
    };
    let mut transactions = HashMap::from([
        (
            txid(90),
            tx(txid(90), vec![], vec![out(0, &wpkh(200), 100_000)]),
        ),
        (fund, tx(fund, vec![from_stranger], fund_vout)),
    ]);
    let mut wallet_txs = vec![
        entry(fund, Some(&a), WalletTxCategory::Receive),
        entry(spend, None, WalletTxCategory::Send),
    ];
    let mut vin = vec![TxInputRef {
        previous_txid: fund,
        previous_vout: 0,
        sequence: 0xffff_fffd,
        coinbase: false,
    }];
    for (i, (address, sats)) in extra_inputs.iter().enumerate() {
        let other = txid(i as u32 + 2);
        if *sats > 0 {
            transactions.insert(other, tx(other, vec![], vec![out(0, address, *sats)]));
            wallet_txs.push(entry(other, Some(address), WalletTxCategory::Receive));
        }
        vin.push(TxInputRef {
            previous_txid: other,
            previous_vout: 0,
            sequence: 0xffff_fffd,
            coinbase: false,
        });
    }
    for o in vout.iter().filter_map(|o| o.address.as_ref()) {
        // `wpkh(3)` stands for a second known address of the wallet.
        if *o == a || *o == wpkh(3) || extra_inputs.iter().any(|(addr, _)| *addr == o) {
            wallet_txs.push(entry(spend, Some(o), WalletTxCategory::Receive));
        }
    }
    let mut spend_tx = tx(spend, vin, vout);
    if !confirmed {
        spend_tx.confirmations = 0;
    }
    transactions.insert(spend, spend_tx);
    let utxos = if listed {
        vec![Utxo {
            txid: fund,
            vout: 0,
            address: Some(a.clone()),
            amount: Amount::from_sat(600),
            confirmations: 3,
            script_type: DescriptorType::P2wpkh,
        }]
    } else {
        vec![]
    };
    let history = WalletHistory {
        wallet_txs,
        utxos,
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
        left_out: Default::default(),
    };
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history)
        .detect_dust(&DetectorThresholds::default(), &mut findings);
    findings
}

#[test]
fn dust_spent_alone_as_fee_gets_no_finding() {
    let findings = spent_dust(0, &[], vec![op_return(0)]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn attack_dust_spent_alone_as_fee_gets_no_finding() {
    let findings = spent_dust(9, &[], vec![op_return(0)]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn dust_spent_with_another_input_stays_a_low_finding() {
    let b = wpkh(2);
    let findings = spent_dust(0, &[(&b, 50_000)], vec![out(0, &wpkh(150), 49_000)]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].severity, Severity::Low);
}

#[test]
fn attack_dust_spent_with_another_input_stays_critical() {
    let b = wpkh(2);
    let findings = spent_dust(9, &[(&b, 50_000)], vec![out(0, &wpkh(150), 49_000)]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].severity, Severity::Critical);
}

#[test]
fn dust_moved_alone_to_the_wallet_still_gets_a_finding() {
    let findings = spent_dust(0, &[], vec![out(0, &wpkh(1), 400)]);
    assert!(
        findings
            .iter()
            .any(|f| f.details.as_ref().is_some_and(|d| d["status"] == "spent")),
        "{findings:?}"
    );
}

#[test]
fn pasted_dust_already_spent_alone_as_fee_gets_no_finding() {
    for strangers in [0, 9] {
        let findings = spent_dust_with(strangers, &[], vec![op_return(0)], true, true);
        assert!(findings.is_empty(), "{findings:?}");
    }
    let b = wpkh(2);
    let merged = spent_dust_with(
        0,
        &[(&b, 50_000)],
        vec![out(0, &wpkh(150), 49_000)],
        true,
        true,
    );
    assert_eq!(merged.len(), 1, "{merged:?}");
}

#[test]
fn an_unconfirmed_fee_only_spend_may_be_replaced_so_the_dust_keeps_its_finding() {
    for listed in [false, true] {
        let findings = spent_dust_with(0, &[], vec![op_return(0)], listed, false);
        assert_eq!(findings.len(), 1, "{findings:?}");
    }
}

fn spent_finding(findings: &[Finding]) -> Option<&Finding> {
    findings
        .iter()
        .find(|f| f.details.as_ref().is_some_and(|d| d["status"] == "spent"))
}

#[test]
fn dust_spent_alone_to_another_own_address_keeps_its_finding() {
    for strangers in [0, 9] {
        let findings = spent_dust(strangers, &[], vec![out(0, &wpkh(3), 400)]);
        assert_moved_elsewhere(&findings, strangers);
    }
}

/// The spent dust finding of a coin whose value went to another address: Critical with an
/// attack-shaped parent (`strangers` > 0), Low otherwise, and the freeze-from-now-on advice.
fn assert_moved_elsewhere(findings: &[Finding], strangers: u8) {
    let f = spent_finding(findings).expect("a spent dust finding");
    let expected = if strangers > 0 {
        Severity::Critical
    } else {
        Severity::Low
    };
    assert_eq!(f.severity, expected, "{f:?}");
    let correction = f.correction.as_deref().expect("a correction");
    assert!(
        correction.contains("never spent with your other coins"),
        "{correction}"
    );
    assert!(!correction.contains("linked none"), "{correction}");
}

#[test]
fn dust_spent_alone_to_a_foreign_address_is_a_payment_and_keeps_its_finding() {
    // In UTXO mode a foreign address may be the user's own, unscanned one.
    for strangers in [0, 9] {
        let findings = spent_dust(strangers, &[], vec![out(0, &wpkh(150), 400)]);
        assert_moved_elsewhere(&findings, strangers);
    }
}

#[test]
fn an_output_with_no_address_but_a_value_is_not_a_fee_only_spend() {
    let mut bare = op_return(0);
    bare.value = Amount::from_sat(400);
    let findings = spent_dust(0, &[], vec![bare]);
    assert!(spent_finding(&findings).is_some(), "{findings:?}");
}

#[test]
fn attack_dust_spent_with_a_coin_at_its_own_address_is_low_and_no_linking_mistake() {
    let a = wpkh(1);
    for strangers in [0, 9] {
        let findings = spent_dust(strangers, &[(&a, 50_000)], vec![out(0, &a, 49_000)]);
        let f = spent_finding(&findings).expect("a spent dust finding");
        assert_eq!(f.severity, Severity::Low, "{f:?}");
        let correction = f.correction.as_deref().expect("a correction");
        assert!(
            correction.contains("linked none of them to this one"),
            "{correction}"
        );
        assert!(
            !correction.contains("never spent with your other coins"),
            "{correction}"
        );
    }
}

#[test]
fn attack_dust_spent_with_an_input_of_unknown_address_stays_critical() {
    let findings = spent_dust(9, &[(&wpkh(1), 0)], vec![out(0, &wpkh(1), 400)]);
    let f = spent_finding(&findings).expect("a spent dust finding");
    assert_eq!(f.severity, Severity::Critical, "{f:?}");
}

#[test]
fn a_same_address_merge_sending_value_elsewhere_keeps_its_severity() {
    let a = wpkh(1);
    for strangers in [0, 9] {
        let payment_and_change = vec![out(0, &wpkh(150), 20_000), out(1, &wpkh(3), 29_000)];
        let findings = spent_dust(strangers, &[(&a, 50_000)], payment_and_change);
        assert_moved_elsewhere(&findings, strangers);
        let change_only = vec![out(0, &a, 20_000), out(1, &wpkh(3), 29_000)];
        let findings = spent_dust(strangers, &[(&a, 50_000)], change_only);
        assert_moved_elsewhere(&findings, strangers);
    }
}

#[test]
fn a_same_address_merge_with_an_op_return_stays_low() {
    let a = wpkh(1);
    let findings = spent_dust(9, &[(&a, 50_000)], vec![out(0, &a, 49_000), op_return(1)]);
    let f = spent_finding(&findings).expect("a spent dust finding");
    assert_eq!(f.severity, Severity::Low, "{f:?}");
}

#[test]
fn attack_dust_paid_to_an_output_with_no_address_but_a_value_keeps_critical() {
    let a = wpkh(1);
    let mut p2pk = op_return(1);
    p2pk.value = Amount::from_sat(20_000);
    let findings = spent_dust(9, &[(&a, 50_000)], vec![out(0, &a, 29_000), p2pk]);
    assert_moved_elsewhere(&findings, 9);
}

#[test]
fn attack_dust_spent_alone_into_an_op_return_and_a_payment_keeps_critical() {
    let findings = spent_dust(9, &[], vec![op_return(0), out(1, &wpkh(150), 400)]);
    assert_moved_elsewhere(&findings, 9);
}

#[test]
fn a_wallet_scan_does_not_count_a_stranger_next_to_dust_at_a_non_ranged_own_address() {
    let a = wpkh(1);
    let mut history = spend_of(&[(&a, 600), (&a, 20_000), (&wpkh(200), 30_000)], &[&a]);
    // The wallet has a ranged descriptor, but `a` comes from an imported, non-ranged one.
    history.ranged_addresses = HashSet::from([wpkh(99)]);
    let findings = dust_spending_full(history);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_partial_scan_lets_an_unattributed_coin_be_the_normal_one() {
    let (a, b) = (wpkh(1), wpkh(200));
    let findings = dust_spending(spend_of(&[(&a, 600), (&b, 50_000)], &[&a]));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert_eq!(f.severity, Severity::Medium, "{f:?}");
    assert!(
        f.description.contains("if that address is yours"),
        "{}",
        f.description
    );
}

#[test]
fn a_full_scan_does_not_let_a_strangers_coin_be_the_normal_one() {
    let (a, b) = (wpkh(1), wpkh(200));
    let mut history = spend_of(&[(&a, 600), (&b, 50_000)], &[&a]);
    history.ranged_addresses = HashSet::from([a.clone()]);
    let findings = dust_spending_full(history);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_known_tie_with_only_an_unattributed_normal_coin_is_medium() {
    let (a, b, c) = (wpkh(1), wpkh(2), wpkh(200));
    let findings = dust_spending(spend_of(&[(&a, 600), (&b, 5_000), (&c, 50_000)], &[&a, &b]));
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].severity, Severity::Medium, "{:?}", findings[0]);
    let c_text = c.assume_checked_ref().to_string();
    assert!(
        findings[0].description.contains(&format!(
            "this ties the dust to {c_text}, if that address is yours"
        )),
        "{}",
        findings[0].description
    );
}

#[test]
fn two_unattributed_addresses_get_the_plural_dust_wording() {
    let a = wpkh(1);
    let findings = dust_spending(spend_of(
        &[
            (&a, 600),
            (&a, 20_000),
            (&wpkh(200), 30_000),
            (&wpkh(201), 30_000),
        ],
        &[&a],
    ));
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0]
            .description
            .contains("if those addresses are yours"),
        "{}",
        findings[0].description
    );
}

/// Replaces the outputs of the spend built by [`spend_of`].
fn with_outputs(mut history: WalletHistory, vout: Vec<TxOutput>) -> WalletHistory {
    if let Some(spend) = history.transactions.get_mut(&txid(100)) {
        spend.vout = vout;
    }
    history
}

/// 600 and 20,000 sats at `a` spent with 30,000 sats from each of `n` unattributed addresses.
fn dust_with_strangers(a: &Address<NetworkUnchecked>, n: u8) -> WalletHistory {
    let strangers: Vec<_> = (0..n).map(|i| wpkh(150 + i)).collect();
    let mut coins = vec![(a, 600), (a, 20_000)];
    coins.extend(strangers.iter().map(|s| (s, 30_000)));
    spend_of(&coins, &[a])
}

/// Equal outputs, one per input, as a CoinJoin round pays them.
fn equal_outputs(n: u32) -> Vec<TxOutput> {
    (0..n)
        .map(|i| out(i, &wpkh(220 + i as u8), 25_000))
        .collect()
}

#[test]
fn a_coinjoin_shaped_spend_in_a_partial_scan_ties_no_unattributed_address() {
    let a = wpkh(1);
    let findings = dust_spending(with_outputs(dust_with_strangers(&a, 8), equal_outputs(10)));
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn equal_outputs_with_two_unattributed_inputs_are_not_coinjoin_shaped() {
    let a = wpkh(1);
    let findings = dust_spending(with_outputs(dust_with_strangers(&a, 2), equal_outputs(4)));
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn many_unattributed_inputs_without_equal_outputs_still_count() {
    let a = wpkh(1);
    let mut vout = equal_outputs(10);
    for (i, o) in vout.iter_mut().enumerate() {
        o.value = Amount::from_sat(25_000 + i as u64);
    }
    let findings = dust_spending(with_outputs(dust_with_strangers(&a, 8), vout));
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn a_long_list_of_unattributed_addresses_is_capped_in_the_description() {
    let a = wpkh(1);
    let findings = dust_spending(dust_with_strangers(&a, 8));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert!(
        f.description
            .contains(" and 3 more, if those addresses are yours"),
        "{}",
        f.description
    );
    let listed = wpkh(155).assume_checked_ref().to_string();
    assert!(!f.description.contains(&listed), "{}", f.description);
    let details = f.details.as_ref().expect("details");
    assert_eq!(
        details["possibly_joined_addresses"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );
}

#[test]
fn a_full_scan_with_only_non_ranged_descriptors_does_not_count_strangers() {
    let a = wpkh(1);
    // No ranged descriptor, but the user gave the scan their keys.
    let findings = dust_spending_full(spend_of(
        &[(&a, 600), (&a, 20_000), (&wpkh(200), 30_000)],
        &[&a],
    ));
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn three_unattributed_inputs_with_two_equal_outputs_are_coinjoin_shaped() {
    let a = wpkh(1);
    let findings = dust_spending(with_outputs(dust_with_strangers(&a, 3), equal_outputs(2)));
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn two_unattributed_inputs_with_two_equal_outputs_still_count() {
    let a = wpkh(1);
    let findings = dust_spending(with_outputs(dust_with_strangers(&a, 2), equal_outputs(2)));
    assert_eq!(findings.len(), 1, "{findings:?}");
}

/// A 100,000-sat coin at `a` peeled by `hops` spends, each paying a stranger and sending its
/// change to the next own address, the last change being `change_sats` at `wpkh(10)`. The
/// scan knows that last address, and the earlier ones when `inputs_known`. When `spent_with`
/// is given, the last change is then spent with that coin (`wpkh(2)`, known) to a stranger;
/// otherwise it is still unspent.
fn own_change(
    hops: u32,
    change_sats: u64,
    inputs_known: bool,
    spent_with: Option<u64>,
) -> WalletHistory {
    let last = wpkh(10);
    let fund = txid(1);
    let mut transactions =
        HashMap::from([(fund, tx(fund, vec![], vec![out(0, &wpkh(1), 100_000)]))]);
    let mut wallet_txs = Vec::new();
    if inputs_known {
        wallet_txs.push(entry(fund, Some(&wpkh(1)), WalletTxCategory::Receive));
    }
    let (mut prev, mut held) = (fund, 100_000u64);
    for hop in 1..=hops {
        let id = txid(1 + hop);
        let change = if hop == hops { change_sats } else { held / 2 };
        let to = if hop == hops {
            last.clone()
        } else {
            wpkh(20 + hop as u8)
        };
        let vin = vec![TxInputRef {
            previous_txid: prev,
            previous_vout: 1.min(hop - 1),
            sequence: 0xffff_fffd,
            coinbase: false,
        }];
        let vout = vec![
            out(0, &wpkh(150 + hop as u8), held - change - 1_000),
            out(1, &to, change),
        ];
        transactions.insert(id, tx(id, vin, vout));
        if inputs_known {
            wallet_txs.push(entry(id, None, WalletTxCategory::Send));
        }
        if inputs_known || hop == hops {
            wallet_txs.push(entry(id, Some(&to), WalletTxCategory::Receive));
        }
        (prev, held) = (id, change);
    }
    let mut utxos = Vec::new();
    match spent_with {
        Some(sats) => {
            let (other, child) = (txid(80), txid(81));
            transactions.insert(other, tx(other, vec![], vec![out(0, &wpkh(2), sats)]));
            wallet_txs.push(entry(other, Some(&wpkh(2)), WalletTxCategory::Receive));
            let vin = [(prev, 1), (other, 0)]
                .into_iter()
                .map(|(previous_txid, previous_vout)| TxInputRef {
                    previous_txid,
                    previous_vout,
                    sequence: 0xffff_fffd,
                    coinbase: false,
                })
                .collect();
            let vout = vec![out(0, &wpkh(160), sats + change_sats - 1_000)];
            transactions.insert(child, tx(child, vin, vout));
            wallet_txs.push(entry(child, None, WalletTxCategory::Send));
        }
        None => utxos.push(Utxo {
            txid: prev,
            vout: 1,
            address: Some(last.clone()),
            amount: Amount::from_sat(change_sats),
            confirmations: 3,
            script_type: DescriptorType::P2wpkh,
        }),
    }
    WalletHistory {
        wallet_txs,
        utxos,
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
        left_out: Default::default(),
    }
}

/// Dust findings of `history`, from a partial scan when `partial`.
fn dust_in(history: WalletHistory, partial: bool) -> Vec<Finding> {
    let mut graph = TxGraph::from_wallet_history(history);
    graph.partial_scan = partial;
    let mut findings = Vec::new();
    graph.detect_dust(&DetectorThresholds::default(), &mut findings);
    findings
}

fn only(findings: &[Finding]) -> &Finding {
    assert_eq!(findings.len(), 1, "{findings:?}");
    &findings[0]
}

fn origin(f: &Finding) -> &str {
    f.details
        .as_ref()
        .and_then(|d| d["origin"].as_str())
        .unwrap_or_default()
}

/// The unspent finding of own change: Low, named as change of the user's spend, freeze first.
fn assert_unspent_own_change(f: &Finding, parent: Txid, from: &Address<NetworkUnchecked>) {
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "own_change", "{f:?}");
    let from = from.assume_checked_ref().to_string();
    assert!(
        f.description.contains(&format!(
            "small change of your own spend in TX {parent}, which spends your coins at {from}"
        )),
        "{}",
        f.description
    );
    assert!(
        !f.description.contains("if that address"),
        "{}",
        f.description
    );
    let correction = f.correction.as_deref().expect("a correction");
    assert!(correction.starts_with("Freeze it"), "{correction}");
    for needle in [
        "already linked to the coins that spend came from",
        "spending it with coins of another origin links those to them as well",
        "spend it alone as fee",
        "Next time, let a remainder this small go to the fee instead of becoming a change output.",
    ] {
        assert!(correction.contains(needle), "{needle}: {correction}");
    }
    assert_no_merge_within_the_chain(correction);
    let details = f.details.as_ref().expect("details");
    assert_eq!(details["parent_input_addresses"], json!([from]));
}

#[test]
fn own_change_under_1000_sats_is_low_and_named_as_change() {
    for sats in [600, 400] {
        let findings = dust_in(own_change(1, sats, true, None), false);
        assert_unspent_own_change(only(&findings), txid(2), &wpkh(1));
    }
}

#[test]
fn the_last_change_of_a_peel_chain_is_own_change() {
    let findings = dust_in(own_change(4, 600, true, None), false);
    assert_unspent_own_change(only(&findings), txid(5), &wpkh(23));
}

/// A 100,000-sat coin of a stranger at `wpkh(200)` paying `sats` to `a`, still unspent, and
/// `recipients` other strangers 500 sats each.
fn received(sats: u64, recipients: u8) -> WalletHistory {
    let (a, stranger) = (wpkh(1), wpkh(200));
    let (theirs, fund) = (txid(90), txid(1));
    let mut vout = vec![out(0, &a, sats)];
    vout.extend((1..=recipients).map(|n| out(u32::from(n), &wpkh(100 + n), 500)));
    vout.push(out(u32::from(recipients) + 1, &stranger, 50_000));
    let vin = vec![TxInputRef {
        previous_txid: theirs,
        previous_vout: 0,
        sequence: 0xffff_fffd,
        coinbase: false,
    }];
    WalletHistory {
        wallet_txs: vec![entry(fund, Some(&a), WalletTxCategory::Receive)],
        utxos: vec![Utxo {
            txid: fund,
            vout: 0,
            address: Some(a.clone()),
            amount: Amount::from_sat(sats),
            confirmations: 3,
            script_type: DescriptorType::P2wpkh,
        }],
        transactions: HashMap::from([
            (theirs, tx(theirs, vec![], vec![out(0, &stranger, 100_000)])),
            (fund, tx(fund, vin, vout)),
        ]),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
        left_out: Default::default(),
    }
}

#[test]
fn received_dust_keeps_its_severity_and_wording() {
    for (sats, severity, label) in [
        (600, Severity::Medium, "dust-class"),
        (500, Severity::High, "STRICT_DUST"),
    ] {
        let findings = dust_in(received(sats, 0), false);
        let f = only(&findings);
        assert_eq!(f.severity, severity, "{f:?}");
        assert_eq!(origin(f), "received", "{f:?}");
        assert_eq!(
            f.description,
            format!(
                "Dust UTXO {}:0 at {} ({sats} sats, {label}, unspent)",
                txid(1),
                wpkh(1).assume_checked_ref()
            )
        );
        let correction = f.correction.as_deref().expect("a correction");
        assert!(
            correction.starts_with(
                "Freeze it in your wallet: spending it with your other coins links your \
                 other addresses to this one. To get rid of it"
            ),
            "{correction}"
        );
        assert!(!correction.contains("change"), "{correction}");
    }
}

#[test]
fn attack_shaped_dust_stays_critical_in_full_and_partial_scans() {
    for partial in [false, true] {
        let findings = dust_in(received(500, 9), partial);
        let f = only(&findings);
        assert_eq!(f.severity, Severity::Critical, "{f:?}");
        assert_eq!(origin(f), "received", "{f:?}");
        assert!(
            f.description.ends_with("matches a dust-attack pattern"),
            "{}",
            f.description
        );
        assert!(!f.description.contains("change"), "{}", f.description);
    }
}

#[test]
fn own_change_spent_with_another_coin_is_a_low_historical_change_finding() {
    let findings = dust_in(own_change(1, 600, true, Some(50_000)), false);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "own_change", "{f:?}");
    assert_eq!(f.details.as_ref().expect("details")["status"], "spent");
    assert!(
        f.description.starts_with("Historical change output"),
        "{}",
        f.description
    );
    assert!(
        f.description.contains(&format!(
            "small change of your own spend in TX {}, which spent your coins at {}",
            txid(2),
            wpkh(1).assume_checked_ref()
        )),
        "{}",
        f.description
    );
    let correction = f.correction.as_deref().expect("a correction");
    assert!(
        correction.starts_with("This change has already been spent."),
        "{correction}"
    );
    for needle in [
        "freeze small change like this in your wallet's coin control",
        "never spent with your other coins",
        "let a remainder this small go to the fee instead of becoming a change output",
    ] {
        assert!(correction.contains(needle), "{needle}: {correction}");
    }
    assert_no_merge_within_the_chain(correction);
}

/// Own change advice never suggests spending the coin with others of its chain: that spend
/// is itself reported as dust spending and toxic change.
fn assert_no_merge_within_the_chain(correction: &str) {
    for banned in [
        "same chain",
        "coins of that",
        "only with",
        "another origin, and",
    ] {
        assert!(!correction.contains(banned), "{banned}: {correction}");
    }
}

#[test]
fn own_change_spent_alone_at_its_address_linked_nothing() {
    let mut history = own_change(1, 600, true, None);
    history.utxos.clear();
    let child = txid(81);
    let vin = vec![TxInputRef {
        previous_txid: txid(2),
        previous_vout: 1,
        sequence: 0xffff_fffd,
        coinbase: false,
    }];
    history
        .transactions
        .insert(child, tx(child, vin, vec![out(0, &wpkh(10), 400)]));
    history
        .wallet_txs
        .push(entry(child, None, WalletTxCategory::Send));
    history
        .wallet_txs
        .push(entry(child, Some(&wpkh(10)), WalletTxCategory::Receive));
    let findings = dust_in(history, false);
    let f = findings
        .iter()
        .find(|f| {
            f.details
                .as_ref()
                .is_some_and(|d| d["txid"] == json!(txid(2)))
        })
        .expect("the change's finding");
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "own_change", "{f:?}");
    assert_eq!(
        f.correction.as_deref(),
        Some(
            "This change has already been spent with no coins from your other addresses, so \
             it linked none of them to this one. Next time, let a remainder this small go to \
             the fee instead of becoming a change output."
        )
    );
}

#[test]
fn own_change_of_unknown_spend_status_is_named_as_change() {
    let mut history = own_change(1, 600, true, None);
    history.utxos.clear();
    let findings = dust_in(history, false);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(f.details.as_ref().expect("details")["status"], "unknown");
    assert_eq!(
        f.description,
        format!(
            "Change output {}:1 at {} (600 sats, spend status unknown); it is small change of \
             your own spend in TX {}, which spends your coins at {}",
            txid(2),
            wpkh(10).assume_checked_ref(),
            txid(2),
            wpkh(1).assume_checked_ref()
        )
    );
}

#[test]
fn possibly_own_change_of_unknown_spend_status_gets_the_conditional_note() {
    let mut history = own_change(1, 600, false, None);
    history.utxos.clear();
    let findings = dust_in(history, true);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "possibly_own_change", "{f:?}");
    assert_eq!(
        f.description,
        format!(
            "Dust output {}:1 at {} (600 sats, spend status unknown); if the inputs of TX {} \
             are yours, this is small change of your own spend; it is already linked to that \
             chain",
            txid(2),
            wpkh(10).assume_checked_ref(),
            txid(2)
        )
    );
}

#[test]
fn received_dust_spent_with_another_coin_keeps_its_historical_finding() {
    let findings = spent_dust(0, &[(&wpkh(2), 50_000)], vec![out(0, &wpkh(150), 49_000)]);
    let f = spent_finding(&findings).expect("a spent dust finding");
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "received", "{f:?}");
    assert!(
        f.description.starts_with("Historical dust output"),
        "{}",
        f.description
    );
    assert!(!f.description.contains("change"), "{}", f.description);
}

/// The received-dust advice, which a coin only possibly the user's change keeps.
fn received_advice(sats: u64, spent: bool) -> String {
    let mut history = received(sats, 0);
    if spent {
        let child = txid(81);
        let vin = vec![TxInputRef {
            previous_txid: txid(1),
            previous_vout: 0,
            sequence: 0xffff_fffd,
            coinbase: false,
        }];
        history
            .transactions
            .insert(child, tx(child, vin, vec![out(0, &wpkh(160), sats)]));
        history
            .wallet_txs
            .push(entry(child, None, WalletTxCategory::Send));
        history.utxos.clear();
        history.transactions.insert(
            txid(80),
            tx(txid(80), vec![], vec![out(0, &wpkh(2), 50_000)]),
        );
    }
    let findings = dust_in(history, false);
    only(&findings).correction.clone().expect("a correction")
}

#[test]
fn a_partial_scan_keeps_received_severity_for_change_of_unattributed_inputs() {
    let from = wpkh(1).assume_checked_ref().to_string();
    for (sats, severity) in [
        (600, Severity::Medium),
        (546, Severity::High),
        (500, Severity::High),
    ] {
        let findings = dust_in(own_change(1, sats, false, None), true);
        let f = only(&findings);
        assert_eq!(f.severity, severity, "{f:?}");
        assert_eq!(origin(f), "possibly_own_change", "{f:?}");
        assert!(f.description.starts_with("Dust UTXO"), "{}", f.description);
        assert!(
            f.description.ends_with(&format!(
                "; if the inputs of TX {} are yours, this is small change of your own spend; \
                 it is already linked to that chain",
                txid(2)
            )),
            "{}",
            f.description
        );
        assert_eq!(
            f.correction.as_deref(),
            Some(received_advice(sats, false).as_str())
        );
        assert_eq!(
            f.details.as_ref().expect("details")["parent_input_addresses"],
            json!([from])
        );
    }
    // The scan that knows the inputs is certain.
    let findings = dust_in(own_change(1, 500, true, None), true);
    assert_unspent_own_change(only(&findings), txid(2), &wpkh(1));
}

#[test]
fn a_full_scan_does_not_call_a_strangers_spend_own_change() {
    let findings = dust_in(own_change(1, 500, false, None), false);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::High, "{f:?}");
    assert_eq!(origin(f), "received", "{f:?}");
}

#[test]
fn a_partial_scan_notes_spent_change_of_unattributed_inputs_conditionally() {
    let findings = dust_in(own_change(1, 600, false, Some(50_000)), true);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "possibly_own_change", "{f:?}");
    assert!(
        f.description.starts_with("Historical dust output"),
        "{}",
        f.description
    );
    assert!(
        f.description.ends_with(&format!(
            "; if the inputs of TX {} are yours, this was small change of your own spend; \
             it was already linked to that chain",
            txid(2)
        )),
        "{}",
        f.description
    );
    assert_eq!(
        f.correction.as_deref(),
        Some(received_advice(600, true).as_str())
    );
}

#[test]
fn a_coinjoin_shaped_parent_in_a_partial_scan_is_received_dust() {
    let mut history = received(500, 0);
    let fund = txid(1);
    let mut vin = Vec::new();
    for i in 0..3u32 {
        let theirs = txid(90 + i);
        history.transactions.insert(
            theirs,
            tx(theirs, vec![], vec![out(0, &wpkh(200 + i as u8), 60_000)]),
        );
        vin.push(TxInputRef {
            previous_txid: theirs,
            previous_vout: 0,
            sequence: 0xffff_fffd,
            coinbase: false,
        });
    }
    let vout = vec![
        out(0, &wpkh(1), 500),
        out(1, &wpkh(210), 50_000),
        out(2, &wpkh(211), 50_000),
    ];
    history.transactions.insert(fund, tx(fund, vin, vout));
    let findings = dust_in(history, true);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::High, "{f:?}");
    assert_eq!(origin(f), "received", "{f:?}");
}

#[test]
fn pasted_own_change_already_spent_is_named_as_change() {
    let mut history = own_change(1, 600, true, Some(50_000));
    history.utxos.push(Utxo {
        txid: txid(2),
        vout: 1,
        address: Some(wpkh(10)),
        amount: Amount::from_sat(600),
        confirmations: 3,
        script_type: DescriptorType::P2wpkh,
    });
    let findings = dust_in(history, false);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "own_change", "{f:?}");
    assert!(
        f.description.starts_with(&format!(
            "Change output {}:1 at {} (600 sats) was pasted as unspent but is already spent",
            txid(2),
            wpkh(10).assume_checked_ref()
        )),
        "{}",
        f.description
    );
}

#[test]
fn a_known_input_makes_change_certain_in_a_partial_scan_next_to_an_unattributed_one() {
    let mut history = own_change(1, 500, true, None);
    let (theirs, spend) = (txid(70), txid(2));
    history
        .transactions
        .insert(theirs, tx(theirs, vec![], vec![out(0, &wpkh(201), 30_000)]));
    if let Some(parent) = history.transactions.get_mut(&spend) {
        parent.vin.push(TxInputRef {
            previous_txid: theirs,
            previous_vout: 0,
            sequence: 0xffff_fffd,
            coinbase: false,
        });
    }
    let findings = dust_in(history, true);
    let f = only(&findings);
    assert_eq!(f.severity, Severity::Low, "{f:?}");
    assert_eq!(origin(f), "own_change", "{f:?}");
}
