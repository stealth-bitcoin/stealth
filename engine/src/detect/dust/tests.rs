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
