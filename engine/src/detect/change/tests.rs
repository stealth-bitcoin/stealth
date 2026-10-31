//! Unit tests for change detection, against an in-memory wallet history.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{
    Address, Amount, Network, ScriptBuf, Txid, WPubkeyHash, WitnessProgram, WitnessVersion,
};
use serde_json::Value;

use crate::config::DetectorThresholds;
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
    let correction = finding.correction.as_deref().unwrap_or_default();
    assert!(correction.starts_with("Use PayJoin"), "{correction}");
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

/// A spent coin: its address (`None` for a script with no address) and whether its parent is loaded.
struct Coin {
    address: Option<Address<NetworkUnchecked>>,
    sats: u64,
    loaded: bool,
}

fn coin(address: &Address<NetworkUnchecked>, sats: u64) -> Coin {
    Coin {
        address: Some(address.clone()),
        sats,
        loaded: true,
    }
}

fn op_return(n: u32) -> TxOutput {
    TxOutput {
        n,
        address: None,
        value: Amount::from_sat(0),
        script_type: DescriptorType::Unknown,
    }
}

/// Change findings for one spend of `coins` to `vout`, scanned by a wallet owning `ours`.
fn findings_for(
    coins: Vec<Coin>,
    vout: Vec<TxOutput>,
    ours: &[&Address<NetworkUnchecked>],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history_for(coins, vout, ours))
        .detect_change_detection(&mut findings);
    findings
}

/// One spend of `coins`, each from its own funding tx, to `vout`, seen by a wallet owning `ours`.
fn history_for(
    coins: Vec<Coin>,
    vout: Vec<TxOutput>,
    ours: &[&Address<NetworkUnchecked>],
) -> WalletHistory {
    let spend = txid(100);
    let mut wallet_txs = Vec::new();
    let mut transactions = HashMap::new();
    let mut vin = Vec::new();
    let mut spends_ours = false;
    for (i, coin) in coins.iter().enumerate() {
        let fund = txid(i as u32 + 1);
        vin.push(TxInputRef {
            previous_txid: fund,
            previous_vout: 0,
            sequence: 0xffff_fffd,
            coinbase: false,
        });
        let funded = TxOutput {
            n: 0,
            address: coin.address.clone(),
            value: Amount::from_sat(coin.sats),
            script_type: DescriptorType::P2wpkh,
        };
        if coin.loaded {
            transactions.insert(fund, tx(fund, vec![], vec![funded]));
        }
        if let Some(addr) = coin.address.as_ref().filter(|a| ours.contains(a)) {
            wallet_txs.push(entry(fund, Some(addr), WalletTxCategory::Receive));
            spends_ours = true;
        }
    }
    if spends_ours {
        wallet_txs.push(entry(spend, None, WalletTxCategory::Send));
    }
    for o in &vout {
        if let Some(addr) = o.address.as_ref().filter(|a| ours.contains(a)) {
            wallet_txs.push(entry(spend, Some(addr), WalletTxCategory::Receive));
        }
    }
    transactions.insert(spend, tx(spend, vin, vout));
    WalletHistory {
        wallet_txs,
        utxos: vec![],
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
    }
}

fn back_to_input(n: u32, sats: u64) -> String {
    format!("Change went back to an input address (output {n}, {sats} sats)")
}

#[test]
fn change_back_to_the_input_address_is_named_as_the_change() {
    let funded = wpkh(1);
    let findings = findings_for(
        vec![coin(&funded, 50_000)],
        vec![
            out(0, &wpkh(101), 46_543),
            out(1, &wpkh(102), 1_234),
            out(2, &funded, 2_107),
        ],
        &[&funded],
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(reasons(&findings[0]), vec![back_to_input(2, 2_107)]);
    assert!(
        findings[0]
            .description
            .ends_with("(1 heuristic(s) matched)"),
        "{}",
        findings[0].description
    );
    let correction = findings[0].correction.as_deref().unwrap_or_default();
    assert!(
        correction.starts_with("Send change to a fresh change address"),
        "{correction}"
    );
}

#[test]
fn change_back_to_an_input_address_wins_over_a_heuristic_pointing_elsewhere() {
    let funded = wpkh(1);
    let own_other = wpkh(3);
    let findings = findings_for(
        vec![coin(&funded, 600_000)],
        vec![
            out(0, &wpkh(101), 100_000),
            out(1, &own_other, 412_345),
            out(2, &funded, 2_107),
        ],
        &[&funded, &own_other],
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        reasons(&findings[0]),
        vec![
            back_to_input(2, 2_107),
            "Round payment (100000 sats) vs non-round change (2107 sats)".to_string(),
        ]
    );
    assert!(
        findings[0]
            .description
            .ends_with("(2 heuristic(s) matched)"),
        "{}",
        findings[0].description
    );
}

#[test]
fn two_outputs_back_to_input_addresses_count_as_one_heuristic() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = findings_for(
        vec![coin(&a, 30_000), coin(&b, 30_000)],
        vec![
            out(0, &wpkh(101), 40_001),
            out(1, &a, 7_777),
            out(2, &b, 8_888),
        ],
        &[&a, &b],
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        reasons(&findings[0]),
        vec![back_to_input(1, 7_777), back_to_input(2, 8_888)]
    );
    assert!(
        findings[0]
            .description
            .ends_with("(1 heuristic(s) matched)"),
        "{}",
        findings[0].description
    );
}

#[test]
fn a_self_transfer_back_to_the_input_addresses_claims_no_change() {
    let (a, b) = (wpkh(1), wpkh(2));
    let all_back = findings_for(
        vec![coin(&a, 30_000), coin(&b, 30_000)],
        vec![out(0, &a, 20_000), out(1, &b, 39_000)],
        &[&a, &b],
    );
    assert!(all_back.is_empty(), "{all_back:?}");

    let own_fresh = wpkh(3);
    let to_own = findings_for(
        vec![coin(&a, 30_000)],
        vec![out(0, &a, 2_107), out(1, &own_fresh, 27_000)],
        &[&a, &own_fresh],
    );
    assert!(to_own.is_empty(), "{to_own:?}");
}

#[test]
fn an_input_whose_parent_is_not_loaded_matches_no_output() {
    let (known, unknown) = (wpkh(1), wpkh(2));
    let mut missing = coin(&unknown, 30_000);
    missing.loaded = false;
    let findings = findings_for(
        vec![coin(&known, 30_000), missing],
        vec![out(0, &wpkh(101), 46_543), out(1, &unknown, 12_345)],
        &[&known, &unknown],
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn outputs_and_inputs_without_an_address_never_match() {
    let funded = wpkh(1);
    let findings = findings_for(
        vec![
            coin(&funded, 30_000),
            Coin {
                address: None,
                sats: 10_000,
                loaded: true,
            },
        ],
        vec![
            out(0, &wpkh(101), 26_543),
            op_return(1),
            out(2, &wpkh(2), 12_345),
        ],
        &[&funded, &wpkh(2)],
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn the_receiver_gets_no_finding_for_the_senders_change_back_to_its_input() {
    let (sender, user) = (wpkh(1), wpkh(2));
    let findings = findings_for(
        vec![coin(&sender, 60_000)],
        vec![out(0, &user, 46_543), out(1, &sender, 12_345)],
        &[&user],
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn change_back_to_the_input_gets_no_script_type_line_it_implies() {
    let funded = wpkh(1);
    let findings = findings_for(
        vec![coin(&funded, 50_000)],
        vec![out(0, &tr(101), 46_543), out(1, &funded, 2_107)],
        &[&funded],
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(reasons(&findings[0]), vec![back_to_input(1, 2_107)]);
    assert!(
        findings[0]
            .description
            .ends_with("(1 heuristic(s) matched)"),
        "{}",
        findings[0].description
    );
}

/// Toxic change findings for a 600-sat coin of `a` spent with a 50,000-sat coin of `big`.
fn toxic_findings(
    a: &Address<NetworkUnchecked>,
    big: &Address<NetworkUnchecked>,
    extra: Vec<Coin>,
    also_ours: &[&Address<NetworkUnchecked>],
) -> Vec<Finding> {
    let mut coins = vec![coin(a, 600), coin(big, 50_000)];
    coins.extend(extra);
    let mut ours = vec![a, big];
    ours.extend_from_slice(also_ours);
    let mut history = history_for(coins, vec![out(0, &wpkh(101), 40_000)], &ours);
    // The 600-sat coin is change from an earlier spend of a coin of `a`.
    let earlier = txid(50);
    history
        .transactions
        .insert(earlier, tx(earlier, vec![], vec![out(0, a, 100_000)]));
    history
        .wallet_txs
        .push(entry(earlier, Some(a), WalletTxCategory::Receive));
    if let Some(source) = history.transactions.get_mut(&txid(1)) {
        source.vin.push(TxInputRef {
            previous_txid: earlier,
            previous_vout: 0,
            sequence: 0xffff_fffd,
            coinbase: false,
        });
    }
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history)
        .detect_toxic_change(&DetectorThresholds::default(), &mut findings);
    findings
}

#[test]
fn small_change_merged_with_a_coin_at_another_address_is_toxic() {
    let findings = toxic_findings(&wpkh(1), &wpkh(2), vec![], &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn small_change_merged_with_a_coin_at_its_own_address_links_nothing_new() {
    let a = wpkh(1);
    let findings = toxic_findings(&a, &a, vec![], &[]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_strangers_input_does_not_make_one_address_toxic() {
    let a = wpkh(1);
    let findings = toxic_findings(&a, &a, vec![coin(&wpkh(200), 30_000)], &[]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_small_own_coin_elsewhere_does_not_make_a_same_address_merge_toxic() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = toxic_findings(&a, &a, vec![coin(&b, 3_000)], &[&b]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_larger_own_coin_elsewhere_still_makes_the_merge_toxic() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = toxic_findings(&a, &a, vec![coin(&b, 30_000)], &[&b]);
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn toxic_change_advice_is_for_next_time_and_offers_wabisabi_only_above_the_minimum() {
    let findings = toxic_findings(&wpkh(1), &wpkh(2), vec![], &[]);
    let correction = findings[0].correction.as_deref().expect("a correction");
    assert!(
        correction.starts_with("Freeze small change like this"),
        "{correction}"
    );
    assert!(correction.contains("from now on"), "{correction}");
    assert!(
        correction.contains("above a CoinJoin coordinator's minimum"),
        "{correction}"
    );
    assert!(correction.contains("WabiSabi"), "{correction}");
    for absent in [
        "spend it alone",
        "OP_RETURN",
        "bump fee",
        "PayJoin",
        "Lightning",
    ] {
        assert!(!correction.contains(absent), "{absent}: {correction}");
    }
}
