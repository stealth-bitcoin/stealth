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
    toxic_findings_of(600, a, big, extra, also_ours)
}

/// As [`toxic_findings`], with `change_sats` of change instead of 600.
fn toxic_findings_of(
    change_sats: u64,
    a: &Address<NetworkUnchecked>,
    big: &Address<NetworkUnchecked>,
    extra: Vec<Coin>,
    also_ours: &[&Address<NetworkUnchecked>],
) -> Vec<Finding> {
    toxic_findings_with(change_sats, 50_000, a, big, extra, also_ours)
}

/// As [`toxic_findings_of`], with `big_sats` at `big` instead of 50,000.
fn toxic_findings_with(
    change_sats: u64,
    big_sats: u64,
    a: &Address<NetworkUnchecked>,
    big: &Address<NetworkUnchecked>,
    extra: Vec<Coin>,
    also_ours: &[&Address<NetworkUnchecked>],
) -> Vec<Finding> {
    toxic_run_partial(toxic_history(
        change_sats,
        big_sats,
        a,
        big,
        extra,
        also_ours,
    ))
}

/// Toxic change findings from a wallet or descriptor scan, which knows the wallet.
fn toxic_run(history: WalletHistory) -> Vec<Finding> {
    toxic_run_in(history, false)
}

/// Toxic change findings from a partial scan, which knows only the given addresses.
fn toxic_run_partial(history: WalletHistory) -> Vec<Finding> {
    toxic_run_in(history, true)
}

fn toxic_run_in(history: WalletHistory, partial: bool) -> Vec<Finding> {
    let mut graph = TxGraph::from_wallet_history(history);
    graph.partial_scan = partial;
    let mut findings = Vec::new();
    graph.detect_toxic_change(&DetectorThresholds::default(), &mut findings);
    findings
}

/// The history behind [`toxic_findings_with`], from a scan that knows only the given addresses.
fn toxic_history(
    change_sats: u64,
    big_sats: u64,
    a: &Address<NetworkUnchecked>,
    big: &Address<NetworkUnchecked>,
    extra: Vec<Coin>,
    also_ours: &[&Address<NetworkUnchecked>],
) -> WalletHistory {
    let mut coins = vec![coin(a, change_sats), coin(big, big_sats)];
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
    history
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
fn a_strangers_input_does_not_make_one_address_toxic_in_a_descriptor_scan() {
    let a = wpkh(1);
    let mut history = toxic_history(600, 50_000, &a, &a, vec![coin(&wpkh(200), 30_000)], &[]);
    // A ranged descriptor derived `a`, so the scan knows the wallet's other addresses.
    history.ranged_addresses = HashSet::from([a.clone()]);
    let findings = toxic_run(history);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_partial_scan_names_an_unattributed_input_as_possibly_tied() {
    let a = wpkh(1);
    let b = wpkh(200);
    let text = |x: &Address<NetworkUnchecked>| x.assume_checked_ref().to_string();
    let findings = toxic_findings(&a, &a, vec![coin(&b, 30_000)], &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert_eq!(f.severity, crate::types::Severity::Medium, "{f:?}");
    assert!(
        f.description.contains(&format!(
            "which ties {} to the change's address {}, if that address is yours",
            text(&b),
            text(&a)
        )),
        "{}",
        f.description
    );
    let details = f.details.as_ref().expect("details");
    assert_eq!(details["tied_addresses"], serde_json::json!([]));
    assert_eq!(
        details["possibly_tied_addresses"],
        serde_json::json!([text(&b)])
    );
}

#[test]
fn a_partial_scan_keeps_a_known_tie_high_and_adds_the_unattributed_one() {
    let (a, b, c) = (wpkh(1), wpkh(2), wpkh(200));
    let text = |x: &Address<NetworkUnchecked>| x.assume_checked_ref().to_string();
    let findings = toxic_findings(&a, &b, vec![coin(&c, 30_000)], &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert_eq!(f.severity, crate::types::Severity::High, "{f:?}");
    assert!(
        f.description.contains(&format!(
            "which ties {} to the change's address {}; it also ties {} to it, if that address is yours",
            text(&b),
            text(&a),
            text(&c)
        )),
        "{}",
        f.description
    );
}

#[test]
fn a_small_own_coin_elsewhere_ties_its_address_to_the_change() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = toxic_findings(&a, &a, vec![coin(&b, 3_000)], &[&b]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_ties(&findings[0], &a, &[&b]);
}

/// The finding names `change` as the change's address and `tied` as the addresses tied to it,
/// and does not claim two transactions were newly linked.
fn assert_ties(
    finding: &Finding,
    change: &Address<NetworkUnchecked>,
    tied: &[&Address<NetworkUnchecked>],
) {
    let text = |a: &Address<NetworkUnchecked>| a.assume_checked_ref().to_string();
    let tied_list = tied.iter().map(|a| text(a)).collect::<Vec<_>>().join(", ");
    assert!(
        finding.description.contains(&format!(
            "ties {tied_list} to the change's address {}",
            text(change)
        )),
        "{}",
        finding.description
    );
    assert!(
        !finding.description.contains("linking both transactions"),
        "{}",
        finding.description
    );
    let details = finding.details.as_ref().expect("details");
    let listed: Vec<String> = details["tied_addresses"]
        .as_array()
        .expect("tied addresses")
        .iter()
        .filter_map(|a| a.as_str().map(String::from))
        .collect();
    assert_eq!(listed, tied.iter().map(|a| text(a)).collect::<Vec<_>>());
}

#[test]
fn a_larger_coin_at_another_address_is_named_as_tied() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = toxic_findings(&a, &b, vec![], &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_ties(&findings[0], &a, &[&b]);
}

#[test]
fn small_own_coins_elsewhere_with_no_larger_coin_are_not_toxic() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = toxic_findings_with(600, 3_000, &a, &b, vec![], &[]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_larger_own_coin_elsewhere_still_makes_the_merge_toxic() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = toxic_findings(&a, &a, vec![coin(&b, 30_000)], &[&b]);
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn toxic_change_advice_is_for_next_time_and_suggests_no_coinjoin() {
    // A coordinator's 5,000-sat minimum applies to outputs too, so change this small cannot
    // come out of a round alone.
    for change in [wpkh(1), tr(1)] {
        for sats in [546, 600, 1_000, 5_000, 10_000] {
            let findings = toxic_findings_of(sats, &change, &wpkh(2), vec![], &[]);
            let correction = findings[0].correction.as_deref().expect("a correction");
            assert!(
                correction.starts_with("Freeze small change like this"),
                "{correction}"
            );
            assert!(correction.contains("from now on"), "{correction}");
            assert!(correction.contains("never merge it"), "{correction}");
            for absent in [
                "CoinJoin",
                "WabiSabi",
                "spend it alone",
                "OP_RETURN",
                "bump fee",
                "PayJoin",
                "Lightning",
            ] {
                assert!(
                    !correction.contains(absent),
                    "{sats} {absent}: {correction}"
                );
            }
        }
    }
}

#[test]
fn a_wallet_scan_does_not_count_a_stranger_next_to_change_at_a_non_ranged_own_address() {
    let a = wpkh(1);
    let mut history = toxic_history(600, 50_000, &a, &a, vec![coin(&wpkh(200), 30_000)], &[]);
    // The wallet has a ranged descriptor, but `a` comes from an imported, non-ranged one.
    history.ranged_addresses = HashSet::from([wpkh(99)]);
    let findings = toxic_run(history);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_partial_scan_lets_an_unattributed_coin_be_the_larger_one() {
    let (a, b) = (wpkh(1), wpkh(200));
    let findings = toxic_findings_with(600, 3_000, &a, &a, vec![coin(&b, 50_000)], &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert_eq!(f.severity, crate::types::Severity::Medium, "{f:?}");
    assert!(
        f.description.contains("if that address is yours"),
        "{}",
        f.description
    );
    let details = f.details.as_ref().expect("details");
    assert_eq!(
        details["possibly_tied_addresses"],
        serde_json::json!([b.assume_checked_ref().to_string()])
    );
}

#[test]
fn a_full_scan_does_not_let_a_strangers_coin_be_the_larger_one() {
    let (a, b) = (wpkh(1), wpkh(200));
    let mut history = toxic_history(600, 3_000, &a, &a, vec![coin(&b, 50_000)], &[]);
    history.ranged_addresses = HashSet::from([a.clone()]);
    let findings = toxic_run(history);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn two_unattributed_addresses_get_the_plural_wording() {
    let a = wpkh(1);
    let findings = toxic_findings(
        &a,
        &a,
        vec![coin(&wpkh(200), 30_000), coin(&wpkh(201), 30_000)],
        &[],
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0]
            .description
            .contains("if those addresses are yours"),
        "{}",
        findings[0].description
    );
}

#[test]
fn a_known_tie_with_only_an_unattributed_larger_coin_is_medium() {
    let (a, b, c) = (wpkh(1), wpkh(2), wpkh(200));
    let findings = toxic_findings_with(600, 3_000, &a, &b, vec![coin(&c, 50_000)], &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        findings[0].severity,
        crate::types::Severity::Medium,
        "{:?}",
        findings[0]
    );
}

/// 600 sats of change at `a` spent with 50,000 sats at `a` and 30,000 sats from each of `n`
/// unattributed addresses, into `vout`.
fn toxic_with_strangers(
    a: &Address<NetworkUnchecked>,
    n: u8,
    vout: Option<Vec<TxOutput>>,
) -> WalletHistory {
    let strangers = (0..n).map(|i| coin(&wpkh(150 + i), 30_000)).collect();
    let mut history = toxic_history(600, 50_000, a, a, strangers, &[]);
    if let (Some(vout), Some(spend)) = (vout, history.transactions.get_mut(&txid(100))) {
        spend.vout = vout;
    }
    history
}

fn equal_outputs(n: u32) -> Vec<TxOutput> {
    (0..n)
        .map(|i| out(i, &wpkh(220 + i as u8), 25_000))
        .collect()
}

#[test]
fn change_in_a_coinjoin_shaped_round_ties_no_unattributed_address() {
    let a = wpkh(1);
    let findings = toxic_run_partial(toxic_with_strangers(&a, 8, Some(equal_outputs(10))));
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn equal_outputs_with_two_unattributed_inputs_still_tie_them() {
    let a = wpkh(1);
    let findings = toxic_run_partial(toxic_with_strangers(&a, 2, Some(equal_outputs(4))));
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn a_coinjoin_shaped_round_lets_no_unattributed_coin_be_the_larger_one() {
    let a = wpkh(1);
    // Only the change is the user's; every larger coin is a participant's.
    let strangers = (0..8).map(|i| coin(&wpkh(150 + i), 30_000)).collect();
    let mut history = toxic_history(600, 3_000, &a, &a, strangers, &[]);
    if let Some(spend) = history.transactions.get_mut(&txid(100)) {
        spend.vout = equal_outputs(10);
    }
    let findings = toxic_run_partial(history);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_long_list_of_tied_addresses_is_capped_in_the_description() {
    let a = wpkh(1);
    let findings = toxic_run_partial(toxic_with_strangers(&a, 8, None));
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert!(
        f.description
            .contains(" and 3 more to the change's address"),
        "{}",
        f.description
    );
    let details = f.details.as_ref().expect("details");
    assert_eq!(
        details["possibly_tied_addresses"].as_array().map(Vec::len),
        Some(8)
    );
}

#[test]
fn a_full_scan_with_only_non_ranged_descriptors_does_not_count_strangers() {
    let a = wpkh(1);
    let findings = toxic_run(toxic_with_strangers(&a, 1, None));
    assert!(findings.is_empty(), "{findings:?}");
}
