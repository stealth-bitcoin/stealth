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
use crate::types::Finding;

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

fn dust_spending(history: WalletHistory) -> Vec<Finding> {
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history)
        .detect_dust_spending(&DetectorThresholds::default(), &mut findings);
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
fn a_strangers_input_does_not_make_one_address_dust_spending() {
    let a = wpkh(1);
    let stranger = wpkh(200);
    let findings = dust_spending(spend_of(
        &[(&a, 546), (&a, 44_980), (&stranger, 30_000)],
        &[&a],
    ));
    assert!(findings.is_empty(), "{findings:?}");
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
        "a 546-sat coin pays about 6 sat/vB",
        // With no runestone or other output, runes are burned, not paid to the miner.
        "an ordinals inscription goes to the miner and runes are burned; either way they are lost",
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
