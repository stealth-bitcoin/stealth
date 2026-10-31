//! Unit tests for input linkage, against an in-memory wallet history.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid, WPubkeyHash};

use crate::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, WalletHistory, WalletTxCategory,
    WalletTxEntry,
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
/// Unnecessary input findings for one spend of `coins` paying 20,000 sats to a stranger,
/// change to `change`, seen by a wallet owning `ours`.
fn unnecessary(
    coins: &[(&Address<NetworkUnchecked>, u64)],
    change: &Address<NetworkUnchecked>,
    ours: &[&Address<NetworkUnchecked>],
) -> Vec<Finding> {
    let spend = txid(100);
    let mut wallet_txs = vec![
        entry(spend, None, WalletTxCategory::Send),
        entry(spend, Some(change), WalletTxCategory::Receive),
    ];
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
    let vout = vec![
        out(0, &wpkh(101), 20_000),
        out(1, change, total - 20_000 - 1_000),
    ];
    transactions.insert(spend, tx(spend, vin, vout));
    let history = WalletHistory {
        wallet_txs,
        utxos: vec![],
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
    };
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history).detect_unnecessary_input(&mut findings);
    findings
}

#[test]
fn an_extra_input_from_another_address_is_unnecessary() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = unnecessary(&[(&a, 1_000_000), (&b, 50_000)], &a, &[&a, &b]);
    assert_eq!(findings.len(), 1, "{findings:?}");
}

#[test]
fn extra_inputs_from_the_same_address_link_nothing_new() {
    let a = wpkh(1);
    let findings = unnecessary(&[(&a, 1_000_000), (&a, 600), (&a, 600)], &a, &[&a]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_strangers_input_does_not_make_one_address_unnecessary() {
    let a = wpkh(1);
    let stranger = wpkh(200);
    let findings = unnecessary(
        &[(&a, 1_000_000), (&a, 600), (&stranger, 30_000)],
        &a,
        &[&a],
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_second_input_at_the_sufficient_inputs_address_is_not_counted_as_unnecessary() {
    let (a, b) = (wpkh(1), wpkh(2));
    let findings = unnecessary(&[(&a, 1_000_000), (&a, 600), (&b, 50_000)], &a, &[&a, &b]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert!(
        f.description.contains("has 1 unnecessary input(s)"),
        "{}",
        f.description
    );
    let details = f.details.as_ref().expect("details");
    assert_eq!(details["unnecessary_count"], 1);
    assert_eq!(details["total_inputs_used"], 3);
}

#[test]
fn the_unnecessary_count_does_not_depend_on_input_order() {
    // Both role assignments, so a tie-break on the address string cannot pass by luck.
    for (a, b) in [(wpkh(1), wpkh(2)), (wpkh(2), wpkh(1))] {
        // B holds two of the inputs, so its coin is the one to keep, even when A's is larger.
        for a_sats in [100_000_000, 120_000_000] {
            let orders: [&[(&Address<NetworkUnchecked>, u64)]; 2] = [
                &[(&a, a_sats), (&b, 100_000_000), (&b, 10_000_000)],
                &[(&b, 100_000_000), (&b, 10_000_000), (&a, a_sats)],
            ];
            for coins in orders {
                let findings = unnecessary(coins, &a, &[&a, &b]);
                assert_eq!(findings.len(), 1, "{findings:?}");
                let details = findings[0].details.as_ref().expect("details");
                assert_eq!(details["unnecessary_count"], 1, "{details}");
                assert_eq!(
                    details["sufficient_input"]["address"],
                    b.assume_checked_ref().to_string()
                );
            }
        }
    }
}
