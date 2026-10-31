//! Unit tests for the address-reuse correction, against an in-memory wallet history.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid, WPubkeyHash};

use crate::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, WalletHistory, WalletTxCategory,
    WalletTxEntry,
};
use crate::graph::TxGraph;
use crate::types::VulnerabilityType;

const CHANGE_BACK: &str = "This address got change back from its own spends";

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

fn out(n: u32, address: Option<&Address<NetworkUnchecked>>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address: address.cloned(),
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

/// `reused` is funded, then a spend of that coin pays `vout`, one of which goes back to `reused`.
/// Returns the reuse correction for `reused`.
fn reuse_correction(
    vout: Vec<TxOutput>,
    ours: &[&Address<NetworkUnchecked>],
    parent_loaded: bool,
) -> String {
    let reused = wpkh(1);
    let (fund, spend) = (txid(1), txid(2));
    let mut wallet_txs = vec![
        entry(fund, Some(&reused), WalletTxCategory::Receive),
        entry(spend, None, WalletTxCategory::Send),
    ];
    for o in &vout {
        if let Some(addr) = o
            .address
            .as_ref()
            .filter(|a| *a == &reused || ours.contains(a))
        {
            wallet_txs.push(entry(spend, Some(addr), WalletTxCategory::Receive));
        }
    }
    let input = TxInputRef {
        previous_txid: fund,
        previous_vout: 0,
        sequence: 0xffff_fffd,
        coinbase: false,
    };
    let mut transactions = HashMap::from([(spend, tx(spend, vec![input], vout))]);
    if parent_loaded {
        transactions.insert(fund, tx(fund, vec![], vec![out(0, Some(&reused), 100_000)]));
    }
    let history = WalletHistory {
        wallet_txs,
        utxos: vec![],
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
    };
    let mut findings = Vec::new();
    TxGraph::from_wallet_history(history).detect_address_reuse(&mut findings);
    let reuse: Vec<_> = findings
        .into_iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::AddressReuse)
        .collect();
    assert_eq!(reuse.len(), 1, "{reuse:?}");
    reuse[0].correction.clone().unwrap_or_default()
}

#[test]
fn a_payment_with_change_back_to_its_input_address_gets_the_change_advice() {
    let correction = reuse_correction(
        vec![
            out(0, Some(&wpkh(101)), 60_000),
            out(1, Some(&wpkh(1)), 39_000),
        ],
        &[],
        true,
    );
    assert!(correction.starts_with(CHANGE_BACK), "{correction}");
}

#[test]
fn an_unloaded_parent_does_not_show_the_spend_came_from_the_address() {
    let correction = reuse_correction(
        vec![
            out(0, Some(&wpkh(101)), 60_000),
            out(1, Some(&wpkh(1)), 39_000),
        ],
        &[],
        false,
    );
    assert!(!correction.contains(CHANGE_BACK), "{correction}");
}

#[test]
fn an_output_with_no_address_is_not_a_payment_to_someone() {
    let correction = reuse_correction(
        vec![out(0, None, 0), out(1, Some(&wpkh(1)), 99_000)],
        &[],
        true,
    );
    assert!(!correction.contains(CHANGE_BACK), "{correction}");
}

#[test]
fn a_spend_paying_only_the_wallet_gets_no_change_advice() {
    let own = wpkh(2);
    let correction = reuse_correction(
        vec![out(0, Some(&own), 60_000), out(1, Some(&wpkh(1)), 39_000)],
        &[&own],
        true,
    );
    assert!(!correction.contains(CHANGE_BACK), "{correction}");
}
