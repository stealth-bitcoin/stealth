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

const CHANGE_BACK: &str = "Your own spends sent change to this address";

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

/// `reused` (`wpkh(1)`) is paid once, then a spend of one coin at `spent` pays `vout`, both
/// confirmed 3 times. The wallet owns `reused` and `ours`. Returns the reuse correction for `reused`.
fn reuse_correction(
    spent: &Address<NetworkUnchecked>,
    vout: Vec<TxOutput>,
    ours: &[&Address<NetworkUnchecked>],
    parent_loaded: bool,
) -> String {
    reuse_correction_at(spent, vout, ours, parent_loaded, 3, 3)
}

/// Like `reuse_correction`, with the other payment to `reused` at `other_confs`
/// confirmations and the spend at `spend_confs`.
fn reuse_correction_at(
    spent: &Address<NetworkUnchecked>,
    vout: Vec<TxOutput>,
    ours: &[&Address<NetworkUnchecked>],
    parent_loaded: bool,
    other_confs: u32,
    spend_confs: u32,
) -> String {
    let reused = wpkh(1);
    let owned = |a: &Address<NetworkUnchecked>| *a == reused || ours.contains(&a);
    let (fund, spend, earlier) = (txid(1), txid(2), txid(3));
    let mut wallet_txs = vec![entry(earlier, Some(&reused), WalletTxCategory::Receive)];
    if owned(spent) {
        wallet_txs.push(entry(fund, Some(spent), WalletTxCategory::Receive));
        wallet_txs.push(entry(spend, None, WalletTxCategory::Send));
    }
    for o in &vout {
        if let Some(addr) = o.address.as_ref().filter(|a| owned(a)) {
            wallet_txs.push(entry(spend, Some(addr), WalletTxCategory::Receive));
        }
    }
    let input = TxInputRef {
        previous_txid: fund,
        previous_vout: 0,
        sequence: 0xffff_fffd,
        coinbase: false,
    };
    for e in &mut wallet_txs {
        e.confirmations = if e.txid == earlier {
            other_confs
        } else {
            spend_confs
        };
    }
    let mut transactions = HashMap::from([
        (spend, tx(spend, vec![input], vout)),
        (
            earlier,
            tx(earlier, vec![], vec![out(0, Some(&reused), 50_000)]),
        ),
    ]);
    if parent_loaded {
        transactions.insert(fund, tx(fund, vec![], vec![out(0, Some(spent), 100_000)]));
    }
    let history = WalletHistory {
        wallet_txs,
        utxos: vec![],
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
        left_out: Default::default(),
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
        &wpkh(1),
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
fn an_unloaded_parent_does_not_show_the_user_made_the_spend() {
    let correction = reuse_correction_at(
        &wpkh(1),
        vec![
            out(0, Some(&wpkh(101)), 60_000),
            out(1, Some(&wpkh(1)), 39_000),
        ],
        &[],
        false,
        5,
        3,
    );
    assert!(!correction.contains(CHANGE_BACK), "{correction}");
}

#[test]
fn an_output_with_no_address_is_not_a_payment_to_someone() {
    let correction = reuse_correction(
        &wpkh(1),
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
        &wpkh(1),
        vec![out(0, Some(&own), 60_000), out(1, Some(&wpkh(1)), 39_000)],
        &[&own],
        true,
    );
    assert!(!correction.contains(CHANGE_BACK), "{correction}");
}

/// A spend from another of the wallet's addresses, paying outside with change to `reused`.
fn change_from_another_address(other_confs: u32, spend_confs: u32) -> String {
    let other = wpkh(2);
    reuse_correction_at(
        &other,
        vec![
            out(0, Some(&wpkh(101)), 60_000),
            out(1, Some(&wpkh(1)), 39_000),
        ],
        &[&other],
        true,
        other_confs,
        spend_confs,
    )
}

#[test]
fn change_landing_on_an_address_that_already_received_gets_the_change_advice() {
    let correction = change_from_another_address(5, 3);
    assert!(correction.starts_with(CHANGE_BACK), "{correction}");
    let unconfirmed_change = change_from_another_address(1, 0);
    assert!(
        unconfirmed_change.starts_with(CHANGE_BACK),
        "{unconfirmed_change}"
    );
}

#[test]
fn change_to_a_fresh_address_that_was_paid_later_keeps_the_plain_correction() {
    let correction = change_from_another_address(1, 3);
    assert!(!correction.contains(CHANGE_BACK), "{correction}");
}

#[test]
fn change_and_a_payment_with_no_known_order_keep_the_plain_correction() {
    let same_block = change_from_another_address(3, 3);
    assert!(!same_block.contains(CHANGE_BACK), "{same_block}");
    let both_unconfirmed = change_from_another_address(0, 0);
    assert!(
        !both_unconfirmed.contains(CHANGE_BACK),
        "{both_unconfirmed}"
    );
}

#[test]
fn a_payment_from_someone_else_with_their_change_is_no_change_of_ours() {
    let correction = reuse_correction_at(
        &wpkh(50),
        vec![
            out(0, Some(&wpkh(1)), 60_000),
            out(1, Some(&wpkh(50)), 39_000),
        ],
        &[],
        true,
        5,
        3,
    );
    assert!(!correction.contains(CHANGE_BACK), "{correction}");
}
