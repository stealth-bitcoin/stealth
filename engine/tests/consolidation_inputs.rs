// How the consolidation detector counts inputs it cannot attribute.
//
// Runs entirely in memory; no bitcoind node required.

use std::collections::HashSet;

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid, WPubkeyHash};
use stealth_engine::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, Utxo, WalletHistory,
    WalletTxCategory, WalletTxEntry,
};
use stealth_engine::{Report, Severity, TxGraph, VulnerabilityType};

fn txid(n: u64) -> Txid {
    format!("{n:064x}").parse().expect("valid txid hex")
}

fn wpkh(seed: u8) -> Address<NetworkUnchecked> {
    let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20]));
    Address::from_script(&script, Network::Regtest)
        .expect("script encodes to an address")
        .to_string()
        .parse()
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

fn out(n: u32, address: Option<Address<NetworkUnchecked>>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address,
        value: Amount::from_sat(sats),
        script_type: DescriptorType::Unknown,
    }
}

fn tx(id: Txid, vin: Vec<TxInputRef>, vout: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: id,
        vin,
        vout,
        version: 2,
        locktime: 0,
        vsize: 300,
        confirmations: 3,
    }
}

// We receive a sweep of two addressless outputs (P2PK, bare multisig) and one
// output at someone else's address; every funding transaction is known.
fn sweep_of_addressless_prevouts(ranged: bool) -> WalletHistory {
    let ours = wpkh(1);
    let (funding_a, funding_b, sweep) = (txid(0xa1), txid(0xa2), txid(0xc0));
    let transactions = [
        tx(
            funding_a,
            vec![vin(txid(0x01), 0)],
            vec![out(0, None, 300_000), out(1, None, 300_000)],
        ),
        tx(
            funding_b,
            vec![vin(txid(0x02), 0)],
            vec![out(0, Some(wpkh(9)), 300_000)],
        ),
        tx(
            sweep,
            vec![vin(funding_a, 0), vin(funding_a, 1), vin(funding_b, 0)],
            vec![out(0, Some(ours.clone()), 890_000)],
        ),
    ];
    WalletHistory {
        wallet_txs: vec![WalletTxEntry {
            txid: sweep,
            address: Some(ours.clone()),
            category: WalletTxCategory::Receive,
            amount: Amount::from_sat(890_000),
            confirmations: 3,
            blockheight: 100,
        }],
        utxos: vec![Utxo {
            txid: sweep,
            vout: 0,
            address: Some(ours),
            amount: Amount::from_sat(890_000),
            confirmations: 3,
            script_type: DescriptorType::P2wpkh,
        }],
        transactions: transactions.into_iter().map(|t| (t.txid, t)).collect(),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: if ranged {
            HashSet::from([wpkh(1)])
        } else {
            HashSet::new()
        },
    }
}

// `ranged` says whether our coin's address came from a ranged descriptor.
fn scan(ranged: bool) -> Report {
    TxGraph::from_wallet_history(sweep_of_addressless_prevouts(ranged)).detect_all(
        &Default::default(),
        None,
        None,
    )
}

fn consolidation_count(report: &Report) -> usize {
    report
        .findings
        .iter()
        .chain(&report.warnings)
        .filter(|f| f.vulnerability_type == VulnerabilityType::Consolidation)
        .count()
}

#[test]
fn addressless_known_prevouts_are_not_unresolved_in_a_full_scan() {
    assert_eq!(consolidation_count(&scan(true)), 0);
}

#[test]
fn addressless_known_prevouts_count_as_unrecognised() {
    let report = scan(false);
    assert_eq!(consolidation_count(&report), 1);
    let warning = report
        .warnings
        .iter()
        .find(|w| w.vulnerability_type == VulnerabilityType::Consolidation)
        .expect("expected a consolidation warning");
    assert_eq!(warning.severity, Severity::Low);
    let details = warning.details.as_ref().expect("details");
    assert_eq!(details["our_inputs_in_consolidation"], 0);
    assert_eq!(details["unrecognised_inputs"], 3);
    assert_eq!(details["unresolved_inputs"], 0);
}
