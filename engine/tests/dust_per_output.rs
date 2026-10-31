// In-memory tests: findings about outputs must tell apart two outputs of one
// transaction paid to the same address.
//
// Shape taken from mainnet tx 69ab1020…5f6c: outputs :0 and :1 (600 sats
// each) pay one address, and both are later spent with a larger coin.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid, WitnessProgram, WitnessVersion};
use stealth_engine::config::DetectorThresholds;
use stealth_engine::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, Utxo, WalletHistory,
    WalletTxCategory, WalletTxEntry,
};
use stealth_engine::{Finding, TxGraph, VulnerabilityType};

fn txid(n: u64) -> Txid {
    format!("{:0<64x}", n).parse().expect("valid txid hex")
}

fn tr(seed: u8) -> Address<NetworkUnchecked> {
    let program = WitnessProgram::new(WitnessVersion::V1, &[seed; 32]).expect("32-byte v1 program");
    let script = ScriptBuf::new_witness_program(&program);
    Address::from_script(&script, Network::Regtest)
        .expect("script encodes to an address")
        .to_string()
        .parse::<Address<NetworkUnchecked>>()
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

fn out(n: u32, addr: &Address<NetworkUnchecked>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address: Some(addr.clone()),
        value: Amount::from_sat(sats),
        script_type: DescriptorType::P2tr,
    }
}

fn tx(id: Txid, vins: Vec<TxInputRef>, vouts: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: id,
        vin: vins,
        vout: vouts,
        version: 2,
        locktime: 0,
        vsize: 200,
        confirmations: 3,
    }
}

fn entry(
    id: Txid,
    addr: Option<&Address<NetworkUnchecked>>,
    category: WalletTxCategory,
    sats: u64,
) -> WalletTxEntry {
    WalletTxEntry {
        txid: id,
        address: addr.cloned(),
        category,
        amount: Amount::from_sat(sats),
        confirmations: 3,
        blockheight: 100,
    }
}

const FUNDING: u64 = 0x41;
const PARENT: u64 = 0x42;
const CHILD: u64 = 0x43;

/// Funding tx pays `own`; the parent spends it into two 600-sat outputs
/// (:0, :1) and a larger one (:3), all at `own`. When `spend_vout1` is
/// false, :1 stays unspent; otherwise the child spends :0, :1 and :3.
fn history(spend_vout1: bool) -> WalletHistory {
    let own = tr(1);
    let ext = tr(200);
    let (funding, parent, child) = (txid(FUNDING), txid(PARENT), txid(CHILD));

    let mut child_inputs = vec![vin(parent, 0), vin(parent, 3)];
    if spend_vout1 {
        child_inputs.insert(1, vin(parent, 1));
    }
    let txs = vec![
        tx(
            funding,
            vec![vin(txid(0x11), 0)],
            vec![out(0, &own, 2_000_000)],
        ),
        tx(
            parent,
            vec![vin(funding, 0)],
            vec![
                out(0, &own, 600),
                out(1, &own, 600),
                out(2, &ext, 1_000_000),
                out(3, &own, 990_000),
            ],
        ),
        tx(child, child_inputs, vec![out(0, &ext, 985_000)]),
    ];
    let transactions: HashMap<Txid, DecodedTransaction> =
        txs.into_iter().map(|t| (t.txid, t)).collect();

    let utxos = if spend_vout1 {
        Vec::new()
    } else {
        vec![Utxo {
            txid: parent,
            vout: 1,
            address: Some(own.clone()),
            amount: Amount::from_sat(600),
            confirmations: 3,
            script_type: DescriptorType::P2tr,
        }]
    };

    WalletHistory {
        wallet_txs: vec![
            entry(funding, Some(&own), WalletTxCategory::Receive, 2_000_000),
            entry(parent, None, WalletTxCategory::Send, 0),
            entry(child, None, WalletTxCategory::Send, 0),
        ],
        utxos,
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([own]),
        ranged_addresses: HashSet::new(),
    }
}

fn findings(history: WalletHistory, kind: VulnerabilityType) -> Vec<Finding> {
    TxGraph::from_wallet_history(history)
        .detect_all(&DetectorThresholds::default(), None, None)
        .findings
        .into_iter()
        .filter(|f| f.vulnerability_type == kind)
        .collect()
}

/// (status, vout) of each dust finding on the parent tx, sorted.
fn parent_dust(history: WalletHistory) -> Vec<(String, u64)> {
    let parent = txid(PARENT).to_string();
    let mut found: Vec<(String, u64)> = findings(history, VulnerabilityType::Dust)
        .iter()
        .filter_map(|f| f.details.as_ref())
        .filter(|d| d["txid"].as_str() == Some(parent.as_str()))
        .map(|d| {
            (
                d["status"].as_str().unwrap_or_default().to_string(),
                d["vout"].as_u64().unwrap_or(u64::MAX),
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn two_spent_dust_outputs_at_one_address_are_two_findings() {
    assert_eq!(
        parent_dust(history(true)),
        vec![("spent".to_string(), 0), ("spent".to_string(), 1)],
    );
}

#[test]
fn spent_dust_is_not_hidden_by_unspent_sibling_at_same_address() {
    assert_eq!(
        parent_dust(history(false)),
        vec![("spent".to_string(), 0), ("unspent".to_string(), 1)],
    );
}

#[test]
fn toxic_change_findings_name_their_output() {
    let toxic = findings(history(true), VulnerabilityType::ToxicChange);
    let mut vouts: Vec<u64> = toxic
        .iter()
        .filter_map(|f| f.details.as_ref())
        .filter_map(|d| d["change_vout"].as_u64())
        .collect();
    vouts.sort();
    assert_eq!(vouts, vec![0, 1]);

    assert_eq!(toxic.len(), 2);
    assert_ne!(toxic[0].description, toxic[1].description);
    assert_ne!(toxic[0].details, toxic[1].details);
}
