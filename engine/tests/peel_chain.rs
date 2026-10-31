// Peel-chain detection against in-memory wallet histories.
//
// Runs entirely in memory; no bitcoind node required. Detectors visit the
// wallet's transactions in txid order, so the txid numbers below decide
// whether a chain's head or one of its tails is seen first.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Network, PubkeyHash, ScriptBuf, Txid, WPubkeyHash};
use stealth_engine::config::DetectorThresholds;
use stealth_engine::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, WalletHistory, WalletTxCategory,
    WalletTxEntry,
};
use stealth_engine::{Finding, Severity, TxGraph, VulnerabilityType};

// ─── builders ───────────────────────────────────────────────────────────────

fn txid(n: u8) -> Txid {
    format!("{n:064x}").parse().expect("valid txid hex")
}

fn parse_addr(script: ScriptBuf) -> Address<NetworkUnchecked> {
    Address::from_script(&script, Network::Regtest)
        .expect("script encodes to an address")
        .to_string()
        .parse()
        .expect("valid regtest address string")
}

// Our addresses are P2WPKH and external ones P2PKH, both seeded by txid.
fn ours(n: u8) -> Address<NetworkUnchecked> {
    parse_addr(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
        [n; 20],
    )))
}

fn external(n: u8) -> Address<NetworkUnchecked> {
    parse_addr(ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([n; 20])))
}

fn out(n: u32, addr: Address<NetworkUnchecked>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address: Some(addr),
        value: Amount::from_sat(sats),
        script_type: DescriptorType::P2wpkh,
    }
}

fn tx(id: u8, vins: &[(u8, u32)], vouts: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: txid(id),
        vin: vins
            .iter()
            .map(|&(prev, vout)| TxInputRef {
                previous_txid: txid(prev),
                previous_vout: vout,
                sequence: 0xffff_fffd,
                coinbase: false,
            })
            .collect(),
        vout: vouts,
        version: 2,
        locktime: 0,
        vsize: 141,
        confirmations: 3,
    }
}

/// A transaction paying `sats` to us from an outside, unknown parent.
fn funding(id: u8, sats: u64) -> DecodedTransaction {
    tx(id, &[(0xFF, 0)], vec![out(0, ours(id), sats)])
}

/// A peel: spends `prev`, pays a small amount out on vout 0 and keeps the
/// large change on vout 1.
fn peel(id: u8, prev: &[(u8, u32)], small: u64, large: u64) -> DecodedTransaction {
    tx(
        id,
        prev,
        vec![out(0, external(id), small), out(1, ours(id), large)],
    )
}

/// A peel whose small output also comes back to us, on `small_addr`.
fn peel_to_self(
    id: u8,
    prev: (u8, u32),
    small_addr: u8,
    small: u64,
    large: u64,
) -> DecodedTransaction {
    tx(
        id,
        &[prev],
        vec![out(0, ours(small_addr), small), out(1, ours(id), large)],
    )
}

/// A linear chain: `fund` pays us, each id in `hops` spends the change of
/// the one before it.
fn chain(fund: u8, hops: &[u8]) -> Vec<DecodedTransaction> {
    let mut txs = vec![funding(fund, 100_000_000)];
    let mut prev = (fund, 0);
    let mut balance = 100_000_000u64;
    for &id in hops {
        balance -= 2_000_000;
        txs.push(peel(id, &[prev], 1_000_000, balance));
        prev = (id, 1);
    }
    txs
}

fn history(txs: Vec<DecodedTransaction>) -> WalletHistory {
    let mut wallet_txs = Vec::new();
    let mut derived_addresses = HashSet::new();
    for t in &txs {
        for o in &t.vout {
            if let Some(addr) = &o.address {
                if (0..=u8::MAX).any(|seed| *addr == ours(seed)) {
                    derived_addresses.insert(addr.clone());
                }
            }
        }
        wallet_txs.push(WalletTxEntry {
            txid: t.txid,
            address: None,
            category: WalletTxCategory::Send,
            amount: Amount::from_sat(0),
            confirmations: 3,
            blockheight: 100,
        });
    }
    WalletHistory {
        wallet_txs,
        utxos: Vec::new(),
        transactions: txs
            .into_iter()
            .map(|t| (t.txid, t))
            .collect::<HashMap<_, _>>(),
        internal_addresses: HashSet::new(),
        derived_addresses,
        ranged_addresses: HashSet::new(),
    }
}

fn peel_findings(txs: Vec<DecodedTransaction>) -> Vec<Finding> {
    let graph = TxGraph::from_wallet_history(history(txs));
    graph
        .detect_all(&DetectorThresholds::default(), None, None)
        .findings
        .into_iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::PeelChain)
        .collect()
}

fn start(f: &Finding) -> String {
    f.details.as_ref().expect("details")["start_txid"]
        .as_str()
        .expect("start_txid is a string")
        .to_string()
}

fn hops(f: &Finding) -> u64 {
    f.details.as_ref().expect("details")["hops"]
        .as_u64()
        .expect("hops is a number")
}

fn chain_txids(f: &Finding) -> Vec<String> {
    f.details.as_ref().expect("details")["txids"]
        .as_array()
        .expect("txids is an array")
        .iter()
        .map(|v| v.as_str().expect("txid is a string").to_string())
        .collect()
}

fn ids(ns: &[u8]) -> Vec<String> {
    ns.iter().map(|&n| txid(n).to_string()).collect()
}

fn starts(findings: &[Finding]) -> Vec<String> {
    let mut s: Vec<String> = findings.iter().map(start).collect();
    s.sort();
    s
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[test]
fn a_chain_and_its_tails_are_one_finding_naming_every_hop() {
    // The mainnet shape: a four-hop chain whose three-, two- and one-hop
    // tails are also peel-shaped and spent by the wallet.
    let findings = peel_findings(chain(0x10, &[0x11, 0x12, 0x13, 0x14]));
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(start(f), txid(0x11).to_string());
    assert_eq!(hops(f), 4);
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(chain_txids(f), ids(&[0x11, 0x12, 0x13, 0x14]));
}

#[test]
fn the_tails_are_dropped_when_they_are_visited_before_the_head() {
    // Txids count down along the chain, so the shortest tail is seen first.
    let findings = peel_findings(chain(0x10, &[0x24, 0x23, 0x22, 0x21]));
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(start(f), txid(0x24).to_string());
    assert_eq!(hops(f), 4);
    assert_eq!(chain_txids(f), ids(&[0x24, 0x23, 0x22, 0x21]));
}

#[test]
fn the_tails_are_dropped_when_the_head_is_visited_in_the_middle() {
    let findings = peel_findings(chain(0x10, &[0x32, 0x34, 0x31, 0x33]));
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(chain_txids(&findings[0]), ids(&[0x32, 0x34, 0x31, 0x33]));
}

#[test]
fn a_three_hop_chain_stays_high() {
    let findings = peel_findings(chain(0x10, &[0x11, 0x12, 0x13]));
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(hops(&findings[0]), 3);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn two_independent_chains_are_two_findings() {
    let mut txs = chain(0x10, &[0x11, 0x12, 0x13]);
    txs.extend(chain(0x40, &[0x41, 0x42, 0x43, 0x44]));
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert_eq!(starts(&findings), ids(&[0x11, 0x41]));
    for f in &findings {
        let expected = if start(f) == txid(0x11).to_string() {
            ids(&[0x11, 0x12, 0x13])
        } else {
            ids(&[0x41, 0x42, 0x43, 0x44])
        };
        assert_eq!(chain_txids(f), expected);
    }
}

#[test]
fn a_chain_that_splits_off_its_peeled_output_is_two_findings() {
    // 0x51 peels to our own 0x60 address and carries on with its change to
    // 0x52 and 0x53; the peeled output then starts its own chain 0x61, 0x62.
    let txs = vec![
        funding(0x50, 100_000_000),
        peel_to_self(0x51, (0x50, 0), 0x60, 20_000_000, 79_000_000),
        peel(0x52, &[(0x51, 1)], 1_000_000, 77_000_000),
        peel(0x53, &[(0x52, 1)], 1_000_000, 75_000_000),
        tx(
            0x61,
            &[(0x51, 0)],
            vec![
                out(0, external(0x61), 1_000_000),
                out(1, ours(0x61), 18_000_000),
            ],
        ),
        peel(0x62, &[(0x61, 1)], 1_000_000, 16_000_000),
    ];
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert_eq!(starts(&findings), ids(&[0x51, 0x61]));
    for f in &findings {
        let expected = if start(f) == txid(0x51).to_string() {
            ids(&[0x51, 0x52, 0x53])
        } else {
            ids(&[0x61, 0x62])
        };
        assert_eq!(chain_txids(f), expected);
    }
}

#[test]
fn two_chains_that_merge_into_one_tail_are_both_reported() {
    // 0x71 and 0x81 peel separately, then one transaction spends both of
    // their change outputs and the chain carries on as one.
    let txs = vec![
        funding(0x70, 100_000_000),
        funding(0x80, 50_000_000),
        peel(0x71, &[(0x70, 0)], 1_000_000, 98_000_000),
        peel(0x81, &[(0x80, 0)], 1_000_000, 48_000_000),
        peel(0x72, &[(0x71, 1), (0x81, 1)], 2_000_000, 143_000_000),
        peel(0x73, &[(0x72, 1)], 2_000_000, 140_000_000),
    ];
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert_eq!(starts(&findings), ids(&[0x71, 0x81]));
    for f in &findings {
        let head = if start(f) == txid(0x71).to_string() {
            0x71
        } else {
            0x81
        };
        assert_eq!(chain_txids(f), ids(&[head, 0x72, 0x73]));
    }
}

#[test]
fn a_chain_longer_than_the_hop_limit_is_still_one_finding() {
    let findings = peel_findings(chain(
        0x10,
        &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
    ));
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let max = DetectorThresholds::default().peel_chain_max_hops;
    assert_eq!(hops(&findings[0]), u64::from(max));
    assert_eq!(start(&findings[0]), txid(0x11).to_string());
}

#[test]
fn a_tail_is_dropped_even_when_the_hop_before_it_cannot_start_a_chain() {
    // 0x92 has three inputs, so no chain starts there, but it is still a hop
    // of the chain from 0x91 and 0x93 is still that chain's tail.
    let txs = vec![
        funding(0x90, 100_000_000),
        funding(0xA0, 1_000_000),
        funding(0xA1, 1_000_000),
        peel(0x91, &[(0x90, 0)], 1_000_000, 98_000_000),
        peel(
            0x92,
            &[(0x91, 1), (0xA0, 0), (0xA1, 0)],
            1_000_000,
            98_000_000,
        ),
        peel(0x93, &[(0x92, 1)], 1_000_000, 96_000_000),
        peel(0x94, &[(0x93, 1)], 1_000_000, 94_000_000),
    ];
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(chain_txids(&findings[0]), ids(&[0x91, 0x92, 0x93, 0x94]));
}
