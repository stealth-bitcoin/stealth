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
    wide_chain(fund, hops, &[])
}

/// Like `chain`, but each hop in `wide` also spends two more of our coins,
/// so it has three inputs and cannot start a chain of its own.
fn wide_chain(fund: u8, hops: &[u8], wide: &[u8]) -> Vec<DecodedTransaction> {
    let mut txs = vec![funding(fund, 100_000_000)];
    let mut prev = (fund, 0);
    let mut balance = 100_000_000u64;
    for &id in hops {
        balance -= 2_000_000;
        if wide.contains(&id) {
            let (a, b) = (id + 0x80, id + 0xC0);
            txs.push(funding(a, 1_000_000));
            txs.push(funding(b, 1_000_000));
            txs.push(peel(id, &[prev, (a, 0), (b, 0)], 1_000_000, balance));
        } else {
            txs.push(peel(id, &[prev], 1_000_000, balance));
        }
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
    peel_findings_with(txs, &DetectorThresholds::default())
}

fn peel_findings_with(
    txs: Vec<DecodedTransaction>,
    thresholds: &DetectorThresholds,
) -> Vec<Finding> {
    let graph = TxGraph::from_wallet_history(history(txs));
    graph
        .detect_all(thresholds, None, None)
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
fn a_chain_that_splits_off_its_peeled_output_is_one_finding() {
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
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(start(f), txid(0x51).to_string());
    assert_eq!(hops(f), 3);
    assert_eq!(chain_txids(f), ids(&[0x51, 0x52, 0x53, 0x61, 0x62]));
    assert_eq!(merged(f), Some(2));
}

#[test]
fn two_chains_that_merge_into_one_tail_are_one_finding() {
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
    // Both paths are 3 hops; the smaller start lists its path first.
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(start(f), txid(0x71).to_string());
    assert_eq!(hops(f), 3);
    assert_eq!(chain_txids(f), ids(&[0x71, 0x72, 0x73, 0x81]));
    assert_eq!(merged(f), Some(2));
    assert!(!truncated(f));
}

#[test]
fn a_merge_lists_the_longest_path_first() {
    // 0x31 to 0x23 is 4 hops, 0x21 to 0x23 only 3, so 0x31 leads although
    // its txid is larger.
    let txs = vec![
        funding(0x20, 100_000_000),
        funding(0x30, 100_000_000),
        peel(0x21, &[(0x20, 0)], 1_000_000, 98_000_000),
        peel(0x31, &[(0x30, 0)], 1_000_000, 98_000_000),
        peel(0x32, &[(0x31, 1)], 1_000_000, 96_000_000),
        peel(0x22, &[(0x21, 1), (0x32, 1)], 1_000_000, 190_000_000),
        peel(0x23, &[(0x22, 1)], 1_000_000, 188_000_000),
    ];
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(start(f), txid(0x31).to_string());
    assert_eq!(hops(f), 4);
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(chain_txids(f), ids(&[0x31, 0x32, 0x22, 0x23, 0x21]));
    assert_eq!(merged(f), Some(2));
}

#[test]
fn a_merge_under_a_lowered_bound_lists_at_most_that_many() {
    // 0x41 to 0x46 and 0x51, 0x52 into 0x43: 8 txs, longest path 6.
    let mut txs = vec![
        funding(0x40, 100_000_000),
        funding(0x50, 100_000_000),
        peel(0x41, &[(0x40, 0)], 1_000_000, 98_000_000),
        peel(0x42, &[(0x41, 1)], 1_000_000, 96_000_000),
        peel(0x51, &[(0x50, 0)], 1_000_000, 98_000_000),
        peel(0x52, &[(0x51, 1)], 1_000_000, 96_000_000),
        peel(0x43, &[(0x42, 1), (0x52, 1)], 1_000_000, 190_000_000),
    ];
    for id in 0x44..=0x46 {
        txs.push(peel(id, &[(id - 1, 1)], 1_000_000, 180_000_000));
    }
    let findings = peel_findings_with(txs.clone(), &bound_of_six());
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(hops(f), 6);
    assert!(!f.description.contains("at least"), "{}", f.description);
    assert_eq!(chain_txids(f), ids(&[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]));
    assert!(truncated(f), "two txs of the set are not listed");
    assert_eq!(merged(f), Some(2));

    let four = DetectorThresholds {
        peel_chain_max_hops: 4,
        ..DetectorThresholds::default()
    };
    let findings = peel_findings_with(txs, &four);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(hops(f), 4);
    assert!(
        f.description.contains("at least 4 hops"),
        "{}",
        f.description
    );
    assert_eq!(chain_txids(f), ids(&[0x41, 0x42, 0x43, 0x44]));
    assert!(truncated(f));
}

fn merged(f: &Finding) -> Option<u64> {
    f.details
        .as_ref()
        .expect("details")
        .get("merged_chains")
        .map(|v| v.as_u64().expect("merged_chains is a number"))
}

fn no_joins(f: &Finding) {
    assert!(f.details.as_ref().expect("details").get("joins").is_none());
}

// `truncated` is only in the details when it is true.
fn truncated(f: &Finding) -> bool {
    match f.details.as_ref().expect("details").get("truncated") {
        None => false,
        Some(v) => {
            assert_eq!(v.as_bool(), Some(true), "truncated is only emitted as true");
            true
        }
    }
}

fn assert_whole_chain(txs: Vec<DecodedTransaction>, hop_ids: &[u8]) {
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(hops(f), hop_ids.len() as u64);
    assert_eq!(chain_txids(f), ids(hop_ids));
    assert_eq!(start(f), txid(hop_ids[0]).to_string());
    assert_eq!(f.severity, Severity::Critical);
    assert!(!truncated(f));
    assert!(!f.description.contains("at least"), "{}", f.description);
}

const TWELVE: [u8; 12] = [
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
];

#[test]
fn a_chain_longer_than_the_hop_limit_is_one_finding_with_every_hop() {
    assert_whole_chain(chain(0x10, &TWELVE), &TWELVE);
}

#[test]
fn a_long_chain_is_whole_when_its_tails_are_visited_first() {
    let reversed: Vec<u8> = TWELVE.iter().rev().map(|n| n + 0x20).collect();
    assert_whole_chain(chain(0x10, &reversed), &reversed);
}

#[test]
fn a_long_chain_is_whole_when_the_hop_after_the_limit_cannot_start_a_chain() {
    // 0x17 is the first hop past the limit from 0x11; the trace from 0x12
    // reaches past it.
    assert_whole_chain(wide_chain(0x10, &TWELVE, &[0x17]), &TWELVE);
}

#[test]
fn a_chain_cut_by_the_hop_limit_says_it_has_at_least_that_many_hops() {
    let hops_ids = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
    let findings = peel_findings_with(chain(0x10, &hops_ids), &bound_of_six());
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(hops(f), 6);
    assert_eq!(chain_txids(f), ids(&hops_ids[..6]));
    assert!(truncated(f));
    assert!(
        f.description.contains("at least 6 hops"),
        "{}",
        f.description
    );
}

#[test]
fn a_long_chain_is_whole_when_only_the_hop_after_the_limit_starts_a_trace() {
    // 0x12 to 0x16 cannot start a chain, so the trace from 0x17 is the only
    // one past the limit, and it starts exactly where 0x11's trace was cut.
    assert_whole_chain(
        wide_chain(0x10, &TWELVE, &[0x12, 0x13, 0x14, 0x15, 0x16]),
        &TWELVE,
    );
}

#[test]
fn a_cycle_in_bad_data_does_not_hang_the_scan() {
    // Real spends cannot form a cycle; 0x62 and 0x63 spend each other here.
    let txs = vec![
        funding(0x60, 100_000_000),
        peel(0x61, &[(0x60, 0)], 1_000_000, 98_000_000),
        peel(0x62, &[(0x61, 1), (0x63, 1)], 1_000_000, 96_000_000),
        peel(0x63, &[(0x62, 1)], 1_000_000, 94_000_000),
    ];
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(chain_txids(f), ids(&[0x61, 0x62, 0x63]));
    assert_eq!(hops(f), 3);
    assert_eq!(f.severity, Severity::High);
    assert!(!truncated(f));
    no_joins(f);
    assert_eq!(merged(f), None);
}

fn bound_of_six() -> DetectorThresholds {
    DetectorThresholds {
        peel_chain_max_hops: 6,
        ..DetectorThresholds::default()
    }
}

#[test]
fn a_cycle_longer_than_the_hop_limit_lists_each_hop_once() {
    // 0x72 to 0x78 spend each other in a loop; with 0x71 that is 8 txs, more
    // than the bound of 6.
    let mut txs = vec![
        funding(0x70, 100_000_000),
        peel(0x71, &[(0x70, 0)], 1_000_000, 90_000_000),
        peel(0x72, &[(0x71, 1), (0x78, 1)], 1_000_000, 90_000_000),
    ];
    for id in 0x73..=0x78 {
        txs.push(peel(id, &[(id - 1, 1)], 1_000_000, 90_000_000));
    }
    let findings = peel_findings_with(txs, &bound_of_six());
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    let listed: Vec<u8> = (0x71..=0x76).collect();
    assert_eq!(chain_txids(f), ids(&listed));
    assert_eq!(hops(f), 6);
    assert!(f.description.contains("at least 6 hops"));
    assert!(truncated(f));
    no_joins(f);
    assert_eq!(merged(f), None);
}

#[test]
fn a_loop_with_no_way_in_longer_than_the_hop_limit_is_one_finding() {
    let mut txs = vec![peel(0x61, &[(0x68, 1)], 1_000_000, 90_000_000)];
    for id in 0x62..=0x68 {
        txs.push(peel(id, &[(id - 1, 1)], 1_000_000, 90_000_000));
    }
    let findings = peel_findings_with(txs, &bound_of_six());
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    let listed: Vec<u8> = (0x61..=0x66).collect();
    assert_eq!(chain_txids(f), ids(&listed));
    assert_eq!(hops(f), 6);
    assert!(truncated(f));
}

#[test]
fn a_very_long_chain_is_scanned_in_linear_time() {
    // 8,000 hops: tracing every tail takes tens of seconds in a debug build,
    // one walk per chain well under a second.
    const HOPS: u32 = 8_000;
    let id = |n: u32| -> Txid { format!("{n:064x}").parse().expect("valid txid hex") };
    let us = ours(1);
    let them = external(1);
    let mut transactions = HashMap::new();
    let mut wallet_txs = Vec::new();
    let mut prev = (id(0), 0);
    transactions.insert(
        id(0),
        DecodedTransaction {
            txid: id(0),
            vin: Vec::new(),
            vout: vec![out(0, us.clone(), 21_000_000_000)],
            version: 2,
            locktime: 0,
            vsize: 141,
            confirmations: 3,
        },
    );
    for n in 1..=HOPS {
        let t = DecodedTransaction {
            txid: id(n),
            vin: vec![TxInputRef {
                previous_txid: prev.0,
                previous_vout: prev.1,
                sequence: 0xffff_fffd,
                coinbase: false,
            }],
            vout: vec![
                out(0, them.clone(), 10_000),
                out(1, us.clone(), 21_000_000_000 - u64::from(n) * 20_000),
            ],
            version: 2,
            locktime: 0,
            vsize: 141,
            confirmations: 3,
        };
        wallet_txs.push(WalletTxEntry {
            txid: id(n),
            address: None,
            category: WalletTxCategory::Send,
            amount: Amount::from_sat(0),
            confirmations: 3,
            blockheight: 100,
        });
        transactions.insert(id(n), t);
        prev = (id(n), 1);
    }
    let history = WalletHistory {
        wallet_txs,
        utxos: Vec::new(),
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([us]),
        ranged_addresses: HashSet::new(),
    };
    let graph = TxGraph::from_wallet_history(history);
    let started = std::time::Instant::now();
    let report = graph.detect_all(&DetectorThresholds::default(), None, None);
    let elapsed = started.elapsed();
    let peels: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::PeelChain)
        .collect();
    assert_eq!(peels.len(), 1);
    assert_eq!(hops(peels[0]), 1_000);
    assert_eq!(chain_txids(peels[0]).len(), 1_000);
    assert!(truncated(peels[0]));
    eprintln!("detect_all on {HOPS} hops took {elapsed:?}");
    assert!(elapsed.as_secs() < 10, "detect_all took {elapsed:?}");
}

#[test]
fn a_chain_that_ends_on_its_own_is_not_truncated() {
    let findings = peel_findings(chain(0x10, &[0x11, 0x12, 0x13]));
    assert!(!truncated(&findings[0]));
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

#[test]
fn a_chain_is_whole_when_no_hop_for_a_while_after_the_old_limit_can_start_a_trace() {
    // 0x12 to 0x18 have three inputs, so the first trace past them starts at
    // 0x19; it is still a tail of the chain from 0x11.
    let hop_ids: Vec<u8> = (0x11..=0x1E).collect();
    let wide: Vec<u8> = (0x12..=0x18).collect();
    assert_whole_chain(wide_chain(0x10, &hop_ids, &wide), &hop_ids);
}

#[test]
fn a_loop_with_no_way_in_is_one_finding_from_its_smallest_txid() {
    // Real spends cannot loop; here 0x61, 0x62 and 0x63 spend each other in
    // a circle, so every start is a later hop of another trace.
    for order in [[0x61, 0x62, 0x63], [0x62, 0x63, 0x61], [0x63, 0x61, 0x62]] {
        let [a, b, c] = order;
        let txs = vec![
            peel(a, &[(c, 1)], 1_000_000, 98_000_000),
            peel(b, &[(a, 1)], 1_000_000, 96_000_000),
            peel(c, &[(b, 1)], 1_000_000, 94_000_000),
        ];
        let findings = peel_findings(txs);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let f = &findings[0];
        let mut expected = vec![a, b, c];
        let first = expected.iter().position(|&n| n == 0x61).unwrap_or(0);
        expected.rotate_left(first);
        assert_eq!(chain_txids(f), ids(&expected));
        assert_eq!(hops(f), 3);
        assert!(!truncated(f));
        no_joins(f);
        assert_eq!(merged(f), None);
    }
}

#[test]
fn a_chain_exactly_as_long_as_the_hop_limit_is_not_truncated() {
    let hop_ids = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let findings = peel_findings_with(chain(0x10, &hop_ids), &bound_of_six());
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(chain_txids(&findings[0]), ids(&hop_ids));
    assert_eq!(hops(&findings[0]), 6);
    assert!(!truncated(&findings[0]));
    assert!(!findings[0].description.contains("at least"));
}

#[test]
fn a_spend_that_is_not_a_peel_ends_the_chain() {
    // 0x14 sends the change of 0x13 on in one output, so the chain ends at 0x13.
    let mut txs = chain(0x10, &[0x11, 0x12, 0x13]);
    txs.push(tx(
        0x14,
        &[(0x13, 1)],
        vec![out(0, external(0x14), 90_000_000)],
    ));
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(chain_txids(&findings[0]), ids(&[0x11, 0x12, 0x13]));
}

fn big_id(n: u32) -> Txid {
    format!("{n:064x}").parse().expect("valid txid hex")
}

fn big_tx(id: u32, vins: &[(u32, u32)], vouts: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: big_id(id),
        vin: vins
            .iter()
            .map(|&(prev, vout)| TxInputRef {
                previous_txid: big_id(prev),
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

#[test]
fn many_chains_merging_into_one_tail_are_one_finding() {
    // T1 to T4000 form one chain; each T(i) from T2 on also spends the change
    // of its own one-input peel S(i), so 4,000 chains share T(i).. as a tail.
    // A covering pass that does not stop at covered txs takes far longer.
    const N: u32 = 4_000;
    let thresholds = DetectorThresholds {
        peel_chain_max_hops: 10_000,
        ..DetectorThresholds::default()
    };
    let (t, s, g) = (|i: u32| i, |i: u32| 100_000 + i, |i: u32| 200_000 + i);
    let us = ours(1);
    let them = external(1);
    let mut txs = vec![big_tx(
        0,
        &[(300_000, 0)],
        vec![out(0, us.clone(), 1 << 40)],
    )];
    txs.push(big_tx(
        t(1),
        &[(0, 0)],
        vec![out(0, them.clone(), 10_000), out(1, us.clone(), 1 << 39)],
    ));
    for i in 2..=N {
        txs.push(big_tx(
            g(i),
            &[(300_000, i)],
            vec![out(0, us.clone(), 1_000_000)],
        ));
        txs.push(big_tx(
            s(i),
            &[(g(i), 0)],
            vec![out(0, them.clone(), 10_000), out(1, us.clone(), 900_000)],
        ));
        txs.push(big_tx(
            t(i),
            &[(t(i - 1), 1), (s(i), 1)],
            vec![out(0, them.clone(), 10_000), out(1, us.clone(), 1 << 39)],
        ));
    }
    let wallet_txs = txs
        .iter()
        .map(|tx| WalletTxEntry {
            txid: tx.txid,
            address: None,
            category: WalletTxCategory::Send,
            amount: Amount::from_sat(0),
            confirmations: 3,
            blockheight: 100,
        })
        .collect();
    let history = WalletHistory {
        wallet_txs,
        utxos: Vec::new(),
        transactions: txs.into_iter().map(|tx| (tx.txid, tx)).collect(),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([us]),
        ranged_addresses: HashSet::new(),
    };
    let graph = TxGraph::from_wallet_history(history);
    let started = std::time::Instant::now();
    let report = graph.detect_all(&thresholds, None, None);
    let elapsed = started.elapsed();
    let peels: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::PeelChain)
        .collect();
    // One flow: T1 and S2 both start a path of N hops.
    assert_eq!(peels.len(), 1, "{} findings", peels.len());
    let f = peels[0];
    // T1 and S2 both start a path of N hops; T1 has the smaller txid.
    assert_eq!(start(f), big_id(t(1)).to_string());
    assert_eq!(hops(f), u64::from(N));
    assert_eq!(merged(f), Some(u64::from(N)));
    // 2N - 1 txs in the set, each listed once.
    let listed = chain_txids(f);
    let unique: HashSet<&String> = listed.iter().collect();
    assert_eq!(listed.len(), 2 * N as usize - 1);
    assert_eq!(unique.len(), listed.len());
    assert!(!truncated(f));
    eprintln!("detect_all on {N} merge points took {elapsed:?}");
    assert!(elapsed.as_secs() < 10, "detect_all took {elapsed:?}");
}

#[test]
fn two_hops_are_a_chain_and_one_is_not() {
    let findings = peel_findings(chain(0x10, &[0x11, 0x12]));
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(hops(&findings[0]), 2);
    assert_eq!(findings[0].severity, Severity::High);
    assert!(peel_findings(chain(0x10, &[0x11])).is_empty());
}

#[test]
fn a_later_send_spending_two_chains_peeled_outputs_does_not_join_them() {
    // 0x13 and 0x23 each send a small output back to the wallet, and 0x30
    // spends both; 0x30 is a single peel, not a chain.
    let txs = vec![
        funding(0x10, 100_000_000),
        funding(0x20, 100_000_000),
        peel(0x11, &[(0x10, 0)], 1_000_000, 98_000_000),
        peel(0x12, &[(0x11, 1)], 1_000_000, 96_000_000),
        peel_to_self(0x13, (0x12, 1), 0x13 + 0x40, 1_000_000, 94_000_000),
        peel(0x21, &[(0x20, 0)], 1_000_000, 98_000_000),
        peel(0x22, &[(0x21, 1)], 1_000_000, 96_000_000),
        peel_to_self(0x23, (0x22, 1), 0x23 + 0x40, 1_000_000, 94_000_000),
        peel(0x30, &[(0x13, 0), (0x23, 0)], 100_000, 1_800_000),
    ];
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert_eq!(starts(&findings), ids(&[0x11, 0x21]));
    for f in &findings {
        let head = if start(f) == txid(0x11).to_string() {
            [0x11, 0x12, 0x13]
        } else {
            [0x21, 0x22, 0x23]
        };
        assert_eq!(chain_txids(f), ids(&head));
        assert_eq!(merged(f), None);
    }
}

#[test]
fn a_side_chain_shorter_than_the_minimum_is_not_counted_as_merged() {
    // With a minimum of 3 hops, 0x21 to 0x14 is only 2 hops: it is listed
    // as part of the flow but is not a chain of its own.
    let thresholds = DetectorThresholds {
        peel_chain_min_hops: 3,
        ..DetectorThresholds::default()
    };
    let txs = vec![
        funding(0x10, 100_000_000),
        funding(0x20, 100_000_000),
        peel(0x11, &[(0x10, 0)], 1_000_000, 98_000_000),
        peel(0x12, &[(0x11, 1)], 1_000_000, 96_000_000),
        peel(0x13, &[(0x12, 1)], 1_000_000, 94_000_000),
        peel(0x21, &[(0x20, 0)], 1_000_000, 98_000_000),
        peel(0x14, &[(0x13, 1), (0x21, 1)], 1_000_000, 190_000_000),
    ];
    let findings = peel_findings_with(txs, &thresholds);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(hops(f), 4);
    assert_eq!(chain_txids(f), ids(&[0x11, 0x12, 0x13, 0x14, 0x21]));
    assert_eq!(merged(f), None);
}

#[test]
fn a_chain_taking_in_another_chains_peeled_output_partway_is_one_flow() {
    // 0x32 spends the change of 0x31 and the output 0x12 peeled back to the
    // wallet, then carries on as 0x33.
    let txs = vec![
        funding(0x10, 100_000_000),
        funding(0x30, 100_000_000),
        peel(0x11, &[(0x10, 0)], 1_000_000, 98_000_000),
        peel_to_self(0x12, (0x11, 1), 0x52, 20_000_000, 77_000_000),
        peel(0x13, &[(0x12, 1)], 1_000_000, 75_000_000),
        peel(0x31, &[(0x30, 0)], 1_000_000, 98_000_000),
        peel(0x32, &[(0x31, 1), (0x12, 0)], 1_000_000, 116_000_000),
        peel(0x33, &[(0x32, 1)], 1_000_000, 114_000_000),
    ];
    let findings = peel_findings(txs);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let f = &findings[0];
    assert_eq!(start(f), txid(0x11).to_string());
    assert_eq!(hops(f), 3);
    assert_eq!(chain_txids(f), ids(&[0x11, 0x12, 0x13, 0x31, 0x32, 0x33]));
    assert_eq!(merged(f), Some(2));
}
