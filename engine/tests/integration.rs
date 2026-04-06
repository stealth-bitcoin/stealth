//! Integration tests for stealth-engine.
//!
//! Each test spins up a fresh regtest Bitcoin Core via `corepc-node`,
//! reproduces one or more privacy vulnerabilities, then runs the
//! detector through the canonical `AnalysisEngine` + `BitcoinCoreRpc`
//! gateway path to verify it fires the expected finding(s).

use std::collections::{BTreeMap, HashSet};

use bitcoin::Txid;
use corepc_node::client::bitcoin::{Address, Amount};
use corepc_node::{AddressType, Input, Node, Output};
use stealth_bitcoincore::BitcoinCoreRpc;
use stealth_engine::gateway::BlockchainGateway;
use stealth_engine::{TxGraph, VulnerabilityType};

// ─── helpers ────────────────────────────────────────────────────────────────

fn node() -> Node {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    Node::with_conf(exe, &conf).expect("failed to start bitcoind")
}

fn mine(node: &Node, n: usize, addr: &Address) {
    node.client.generate_to_address(n, addr).unwrap();
}

fn gateway_for(node: &Node) -> BitcoinCoreRpc {
    let cookie =
        std::fs::read_to_string(&node.params.cookie_file).expect("failed to read cookie file");
    let mut parts = cookie.trim().splitn(2, ':');
    let user = parts.next().unwrap().to_string();
    let pass = parts.next().unwrap().to_string();
    BitcoinCoreRpc::from_url(&node.rpc_url(), Some(user), Some(pass))
        .expect("failed to build gateway")
}

fn scan_wallet(gateway: &BitcoinCoreRpc, wallet: &str) -> stealth_engine::Report {
    let history = gateway.scan_wallet(wallet).expect("scan_wallet failed");
    let graph = TxGraph::from_wallet_history(history);
    graph.detect_all(&Default::default(), None, None)
}

fn scan_wallet_with(
    gateway: &BitcoinCoreRpc,
    wallet: &str,
    known_risky: Option<&HashSet<Txid>>,
    known_exchange: Option<&HashSet<Txid>>,
) -> stealth_engine::Report {
    let history = gateway.scan_wallet(wallet).expect("scan_wallet failed");
    let graph = TxGraph::from_wallet_history(history);
    graph.detect_all(&Default::default(), known_risky, known_exchange)
}

fn has_finding(report: &stealth_engine::Report, vtype: VulnerabilityType) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.vulnerability_type == vtype)
}

// ─── 1. Address Reuse ───────────────────────────────────────────────────────

#[test]
fn detect_address_reuse() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Reuse the same alice address twice
    let reused = alice.new_address().unwrap();
    bob.send_to_address(&reused, Amount::from_sat(1_000_000))
        .unwrap();
    bob.send_to_address(&reused, Amount::from_sat(2_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::AddressReuse));
}

// ─── 2. Common Input Ownership Heuristic (CIOH) ────────────────────────────

#[test]
fn detect_cioh() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice multiple small UTXOs (each to a different address)
    for _ in 0..5 {
        let a = alice.new_address().unwrap();
        bob.send_to_address(&a, Amount::from_sat(500_000)).unwrap();
    }
    mine(&node, 1, &da);

    // Alice consolidates them into one tx (multi-input -> CIOH)
    let utxos = alice.list_unspent().unwrap();
    let small: Vec<_> = utxos.0.iter().filter(|u| u.amount < 0.006).collect();
    assert!(small.len() >= 2, "need at least 2 small utxos");

    let inputs: Vec<Input> = small
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = small.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let fee_sats: u64 = 10_000;
    let dest = bob.new_address().unwrap();
    let outputs = vec![Output::new(dest, Amount::from_sat(total_sats - fee_sats))];

    let raw = alice.create_raw_transaction(&inputs, &outputs).unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    assert!(signed.complete);
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Cioh));
}

// ─── 3. Dust UTXO Detection ────────────────────────────────────────────────

#[test]
fn detect_dust() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Create 1000-sat dust output to alice via raw tx
    let dust_addr = alice.new_address().unwrap();
    let bob_utxos = bob.list_unspent().unwrap();
    let big = bob_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();

    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 1_000;
    let fee_sats: u64 = 10_000;
    let change_sats = big_sats - dust_sats - fee_sats;

    let change_addr = bob.new_address().unwrap();
    let raw = bob
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dust_addr, Amount::from_sat(dust_sats)),
                Output::new(change_addr, Amount::from_sat(change_sats)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = bob.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    bob.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Dust));
}

// ─── 4. Dust Spending with Normal Inputs ────────────────────────────────────

#[test]
fn detect_dust_spending() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a normal UTXO
    let alice_normal = alice.new_address().unwrap();
    bob.send_to_address(&alice_normal, Amount::from_btc(0.5).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a dust UTXO via raw tx
    let dust_addr = alice.new_address().unwrap();
    let bob_utxos = bob.list_unspent().unwrap();
    let big = bob_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();
    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 1_000;
    let fee_sats: u64 = 10_000;

    let change_addr = bob.new_address().unwrap();
    let raw = bob
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dust_addr, Amount::from_sat(dust_sats)),
                Output::new(
                    change_addr,
                    Amount::from_sat(big_sats - dust_sats - fee_sats),
                ),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = bob.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    bob.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    // Now alice spends dust + normal together
    let utxos = alice.list_unspent().unwrap();
    let dust_u = utxos
        .0
        .iter()
        .find(|u| (u.amount * 1e8).round() as u64 <= 1000)
        .expect("dust utxo");
    let normal_u = utxos
        .0
        .iter()
        .find(|u| u.amount > 0.001)
        .expect("normal utxo");

    let total_sats = (dust_u.amount * 1e8).round() as u64 + (normal_u.amount * 1e8).round() as u64;
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[
                Input {
                    txid: dust_u.txid.parse().unwrap(),
                    vout: dust_u.vout as u64,
                    sequence: None,
                },
                Input {
                    txid: normal_u.txid.parse().unwrap(),
                    vout: normal_u.vout as u64,
                    sequence: None,
                },
            ],
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::DustSpending));
}

// ─── 5. Change Detection ───────────────────────────────────────────────────

#[test]
fn detect_change_detection() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund alice with a clean 1 BTC UTXO
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Alice sends a round 0.05 BTC to bob via send_to_address.
    // Bitcoin Core will automatically create a change output.
    let bob_addr = bob.new_address().unwrap();
    alice
        .send_to_address(&bob_addr, Amount::from_sat(5_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ChangeDetection));
}

// ─── 6. Consolidation Origin ───────────────────────────────────────────────

#[test]
fn detect_consolidation() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice 4 small UTXOs
    for _ in 0..4 {
        let a = alice.new_address().unwrap();
        bob.send_to_address(&a, Amount::from_sat(300_000)).unwrap();
    }
    mine(&node, 1, &da);

    // Alice consolidates into one address (>=3 inputs, <=2 outputs)
    let utxos = alice.list_unspent().unwrap();
    let small: Vec<_> = utxos
        .0
        .iter()
        .filter(|u| u.amount > 0.002 && u.amount < 0.004)
        .collect();
    assert!(small.len() >= 3, "need at least 3 small utxos");

    let inputs: Vec<Input> = small
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = small.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let consol_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(
                consol_addr,
                Amount::from_sat(total_sats - 10_000),
            )],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Consolidation));
}

// ─── 7. Script Type Mixing ─────────────────────────────────────────────────

#[test]
fn detect_script_type_mixing() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice one P2WPKH and one P2TR utxo
    let wpkh_addr = alice.new_address_with_type(AddressType::Bech32).unwrap();
    let tr_addr = alice.new_address_with_type(AddressType::Bech32m).unwrap();
    bob.send_to_address(&wpkh_addr, Amount::from_sat(500_000))
        .unwrap();
    bob.send_to_address(&tr_addr, Amount::from_sat(500_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both types together
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2, "need at least 2 utxos");

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ScriptTypeMixing));
}

// ─── 8. Cluster Merge ──────────────────────────────────────────────────────

#[test]
fn detect_cluster_merge() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let carol = node.create_wallet("carol").unwrap();
    // Fund bob and carol
    let ba = bob.new_address().unwrap();
    let ca = carol.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    node.client
        .send_to_address(&ca, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Bob sends to alice_addr_1, Carol sends to alice_addr_2
    let a1 = alice.new_address().unwrap();
    let a2 = alice.new_address().unwrap();
    bob.send_to_address(&a1, Amount::from_sat(400_000)).unwrap();
    carol
        .send_to_address(&a2, Amount::from_sat(400_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both together -> cluster merge
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2, "need at least 2 utxos");

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ClusterMerge));
}

// ─── 9. Lookback Depth / UTXO Age ──────────────────────────────────────────

#[test]
fn detect_utxo_age_spread() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();

    // Old UTXO
    let old_addr = alice.new_address().unwrap();
    node.client
        .send_to_address(&old_addr, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 20, &da);

    // New UTXO
    let new_addr = alice.new_address().unwrap();
    node.client
        .send_to_address(&new_addr, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::UtxoAgeSpread));
}

// ─── 10. Exchange Origin ───────────────────────────────────────────────────

#[test]
fn detect_exchange_origin() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let exchange = node.create_wallet("exchange").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    // Fund exchange
    let ea = exchange.new_address().unwrap();
    node.client
        .send_to_address(&ea, Amount::from_btc(5.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Exchange batch withdrawal to 8 addresses (alice gets some, bob gets some)
    let mut amounts: BTreeMap<Address, Amount> = BTreeMap::new();
    for i in 0..5u64 {
        let a = alice.new_address().unwrap();
        amounts.insert(a, Amount::from_sat(1_000_000 + i * 100_000));
    }
    for i in 0..3u64 {
        let b = bob.new_address().unwrap();
        amounts.insert(b, Amount::from_sat(1_000_000 + i * 200_000));
    }
    let send_result = exchange.send_many(amounts).unwrap();
    mine(&node, 1, &da);

    let exchange_txids: HashSet<Txid> = [send_result.0.parse::<Txid>().unwrap()]
        .into_iter()
        .collect();
    let gateway = gateway_for(&node);
    let report = scan_wallet_with(&gateway, "alice", None, Some(&exchange_txids));
    assert!(has_finding(&report, VulnerabilityType::ExchangeOrigin));
}

// ─── 11. Tainted UTXOs ─────────────────────────────────────────────────────

#[test]
fn detect_tainted_utxo_merge() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let risky = node.create_wallet("risky").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund
    let ra = risky.new_address().unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ra, Amount::from_btc(2.0).unwrap())
        .unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Risky sends to alice
    let ta = alice.new_address().unwrap();
    let taint_result = risky
        .send_to_address(&ta, Amount::from_sat(1_000_000))
        .unwrap();
    let taint_txid: Txid = taint_result.0.parse().unwrap();

    // Bob sends clean to alice
    let ca = alice.new_address().unwrap();
    bob.send_to_address(&ca, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both together (tainted + clean)
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2);

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let carol = node.create_wallet("carol").unwrap();
    let dest = carol.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let risky_txids: HashSet<Txid> = [taint_txid].into_iter().collect();
    let gateway = gateway_for(&node);
    let report = scan_wallet_with(&gateway, "alice", Some(&risky_txids), None);
    assert!(has_finding(&report, VulnerabilityType::TaintedUtxoMerge));
}

// ─── 12. Behavioral Fingerprint ────────────────────────────────────────────

#[test]
fn detect_behavioral_fingerprint() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let carol = node.create_wallet("carol").unwrap();

    // Fund alice generously
    let aa = alice.new_address().unwrap();
    node.client
        .send_to_address(&aa, Amount::from_btc(5.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice sends 5 round-amount payments (behavioral pattern)
    for i in 1u64..=5 {
        let dest = carol.new_address().unwrap();
        alice
            .send_to_address(&dest, Amount::from_sat(i * 1_000_000))
            .unwrap();
        mine(&node, 1, &da);
    }

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(report
        .findings
        .iter()
        .any(|f| f.vulnerability_type == VulnerabilityType::BehavioralFingerprint));
}

// ─── Full Report Smoke Test ─────────────────────────────────────────────────

#[test]
fn full_report_generates() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");

    assert_eq!(
        report.summary.findings + report.summary.warnings,
        report.findings.len() + report.warnings.len()
    );
    assert_eq!(report.stats.utxos_current, 1);
}

// ─── 13. Dust Attack Detection ─────────────────────────────────────────────

#[test]
fn detect_dust_attack() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let attacker = node.create_wallet("attacker").unwrap();

    // Fund attacker
    let aa = attacker.new_address().unwrap();
    node.client
        .send_to_address(&aa, Amount::from_btc(1.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Attacker creates a dust attack: 1 input, 12 outputs (all tiny) to
    // various addresses including some of alice's
    let attacker_utxos = attacker.list_unspent().unwrap();
    let big = attacker_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();
    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 546;
    let n_dust: u64 = 12;
    let fee_sats: u64 = 10_000;

    // Create 12 tiny outputs — 5 to alice, 7 to random other wallets
    let mut outputs_vec = Vec::new();
    for _ in 0..5 {
        let a = alice.new_address().unwrap();
        outputs_vec.push(Output::new(a, Amount::from_sat(dust_sats)));
    }
    // Create "other" wallets for diversity
    for i in 0..7 {
        let other_name = format!("other_{}", i);
        let other = node.create_wallet(&other_name).unwrap();
        let oa = other.new_address().unwrap();
        outputs_vec.push(Output::new(oa, Amount::from_sat(dust_sats)));
    }

    let change_sats = big_sats - (dust_sats * n_dust) - fee_sats;
    let change_addr = attacker.new_address().unwrap();
    outputs_vec.push(Output::new(change_addr, Amount::from_sat(change_sats)));

    let raw = attacker
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &outputs_vec,
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = attacker.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    attacker.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::DustAttack));
}

// ─── 14. Peel Chain Detection ──────────────────────────────────────────────

#[test]
fn detect_peel_chain() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund alice
    let aa = alice.new_address().unwrap();
    node.client
        .send_to_address(&aa, Amount::from_btc(1.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice creates a peel chain: 3 consecutive 2-output transactions
    // where the large output feeds the next transaction
    for i in 0..3 {
        let utxos = alice.list_unspent().unwrap();
        let big = utxos
            .0
            .iter()
            .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
            .unwrap();
        let big_sats = (big.amount * 1e8).round() as u64;
        let peel_amount: u64 = 50_000 + i * 10_000; // Small "peeled" payment
        let fee_sats: u64 = 10_000;
        let change_sats = big_sats - peel_amount - fee_sats;

        let peel_addr = bob.new_address().unwrap();
        let change_addr = alice.new_address().unwrap();
        let raw = alice
            .create_raw_transaction(
                &[Input {
                    txid: big.txid.parse().unwrap(),
                    vout: big.vout as u64,
                    sequence: None,
                }],
                &[
                    Output::new(peel_addr, Amount::from_sat(peel_amount)),
                    Output::new(change_addr, Amount::from_sat(change_sats)),
                ],
            )
            .unwrap();
        let tx = raw.transaction().unwrap();
        let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
        let stx = signed.into_model().unwrap().tx;
        alice.send_raw_transaction(&stx).unwrap();
        mine(&node, 1, &da);
    }

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::PeelChain));
}

// ─── 15. Deterministic Link Detection ──────────────────────────────────────

#[test]
fn detect_deterministic_links() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice two UTXOs: 700k and 400k sats
    let a1 = alice.new_address().unwrap();
    let a2 = alice.new_address().unwrap();
    bob.send_to_address(&a1, Amount::from_sat(700_000)).unwrap();
    bob.send_to_address(&a2, Amount::from_sat(400_000)).unwrap();
    mine(&node, 1, &da);

    // Alice spends both into two outputs: 600k and 400k.
    // Only one valid interpretation: 700k→600k, 400k→400k
    // (400k < 600k so it can't fund the 600k output = deterministic link)
    let utxos = alice.list_unspent().unwrap();
    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();

    let dest1 = bob.new_address().unwrap();
    let dest2 = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[
                Output::new(dest1, Amount::from_sat(600_000)),
                Output::new(dest2, Amount::from_sat(400_000)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::DeterministicLink));
}

// ─── 16. Unnecessary Input Detection ───────────────────────────────────────

#[test]
fn detect_unnecessary_input() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(3.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a big UTXO (1 BTC) and a small UTXO (0.01 BTC)
    let a1 = alice.new_address().unwrap();
    let a2 = alice.new_address().unwrap();
    bob.send_to_address(&a1, Amount::from_btc(1.0).unwrap())
        .unwrap();
    bob.send_to_address(&a2, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice sends 0.005 BTC (500k sats) using BOTH inputs — unnecessary
    // because the 1 BTC input alone is enough
    let utxos = alice.list_unspent().unwrap();
    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    assert!(inputs.len() >= 2);

    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let payment_sats: u64 = 500_000;
    let fee_sats: u64 = 10_000;
    let change_sats = total_sats - payment_sats - fee_sats;

    let dest = bob.new_address().unwrap();
    let change_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[
                Output::new(dest, Amount::from_sat(payment_sats)),
                Output::new(change_addr, Amount::from_sat(change_sats)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::UnnecessaryInput));
}

// ─── 17. Toxic Change Detection ────────────────────────────────────────────

#[test]
fn detect_toxic_change() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(3.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a UTXO that will produce toxic change
    let aa = alice.new_address().unwrap();
    bob.send_to_address(&aa, Amount::from_sat(100_000)).unwrap();
    mine(&node, 1, &da);

    // Alice sends, leaving tiny change (5000 sats — in toxic range)
    let utxos = alice.list_unspent().unwrap();
    let big = utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();
    let big_sats = (big.amount * 1e8).round() as u64;
    let fee_sats: u64 = 10_000;
    let toxic_change: u64 = 5_000;
    let payment_sats = big_sats - fee_sats - toxic_change;

    let dest = bob.new_address().unwrap();
    let change_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dest, Amount::from_sat(payment_sats)),
                Output::new(change_addr.clone(), Amount::from_sat(toxic_change)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    // Now give alice another big UTXO
    let aa2 = alice.new_address().unwrap();
    bob.send_to_address(&aa2, Amount::from_btc(1.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends toxic change + big UTXO together (the vulnerability)
    let utxos2 = alice.list_unspent().unwrap();
    let inputs2: Vec<Input> = utxos2
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    assert!(inputs2.len() >= 2);

    let total2: u64 = utxos2
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let dest2 = bob.new_address().unwrap();
    let raw2 = alice
        .create_raw_transaction(
            &inputs2,
            &[Output::new(dest2, Amount::from_sat(total2 - 10_000))],
        )
        .unwrap();
    let tx2 = raw2.transaction().unwrap();
    let signed2 = alice.sign_raw_transaction_with_wallet(&tx2).unwrap();
    let stx2 = signed2.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx2).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ToxicChange));
}
