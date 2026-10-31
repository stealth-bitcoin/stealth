use crate::common::*;
use serde_json::{json, Value};

/// Alice pays bob in a replaceable tx, bumps its fee and the replacement is
/// mined, so Core reports the original with negative confirmations. Only the
/// sender's wallet lists it: Core leaves conflicted receives out.
/// Returns the original and the replacement.
fn replaced_payment(node: &Node, miner: &Address, alice: &corepc_node::Client) -> (Txid, Txid) {
    let to = node.create_wallet("bob").unwrap().new_address().unwrap();
    let original: String = alice
        .call(
            "sendtoaddress",
            &[
                json!(to.to_string()),
                json!(0.001),
                json!(""),
                json!(""),
                json!(false),
                json!(true),
            ],
        )
        .expect("sendtoaddress");
    let bumped: Value = alice.call("bumpfee", &[json!(original)]).expect("bumpfee");
    mine(node, 1, miner);
    let replacement = bumped["txid"].as_str().expect("bumpfee txid");
    (original.parse().unwrap(), replacement.parse().unwrap())
}

#[test]
fn a_conflicted_wallet_tx_is_left_out_of_a_wallet_scan() {
    let node = node();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, _) = fund_sender(&node, &miner, "alice", 1_000_000);
    let (original, replacement) = replaced_payment(&node, &miner, &alice);

    let entry: Value = alice
        .call("gettransaction", &[json!(original.to_string())])
        .expect("gettransaction");
    assert!(
        entry["confirmations"].as_i64().unwrap() < 0,
        "the replaced payment must be conflicted: {entry}"
    );

    let gateway = gateway_for(&node);
    let history = gateway
        .scan_wallet("alice")
        .expect("a conflicted tx must not fail the scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&original));
    assert!(!graph.tx_cache.contains_key(&original));
    assert!(graph.our_txids.contains(&replacement));

    let report = graph.detect_all(&Default::default(), None, None);
    assert_eq!(report.stats.conflicted_txids, vec![original]);
}

#[test]
fn a_cached_descriptor_scan_names_the_conflicted_tx_it_left_out() {
    let node = node();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, funded) = fund_sender(&node, &miner, "alice", 1_000_000);
    let gateway = gateway_for(&node);
    let settings = EngineSettings {
        persist_scan_wallet: true,
        ..EngineSettings::default()
    };
    let descriptor = format!("addr({funded})");
    let scan = || {
        AnalysisEngine::new(&gateway, settings.clone())
            .analyze(ScanTarget::Descriptor(descriptor.clone()))
    };

    // The cache wallet stays loaded, so it sees the original before it is replaced.
    scan().expect("first scan");
    let (original, _) = replaced_payment(&node, &miner, &alice);

    let report = scan().expect("a conflicted tx must not fail the scan");
    // The funding tx and the replacement that spent it.
    assert_eq!(report.stats.transactions_analyzed, 2);
    assert_eq!(report.stats.conflicted_txids, vec![original]);
}

/// Alice pays bob, spends that payment's unconfirmed change, spends that
/// change in turn, then a double spend of the payment's input is mined. Core
/// reports all three at negative depth; only the payment lists a wallet conflict.
#[test]
fn txs_depending_on_a_conflicted_one_are_left_out_and_named_too() {
    let node = node();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, _) = fund_sender(&node, &miner, "alice", 1_000_000);
    let bob = node.create_wallet("bob").unwrap().new_address().unwrap();
    let funding = alice.list_unspent().unwrap().0.remove(0);

    let send = |sats: u64| -> Txid {
        let txid: String = alice
            .call(
                "sendtoaddress",
                &[
                    json!(bob.to_string()),
                    json!(Amount::from_sat(sats).to_btc()),
                ],
            )
            .expect("sendtoaddress");
        txid.parse().unwrap()
    };
    let payment = send(100_000);
    let child = send(200_000);
    let grandchild = send(300_000);
    for (spender, spent) in [(child, payment), (grandchild, child)] {
        let decoded = gateway_for(&node).get_transaction(spender).unwrap();
        assert!(
            decoded.vin.iter().any(|i| i.previous_txid == spent),
            "each send must spend the previous one's change"
        );
    }

    // A higher-fee spend of the payment's input evicts both and is mined.
    let back = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[Input {
                txid: funding.txid.parse().unwrap(),
                vout: funding.vout as u64,
                sequence: None,
            }],
            &[Output::new(back, Amount::from_sat(1_000_000 - 50_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    alice
        .send_raw_transaction(&signed.into_model().unwrap().tx)
        .unwrap();
    mine(&node, 1, &miner);

    for descendant in [child, grandchild] {
        let entry: Value = alice
            .call("gettransaction", &[json!(descendant.to_string())])
            .expect("gettransaction");
        assert!(entry["confirmations"].as_i64().unwrap() < 0, "{entry}");
        assert_eq!(entry["walletconflicts"], json!([]), "{entry}");
    }

    let history = gateway_for(&node)
        .scan_wallet("alice")
        .expect("a conflicted descendant must not fail the scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&payment));
    assert!(!graph.our_txids.contains(&child));
    assert!(!graph.our_txids.contains(&grandchild));
    let report = graph.detect_all(&Default::default(), None, None);
    let mut expected = vec![payment, child, grandchild];
    expected.sort_by_key(Txid::to_string);
    assert_eq!(report.stats.conflicted_txids, expected);
}

/// A node that keeps new wallet txs out of its mempool, so they can be abandoned.
fn node_without_wallet_broadcast() -> Node {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    conf.args.push("-walletbroadcast=0");
    Node::with_conf(exe, &conf).expect("failed to start bitcoind")
}

/// Like [`fund_sender`], on a node that does not broadcast wallet txs itself.
fn fund_without_broadcast(node: &Node, miner: &Address) -> corepc_node::Client {
    let alice = node.create_wallet("alice").unwrap();
    let txid = node
        .client
        .send_to_address(&alice.new_address().unwrap(), Amount::from_sat(1_000_000))
        .unwrap()
        .txid()
        .unwrap();
    let funding: Value = node
        .client
        .call("gettransaction", &[json!(txid.to_string())])
        .unwrap();
    let _: Value = node
        .client
        .call("sendrawtransaction", &[funding["hex"].clone()])
        .unwrap();
    mine(node, 1, miner);
    alice
}

fn pay_bob(node: &Node, alice: &corepc_node::Client, replaceable: bool) -> Txid {
    let to = node.create_wallet("bob").unwrap().new_address().unwrap();
    let txid: String = alice
        .call(
            "sendtoaddress",
            &[
                json!(to.to_string()),
                json!(0.001),
                json!(""),
                json!(""),
                json!(false),
                json!(replaceable),
            ],
        )
        .expect("sendtoaddress");
    txid.parse().unwrap()
}

#[test]
fn a_tx_replaced_by_one_still_in_the_mempool_is_left_out_and_named() {
    let node = node();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, _) = fund_sender(&node, &miner, "alice", 1_000_000);
    let original = pay_bob(&node, &alice, true);
    let bumped: Value = alice
        .call("bumpfee", &[json!(original.to_string())])
        .expect("bumpfee");
    let replacement: Txid = bumped["txid"].as_str().unwrap().parse().unwrap();

    let history = gateway_for(&node)
        .scan_wallet("alice")
        .expect("a replaced tx must not fail the scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&original));
    assert!(graph.our_txids.contains(&replacement));
    assert!(graph.tx_cache.contains_key(&replacement));

    let report = graph.detect_all(&Default::default(), None, None);
    let replaced: Vec<(Txid, Txid)> = report
        .stats
        .mempool_conflicted_txids
        .iter()
        .map(|r| (r.txid, r.conflicts_with))
        .collect();
    assert_eq!(replaced, vec![(original, replacement)]);
    assert!(report.stats.conflicted_txids.is_empty());
}

#[test]
fn an_abandoned_tx_is_left_out_and_named() {
    let node = node_without_wallet_broadcast();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let alice = fund_without_broadcast(&node, &miner);
    let abandoned = pay_bob(&node, &alice, false);
    let _: Value = alice
        .call("abandontransaction", &[json!(abandoned.to_string())])
        .expect("abandontransaction");

    let history = gateway_for(&node)
        .scan_wallet("alice")
        .expect("an abandoned tx must not fail the scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&abandoned));
    let report = graph.detect_all(&Default::default(), None, None);
    assert_eq!(report.stats.abandoned_txids, vec![abandoned]);
    assert_eq!(
        report.stats.transactions_analyzed, 1,
        "the funding tx stays"
    );
}

#[test]
fn an_unbroadcast_tx_is_left_out_as_unavailable() {
    let node = node_without_wallet_broadcast();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let alice = fund_without_broadcast(&node, &miner);
    let payment = pay_bob(&node, &alice, false);

    let history = gateway_for(&node)
        .scan_wallet("alice")
        .expect("a wallet tx the node never had must not fail the scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&payment));
    let report = graph.detect_all(&Default::default(), None, None);
    assert_eq!(report.stats.unavailable_txids, vec![payment]);
    assert_eq!(
        report.stats.transactions_analyzed, 1,
        "the funding tx stays"
    );
}

/// What a wallet scan left out because a tx in the mempool conflicts with it.
fn mempool_conflicted(report: &stealth_engine::Report) -> Vec<(Txid, Txid)> {
    report
        .stats
        .mempool_conflicted_txids
        .iter()
        .map(|c| (c.txid, c.conflicts_with))
        .collect()
}

#[test]
fn the_receiver_of_a_payment_bumped_but_not_mined_leaves_it_out() {
    let node = node();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, _) = fund_sender(&node, &miner, "alice", 1_000_000);
    let bob = node.create_wallet("bob").unwrap();
    let to = bob.new_address().unwrap();
    let gateway = gateway_for(&node);
    let settings = EngineSettings {
        persist_scan_wallet: true,
        ..EngineSettings::default()
    };
    let descriptor = format!("addr({to})");
    let cached_scan = || {
        AnalysisEngine::new(&gateway, settings.clone())
            .analyze(ScanTarget::Descriptor(descriptor.clone()))
    };
    cached_scan().expect("first scan");

    let original: String = alice
        .call(
            "sendtoaddress",
            &[
                json!(to.to_string()),
                json!(0.001),
                json!(""),
                json!(""),
                json!(false),
                json!(true),
            ],
        )
        .expect("sendtoaddress");
    let original: Txid = original.parse().unwrap();
    let bumped: Value = alice
        .call("bumpfee", &[json!(original.to_string())])
        .expect("bumpfee");
    let replacement: Txid = bumped["txid"].as_str().unwrap().parse().unwrap();

    let history = gateway
        .scan_wallet("bob")
        .expect("a payment bumped by its sender must not fail the receiver's scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&original));
    assert!(graph.our_txids.contains(&replacement));
    let report = graph.detect_all(&Default::default(), None, None);
    assert_eq!(mempool_conflicted(&report), vec![(original, replacement)]);

    let cached = cached_scan().expect("nor the cached descriptor scan");
    assert_eq!(mempool_conflicted(&cached), vec![(original, replacement)]);
    assert_eq!(cached.stats.transactions_analyzed, 1);
}

#[test]
fn a_raw_double_spend_of_the_wallets_own_payment_leaves_out_it_and_its_child() {
    let node = node();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, _) = fund_sender(&node, &miner, "alice", 1_000_000);
    let funding = alice.list_unspent().unwrap().0.remove(0);
    let payment = pay_bob(&node, &alice, false);
    let child: String = alice
        .call(
            "sendtoaddress",
            &[
                json!(node.client.new_address().unwrap().to_string()),
                json!(0.002),
            ],
        )
        .expect("sendtoaddress");
    let child: Txid = child.parse().unwrap();

    let back = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[Input {
                txid: funding.txid.parse().unwrap(),
                vout: funding.vout as u64,
                sequence: None,
            }],
            &[Output::new(back, Amount::from_sat(1_000_000 - 50_000))],
        )
        .unwrap();
    let signed = alice
        .sign_raw_transaction_with_wallet(&raw.transaction().unwrap())
        .unwrap();
    let double_spend = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&double_spend).unwrap();
    let double_spend = double_spend.compute_txid();

    let history = gateway_for(&node)
        .scan_wallet("alice")
        .expect("a double spend in the mempool must not fail the scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&payment));
    assert!(!graph.our_txids.contains(&child));
    assert!(graph.our_txids.contains(&double_spend));
    let report = graph.detect_all(&Default::default(), None, None);
    let mut expected = vec![(payment, double_spend), (child, double_spend)];
    expected.sort_by_key(|(txid, _)| txid.to_string());
    assert_eq!(mempool_conflicted(&report), expected);
}

/// The sender double-spends a payment to bob with a raw tx back to itself;
/// bob's wallet holds neither the double spend nor anything paying him now.
#[test]
fn the_receiver_of_a_payment_double_spent_away_from_him_leaves_it_out() {
    let node = node();
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, _) = fund_sender(&node, &miner, "alice", 1_000_000);
    let funding = alice.list_unspent().unwrap().0.remove(0);
    let bob = node.create_wallet("bob").unwrap();
    let to = bob.new_address().unwrap();
    let gateway = gateway_for(&node);
    let settings = EngineSettings {
        persist_scan_wallet: true,
        ..EngineSettings::default()
    };
    let descriptor = format!("addr({to})");
    let cached_scan = || {
        AnalysisEngine::new(&gateway, settings.clone())
            .analyze(ScanTarget::Descriptor(descriptor.clone()))
    };
    cached_scan().expect("first scan");

    let payment: String = alice
        .call("sendtoaddress", &[json!(to.to_string()), json!(0.001)])
        .expect("sendtoaddress");
    let payment: Txid = payment.parse().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[Input {
                txid: funding.txid.parse().unwrap(),
                vout: funding.vout as u64,
                sequence: None,
            }],
            &[Output::new(
                alice.new_address().unwrap(),
                Amount::from_sat(1_000_000 - 50_000),
            )],
        )
        .unwrap();
    let signed = alice
        .sign_raw_transaction_with_wallet(&raw.transaction().unwrap())
        .unwrap();
    let double_spend = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&double_spend).unwrap();
    let double_spend = double_spend.compute_txid();

    let history = gateway
        .scan_wallet("bob")
        .expect("a payment double-spent away must not fail the receiver's scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&payment));
    assert!(!graph.our_txids.contains(&double_spend));
    let report = graph.detect_all(&Default::default(), None, None);
    assert_eq!(mempool_conflicted(&report), vec![(payment, double_spend)]);

    let cached = cached_scan().expect("nor the cached descriptor scan");
    assert_eq!(mempool_conflicted(&cached), vec![(payment, double_spend)]);
    assert_eq!(cached.stats.transactions_analyzed, 0);
}

/// A node on a datadir kept across restarts, with extra arguments.
fn node_on(datadir: &std::path::Path, args: &[&str]) -> Node {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.staticdir = Some(datadir.to_path_buf());
    conf.args.push("-txindex");
    conf.args.extend_from_slice(args);
    Node::with_conf(exe, &conf).expect("failed to start bitcoind")
}

/// Removes a test's datadir when the test ends, passing or not.
struct TempDatadir(std::path::PathBuf);

impl Drop for TempDatadir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Core keeps replaced_by_txid on a bumped original for good: abandon the
/// replacement while it is out of the mempool and the wallet rebroadcasts the
/// original, which is then live and must be analyzed.
#[test]
fn a_bumped_original_back_in_the_mempool_is_analyzed() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // Declared before the nodes, so it is dropped after them.
    let guard = TempDatadir(std::env::temp_dir().join(format!("stealth-rebroadcast-{nanos}")));
    std::fs::create_dir_all(&guard.0).unwrap();
    let datadir = guard.0.as_path();

    let mut first = node_on(datadir, &[]);
    let miner = first.client.new_address().unwrap();
    mine(&first, 110, &miner);
    let to = first.client.new_address().unwrap();
    let original: String = first
        .client
        .call(
            "sendtoaddress",
            &[
                json!(to.to_string()),
                json!(0.001),
                json!(""),
                json!(""),
                json!(false),
                json!(true),
            ],
        )
        .expect("sendtoaddress");
    let bumped: Value = first
        .client
        .call("bumpfee", &[json!(original)])
        .expect("bumpfee");
    let original: Txid = original.parse().unwrap();
    let replacement: Txid = bumped["txid"].as_str().unwrap().parse().unwrap();
    first.stop().unwrap();

    // Without the saved mempool or wallet broadcast, the replacement is out and can be abandoned.
    let mut second = node_on(datadir, &["-persistmempool=0", "-walletbroadcast=0"]);
    let _: Value = second
        .client
        .call("abandontransaction", &[json!(replacement.to_string())])
        .expect("abandontransaction");
    second.stop().unwrap();

    let node = node_on(datadir, &["-persistmempool=0"]);
    let mempool: Vec<String> = node.client.call("getrawmempool", &[]).unwrap();
    assert_eq!(
        mempool,
        vec![original.to_string()],
        "the wallet rebroadcasts the original"
    );

    let history = gateway_for(&node).scan_wallet("default").expect("scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(
        graph.our_txids.contains(&original),
        "the live original is analyzed"
    );
    let report = graph.detect_all(&Default::default(), None, None);
    assert!(mempool_conflicted(&report).is_empty(), "{:?}", report.stats);
    assert_eq!(report.stats.abandoned_txids, vec![replacement]);
    drop(node);
}

/// A payment and a child spending its change, both expired from the mempool.
#[test]
fn txs_expired_from_the_mempool_are_left_out_as_unavailable() {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    conf.args.push("-mempoolexpiry=1");
    let node = Node::with_conf(exe, &conf).expect("failed to start bitcoind");
    let miner = node.client.new_address().unwrap();
    mine(&node, 110, &miner);
    let (alice, _) = fund_sender(&node, &miner, "alice", 1_000_000);
    let bob = node.create_wallet("bob").unwrap();
    let to = bob.new_address().unwrap();
    let gateway = gateway_for(&node);
    let settings = EngineSettings {
        persist_scan_wallet: true,
        ..EngineSettings::default()
    };
    let descriptor = format!("addr({to})");
    let cached_scan = || {
        AnalysisEngine::new(&gateway, settings.clone())
            .analyze(ScanTarget::Descriptor(descriptor.clone()))
    };
    cached_scan().expect("first scan");

    let payment: String = alice
        .call("sendtoaddress", &[json!(to.to_string()), json!(0.001)])
        .expect("sendtoaddress");
    let payment: Txid = payment.parse().unwrap();
    let child: String = alice
        .call(
            "sendtoaddress",
            &[
                json!(node.client.new_address().unwrap().to_string()),
                json!(0.002),
            ],
        )
        .expect("sendtoaddress");
    let child: Txid = child.parse().unwrap();

    // Past the one-hour expiry, the next tx the mempool accepts expires both.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _: Value = node
        .client
        .call("setmocktime", &[json!(now + 2 * 3600)])
        .unwrap();
    node.client
        .send_to_address(
            &node.client.new_address().unwrap(),
            Amount::from_sat(10_000),
        )
        .unwrap();
    let mempool: Vec<String> = node.client.call("getrawmempool", &[]).unwrap();
    assert!(!mempool.contains(&payment.to_string()), "{mempool:?}");
    assert!(!mempool.contains(&child.to_string()), "{mempool:?}");

    let report = scan_wallet(&gateway, "bob");
    assert_eq!(report.stats.unavailable_txids, vec![payment]);
    let alice_history = gateway
        .scan_wallet("alice")
        .expect("expired txs must not fail the sender's scan");
    let graph = TxGraph::from_wallet_history(alice_history);
    assert!(!graph.our_txids.contains(&payment));
    assert!(!graph.our_txids.contains(&child));
    let report = graph.detect_all(&Default::default(), None, None);
    let mut expected = vec![payment, child];
    expected.sort_by_key(Txid::to_string);
    assert_eq!(report.stats.unavailable_txids, expected);

    let cached = cached_scan().expect("nor the cached descriptor scan");
    assert_eq!(cached.stats.unavailable_txids, vec![payment]);
    assert_eq!(cached.stats.transactions_analyzed, 0);
}
