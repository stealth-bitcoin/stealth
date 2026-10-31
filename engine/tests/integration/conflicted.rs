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
