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

/// Alice pays bob, spends that payment's unconfirmed change, then a double
/// spend of the payment's input is mined. Core reports both at negative
/// depth; only the payment lists a wallet conflict.
#[test]
fn a_tx_spending_a_conflicted_one_is_left_out_and_named_too() {
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
    let decoded = gateway_for(&node).get_transaction(child).unwrap();
    assert!(
        decoded.vin.iter().any(|i| i.previous_txid == payment),
        "the second send must spend the first one's change"
    );

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

    let child_entry: Value = alice
        .call("gettransaction", &[json!(child.to_string())])
        .expect("gettransaction");
    assert!(
        child_entry["confirmations"].as_i64().unwrap() < 0,
        "{child_entry}"
    );
    assert_eq!(child_entry["walletconflicts"], json!([]), "{child_entry}");

    let history = gateway_for(&node)
        .scan_wallet("alice")
        .expect("a conflicted descendant must not fail the scan");
    let graph = TxGraph::from_wallet_history(history);
    assert!(!graph.our_txids.contains(&payment));
    assert!(!graph.our_txids.contains(&child));
    let report = graph.detect_all(&Default::default(), None, None);
    let mut expected = vec![payment, child];
    expected.sort_by_key(Txid::to_string);
    assert_eq!(report.stats.conflicted_txids, expected);
}
