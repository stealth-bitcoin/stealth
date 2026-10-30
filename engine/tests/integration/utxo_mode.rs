use crate::common::*;

use stealth_engine::engine::UtxoInput;

// ─── ScanTarget::Utxos correctness ─────────────────────────────────────────

fn utxo_inputs_for(wallet: &corepc_node::Client) -> Vec<UtxoInput> {
    let unspent = wallet.list_unspent().expect("list_unspent failed");
    unspent
        .0
        .iter()
        .map(|u| UtxoInput {
            txid: u.txid.parse().expect("invalid txid from listunspent"),
            vout: u.vout as u32,
            value: None,
            address: None,
        })
        .collect()
}

#[test]
fn utxo_scan_sees_real_confirmations_for_age_spread() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let a1 = alice.new_address().unwrap();
    node.client.send_to_address(&a1, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Age the first utxo well past the spread threshold (10 blocks).
    mine(&node, 15, &da);

    let a2 = alice.new_address().unwrap();
    node.client.send_to_address(&a2, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let report = engine
        .analyze(ScanTarget::Utxos(utxo_inputs_for(&alice)))
        .expect("utxo scan failed");

    assert!(
        has_finding(&report, VulnerabilityType::UtxoAgeSpread),
        "age spread must fire when utxo confirmations differ by more than the threshold"
    );
}

#[test]
fn ownership_descriptors_suppress_own_batch_false_positive() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let a1 = alice.new_address().unwrap();
    node.client
        .send_to_address(&a1, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice pays 8 parties in one batch, mirroring an exchange-like shape.
    let mut amounts: BTreeMap<Address, Amount> = BTreeMap::new();
    for i in 0..8u64 {
        let b = bob.new_address().unwrap();
        amounts.insert(b, Amount::from_sat(1_000_000 + i * 100_000));
    }
    alice.send_many(amounts).expect("batch send failed");
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let utxos = utxo_inputs_for(&alice);
    assert!(!utxos.is_empty(), "alice must hold change from her batch");

    // Without ownership context her own batch reads as an exchange payout.
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let naive = engine
        .analyze(ScanTarget::Utxos(utxos.clone()))
        .expect("naive scan failed");
    assert!(
        has_finding(&naive, VulnerabilityType::ExchangeOrigin),
        "precondition: the false positive fires without context"
    );

    // With her own descriptors the engine recognizes her as the sender.
    let settings = EngineSettings {
        ownership_descriptors: wallet_descriptors(&alice),
        ..EngineSettings::default()
    };
    let engine = AnalysisEngine::new(&gateway, settings);
    let informed = engine
        .analyze(ScanTarget::Utxos(utxos))
        .expect("informed scan failed");
    assert!(
        !has_finding(&informed, VulnerabilityType::ExchangeOrigin),
        "ownership context must suppress the exchange-origin false positive"
    );
}

#[test]
fn utxo_scan_counts_address_reuse_from_the_chain_not_from_the_pasted_outputs() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let a1 = alice.new_address().unwrap();
    for _ in 0..3 {
        node.client
            .send_to_address(&a1, Amount::from_sat(100_000))
            .unwrap();
        mine(&node, 1, &da);
    }

    // One of the three outputs, pasted alone.
    let one: Vec<UtxoInput> = utxo_inputs_for(&alice).into_iter().take(1).collect();
    let gateway = gateway_for(&node);
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let report = engine
        .analyze(ScanTarget::Utxos(one))
        .expect("utxo scan failed");

    let reuse = report
        .findings
        .iter()
        .find(|f| f.vulnerability_type == VulnerabilityType::AddressReuse)
        .expect("the address was paid three times, so reuse must be reported");
    assert!(
        reuse.description.contains("reused across 3 transactions"),
        "the count must be the chain's, got: {}",
        reuse.description
    );
    assert_eq!(report.stats.addresses_without_history, 0);
}

#[test]
fn utxo_scan_on_a_node_without_wallet_support_reports_the_history_caveat() {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    conf.args.push("-disablewallet");
    conf.wallet = None;
    let node = Node::with_conf(exe, &conf).expect("failed to start bitcoind");
    assert_caveat_on_a_pasted_coinbase(&node);
}

#[test]
fn utxo_scan_for_a_user_the_whitelist_denies_a_history_call_reports_the_history_caveat() {
    let base = "getblockchaininfo,getnetworkinfo,getblockcount,generatetoaddress,\
                getbestblockhash,getblock,getrawtransaction,deriveaddresses,getindexinfo,\
                unloadwallet,abortrescan,getwalletinfo,stop";
    // Each case leaves a call the address-history load needs out of the whitelist.
    for allowed in [
        "getdescriptorinfo",
        "getdescriptorinfo,createwallet",
        "getdescriptorinfo,createwallet,importdescriptors",
    ] {
        let exe = corepc_node::exe_path().expect("bitcoind not found");
        let mut conf = corepc_node::Conf::default();
        conf.args.push("-txindex");
        let whitelist = format!("-rpcwhitelist=__cookie__:{base},{allowed}");
        conf.args.push(&whitelist);
        conf.wallet = None;
        let node = Node::with_conf(exe, &conf).expect("failed to start bitcoind");
        assert_caveat_on_a_pasted_coinbase(&node);
    }
}

#[test]
fn utxo_scan_for_a_user_the_whitelist_denies_getrawtransaction_names_the_call() {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    conf.args.push(
        "-rpcwhitelist=__cookie__:getblockchaininfo,getnetworkinfo,getblockcount,\
         generatetoaddress,getbestblockhash,getblock,stop",
    );
    conf.wallet = None;
    let node = Node::with_conf(exe, &conf).expect("failed to start bitcoind");
    let coinbase = mine_a_coinbase(&node);

    let gateway = gateway_for(&node);
    let error = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![UtxoInput {
            txid: coinbase,
            vout: 0,
            value: None,
            address: None,
        }]))
        .expect_err("the pasted output cannot be fetched");
    assert!(
        error
            .to_string()
            .contains("getrawtransaction: forbidden by the node (rpcwhitelist or rpcallowip)"),
        "{error}"
    );
}

fn mine_a_coinbase(node: &Node) -> Txid {
    let miner: Address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        .parse::<Address<_>>()
        .unwrap()
        .assume_checked();
    mine(node, 1, &miner);
    let tip = node
        .client
        .call::<serde_json::Value>("getbestblockhash", &[])
        .unwrap();
    let block = node
        .client
        .call::<serde_json::Value>("getblock", &[tip, serde_json::json!(1)])
        .unwrap();
    block["tx"][0].as_str().unwrap().parse().unwrap()
}

fn assert_caveat_on_a_pasted_coinbase(node: &Node) {
    let coinbase = mine_a_coinbase(node);

    let gateway = gateway_for(node);
    let report = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![UtxoInput {
            txid: coinbase,
            vout: 0,
            value: None,
            address: None,
        }]))
        .expect("a node that cannot rescan still yields a report");
    assert_eq!(report.stats.addresses_without_history, 1);
}

#[test]
fn utxo_scan_on_a_node_without_txindex_reports_the_history_caveat() {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let node = Node::with_conf(exe, &corepc_node::Conf::default()).expect("bitcoind");
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let a1 = alice.new_address().unwrap();
    node.client
        .send_to_address(&a1, Amount::from_sat(100_000))
        .unwrap();
    mine(&node, 1, &da);
    // The second payment stays in the mempool, the only place a node
    // without txindex can look a non-wallet transaction up.
    let pending: Txid = node
        .client
        .send_to_address(&a1, Amount::from_sat(100_000))
        .unwrap()
        .0
        .parse()
        .unwrap();
    let raw = node
        .client
        .call::<serde_json::Value>(
            "getrawtransaction",
            &[
                serde_json::json!(pending.to_string()),
                serde_json::json!(true),
            ],
        )
        .unwrap();
    let vout = raw["vout"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["scriptPubKey"]["address"] == a1.to_string())
        .and_then(|o| o["n"].as_u64())
        .expect("the payment output") as u32;
    let pasted = vec![UtxoInput {
        txid: pending,
        vout,
        value: None,
        address: None,
    }];

    let gateway = gateway_for(&node);
    let report = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(pasted))
        .expect("an address history the node cannot look up is a caveat");
    assert_eq!(report.stats.addresses_without_history, 1);
}

#[test]
fn utxo_scan_on_a_pruned_node_reports_the_history_caveat() {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-prune=1");
    conf.args.push("-fastprune");
    let node = Node::with_conf(exe, &conf).expect("bitcoind");
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let a1 = alice.new_address().unwrap();
    node.client
        .send_to_address(&a1, Amount::from_sat(100_000))
        .unwrap();
    mine(&node, 600, &da);
    node.client
        .call::<serde_json::Value>("pruneblockchain", &[serde_json::json!(500)])
        .unwrap();
    let pending: Txid = node
        .client
        .send_to_address(&a1, Amount::from_sat(100_000))
        .unwrap()
        .0
        .parse()
        .unwrap();
    let vout = payment_vout(&node, pending, &a1);

    let gateway = gateway_for(&node);
    let report = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![UtxoInput {
            txid: pending,
            vout,
            value: None,
            address: None,
        }]))
        .expect("a rescan the pruned node cannot do is a caveat");
    assert_eq!(report.stats.addresses_without_history, 1);
}

fn payment_vout(node: &Node, txid: Txid, to: &Address) -> u32 {
    let raw = node
        .client
        .call::<serde_json::Value>(
            "getrawtransaction",
            &[serde_json::json!(txid.to_string()), serde_json::json!(true)],
        )
        .unwrap();
    raw["vout"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["scriptPubKey"]["address"] == to.to_string())
        .and_then(|o| o["n"].as_u64())
        .expect("the payment output") as u32
}
