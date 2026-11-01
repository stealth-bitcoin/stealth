use crate::common::*;

use stealth_engine::engine::{HistoryLimit, UtxoInput};
use stealth_engine::error::{AnalysisError, HistoryOf};

/// An address paid five times, each payment in its own block.
fn address_paid_five_times(node: &Node) -> Address {
    let da = node.client.new_address().expect("default address");
    mine(node, 110, &da);
    let alice = node.create_wallet("alice").expect("create alice");
    let aa = alice.new_address().expect("alice address");
    for _ in 0..5 {
        node.client
            .send_to_address(&aa, Amount::from_sat(100_000))
            .expect("pay alice");
        mine(node, 1, &da);
    }
    aa
}

fn limited_to(max_txs: u64) -> EngineSettings {
    EngineSettings {
        history_limit: HistoryLimit::at_most(max_txs),
        ..EngineSettings::default()
    }
}

/// Wallets loaded on the node apart from the test's own.
fn stealth_wallets_loaded(node: &Node) -> Vec<String> {
    node.client
        .call::<Vec<String>>("listwallets", &[])
        .expect("listwallets")
        .into_iter()
        .filter(|name| name.starts_with("_stealth"))
        .collect()
}

#[test]
fn a_descriptor_scan_above_the_limit_stops_and_leaves_no_wallet_loaded() {
    let node = node();
    let aa = address_paid_five_times(&node);
    let gateway = gateway_for(&node);

    let error = AnalysisEngine::new(&gateway, limited_to(3))
        .analyze(ScanTarget::Descriptor(format!("addr({aa})")))
        .expect_err("five txs are above a limit of three");
    assert_eq!(
        error,
        AnalysisError::HistoryTooLarge {
            of: HistoryOf::Wallet,
            tx_count: 5,
            limit: 3
        }
    );
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());

    let report = AnalysisEngine::new(&gateway, limited_to(5))
        .analyze(ScanTarget::Descriptor(format!("addr({aa})")))
        .expect("five txs are at a limit of five");
    assert_eq!(report.stats.transactions_analyzed, 5);
}

#[test]
fn a_cache_wallet_above_the_limit_is_unloaded_and_reused_by_the_next_scan() {
    let node = node();
    let aa = address_paid_five_times(&node);
    let gateway = gateway_for(&node);
    let cached = |max_txs| EngineSettings {
        persist_scan_wallet: true,
        ..limited_to(max_txs)
    };

    let error = AnalysisEngine::new(&gateway, cached(3))
        .analyze(ScanTarget::Descriptor(format!("addr({aa})")))
        .expect_err("five txs are above a limit of three");
    assert!(
        matches!(error, AnalysisError::HistoryTooLarge { tx_count: 5, .. }),
        "{error}"
    );
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());

    // The stop came after the build finished, so the wallet left on disk is a complete cache.
    let resolved =
        stealth_engine::descriptor::normalize_descriptors(&[format!("addr({aa})")], 999, &gateway)
            .expect("normalize");
    let cache = stealth_bitcoincore::cache_wallet_name(&resolved);
    let on_disk: serde_json::Value = node
        .client
        .call("listwalletdir", &[])
        .expect("listwalletdir");
    assert!(
        on_disk["wallets"]
            .as_array()
            .is_some_and(|wallets| wallets.iter().any(|w| w["name"] == cache)),
        "{on_disk}"
    );
    node.client
        .call::<serde_json::Value>("loadwallet", &[cache.clone().into()])
        .expect("loadwallet");
    assert!(
        gateway
            .cache_is_complete(&cache, &resolved)
            .expect("cache check"),
        "the next scan must reuse the cache, not build it again"
    );
    node_wallet(&node, &cache)
        .call::<serde_json::Value>("unloadwallet", &[])
        .expect("unloadwallet");

    let report = AnalysisEngine::new(&gateway, cached(5))
        .analyze(ScanTarget::Descriptor(format!("addr({aa})")))
        .expect("the cache wallet loads again");
    assert_eq!(report.stats.transactions_analyzed, 5);
}

#[test]
fn a_utxo_scan_whose_address_history_is_above_the_limit_stops() {
    let node = node();
    let aa = address_paid_five_times(&node);
    let alice = node_wallet(&node, "alice");
    let unspent = alice.list_unspent().expect("listunspent");
    let pasted = UtxoInput {
        txid: unspent.0[0].txid.parse().expect("txid"),
        vout: unspent.0[0].vout as u32,
        value: None,
        address: Some(aa.to_string().parse().expect("address")),
    };
    let gateway = gateway_for(&node);

    let error = AnalysisEngine::new(&gateway, limited_to(3))
        .analyze(ScanTarget::Utxos(vec![pasted.clone()]))
        .expect_err("the address history is above the limit");
    assert_eq!(
        error,
        AnalysisError::HistoryTooLarge {
            of: HistoryOf::PastedAddresses,
            tx_count: 5,
            limit: 3
        }
    );
    assert!(
        error
            .to_string()
            .starts_with("the history of the pasted outputs' addresses holds 5 transactions"),
        "{error}"
    );
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());

    let report = AnalysisEngine::new(&gateway, limited_to(5))
        .analyze(ScanTarget::Utxos(vec![pasted]))
        .expect("at the limit");
    assert_eq!(report.stats.addresses_without_history, 0);
}

/// A node whose RPC user may make every call a scan needs except getwalletinfo,
/// with an address paid five times.
fn node_refusing_getwalletinfo() -> (Node, Address) {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    conf.args.push(
        "-rpcwhitelist=__cookie__:getblockchaininfo,getnetworkinfo,getblockcount,\
         generatetoaddress,getbestblockhash,getblock,getrawtransaction,deriveaddresses,\
         getindexinfo,getdescriptorinfo,createwallet,importdescriptors,listtransactions,\
         listunspent,getmempoolinfo,gettxout,unloadwallet,abortrescan,listwallets,\
         getnewaddress,sendtoaddress,stop",
    );
    let node = Node::with_conf(exe, &conf).expect("failed to start bitcoind");
    let aa = address_paid_five_times(&node);
    (node, aa)
}

#[test]
fn a_descriptor_scan_the_node_will_not_count_goes_on_unchecked() {
    let (node, aa) = node_refusing_getwalletinfo();
    let gateway = gateway_for(&node);
    let report = AnalysisEngine::new(&gateway, limited_to(3))
        .analyze(ScanTarget::Descriptor(format!("addr({aa})")))
        .expect("the count is unknown, so the scan goes on");
    assert_eq!(report.stats.transactions_analyzed, 5);
}

#[test]
fn a_utxo_scan_the_node_will_not_count_keeps_its_address_history() {
    let (node, aa) = node_refusing_getwalletinfo();
    let gateway = gateway_for(&node);
    // The pasted output comes from the history the gateway serves.
    let history = gateway
        .scan_descriptors(
            &[stealth_engine::gateway::ResolvedDescriptor {
                desc: gateway
                    .normalize_descriptor(&format!("addr({aa})"))
                    .expect("normalize"),
                internal: false,
                active: false,
                range_end: 0,
            }],
            false,
            &HistoryLimit::at_most(3),
        )
        .expect("history");
    let pasted = UtxoInput {
        txid: history.utxos[0].txid,
        vout: history.utxos[0].vout,
        value: None,
        address: Some(aa.to_string().parse().expect("address")),
    };
    let report = AnalysisEngine::new(&gateway, limited_to(3))
        .analyze(ScanTarget::Utxos(vec![pasted]))
        .expect("the count is unknown, so the scan goes on");
    assert_eq!(report.stats.addresses_without_history, 0);
    assert_eq!(report.stats.transactions_analyzed, 5);
}
