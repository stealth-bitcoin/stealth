use crate::common::*;

use stealth_engine::gateway::ResolvedDescriptor;

// ─── Non-ranged descriptor derivation ──────────────────────────────────────

#[test]
fn scan_descriptors_derives_addresses_for_unranged_addr_descriptor() {
    let node = node();
    let da = node.client.new_address().expect("default address");
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").expect("create alice");
    let aa = alice.new_address().expect("alice address");
    node.client
        .send_to_address(&aa, Amount::ONE_BTC)
        .expect("fund alice");
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let desc = gateway
        .normalize_descriptor(&format!("addr({aa})"))
        .expect("normalize addr descriptor");
    let resolved = ResolvedDescriptor {
        desc,
        internal: false,
        active: true,
        range_end: 999,
    };

    let history = gateway
        .scan_descriptors(&[resolved], false)
        .expect("scan_descriptors");

    assert!(
        !history.wallet_txs.is_empty(),
        "funding tx must be visible to the descriptor scan"
    );
    let expected = aa
        .to_string()
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .expect("parse alice address");
    assert!(
        history.derived_addresses.contains(&expected),
        "derived_addresses must contain the addr() descriptor address, got: {:?}",
        history.derived_addresses
    );
}

// ─── listtransactions pagination ───────────────────────────────────────────

#[test]
fn list_transactions_paginates_beyond_page_size() {
    let node = node();
    let da = node.client.new_address().expect("default address");
    mine(&node, 110, &da);

    // One block per send: distinct heights make the ordering assertion
    // below sensitive to page reassembly.
    let bob = node.create_wallet("bob").expect("create bob");
    for _ in 0..12 {
        let ba = bob.new_address().expect("bob address");
        node.client
            .send_to_address(&ba, Amount::from_sat(100_000))
            .expect("fund bob");
        mine(&node, 1, &da);
    }

    let gateway = gateway_for(&node).with_tx_page_size(5);
    let history = gateway.scan_wallet("bob").expect("scan_wallet");

    assert_eq!(
        history.wallet_txs.len(),
        12,
        "all wallet transactions must be returned across pages"
    );
    let unique: HashSet<Txid> = history.wallet_txs.iter().map(|entry| entry.txid).collect();
    assert_eq!(unique.len(), 12, "pages must not duplicate transactions");
    let heights: Vec<u32> = history
        .wallet_txs
        .iter()
        .map(|entry| entry.blockheight)
        .collect();
    assert!(
        heights.windows(2).all(|pair| pair[0] <= pair[1]),
        "entries must stay oldest-first across page boundaries, got: {heights:?}"
    );
}

// ─── rpc errors ────────────────────────────────────────────────────────────

#[test]
fn rpc_error_reports_the_node_message_not_the_http_status() {
    let node = node();
    let gateway = gateway_for(&node);
    let unknown: Txid = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        .parse()
        .expect("txid");

    let err = gateway
        .get_transaction(unknown)
        .expect_err("an unknown txid must fail");
    let text = err.to_string();

    assert!(
        text.contains("No such mempool or blockchain transaction"),
        "the node's own message must reach the caller, got: {text}"
    );
    assert!(
        !text.contains("500"),
        "an RPC error is not a transport failure, got: {text}"
    );
}

#[test]
fn a_single_fetch_of_an_unknown_txid_is_not_found_and_names_it() {
    let node = node();
    let gateway = gateway_for(&node);
    let unknown: Txid = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        .parse()
        .expect("txid");

    let err = gateway
        .get_transaction(unknown)
        .expect_err("an unknown txid must fail");

    assert!(
        matches!(
            err,
            stealth_engine::error::AnalysisError::TransactionNotFound(_)
        ),
        "a lookup miss must be classified like the batch fetch, got: {err:?}"
    );
    assert!(err.to_string().contains(&unknown.to_string()), "{err}");
}

#[test]
fn txindex_synced_reflects_the_node() {
    let indexed = node();
    let gateway = gateway_for(&indexed);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !gateway.txindex_synced().unwrap() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        gateway.txindex_synced().unwrap(),
        "a -txindex node must report a synced index"
    );

    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let plain = Node::with_conf(exe, &corepc_node::Conf::default()).expect("bitcoind");
    assert!(
        !gateway_for(&plain).txindex_synced().unwrap(),
        "a node without -txindex has no index to rely on"
    );
}
