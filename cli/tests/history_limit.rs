//! The CLI against a regtest node, at the history limit.

use std::process::{Command, Output, Stdio};

use corepc_node::client::bitcoin::{Address, Amount};
use corepc_node::Node;

fn node_with_an_address_paid_five_times() -> (Node, Address) {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    let node = Node::with_conf(exe, &conf).expect("failed to start bitcoind");
    let da = node.client.new_address().expect("default address");
    node.client.generate_to_address(110, &da).expect("mine");
    let alice = node.create_wallet("alice").expect("create alice");
    let aa = alice.new_address().expect("alice address");
    for _ in 0..5 {
        node.client
            .send_to_address(&aa, Amount::from_sat(100_000))
            .expect("pay alice");
        node.client.generate_to_address(1, &da).expect("mine");
    }
    (node, aa)
}

// stdin is not a terminal here, so nobody is asked.
fn scan(node: &Node, address: &Address, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stealth-cli"))
        .args(["scan", "--descriptor", &format!("addr({address})")])
        .args(["--rpc-url", &node.rpc_url()])
        .arg("--rpc-cookie")
        .arg(&node.params.cookie_file)
        .args(flags)
        .env_remove("STEALTH_RPC_USER")
        .env_remove("STEALTH_RPC_PASS")
        .stdin(Stdio::null())
        .output()
        .expect("run stealth-cli")
}

fn stealth_wallets_loaded(node: &Node) -> Vec<String> {
    node.client
        .call::<Vec<String>>("listwallets", &[])
        .expect("listwallets")
        .into_iter()
        .filter(|name| name.starts_with("_stealth"))
        .collect()
}

#[test]
fn a_history_above_max_txs_stops_with_the_count_and_the_flags() {
    let (node, aa) = node_with_an_address_paid_five_times();

    let stopped = scan(&node, &aa, &["--max-txs", "3"]);
    let stderr = String::from_utf8_lossy(&stopped.stderr);
    assert_eq!(stopped.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("5 transactions"), "{stderr}");
    assert!(stderr.contains("limit of 3"), "{stderr}");
    assert!(stderr.contains("--max-txs 5"), "{stderr}");
    assert!(stderr.contains("--no-limits"), "{stderr}");
    assert!(stopped.stdout.is_empty());
    assert_eq!(stealth_wallets_loaded(&node), Vec::<String>::new());

    for flags in [&["--max-txs", "5"][..], &["--no-limits"]] {
        let scanned = scan(&node, &aa, flags);
        let stdout = String::from_utf8_lossy(&scanned.stdout);
        assert!(
            stdout.contains("Scanned 5 transactions"),
            "{flags:?}: {stdout}{}",
            String::from_utf8_lossy(&scanned.stderr)
        );
    }
}

#[test]
fn the_default_limit_lets_a_small_history_through() {
    let (node, aa) = node_with_an_address_paid_five_times();
    let scanned = scan(&node, &aa, &[]);
    assert!(String::from_utf8_lossy(&scanned.stdout).contains("Scanned 5 transactions"));
}
