// Shared helpers and re-exports for all integration test modules.

pub use corepc_node::client::bitcoin::{Address, Amount};
pub use corepc_node::{AddressType, Input, Node, Output};
pub use std::collections::{BTreeMap, HashSet};
pub use stealth_bitcoincore::BitcoinCoreRpc;
pub use stealth_engine::engine::{AnalysisEngine, EngineSettings, ScanTarget};
pub use stealth_engine::gateway::BlockchainGateway;
pub use stealth_engine::{TxGraph, VulnerabilityType};

pub use bitcoin::Txid;
// ─── helpers ────────────────────────────────────────────────────────────────

pub fn node() -> Node {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    Node::with_conf(exe, &conf).expect("failed to start bitcoind")
}

pub fn mine(node: &Node, n: usize, addr: &Address) {
    node.client.generate_to_address(n, addr).unwrap();
}

pub fn gateway_for(node: &Node) -> BitcoinCoreRpc {
    let cookie =
        std::fs::read_to_string(&node.params.cookie_file).expect("failed to read cookie file");
    let mut parts = cookie.trim().splitn(2, ':');
    let user = parts.next().unwrap().to_string();
    let pass = parts.next().unwrap().to_string();
    BitcoinCoreRpc::from_url(&node.rpc_url(), Some(user), Some(pass))
        .expect("failed to build gateway")
}

pub fn scan_wallet(gateway: &BitcoinCoreRpc, wallet: &str) -> stealth_engine::Report {
    let history = gateway.scan_wallet(wallet).expect("scan_wallet failed");
    let graph = TxGraph::from_wallet_history(history);
    graph.detect_all(&Default::default(), None, None)
}

pub fn scan_wallet_with(
    gateway: &BitcoinCoreRpc,
    wallet: &str,
    known_risky: Option<&HashSet<Txid>>,
    known_exchange: Option<&HashSet<Txid>>,
) -> stealth_engine::Report {
    let history = gateway.scan_wallet(wallet).expect("scan_wallet failed");
    let graph = TxGraph::from_wallet_history(history);
    graph.detect_all(&Default::default(), known_risky, known_exchange)
}

pub fn has_finding(report: &stealth_engine::Report, vtype: VulnerabilityType) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.vulnerability_type == vtype)
}

/// A client bound to one of the node's wallets, for RPCs the engine does not expose.
pub fn node_wallet(node: &Node, name: &str) -> corepc_node::Client {
    corepc_node::Client::new_with_auth(
        &format!("{}/wallet/{}", node.rpc_url(), name),
        corepc_node::client::client_sync::Auth::CookieFile(node.params.cookie_file.clone()),
    )
    .expect("wallet client")
}

/// Every descriptor string of a wallet, as Core prints them.
pub fn wallet_descriptors(wallet: &corepc_node::Client) -> Vec<String> {
    let resp: serde_json::Value = wallet
        .call("listdescriptors", &[])
        .expect("listdescriptors failed");
    resp["descriptors"]
        .as_array()
        .expect("descriptors array missing")
        .iter()
        .filter_map(|d| d["desc"].as_str().map(str::to_owned))
        .collect()
}
