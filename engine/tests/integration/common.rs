// Shared helpers and re-exports for all integration test modules.

pub use corepc_node::client::bitcoin::{Address, Amount, TxOut};
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

/// Fund a fresh wallet `name` with one UTXO of `sats` at a single address and
/// return the wallet and that address.
pub fn fund_sender(
    node: &Node,
    miner: &Address,
    name: &str,
    sats: u64,
) -> (corepc_node::Client, Address) {
    let wallet = node.create_wallet(name).unwrap();
    let addr = wallet.new_address().unwrap();
    node.client
        .send_to_address(&addr, Amount::from_sat(sats))
        .unwrap();
    mine(node, 1, miner);
    (wallet, addr)
}

/// Spend the sender's only UTXO to `outputs` in order, repeated addresses
/// allowed, and send what is left minus a fixed fee back to `change`.
pub fn spend_to(wallet: &corepc_node::Client, outputs: &[(Address, u64)], change: &Address) {
    let utxos = wallet.list_unspent().unwrap();
    assert_eq!(utxos.0.len(), 1, "sender must hold exactly one UTXO");
    let input = &utxos.0[0];
    let input_sats = (input.amount * 1e8).round() as u64;
    let fee_sats: u64 = 20_000;
    let paid: u64 = outputs.iter().map(|(_, sats)| sats).sum();

    let raw = wallet
        .create_raw_transaction(
            &[Input {
                txid: input.txid.parse().unwrap(),
                vout: input.vout as u64,
                sequence: None,
            }],
            &[Output::new(
                change.clone(),
                Amount::from_sat(input_sats - paid - fee_sats),
            )],
        )
        .unwrap();
    let mut tx = raw.transaction().unwrap();
    // createrawtransaction rejects repeated addresses, so add the rest here.
    let change_out = tx.output.remove(0);
    tx.output = outputs
        .iter()
        .map(|(addr, sats)| TxOut {
            value: Amount::from_sat(*sats),
            script_pubkey: addr.script_pubkey(),
        })
        .collect();
    tx.output.push(change_out);
    let signed = wallet.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    wallet.send_raw_transaction(&stx).unwrap();
}
