// Shared helpers and re-exports for all integration test modules.

pub use corepc_node::client::bitcoin::{Address, Amount, ScriptBuf, TxOut};
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
    let outputs: Vec<TxOut> = outputs
        .iter()
        .map(|(addr, sats)| TxOut {
            value: Amount::from_sat(*sats),
            script_pubkey: addr.script_pubkey(),
        })
        .collect();
    spend_to_scripts(wallet, outputs, change);
}

/// Like [`spend_to`], with the outputs given as raw scripts.
pub fn spend_to_scripts(wallet: &corepc_node::Client, outputs: Vec<TxOut>, change: &Address) {
    let utxos = wallet.list_unspent().unwrap();
    assert_eq!(utxos.0.len(), 1, "sender must hold exactly one UTXO");
    let input = &utxos.0[0];
    let input_sats = (input.amount * 1e8).round() as u64;
    let fee_sats: u64 = 20_000;
    let paid: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();

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
    tx.output = outputs;
    tx.output.push(change_out);
    let signed = wallet.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    wallet.send_raw_transaction(&stx).unwrap();
}

/// Scan alice after a 1M-sat sender pays `alice_sats` to fresh alice
/// addresses, `other_sats` to fresh outside addresses, `self_outputs` back
/// to its own input address, an optional empty OP_RETURN, and change back to
/// its input address.
pub fn payout_report(
    alice_sats: &[u64],
    other_sats: &[u64],
    self_outputs: &[u64],
    op_return: bool,
) -> stealth_engine::Report {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let (sender, sender_addr) = fund_sender(&node, &da, "sender", 1_000_000);

    let mut outputs = Vec::new();
    for &sats in alice_sats {
        outputs.push((alice.new_address().unwrap(), sats));
    }
    for &sats in other_sats {
        outputs.push((node.client.new_address().unwrap(), sats));
    }
    for &sats in self_outputs {
        outputs.push((sender_addr.clone(), sats));
    }
    let mut outputs: Vec<TxOut> = outputs
        .into_iter()
        .map(|(addr, sats)| TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: addr.script_pubkey(),
        })
        .collect();
    if op_return {
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([]),
        });
    }
    spend_to_scripts(&sender, outputs, &sender_addr);
    mine(&node, 1, &da);

    scan_wallet(&gateway_for(&node), "alice")
}

pub fn has_dust_attack(report: &stealth_engine::Report) -> bool {
    report.findings.iter().any(|f| {
        f.vulnerability_type == VulnerabilityType::Dust
            && f.details
                .as_ref()
                .and_then(|d| d.get("dust_attack"))
                .is_some()
    })
}

// Funds `n` fresh UTXOs of `sats` each in `wallet`, returning them as inputs.
pub fn fund_coins(node: &Node, wallet: &corepc_node::Client, n: usize, sats: u64) -> Vec<Input> {
    let addrs = (0..n).map(|_| wallet.new_address().unwrap()).collect();
    fund_coins_at(node, wallet, addrs, sats)
}

// Funds one UTXO of `sats` at each of `addrs` (owned by `wallet`), returning them as inputs.
pub fn fund_coins_at(
    node: &Node,
    wallet: &corepc_node::Client,
    addrs: Vec<Address>,
    sats: u64,
) -> Vec<Input> {
    let da = node.client.new_address().unwrap();
    let mut txids = Vec::new();
    for a in addrs {
        let sent = node
            .client
            .send_to_address(&a, Amount::from_sat(sats))
            .unwrap();
        txids.push(sent.txid().unwrap());
    }
    mine(node, 1, &da);
    wallet
        .list_unspent()
        .unwrap()
        .0
        .iter()
        .filter(|u| txids.contains(&u.txid.parse().unwrap()))
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect()
}

// Spends `inputs` into one output at `dest`, each signer signing its own inputs.
pub fn merge_into(
    node: &Node,
    signers: &[&corepc_node::Client],
    inputs: &[Input],
    dest: Address,
    total_sats: u64,
) {
    let outputs = [Output::new(dest, Amount::from_sat(total_sats - 10_000))];
    spend(node, signers, inputs, &outputs);
}

// Spends `inputs` into `outputs`, each signer signing its own inputs, and mines it.
pub fn spend(node: &Node, signers: &[&corepc_node::Client], inputs: &[Input], outputs: &[Output]) {
    let raw = signers[0].create_raw_transaction(inputs, outputs).unwrap();
    let mut tx = raw.transaction().unwrap();
    for signer in signers {
        tx = signer
            .sign_raw_transaction_with_wallet(&tx)
            .unwrap()
            .into_model()
            .unwrap()
            .tx;
    }
    node.client.send_raw_transaction(&tx).unwrap();
    let da = node.client.new_address().unwrap();
    mine(node, 1, &da);
}

pub fn consolidation_finding(report: &stealth_engine::Report) -> &stealth_engine::Finding {
    report
        .findings
        .iter()
        .find(|f| f.vulnerability_type == VulnerabilityType::Consolidation)
        .expect("expected a consolidation finding")
}

// The neutral, low-severity warning, with its (ours, unrecognised, unresolved) input counts.
pub fn assert_consolidation_warning(
    report: &stealth_engine::Report,
    ours: u64,
    unrecognised: u64,
    unresolved: u64,
) {
    assert!(!has_finding(report, VulnerabilityType::Consolidation));
    let warning = report
        .warnings
        .iter()
        .find(|w| w.vulnerability_type == VulnerabilityType::Consolidation)
        .expect("expected a consolidation warning");
    assert_eq!(warning.severity, stealth_engine::Severity::Low);
    assert!(
        warning.description.contains("cannot tell whose"),
        "{}",
        warning.description
    );
    let correction = warning.correction.as_deref().unwrap_or_default();
    assert!(
        correction.starts_with("If these inputs were yours")
            && correction.contains("avoid merging"),
        "{correction}"
    );
    assert!(!correction.contains("nothing to do"), "{correction}");
    let details = warning.details.as_ref().expect("warning details");
    assert_eq!(details["our_inputs_in_consolidation"], ours);
    assert_eq!(details["unrecognised_inputs"], unrecognised);
    assert_eq!(details["unresolved_inputs"], unresolved);
}

pub fn assert_no_consolidation(report: &stealth_engine::Report) {
    assert!(!has_finding(report, VulnerabilityType::Consolidation));
    assert!(!has_warning(report, VulnerabilityType::Consolidation));
}

pub fn has_warning(report: &stealth_engine::Report, vtype: VulnerabilityType) -> bool {
    report
        .warnings
        .iter()
        .any(|f| f.vulnerability_type == vtype)
}

pub fn change_address(wallet: &corepc_node::Client) -> Address {
    let change: String = wallet
        .call("getrawchangeaddress", &[serde_json::json!("bech32")])
        .unwrap();
    change.parse::<Address<_>>().unwrap().assume_checked()
}

// Alice merges one wpkh coin and three taproot coins into `dest`; returns her
// wpkh descriptors, the view a zpub scan has.
pub fn merge_across_script_types_into(
    node: &Node,
    dest: impl Fn(&corepc_node::Client) -> Address,
) -> (corepc_node::Client, Vec<String>) {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let taproot = (0..3)
        .map(|_| alice.new_address_with_type(AddressType::Bech32m).unwrap())
        .collect();
    let mut inputs = fund_coins_at(node, &alice, vec![alice.new_address().unwrap()], 300_000);
    inputs.extend(fund_coins_at(node, &alice, taproot, 300_000));
    merge_into(node, &[&alice], &inputs, dest(&alice), 1_200_000);

    let wpkh: Vec<String> = wallet_descriptors(&alice)
        .into_iter()
        .filter(|d| d.starts_with("wpkh("))
        .collect();
    assert_eq!(wpkh.len(), 2, "receive and change wpkh descriptors");
    (alice, wpkh)
}

// The change-address warning names both a cross-account merge and a collaborative tx.
pub fn assert_change_address_wording(warning: &stealth_engine::Finding) {
    for part in [
        "your change address",
        "another account or script type",
        "beyond the scanned derivation range",
        "collaborative transaction (Payjoin, CoinJoin, dual-funded channel)",
    ] {
        assert!(
            warning.description.contains(part),
            "{}",
            warning.description
        );
    }
    let correction = warning.correction.as_deref().unwrap_or_default();
    assert!(
        correction.starts_with(
            "If these inputs were yours, from another account, script type or beyond the \
             scanned derivation range:"
        ),
        "{correction}"
    );
}
