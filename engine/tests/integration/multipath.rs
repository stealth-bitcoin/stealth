use crate::common::*;

use stealth_engine::engine::UtxoInput;

// ─── Multipath descriptors (`/<0;1>/*`) ────────────────────────────────────

/// Alice's wpkh receive descriptor without its checksum.
fn receive_wpkh(alice: &corepc_node::Client) -> String {
    let desc = wallet_descriptors(alice)
        .into_iter()
        .find(|d| d.starts_with("wpkh(") && d.contains("/0/*"))
        .expect("a wpkh receive descriptor");
    desc.split('#').next().unwrap_or_default().to_owned()
}

fn multipath(receive: &str) -> String {
    receive.replace("/0/*", "/<0;1>/*")
}

fn explicit(receive: &str) -> Vec<String> {
    vec![receive.to_owned(), receive.replace("/0/*", "/1/*")]
}

/// Alice is funded on a receive address, pays bob with change, then pays him
/// again from that change alone: the last tx touches only her change chain.
fn alice_spends_from_change(node: &Node) -> corepc_node::Client {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(node, 1, &da);
    for _ in 0..2 {
        alice
            .send_to_address(&bob.new_address().unwrap(), Amount::from_sat(5_000_000))
            .unwrap();
        mine(node, 1, &da);
    }
    alice
}

fn scan(gateway: &BitcoinCoreRpc, target: ScanTarget, persist: bool) -> stealth_engine::Report {
    let settings = EngineSettings {
        persist_scan_wallet: persist,
        ..EngineSettings::default()
    };
    AnalysisEngine::new(gateway, settings)
        .analyze(target)
        .expect("scan")
}

fn as_json(report: &stealth_engine::Report) -> serde_json::Value {
    serde_json::to_value(report).expect("report serializes")
}

#[test]
fn a_multipath_descriptor_scans_like_its_receive_and_change_descriptors() {
    let node = node();
    let alice = alice_spends_from_change(&node);
    let receive = receive_wpkh(&alice);
    let gateway = gateway_for(&node);

    let both = scan(&gateway, ScanTarget::Descriptors(explicit(&receive)), false);
    let one = scan(&gateway, ScanTarget::Descriptor(multipath(&receive)), false);

    assert_eq!(both.stats.transactions_analyzed, 3, "{both:?}");
    assert!(has_finding(&both, VulnerabilityType::ChangeDetection));
    assert_eq!(as_json(&one), as_json(&both));
}

#[test]
fn a_multipath_descriptor_resolves_to_the_explicit_receive_and_change_pair() {
    let node = node();
    let alice = node.create_wallet("alice").unwrap();
    let receive = receive_wpkh(&alice);
    let gateway = gateway_for(&node);
    let range_end = stealth_engine::config::AnalysisConfig::default().derivation_range_end;

    let resolve = |raw: Vec<String>| {
        stealth_engine::descriptor::normalize_descriptors(&raw, range_end, &gateway)
            .expect("normalize")
    };
    let from_multipath = resolve(vec![multipath(&receive)]);
    assert_eq!(from_multipath, resolve(explicit(&receive)));
    assert_eq!(
        from_multipath
            .iter()
            .map(|d| d.internal)
            .collect::<Vec<_>>(),
        vec![false, true]
    );
    assert_eq!(
        stealth_bitcoincore::cache_wallet_name(&from_multipath),
        stealth_bitcoincore::cache_wallet_name(&resolve(explicit(&receive)))
    );
}

#[test]
fn a_multipath_scan_and_an_explicit_scan_share_one_cache_wallet() {
    let node = node();
    let alice = alice_spends_from_change(&node);
    let receive = receive_wpkh(&alice);
    let gateway = gateway_for(&node);

    let one = scan(&gateway, ScanTarget::Descriptor(multipath(&receive)), true);
    let both = scan(&gateway, ScanTarget::Descriptors(explicit(&receive)), true);

    let cached: Vec<String> = node
        .client
        .call::<Vec<String>>("listwallets", &[])
        .expect("listwallets")
        .into_iter()
        .filter(|name| name.starts_with("_stealth_cache_"))
        .collect();
    assert_eq!(cached.len(), 1, "{cached:?}");
    assert_eq!(one.stats.transactions_analyzed, 3);
    assert_eq!(as_json(&one), as_json(&both));
}

#[test]
fn a_multipath_ownership_descriptor_owns_the_change_chain() {
    let node = node();
    let (alice, wpkh) = merge_across_script_types_into(&node, change_address);
    let receive = wpkh
        .iter()
        .find(|d| d.contains("/0/*"))
        .map(|d| d.split('#').next().unwrap_or_default().to_owned())
        .expect("receive descriptor");
    let utxos: Vec<UtxoInput> = alice
        .list_unspent()
        .unwrap()
        .0
        .iter()
        .map(|u| UtxoInput {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u32,
            value: None,
            address: None,
        })
        .collect();
    let gateway = gateway_for(&node);
    let owned_by = |ownership_descriptors: Vec<String>| {
        let settings = EngineSettings {
            ownership_descriptors,
            ..EngineSettings::default()
        };
        AnalysisEngine::new(&gateway, settings)
            .analyze(ScanTarget::Utxos(utxos.clone()))
            .expect("utxo scan")
    };

    let one = owned_by(vec![multipath(&receive)]);
    let warning = one
        .warnings
        .iter()
        .find(|w| w.vulnerability_type == VulnerabilityType::Consolidation)
        .expect("warning");
    assert_change_address_wording(warning);
    assert_eq!(as_json(&one), as_json(&owned_by(explicit(&receive))));
}

#[test]
fn a_multipath_descriptor_without_a_wildcard_is_a_partial_scan_like_its_paths() {
    let (node, a, bobs, _) = crate::dust::dust_merged_with_a_third_coin(false);
    let alice = node_wallet(&node, "alice");
    let info: serde_json::Value = alice
        .call("getaddressinfo", &[serde_json::json!(a.to_string())])
        .unwrap();
    let index = info["hdkeypath"]
        .as_str()
        .and_then(|path| path.rsplit('/').next())
        .expect("hd key path")
        .to_owned();
    let receive = receive_wpkh(&alice);
    let at = |step: &str| receive.replace("/0/*", &format!("/{step}/{index}"));
    let gateway = gateway_for(&node);

    let one = scan(&gateway, ScanTarget::Descriptor(at("<0;1>")), false);
    // A partial scan cannot tell Bob's coin from another of Alice's addresses.
    let dust = crate::dust::finding_of(&one, VulnerabilityType::DustSpending);
    assert_eq!(dust.severity, stealth_engine::Severity::Medium);
    assert!(dust.description.contains(&bobs.to_string()), "{dust:?}");
    let both = scan(
        &gateway,
        ScanTarget::Descriptors(vec![at("0"), at("1")]),
        false,
    );
    assert_eq!(as_json(&one), as_json(&both));

    // Ranged, the same multipath descriptor is a full scan: Bob's coin is a stranger's.
    let full = scan(&gateway, ScanTarget::Descriptor(multipath(&receive)), false);
    assert!(
        !has_finding(&full, VulnerabilityType::DustSpending),
        "{:?}",
        full.findings
    );
}
