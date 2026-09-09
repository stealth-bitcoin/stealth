use crate::common::*;

// ─── Full Report Smoke Test ─────────────────────────────────────────────────

#[test]
fn full_report_generates() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");

    assert_eq!(
        report.summary.findings + report.summary.warnings,
        report.findings.len() + report.warnings.len()
    );
    assert_eq!(report.stats.utxos_current, 1);
}

// ─── Persistent (cached) scan wallet ───────────────────────────────────────

fn loaded_cache_wallets(node: &Node) -> Vec<String> {
    node.client
        .call::<Vec<String>>("listwallets", &[])
        .expect("listwallets")
        .into_iter()
        .filter(|name| name.starts_with("_stealth_cache_"))
        .collect()
}

#[test]
fn persistent_scan_wallet_is_reused_across_scans() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let descriptor = format!("addr({aa})");

    let settings = EngineSettings {
        persist_scan_wallet: true,
        ..EngineSettings::default()
    };

    // First scan pays the import/rescan and leaves the cache wallet loaded.
    let engine = AnalysisEngine::new(&gateway, settings.clone());
    let first = engine
        .analyze(ScanTarget::Descriptor(descriptor.clone()))
        .unwrap();
    let cached = loaded_cache_wallets(&node);
    assert_eq!(
        cached.len(),
        1,
        "one persistent cache wallet must remain loaded, got: {cached:?}"
    );
    let cache_name = cached[0].clone();

    // New confirmed activity on the same address after the first scan.
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Second scan reuses the existing cache wallet (no new one appears) and
    // must pick up the new block: the catch-up is what the cache buys us.
    let engine = AnalysisEngine::new(&gateway, settings);
    let second = engine.analyze(ScanTarget::Descriptor(descriptor)).unwrap();

    let cached = loaded_cache_wallets(&node);
    assert_eq!(
        cached,
        vec![cache_name],
        "the second scan must reuse the same cache wallet, got: {cached:?}"
    );
    assert!(first.stats.transactions_analyzed >= 1);
    assert!(
        second.stats.transactions_analyzed > first.stats.transactions_analyzed,
        "the reused scan must catch up to new activity: first={}, second={}",
        first.stats.transactions_analyzed,
        second.stats.transactions_analyzed
    );
}

#[test]
fn concurrent_persistent_scans_share_one_cache_wallet() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let descriptor = format!("addr({aa})");

    // Two scans of the same descriptors hit the same cache name. The
    // per-cache lock serialises them: no createwallet race, and the loser
    // reads a fully-imported wallet, so both must succeed identically.
    let (first, second) = std::thread::scope(|scope| {
        let g = &gateway;
        let d = &descriptor;
        let run = || {
            let settings = EngineSettings {
                persist_scan_wallet: true,
                ..EngineSettings::default()
            };
            AnalysisEngine::new(g, settings)
                .analyze(ScanTarget::Descriptor(d.clone()))
                .expect("concurrent persistent scan must succeed")
        };
        let handle = scope.spawn(run);
        let first = run();
        (first, handle.join().expect("scan thread panicked"))
    });

    assert_eq!(
        first.stats.transactions_analyzed, second.stats.transactions_analyzed,
        "both concurrent scans must observe the same history"
    );
    let cached = loaded_cache_wallets(&node);
    assert_eq!(
        cached.len(),
        1,
        "concurrent scans must converge on a single cache wallet, got: {cached:?}"
    );
}

#[test]
fn non_persistent_scan_leaves_no_cache_wallet() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let descriptor = format!("addr({aa})");

    // Default settings keep the current behaviour: the temporary scan
    // wallet is discarded and nothing cache-prefixed survives.
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    engine.analyze(ScanTarget::Descriptor(descriptor)).unwrap();

    assert!(
        loaded_cache_wallets(&node).is_empty(),
        "a non-persistent scan must not leave a cache wallet behind"
    );
}

// ─── Cache wallets left behind by a failed or cancelled build ──────────────

fn cache_name_for(gateway: &BitcoinCoreRpc, descriptor: &str) -> String {
    let desc = gateway
        .normalize_descriptor(descriptor)
        .expect("normalize descriptor");
    stealth_bitcoincore::cache_wallet_name(&[stealth_engine::gateway::ResolvedDescriptor {
        desc,
        internal: false,
        active: true,
        range_end: stealth_engine::config::AnalysisConfig::default().derivation_range_end,
    }])
}

fn blank_wallet(node: &Node, name: &str) {
    node.client
        .call::<serde_json::Value>(
            "createwallet",
            &[
                name.into(),
                true.into(),
                true.into(),
                "".into(),
                false.into(),
                true.into(),
            ],
        )
        .expect("createwallet");
}

fn funded_address(node: &Node) -> (corepc_node::Client, Address) {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(node, 1, &da);
    (alice, aa)
}

fn cached_scan(gateway: &BitcoinCoreRpc, descriptor: &str) -> stealth_engine::Report {
    let settings = EngineSettings {
        persist_scan_wallet: true,
        ..EngineSettings::default()
    };
    AnalysisEngine::new(gateway, settings)
        .analyze(ScanTarget::Descriptor(descriptor.to_owned()))
        .expect("cached scan")
}

#[test]
fn a_cache_wallet_left_empty_by_a_failed_import_is_filled_not_trusted() {
    let node = node();
    let (_alice, aa) = funded_address(&node);
    let gateway = gateway_for(&node);
    let descriptor = format!("addr({aa})");

    // What a crashed first build leaves behind: the wallet exists, holds
    // nothing, and unloadwallet cannot delete it.
    blank_wallet(&node, &cache_name_for(&gateway, &descriptor));

    let report = cached_scan(&gateway, &descriptor);
    assert_eq!(
        report.stats.transactions_analyzed, 1,
        "the empty cache wallet must be imported into, not read as empty history"
    );
}

#[test]
fn a_cache_wallet_without_the_completion_marker_is_rescanned() {
    let node = node();
    let (_alice, aa) = funded_address(&node);
    let gateway = gateway_for(&node);
    let descriptor = format!("addr({aa})");
    let name = cache_name_for(&gateway, &descriptor);

    // A build that was cut short: descriptors present, history missing.
    blank_wallet(&node, &name);
    let wallet = node_wallet(&node, &name);
    let desc = gateway.normalize_descriptor(&descriptor).unwrap();
    // Regtest rescans its recent blocks whatever the timestamp, so what
    // this wallet lacks is the marker a finished build sets last.
    wallet
        .call::<serde_json::Value>(
            "importdescriptors",
            &[serde_json::json!([{ "desc": desc, "timestamp": "now" }])],
        )
        .expect("importdescriptors");
    let before: serde_json::Value = wallet
        .call("getaddressinfo", &[aa.to_string().into()])
        .expect("getaddressinfo");
    assert!(
        !before["labels"]
            .to_string()
            .contains("stealth-cache-complete"),
        "{before}"
    );

    let report = cached_scan(&gateway, &descriptor);
    assert_eq!(report.stats.transactions_analyzed, 1);
    let after: serde_json::Value = node_wallet(&node, &name)
        .call("getaddressinfo", &[aa.to_string().into()])
        .expect("getaddressinfo");
    assert!(
        after["labels"]
            .as_array()
            .is_some_and(|l| l.iter().any(|v| v == "stealth-cache-complete")),
        "an unmarked cache wallet must be built again, which ends by setting the marker: {after}"
    );
}

#[test]
fn a_cancelled_first_cached_scan_is_not_kept_as_a_complete_cache() {
    let node = node();
    let (_alice, aa) = funded_address(&node);
    let gateway = gateway_for(&node);
    let descriptor = format!("addr({aa})");

    let sink = stealth_engine::progress::ScanProgress::new();
    sink.request_cancel();
    let settings = EngineSettings {
        persist_scan_wallet: true,
        progress: Some(sink),
        ..EngineSettings::default()
    };
    let cancelled =
        AnalysisEngine::new(&gateway, settings).analyze(ScanTarget::Descriptor(descriptor.clone()));
    assert!(
        cancelled.is_err(),
        "a cancelled build must not come back as a finished scan"
    );
    assert!(
        loaded_cache_wallets(&node).is_empty(),
        "the half-built cache wallet must not stay loaded"
    );

    // The next cached scan rebuilds it and sees the real history.
    let report = cached_scan(&gateway, &descriptor);
    assert_eq!(report.stats.transactions_analyzed, 1);
    assert_eq!(loaded_cache_wallets(&node).len(), 1);
}

// Only the hardened markers change (`84h` -> `84'`); the key material keeps its h's.
fn apostrophe_form(descriptor: &str) -> String {
    let bare = descriptor.split('#').next().unwrap();
    let mut out = String::new();
    let chars: Vec<char> = bare.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        let hardened = *c == 'h'
            && i > 0
            && chars[i - 1].is_ascii_digit()
            && matches!(chars.get(i + 1), Some('/') | Some(']'));
        out.push(if hardened { '\'' } else { *c });
    }
    out
}

#[test]
fn a_descriptor_written_with_apostrophes_normalizes_to_the_h_form() {
    let node = node();
    let gateway = gateway_for(&node);
    let alice = node.create_wallet("alice").unwrap();
    let h_form = wallet_descriptors(&alice)
        .into_iter()
        .find(|d| d.starts_with("wpkh(") && d.contains("/0/*"))
        .expect("a wpkh receive descriptor");
    let apostrophes = apostrophe_form(&h_form);

    let normalized = gateway
        .normalize_descriptor(&apostrophes)
        .expect("normalize");
    assert!(
        !normalized.contains('\''),
        "Core prints hardened steps as h; the normalized form must too, got: {normalized}"
    );
}

#[test]
fn a_cache_built_from_an_apostrophe_descriptor_is_recognized_as_complete() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);
    let gateway = gateway_for(&node);
    let h_form = wallet_descriptors(&alice)
        .into_iter()
        .find(|d| d.starts_with("wpkh(") && d.contains("/0/*"))
        .expect("a wpkh receive descriptor");
    let apostrophes = apostrophe_form(&h_form);

    let first = cached_scan(&gateway, &apostrophes);
    assert_eq!(first.stats.transactions_analyzed, 1);
    let cached = loaded_cache_wallets(&node);
    assert_eq!(cached.len(), 1, "{cached:?}");

    let resolved = stealth_engine::descriptor::normalize_descriptors(
        &[apostrophes],
        stealth_engine::config::AnalysisConfig::default().derivation_range_end,
        &gateway,
    )
    .expect("normalize");
    assert!(
        gateway
            .cache_is_complete(&cached[0], &resolved)
            .expect("completeness check"),
        "a finished build must be trusted on reuse, whatever form the user typed"
    );
}

// ─── Ancestor depth bound ──────────────────────────────────────────────────

#[test]
fn ancestor_walk_is_bounded_by_max_depth() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    // Build a linear 5-tx chain: bob funds himself repeatedly, then pays
    // alice. Bob always holds exactly one UTXO, so each send spends the
    // previous transaction's output.
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    for _ in 0..3 {
        let next = bob.new_address().unwrap();
        bob.call::<serde_json::Value>("sendall", &[serde_json::json!([next.to_string()])])
            .unwrap();
        mine(&node, 1, &da);
        let utxos = bob.list_unspent().unwrap();
        assert_eq!(utxos.0.len(), 1, "bob must stay at a single utxo");
    }

    let aa = alice.new_address().unwrap();
    bob.call::<serde_json::Value>("sendall", &[serde_json::json!([aa.to_string()])])
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let history = gateway.scan_wallet("alice").unwrap();

    // Alice's tx (depth 0) + parent (1) + grandparent (2). The two
    // older ancestors of the chain must not be fetched.
    assert_eq!(history.transactions.len(), 3);
}
