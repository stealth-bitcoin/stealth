use crate::common::*;

use stealth_engine::progress::{ScanPhase, ScanProgress};

// ─── Progress sink wiring through the descriptor scan path ─────────────────

#[test]
fn descriptor_scan_reports_phases_and_wallet_name_to_sink() {
    let node = node();
    let da = node.client.new_address().expect("miner address");
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").expect("create alice wallet");
    let aa = alice.new_address().expect("alice address");
    node.client
        .send_to_address(&aa, Amount::ONE_BTC)
        .expect("fund alice");
    mine(&node, 1, &da);

    let descs = alice
        .call::<serde_json::Value>("listdescriptors", &[])
        .expect("listdescriptors");
    let descriptor = descs["descriptors"]
        .as_array()
        .expect("descriptors array")
        .iter()
        .filter_map(|d| d["desc"].as_str())
        .find(|desc| desc.starts_with("wpkh(") && desc.contains("/0/*"))
        .expect("no external wpkh descriptor found")
        .to_owned();

    let gateway = gateway_for(&node);
    let sink = ScanProgress::new();
    let settings = EngineSettings {
        progress: Some(sink.clone()),
        ..EngineSettings::default()
    };
    let engine = AnalysisEngine::new(&gateway, settings);
    let report = engine
        .analyze(ScanTarget::Descriptor(descriptor))
        .expect("descriptor scan failed");
    assert!(report.stats.transactions_analyzed >= 1);

    // Structure only: regtest rescans finish too fast for percentage
    // assertions, but the phase sequence must be recorded in order.
    let phases = sink.phase_history();
    let rescanning = phases
        .iter()
        .position(|p| *p == ScanPhase::Rescanning)
        .unwrap_or_else(|| panic!("rescanning phase missing, got {phases:?}"));
    let analyzing = phases
        .iter()
        .position(|p| *p == ScanPhase::Analyzing)
        .unwrap_or_else(|| panic!("analyzing phase missing, got {phases:?}"));
    assert!(
        rescanning < analyzing,
        "rescanning must precede analyzing, got {phases:?}"
    );
    assert!(
        phases.contains(&ScanPhase::LoadingHistory),
        "loading_history phase missing, got {phases:?}"
    );

    let snapshot = sink.snapshot();
    let wallet_name = snapshot
        .wallet_name
        .expect("temporary wallet name was not reported to the sink");
    assert!(
        wallet_name.starts_with("_stealth_scan_"),
        "unexpected wallet name: {wallet_name}"
    );
}
