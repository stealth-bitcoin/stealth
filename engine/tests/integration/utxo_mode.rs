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
