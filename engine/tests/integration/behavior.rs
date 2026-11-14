use crate::common::*;

// ─── 7. Script Type Mixing ─────────────────────────────────────────────────

#[test]
fn detect_script_type_mixing() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice one P2WPKH and one P2TR utxo
    let wpkh_addr = alice.new_address_with_type(AddressType::Bech32).unwrap();
    let tr_addr = alice.new_address_with_type(AddressType::Bech32m).unwrap();
    bob.send_to_address(&wpkh_addr, Amount::from_sat(500_000))
        .unwrap();
    bob.send_to_address(&tr_addr, Amount::from_sat(500_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both types together
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2, "need at least 2 utxos");

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ScriptTypeMixing));
}

// ─── 9. Lookback Depth / UTXO Age ──────────────────────────────────────────

#[test]
fn detect_utxo_age_spread() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();

    // Old UTXO
    let old_addr = alice.new_address().unwrap();
    node.client
        .send_to_address(&old_addr, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 20, &da);

    // New UTXO
    let new_addr = alice.new_address().unwrap();
    node.client
        .send_to_address(&new_addr, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::UtxoAgeSpread));
}

// ─── 12. Behavioral Fingerprint ────────────────────────────────────────────

#[test]
fn detect_behavioral_fingerprint() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let carol = node.create_wallet("carol").unwrap();

    // Fund alice generously
    let aa = alice.new_address().unwrap();
    node.client
        .send_to_address(&aa, Amount::from_btc(5.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice sends 5 round-amount payments (behavioral pattern)
    for i in 1u64..=5 {
        let dest = carol.new_address().unwrap();
        alice
            .send_to_address(&dest, Amount::from_sat(i * 1_000_000))
            .unwrap();
        mine(&node, 1, &da);
    }

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(report
        .findings
        .iter()
        .any(|f| f.vulnerability_type == VulnerabilityType::BehavioralFingerprint));
}

// ─── 14. Peel Chain Detection ──────────────────────────────────────────────

#[test]
fn detect_peel_chain() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund alice
    let aa = alice.new_address().unwrap();
    node.client
        .send_to_address(&aa, Amount::from_btc(1.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice creates a peel chain: 3 consecutive 2-output transactions
    // where the large output feeds the next transaction
    let mut chain = Vec::new();
    for i in 0..3 {
        let utxos = alice.list_unspent().unwrap();
        let big = utxos
            .0
            .iter()
            .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
            .unwrap();
        let big_sats = (big.amount * 1e8).round() as u64;
        let peel_amount: u64 = 50_000 + i * 10_000; // Small "peeled" payment
        let fee_sats: u64 = 10_000;
        let change_sats = big_sats - peel_amount - fee_sats;

        let peel_addr = bob.new_address().unwrap();
        let change_addr = alice.new_address().unwrap();
        let raw = alice
            .create_raw_transaction(
                &[Input {
                    txid: big.txid.parse().unwrap(),
                    vout: big.vout as u64,
                    sequence: None,
                }],
                &[
                    Output::new(peel_addr, Amount::from_sat(peel_amount)),
                    Output::new(change_addr, Amount::from_sat(change_sats)),
                ],
            )
            .unwrap();
        let tx = raw.transaction().unwrap();
        let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
        let stx = signed.into_model().unwrap().tx;
        alice.send_raw_transaction(&stx).unwrap();
        chain.push(stx.compute_txid().to_string());
        mine(&node, 1, &da);
    }

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    // The two-hop tail starting at the second peel is part of the same chain.
    let peels: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::PeelChain)
        .collect();
    assert_eq!(peels.len(), 1, "{peels:#?}");
    let details = peels[0].details.as_ref().unwrap();
    assert_eq!(details["start_txid"], chain[0].as_str());
    assert_eq!(details["hops"], 3);
    assert_eq!(details["txids"], serde_json::json!(chain));
}
