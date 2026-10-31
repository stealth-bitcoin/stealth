use crate::common::*;

// ─── 5. Change Detection ───────────────────────────────────────────────────

#[test]
fn detect_change_detection() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund alice with a clean 1 BTC UTXO
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Alice sends a round 0.05 BTC to bob via send_to_address.
    // Bitcoin Core will automatically create a change output.
    let bob_addr = bob.new_address().unwrap();
    alice
        .send_to_address(&bob_addr, Amount::from_sat(5_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ChangeDetection));
}

#[test]
fn change_back_to_the_input_address_is_the_named_change() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    pay_with_change_back_to_input(&node, &alice);

    let report = scan_wallet(&gateway_for(&node), "alice");
    let change: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::ChangeDetection)
        .collect();
    assert_eq!(change.len(), 1, "{change:?}");
    let reasons = change[0].details.as_ref().unwrap()["reasons"].to_string();
    assert!(
        reasons.contains("Change went back to an input address (output 1, 69990000 sats)"),
        "{reasons}"
    );
    let correction = change[0].correction.as_deref().unwrap();
    assert!(
        correction.starts_with("Send change to a fresh change address"),
        "{correction}"
    );
}

// ─── 17. Toxic Change Detection ────────────────────────────────────────────

#[test]
fn detect_toxic_change() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(3.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a UTXO that will produce toxic change
    let aa = alice.new_address().unwrap();
    bob.send_to_address(&aa, Amount::from_sat(100_000)).unwrap();
    mine(&node, 1, &da);

    // Alice sends, leaving tiny change (5000 sats — in toxic range)
    let utxos = alice.list_unspent().unwrap();
    let big = utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();
    let big_sats = (big.amount * 1e8).round() as u64;
    let fee_sats: u64 = 10_000;
    let toxic_change: u64 = 5_000;
    let payment_sats = big_sats - fee_sats - toxic_change;

    let dest = bob.new_address().unwrap();
    let change_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dest, Amount::from_sat(payment_sats)),
                Output::new(change_addr.clone(), Amount::from_sat(toxic_change)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    // Now give alice another big UTXO
    let aa2 = alice.new_address().unwrap();
    bob.send_to_address(&aa2, Amount::from_btc(1.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends toxic change + big UTXO together (the vulnerability)
    let utxos2 = alice.list_unspent().unwrap();
    let inputs2: Vec<Input> = utxos2
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    assert!(inputs2.len() >= 2);

    let total2: u64 = utxos2
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let dest2 = bob.new_address().unwrap();
    let raw2 = alice
        .create_raw_transaction(
            &inputs2,
            &[Output::new(dest2, Amount::from_sat(total2 - 10_000))],
        )
        .unwrap();
    let tx2 = raw2.transaction().unwrap();
    let signed2 = alice.sign_raw_transaction_with_wallet(&tx2).unwrap();
    let stx2 = signed2.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx2).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::ToxicChange));
}
