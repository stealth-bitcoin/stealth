use crate::common::*;

// ─── 3. Dust UTXO Detection ────────────────────────────────────────────────

#[test]
fn detect_dust() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Create 1000-sat dust output to alice via raw tx
    let dust_addr = alice.new_address().unwrap();
    let bob_utxos = bob.list_unspent().unwrap();
    let big = bob_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();

    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 1_000;
    let fee_sats: u64 = 10_000;
    let change_sats = big_sats - dust_sats - fee_sats;

    let change_addr = bob.new_address().unwrap();
    let raw = bob
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dust_addr, Amount::from_sat(dust_sats)),
                Output::new(change_addr, Amount::from_sat(change_sats)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = bob.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    bob.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Dust));
}

// ─── 4. Dust Spending with Normal Inputs ────────────────────────────────────

#[test]
fn detect_dust_spending() {
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

    // Give alice a normal UTXO
    let alice_normal = alice.new_address().unwrap();
    bob.send_to_address(&alice_normal, Amount::from_btc(0.5).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a dust UTXO via raw tx
    let dust_addr = alice.new_address().unwrap();
    let bob_utxos = bob.list_unspent().unwrap();
    let big = bob_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();
    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 1_000;
    let fee_sats: u64 = 10_000;

    let change_addr = bob.new_address().unwrap();
    let raw = bob
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dust_addr, Amount::from_sat(dust_sats)),
                Output::new(
                    change_addr,
                    Amount::from_sat(big_sats - dust_sats - fee_sats),
                ),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = bob.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    bob.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    // Now alice spends dust + normal together
    let utxos = alice.list_unspent().unwrap();
    let dust_u = utxos
        .0
        .iter()
        .find(|u| (u.amount * 1e8).round() as u64 <= 1000)
        .expect("dust utxo");
    let normal_u = utxos
        .0
        .iter()
        .find(|u| u.amount > 0.001)
        .expect("normal utxo");

    let total_sats = (dust_u.amount * 1e8).round() as u64 + (normal_u.amount * 1e8).round() as u64;
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[
                Input {
                    txid: dust_u.txid.parse().unwrap(),
                    vout: dust_u.vout as u64,
                    sequence: None,
                },
                Input {
                    txid: normal_u.txid.parse().unwrap(),
                    vout: normal_u.vout as u64,
                    sequence: None,
                },
            ],
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
    assert!(has_finding(&report, VulnerabilityType::DustSpending));
}

// ─── 13. Dust Attack Detection ─────────────────────────────────────────────
//
// Dust-attack detection is folded into the Dust detector: when a dust
// UTXO's parent transaction matches the attack signature, the existing
// Dust finding is escalated to `Critical` and carries a `dust_attack`
// evidence object inside `details`.

#[test]
fn detect_dust_attack() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let attacker = node.create_wallet("attacker").unwrap();

    // Fund attacker
    let aa = attacker.new_address().unwrap();
    node.client
        .send_to_address(&aa, Amount::from_btc(1.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Attacker creates a dust attack: 1 input, 12 outputs (all tiny) to
    // various addresses including some of alice's
    let attacker_utxos = attacker.list_unspent().unwrap();
    let big = attacker_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();
    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 546;
    let n_dust: u64 = 12;
    let fee_sats: u64 = 10_000;

    // Create 12 tiny outputs — 5 to alice, 7 to random other wallets
    let mut outputs_vec = Vec::new();
    for _ in 0..5 {
        let a = alice.new_address().unwrap();
        outputs_vec.push(Output::new(a, Amount::from_sat(dust_sats)));
    }
    // Create "other" wallets for diversity
    for i in 0..7 {
        let other_name = format!("other_{}", i);
        let other = node.create_wallet(&other_name).unwrap();
        let oa = other.new_address().unwrap();
        outputs_vec.push(Output::new(oa, Amount::from_sat(dust_sats)));
    }

    let change_sats = big_sats - (dust_sats * n_dust) - fee_sats;
    let change_addr = attacker.new_address().unwrap();
    outputs_vec.push(Output::new(change_addr, Amount::from_sat(change_sats)));

    let raw = attacker
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &outputs_vec,
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = attacker.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    attacker.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");

    // The dust outputs are flagged as Dust, and at least one Dust
    // finding carries dust-attack evidence with Critical severity.
    let dust_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::Dust)
        .collect();
    assert!(
        !dust_findings.is_empty(),
        "expected at least one Dust finding from the attack outputs"
    );
    let escalated = dust_findings.iter().any(|f| {
        f.severity == stealth_engine::Severity::Critical
            && f.details
                .as_ref()
                .and_then(|d| d.get("dust_attack"))
                .is_some()
    });
    assert!(
        escalated,
        "expected at least one Dust finding to carry dust_attack evidence: {:?}",
        dust_findings
    );
}

// A dust attack that also pays many outputs back to the sender's own input
// address (the shape of mainnet tx 707545c7...): those outputs are the
// sender's change, so they must not dilute the address-diversity ratio.

fn dust_attack_with_self_outputs(node: &Node) -> stealth_engine::Report {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let (attacker, attacker_addr) = fund_sender(node, &da, "attacker", 1_000_000);

    let mut outputs = vec![(alice.new_address().unwrap(), 330)];
    for _ in 0..11 {
        outputs.push((node.client.new_address().unwrap(), 330));
    }
    for _ in 0..12 {
        outputs.push((attacker_addr.clone(), 900));
    }
    spend_to(&attacker, &outputs, &attacker_addr);
    mine(node, 1, &da);

    scan_wallet(&gateway_for(node), "alice")
}

#[test]
fn dust_attack_ignores_sender_self_outputs() {
    let node = node();
    let report = dust_attack_with_self_outputs(&node);

    let escalated = report.findings.iter().find(|f| {
        f.vulnerability_type == VulnerabilityType::Dust
            && f.severity == stealth_engine::Severity::Critical
    });
    let evidence = escalated
        .and_then(|f| f.details.as_ref())
        .and_then(|d| d.get("dust_attack"))
        .unwrap_or_else(|| panic!("expected a dust-attack finding: {:?}", report.findings));
    assert_eq!(evidence["total_outputs"], 12);
    assert_eq!(evidence["unique_addresses"], 12);
}

#[test]
fn dust_attack_with_self_outputs_is_not_exchange_origin() {
    let node = node();
    let report = dust_attack_with_self_outputs(&node);
    assert!(
        !has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "a dust attack is not an exchange withdrawal: {:?}",
        report.findings
    );
}
