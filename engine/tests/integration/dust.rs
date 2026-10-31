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
    assert_dust_advice(
        &report,
        VulnerabilityType::Dust,
        "OP_RETURN output carrying 4 bytes of data",
    );
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
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.vulnerability_type == VulnerabilityType::Dust
                && f.details.as_ref().is_some_and(|d| d["status"] == "spent")),
        "dust spent with another input keeps its finding: {:?}",
        report.findings
    );
    assert_dust_advice(&report, VulnerabilityType::DustSpending, "from now on");
}

/// Signs and broadcasts a raw spend of `inputs` from `wallet`, then mines it.
fn spend_raw(
    node: &Node,
    wallet: &corepc_node::Client,
    inputs: &[Input],
    outputs: &[Output],
    miner: &Address,
) {
    let raw = wallet.create_raw_transaction(inputs, outputs).unwrap();
    let tx = raw.transaction().unwrap();
    let signed = wallet.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    wallet.send_raw_transaction(&stx).unwrap();
    mine(node, 1, miner);
}

#[test]
fn coins_of_one_address_spent_together_link_nothing_new() {
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

    // Alice pays bob from address `a`, leaving 600 sats of change back at `a`.
    let a = alice.new_address().unwrap();
    bob.send_to_address(&a, Amount::from_sat(100_000)).unwrap();
    mine(&node, 1, &da);
    let first = alice.list_unspent().unwrap().0.remove(0);
    spend_raw(
        &node,
        &alice,
        &[Input {
            txid: first.txid.parse().unwrap(),
            vout: first.vout as u64,
            sequence: None,
        }],
        &[
            Output::new(bob.new_address().unwrap(), Amount::from_sat(89_400)),
            Output::new(a.clone(), Amount::from_sat(600)),
        ],
        &da,
    );

    // A larger coin lands at the same address; alice spends both together.
    bob.send_to_address(&a, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);
    let coins = alice.list_unspent().unwrap().0;
    assert_eq!(coins.len(), 2);
    let inputs: Vec<Input> = coins
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    spend_raw(
        &node,
        &alice,
        &inputs,
        &[
            Output::new(bob.new_address().unwrap(), Amount::from_sat(20_000)),
            Output::new(alice.new_address().unwrap(), Amount::from_sat(970_600)),
        ],
        &da,
    );

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    for kind in [
        VulnerabilityType::DustSpending,
        VulnerabilityType::ToxicChange,
        VulnerabilityType::UnnecessaryInput,
    ] {
        assert!(
            !has_finding(&report, kind),
            "{kind:?}: {:?}",
            report.findings
        );
    }
}

/// `coin` signed into a tx with it as the only input and one 0-value OP_RETURN carrying `data`.
fn signed_fee_only_spend(
    wallet: &corepc_node::Client,
    coin: &Input,
    data: &[u8; 4],
    len: usize,
) -> corepc_node::client::bitcoin::Transaction {
    let raw = wallet
        .create_raw_transaction(
            std::slice::from_ref(coin),
            &[Output::new(
                wallet.new_address().unwrap(),
                Amount::from_sat(1),
            )],
        )
        .unwrap();
    let mut tx = raw.transaction().unwrap();
    let push =
        corepc_node::client::bitcoin::script::PushBytesBuf::try_from(data[..len].to_vec()).unwrap();
    tx.output = vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(push),
    }];
    wallet
        .sign_raw_transaction_with_wallet(&tx)
        .unwrap()
        .into_model()
        .unwrap()
        .tx
}

/// Mempool verdict on `coin` spent alone as fee to one 0-value OP_RETURN carrying `data`,
/// with the fee rate it pays in sat/vB.
fn fee_only_spend(
    wallet: &corepc_node::Client,
    coin: &Input,
    sats: u64,
    data: &[u8; 4],
    len: usize,
) -> (serde_json::Value, f64) {
    fee_only_spend_at(wallet, coin, sats, data, len, None)
}

/// As [`fee_only_spend`], with `maxfeerate` (BTC/kvB) passed to `testmempoolaccept` when set.
fn fee_only_spend_at(
    wallet: &corepc_node::Client,
    coin: &Input,
    sats: u64,
    data: &[u8; 4],
    len: usize,
    maxfeerate: Option<f64>,
) -> (serde_json::Value, f64) {
    let stx = signed_fee_only_spend(wallet, coin, data, len);
    let hex = corepc_node::client::bitcoin::consensus::encode::serialize_hex(&stx);
    let verdict: serde_json::Value = wallet
        .call(
            "testmempoolaccept",
            &match maxfeerate {
                Some(rate) => vec![serde_json::json!([hex]), serde_json::json!(rate)],
                None => vec![serde_json::json!([hex])],
            },
        )
        .unwrap();
    (verdict[0].clone(), sats as f64 / stx.vsize() as f64)
}

#[test]
fn the_fee_only_spend_in_the_dust_advice_is_standard() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let coin = fund_coins(&node, &alice, 1, 546).remove(0);

    // Without data the tx is 61 non-witness bytes, under Core's 65-byte minimum.
    let (bare, _) = fee_only_spend(&alice, &coin, 546, b"ash!", 0);
    assert_eq!(bare["allowed"], false, "{bare}");
    assert_eq!(bare["reject-reason"], "tx-size-small", "{bare}");

    let (with_data, rate) = fee_only_spend(&alice, &coin, 546, b"ash!", 4);
    assert_eq!(with_data["allowed"], true, "{with_data}");
    assert!((5.5..6.5).contains(&rate), "about 6 sat/vB: {rate}");
}

#[test]
fn a_fee_only_spend_of_a_1000_sat_coin_passes_the_default_maxfeerate() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let coin = fund_coins(&node, &alice, 1, 1_000).remove(0);

    // The default maxfeerate is 0.10 BTC/kvB, 10,000 sat/vB, far above this coin's rate.
    let (verdict, rate) = fee_only_spend(&alice, &coin, 1_000, b"ash!", 4);
    assert!(rate > 10.0, "{rate}");
    assert_eq!(verdict["allowed"], true, "{verdict}");
    let (capped, _) = fee_only_spend_at(&alice, &coin, 1_000, b"ash!", 4, Some(0.0001));
    assert_eq!(capped["reject-reason"], "max-fee-exceeded", "{capped}");
}

#[test]
fn dust_given_away_alone_as_fee_gets_no_finding() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let coin = fund_coins(&node, &alice, 1, 600).remove(0);

    let before = scan_wallet(&gateway_for(&node), "alice");
    assert!(has_finding(&before, VulnerabilityType::Dust));

    let stx = signed_fee_only_spend(&alice, &coin, b"ash!", 4);
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let after = scan_wallet(&gateway_for(&node), "alice");
    assert!(
        !has_finding(&after, VulnerabilityType::Dust),
        "{:?}",
        after.findings
    );
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

// The attack needs ten recipients; change back to the sender does not count.

#[test]
fn dust_attack_needs_ten_recipients_besides_change() {
    let report = payout_report(&[330], &[330; 8], &[], false);
    assert!(has_finding(&report, VulnerabilityType::Dust));
    assert!(
        !has_dust_attack(&report),
        "nine recipients plus change is below the attack threshold: {:?}",
        report.findings
    );
}

#[test]
fn dust_attack_fires_at_ten_recipients_besides_change() {
    let report = payout_report(&[330], &[330; 9], &[], false);
    assert!(
        has_dust_attack(&report),
        "ten recipients plus change is a dust attack: {:?}",
        report.findings
    );
}
