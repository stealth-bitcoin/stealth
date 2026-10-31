use crate::common::*;

// ─── 6. Consolidation Origin ───────────────────────────────────────────────

#[test]
fn detect_consolidation() {
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

    // Give alice 4 small UTXOs
    for _ in 0..4 {
        let a = alice.new_address().unwrap();
        bob.send_to_address(&a, Amount::from_sat(300_000)).unwrap();
    }
    mine(&node, 1, &da);

    // Alice consolidates into one address (>=3 inputs, <=2 outputs)
    let utxos = alice.list_unspent().unwrap();
    let small: Vec<_> = utxos
        .0
        .iter()
        .filter(|u| u.amount > 0.002 && u.amount < 0.004)
        .collect();
    assert!(small.len() >= 3, "need at least 3 small utxos");

    let inputs: Vec<Input> = small
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = small.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let consol_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(
                consol_addr,
                Amount::from_sat(total_sats - 10_000),
            )],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Consolidation));
}

// Funds `n` fresh UTXOs of `sats` each in `wallet`, returning them as inputs.
fn fund_coins(node: &Node, wallet: &corepc_node::Client, n: usize, sats: u64) -> Vec<Input> {
    let da = node.client.new_address().unwrap();
    let mut txids = Vec::new();
    for _ in 0..n {
        let a = wallet.new_address().unwrap();
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
fn merge_into(
    node: &Node,
    signers: &[&corepc_node::Client],
    inputs: &[Input],
    dest: Address,
    total_sats: u64,
) {
    let raw = signers[0]
        .create_raw_transaction(
            inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
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

#[test]
fn consolidation_made_by_someone_else_is_not_ours() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Bob sweeps four of his own coins into a single payment to alice.
    let inputs = fund_coins(&node, &bob, 4, 300_000);
    merge_into(
        &node,
        &[&bob],
        &inputs,
        alice.new_address().unwrap(),
        1_200_000,
    );

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(!has_finding(&report, VulnerabilityType::Consolidation));
}

#[test]
fn consolidation_with_two_of_our_coins_among_others_fires() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Alice merges two of her coins with one of bob's into her own address.
    let mut inputs = fund_coins(&node, &alice, 2, 300_000);
    inputs.extend(fund_coins(&node, &bob, 1, 300_000));
    merge_into(
        &node,
        &[&alice, &bob],
        &inputs,
        alice.new_address().unwrap(),
        900_000,
    );

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::Consolidation));
}

#[test]
fn consolidation_with_a_single_coin_of_ours_does_not_fire() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Alice adds one coin to bob's three, as a Payjoin receiver would.
    let mut inputs = fund_coins(&node, &bob, 3, 300_000);
    inputs.extend(fund_coins(&node, &alice, 1, 300_000));
    merge_into(
        &node,
        &[&bob, &alice],
        &inputs,
        alice.new_address().unwrap(),
        1_200_000,
    );

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(!has_finding(&report, VulnerabilityType::Consolidation));
}

// ─── 10. Exchange Origin ───────────────────────────────────────────────────

#[test]
fn detect_exchange_origin() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let exchange = node.create_wallet("exchange").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    // Fund exchange
    let ea = exchange.new_address().unwrap();
    node.client
        .send_to_address(&ea, Amount::from_btc(5.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Exchange batch withdrawal to 8 addresses (alice gets some, bob gets some)
    let mut amounts: BTreeMap<Address, Amount> = BTreeMap::new();
    for i in 0..5u64 {
        let a = alice.new_address().unwrap();
        amounts.insert(a, Amount::from_sat(1_000_000 + i * 100_000));
    }
    for i in 0..3u64 {
        let b = bob.new_address().unwrap();
        amounts.insert(b, Amount::from_sat(1_000_000 + i * 200_000));
    }
    let send_result = exchange.send_many(amounts).unwrap();
    mine(&node, 1, &da);

    let exchange_txids: HashSet<Txid> = [send_result.0.parse::<Txid>().unwrap()]
        .into_iter()
        .collect();
    let gateway = gateway_for(&node);
    let report = scan_wallet_with(&gateway, "alice", None, Some(&exchange_txids));
    assert!(has_finding(&report, VulnerabilityType::ExchangeOrigin));
}

// Outputs paying back to one of the batch's own input addresses are the
// sender's change: the batch is judged on its other outputs only.

fn exchange_batch_report(recipient_sats: &[u64], self_outputs: &[u64]) -> stealth_engine::Report {
    payout_report(
        &recipient_sats[..1],
        &recipient_sats[1..],
        self_outputs,
        false,
    )
}

#[test]
fn exchange_batch_with_change_to_input_address_still_counts() {
    let report = exchange_batch_report(&[100_000; 5], &[]);
    assert!(
        has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "five recipients plus change is a batch: {:?}",
        report.findings
    );
}

#[test]
fn exchange_batch_output_count_skips_change_to_input_address() {
    // Small payouts against a 1M-sat input still trip the median-ratio signal.
    let report = exchange_batch_report(&[50_000; 4], &[]);
    assert!(
        !has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "four recipients plus change is below the batch threshold: {:?}",
        report.findings
    );
}

#[test]
fn exchange_batch_median_skips_outputs_to_input_address() {
    // Four distinct recipients (one paid twice) at 150k sats, and seven small
    // outputs back to the sender that would drag the median down to 1k sats.
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let (exchange, exchange_addr) = fund_sender(&node, &da, "exchange", 1_000_000);

    let repeated = node.client.new_address().unwrap();
    let mut outputs = vec![
        (alice.new_address().unwrap(), 150_000),
        (node.client.new_address().unwrap(), 150_000),
        (node.client.new_address().unwrap(), 150_000),
        (repeated.clone(), 150_000),
        (repeated, 150_000),
    ];
    for _ in 0..7 {
        outputs.push((exchange_addr.clone(), 1_000));
    }
    spend_to(&exchange, &outputs, &exchange_addr);
    mine(&node, 1, &da);

    let report = scan_wallet(&gateway_for(&node), "alice");
    assert!(
        !has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "only the output count signal holds on the recipients: {:?}",
        report.findings
    );
}

// A payout that sends the wallet a normal amount alongside many dust outputs
// matches the dust-attack pattern, but the wallet's coin is not dust and gets
// no dust finding, so the batch signals still decide.
#[test]
fn exchange_batch_with_normal_payout_among_dust_still_counts() {
    let mut recipients = vec![100_000];
    recipients.extend([330; 11]);
    let report = exchange_batch_report(&recipients, &[]);
    assert!(
        !has_finding(&report, VulnerabilityType::Dust),
        "the wallet received no dust: {:?}",
        report.findings
    );
    assert!(
        has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "twelve distinct recipients is a batch: {:?}",
        report.findings
    );
}

#[test]
fn exchange_batch_paying_dust_without_attack_pattern_still_counts() {
    let report = exchange_batch_report(&[800, 100_000, 100_000, 100_000, 100_000], &[]);
    assert!(
        has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "a small payout in a five-recipient batch is still a batch: {:?}",
        report.findings
    );
}

#[test]
fn dust_class_payout_in_dust_attack_is_not_exchange_origin() {
    // 800 sats is dust-class but above strict dust; the dust finding still
    // carries the attack evidence, so no exchange origin.
    let mut recipients = vec![800];
    recipients.extend([330; 11]);
    let report = exchange_batch_report(&recipients, &[]);
    assert!(
        has_dust_attack(&report),
        "expected a dust-attack finding: {:?}",
        report.findings
    );
    assert!(
        !has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "dust from a dust attack is not an exchange payout: {:?}",
        report.findings
    );
}

#[test]
fn exchange_batch_output_count_skips_op_return() {
    // Four small recipients, an OP_RETURN and change to the input address.
    let report = payout_report(&[50_000], &[50_000; 3], &[], true);
    assert!(
        !has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "an OP_RETURN is not a batch recipient: {:?}",
        report.findings
    );
}

#[test]
fn normal_payout_next_to_dust_in_dust_attack_still_counts() {
    // The wallet gets one dust output and one normal payout; only the dust is
    // covered by the dust-attack finding.
    let report = payout_report(&[330, 100_000], &[330; 10], &[], false);
    assert!(has_dust_attack(&report), "{:?}", report.findings);
    assert!(
        has_finding(&report, VulnerabilityType::ExchangeOrigin),
        "the normal payout is still from a batch: {:?}",
        report.findings
    );
}

// ─── 11. Tainted UTXOs ─────────────────────────────────────────────────────

#[test]
fn detect_tainted_utxo_merge() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let risky = node.create_wallet("risky").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund
    let ra = risky.new_address().unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ra, Amount::from_btc(2.0).unwrap())
        .unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Risky sends to alice
    let ta = alice.new_address().unwrap();
    let taint_result = risky
        .send_to_address(&ta, Amount::from_sat(1_000_000))
        .unwrap();
    let taint_txid: Txid = taint_result.0.parse().unwrap();

    // Bob sends clean to alice
    let ca = alice.new_address().unwrap();
    bob.send_to_address(&ca, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both together (tainted + clean)
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2);

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
    let carol = node.create_wallet("carol").unwrap();
    let dest = carol.new_address().unwrap();
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

    let risky_txids: HashSet<Txid> = [taint_txid].into_iter().collect();
    let gateway = gateway_for(&node);
    let report = scan_wallet_with(&gateway, "alice", Some(&risky_txids), None);
    assert!(has_finding(&report, VulnerabilityType::TaintedUtxoMerge));
}
