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
    let details = consolidation_finding(&report)
        .details
        .clone()
        .expect("details");
    assert_eq!(details["our_inputs_in_consolidation"], 4);
}

// Bob sweeps four of his own coins into a single payment to alice.
fn receive_from_a_sweep(node: &Node) -> corepc_node::Client {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let inputs = fund_coins(node, &bob, 4, 300_000);
    merge_into(
        node,
        &[&bob],
        &inputs,
        alice.new_address().unwrap(),
        1_200_000,
    );
    alice
}

// Bob pays alice from three of his coins, keeping change.
fn receive_an_ordinary_payment(node: &Node) -> corepc_node::Client {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let inputs = fund_coins(node, &bob, 3, 300_000);
    let outputs = [
        Output::new(alice.new_address().unwrap(), Amount::from_sat(500_000)),
        Output::new(bob.new_address().unwrap(), Amount::from_sat(390_000)),
    ];
    spend(node, &[&bob], &inputs, &outputs);
    alice
}

#[test]
fn wallet_scan_of_a_payment_from_someone_elses_coins_is_silent() {
    let node = node();
    receive_an_ordinary_payment(&node);

    let gateway = gateway_for(&node);
    assert_no_consolidation(&scan_wallet(&gateway, "alice"));
}

#[test]
fn descriptor_scan_of_a_sweep_by_someone_else_is_silent() {
    let node = node();
    let alice = receive_from_a_sweep(&node);

    let gateway = gateway_for(&node);
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let report = engine
        .analyze(ScanTarget::Descriptors(wallet_descriptors(&alice)))
        .expect("descriptor scan failed");
    assert_no_consolidation(&report);
}

#[test]
fn single_address_scan_of_a_sweep_by_someone_else_warns() {
    let node = node();
    let alice = receive_from_a_sweep(&node);
    let utxos = alice.list_unspent().unwrap();
    let address = &utxos.0[0].address;

    let gateway = gateway_for(&node);
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());
    let report = engine
        .analyze(ScanTarget::Descriptor(format!("addr({address})")))
        .expect("address scan failed");
    assert_consolidation_warning(&report, 0, 4, 0);
}

#[test]
fn consolidation_with_unresolved_inputs_counts_them_as_unknown() {
    let node = node();
    receive_from_a_sweep(&node);

    // Depth 0 leaves the sweep's funding transactions unfetched.
    let gateway = gateway_for(&node).with_max_ancestor_depth(0);
    assert_consolidation_warning(&scan_wallet(&gateway, "alice"), 0, 0, 4);
}

#[test]
fn consolidation_of_coins_at_one_reused_address_fires() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let reused = alice.new_address().unwrap();
    let inputs = fund_coins_at(&node, &alice, vec![reused.clone(); 4], 300_000);
    merge_into(
        &node,
        &[&alice],
        &inputs,
        alice.new_address().unwrap(),
        1_200_000,
    );

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    let details = consolidation_finding(&report)
        .details
        .clone()
        .expect("details");
    assert_eq!(details["our_inputs_in_consolidation"], 4);
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
    let details = consolidation_finding(&report)
        .details
        .clone()
        .expect("details");
    assert_eq!(details["our_inputs_in_consolidation"], 2);
    assert!(!has_warning(&report, VulnerabilityType::Consolidation));
}

// Alice adds one coin to bob's three, as a Payjoin receiver would.
fn add_one_coin_to_someone_elses(node: &Node) {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let mut inputs = fund_coins(node, &bob, 3, 300_000);
    inputs.extend(fund_coins(node, &alice, 1, 300_000));
    merge_into(
        node,
        &[&bob, &alice],
        &inputs,
        alice.new_address().unwrap(),
        1_200_000,
    );
}

#[test]
fn consolidation_with_a_single_coin_of_ours_does_not_fire() {
    let node = node();
    add_one_coin_to_someone_elses(&node);

    let gateway = gateway_for(&node);
    assert_no_consolidation(&scan_wallet(&gateway, "alice"));
}

#[test]
fn single_coin_of_ours_among_unresolved_inputs_warns() {
    let node = node();
    add_one_coin_to_someone_elses(&node);

    // Depth 0 leaves bob's funding transactions unfetched; alice's own is a wallet tx.
    let gateway = gateway_for(&node).with_max_ancestor_depth(0);
    assert_consolidation_warning(&scan_wallet(&gateway, "alice"), 1, 0, 3);
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

fn scan_descriptors(node: &Node, descriptors: Vec<String>) -> stealth_engine::Report {
    let gateway = gateway_for(node);
    AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Descriptors(descriptors))
        .expect("descriptor scan failed")
}

#[test]
fn ranged_scan_warns_when_a_consolidation_pays_our_change_address() {
    let node = node();
    let (_alice, wpkh) = merge_across_script_types_into(&node, change_address);
    let report = scan_descriptors(&node, wpkh);
    assert_consolidation_warning(&report, 1, 3, 0);
    let warning = report
        .warnings
        .iter()
        .find(|w| w.vulnerability_type == VulnerabilityType::Consolidation)
        .expect("warning");
    assert_change_address_wording(warning);
}

#[test]
fn ranged_scan_is_silent_when_a_consolidation_pays_our_receive_address() {
    let node = node();
    let (_alice, wpkh) =
        merge_across_script_types_into(&node, |alice| alice.new_address().unwrap());
    let report = scan_descriptors(&node, wpkh);
    assert_no_consolidation(&report);
}

// Carol consolidates three of her coins into one of her receive addresses.
fn someone_consolidates_own_coins(node: &Node) -> (corepc_node::Client, Address) {
    let carol = node.create_wallet("carol").unwrap();
    let dest = carol.new_address().unwrap();
    let inputs = fund_coins(node, &carol, 3, 300_000);
    merge_into(node, &[&carol], &inputs, dest.clone(), 900_000);
    (carol, dest)
}

#[test]
fn a_coin_at_a_fixed_address_beside_a_ranged_descriptor_warns() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let (_carol, dest) = someone_consolidates_own_coins(&node);

    // The ranged descriptors say nothing about the coin at `dest`.
    let mut descriptors = wallet_descriptors(&alice);
    descriptors.push(format!("addr({dest})"));
    assert_consolidation_warning(&scan_descriptors(&node, descriptors), 0, 3, 0);
}

#[test]
fn a_sweep_to_a_ranged_receive_address_beside_a_fixed_one_is_silent() {
    let node = node();
    let alice = receive_from_a_sweep(&node);
    let (_carol, dest) = someone_consolidates_own_coins(&node);

    // The xpub-derived coin is covered even though an addr() rides along.
    let mut descriptors = wallet_descriptors(&alice);
    descriptors.push(format!("addr({dest})"));
    let report = scan_descriptors(&node, descriptors);
    let flagged: Vec<_> = report
        .warnings
        .iter()
        .filter(|w| w.vulnerability_type == VulnerabilityType::Consolidation)
        .collect();
    assert_eq!(
        flagged.len(),
        1,
        "only the coin at the fixed address: {flagged:?}"
    );
    let details = flagged[0].details.as_ref().expect("details");
    assert_eq!(details["consolidation_inputs"], 3);
}

#[test]
fn paying_from_three_of_our_coins_with_change_is_our_consolidation() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // The coin left in the wallet is the change of a payment from three own coins.
    let inputs = fund_coins(&node, &alice, 3, 300_000);
    let outputs = [
        Output::new(bob.new_address().unwrap(), Amount::from_sat(500_000)),
        Output::new(change_address(&alice), Amount::from_sat(390_000)),
    ];
    spend(&node, &[&alice], &inputs, &outputs);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    let details = consolidation_finding(&report)
        .details
        .clone()
        .expect("details");
    assert_eq!(details["our_inputs_in_consolidation"], 3);
    assert!(!has_warning(&report, VulnerabilityType::Consolidation));
}

#[test]
fn unresolved_inputs_on_a_change_address_get_the_unchecked_wording() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let mut inputs = fund_coins(&node, &bob, 3, 300_000);
    inputs.extend(fund_coins(&node, &alice, 1, 300_000));
    merge_into(
        &node,
        &[&bob, &alice],
        &inputs,
        change_address(&alice),
        1_200_000,
    );

    // Depth 0 leaves bob's funding transactions unfetched.
    let gateway = gateway_for(&node).with_max_ancestor_depth(0);
    let report = scan_wallet(&gateway, "alice");
    assert_consolidation_warning(&report, 1, 0, 3);
    let warning = report
        .warnings
        .iter()
        .find(|w| w.vulnerability_type == VulnerabilityType::Consolidation)
        .expect("warning");
    assert!(
        !warning.description.contains("another account"),
        "{}",
        warning.description
    );
}

// A watch-only wallet imports one fixed address, which then receives bob's sweep.
fn watch_a_fixed_address_receiving_a_sweep(node: &Node) {
    let da = node.client.new_address().unwrap();
    mine(node, 110, &da);
    node.client
        .call::<serde_json::Value>(
            "createwallet",
            &[
                serde_json::json!("watch"),
                serde_json::json!(true),
                serde_json::json!(true),
            ],
        )
        .unwrap();
    let watch = corepc_node::Client::new_with_auth(
        &node.rpc_url_with_wallet("watch"),
        corepc_node::client::client_sync::Auth::CookieFile(node.params.cookie_file.clone()),
    )
    .unwrap();
    let carol = node.create_wallet("carol").unwrap();
    let watched = carol.new_address().unwrap();
    let info: serde_json::Value = node
        .client
        .call(
            "getdescriptorinfo",
            &[serde_json::json!(format!("addr({watched})"))],
        )
        .unwrap();
    let imported: serde_json::Value = watch
        .call(
            "importdescriptors",
            &[serde_json::json!([{
                "desc": info["descriptor"],
                "timestamp": "now",
            }])],
        )
        .unwrap();
    assert_eq!(imported[0]["success"], true, "{imported}");

    let bob = node.create_wallet("bob").unwrap();
    let inputs = fund_coins(node, &bob, 4, 300_000);
    merge_into(node, &[&bob], &inputs, watched, 1_200_000);
}

#[test]
fn wallet_scan_warns_on_a_sweep_to_an_imported_fixed_address() {
    let node = node();
    watch_a_fixed_address_receiving_a_sweep(&node);

    let gateway = gateway_for(&node);
    assert_consolidation_warning(&scan_wallet(&gateway, "watch"), 0, 4, 0);
}
