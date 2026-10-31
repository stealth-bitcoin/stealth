use crate::common::*;

// ─── 1. Address Reuse ───────────────────────────────────────────────────────

#[test]
fn detect_address_reuse() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Reuse the same alice address twice
    let reused = alice.new_address().unwrap();
    bob.send_to_address(&reused, Amount::from_sat(1_000_000))
        .unwrap();
    bob.send_to_address(&reused, Amount::from_sat(2_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let gateway = gateway_for(&node);
    let report = scan_wallet(&gateway, "alice");
    assert!(has_finding(&report, VulnerabilityType::AddressReuse));
    let reuse = reuse_correction(&report, &reused);
    assert!(
        reuse.starts_with("Generate a fresh address for every payment received."),
        "{reuse}"
    );
}

fn reuse_correction(report: &stealth_engine::Report, address: &Address) -> String {
    let address = address.to_string();
    let found: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::AddressReuse)
        .filter(|f| f.details.as_ref().unwrap()["address"] == address.as_str())
        .collect();
    assert_eq!(found.len(), 1, "{:?}", report.findings);
    found[0].correction.clone().unwrap()
}

#[test]
fn reuse_from_change_back_to_the_input_address_says_so() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let funded = alice.new_address().unwrap();
    let reused = pay_with_change_back_to_input(&node, &alice, funded);

    let report = scan_wallet(&gateway_for(&node), "alice");
    let reuse = reuse_correction(&report, &reused);
    assert!(
        reuse.starts_with(
            "This address got change back from its own spends: send change to a fresh \
             change address instead, as wallets do by default."
        ),
        "{reuse}"
    );
    assert!(
        reuse.contains("Generate a fresh address for every payment received."),
        "{reuse}"
    );
}

/// Alice spends every coin she holds in one transaction to `outputs`.
fn spend_all(alice: &corepc_node::Client, outputs: impl Fn(u64) -> Vec<Output>) {
    let coins = alice.list_unspent().unwrap().0;
    let inputs: Vec<Input> = coins
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total: u64 = coins.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let raw = alice
        .create_raw_transaction(&inputs, &outputs(total - 10_000))
        .unwrap();
    let signed = alice
        .sign_raw_transaction_with_wallet(&raw.transaction().unwrap())
        .unwrap();
    alice
        .send_raw_transaction(&signed.into_model().unwrap().tx)
        .unwrap();
}

#[test]
fn a_self_consolidation_into_a_reused_address_keeps_the_plain_correction() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let (a, b) = (alice.new_address().unwrap(), alice.new_address().unwrap());
    node.client.send_to_address(&a, Amount::ONE_BTC).unwrap();
    node.client.send_to_address(&b, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);
    spend_all(&alice, |sats| {
        vec![Output::new(a.clone(), Amount::from_sat(sats))]
    });
    mine(&node, 1, &da);

    let report = scan_wallet(&gateway_for(&node), "alice");
    let reuse = reuse_correction(&report, &a);
    assert!(
        reuse.starts_with("Generate a fresh address for every payment received."),
        "{reuse}"
    );
}

#[test]
fn reuse_by_payments_later_spent_to_a_fresh_change_address_keeps_the_plain_correction() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);
    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let reused = alice.new_address().unwrap();
    node.client
        .send_to_address(&reused, Amount::ONE_BTC)
        .unwrap();
    node.client
        .send_to_address(&reused, Amount::ONE_BTC)
        .unwrap();
    mine(&node, 1, &da);
    let (payee, change) = (bob.new_address().unwrap(), alice.new_address().unwrap());
    spend_all(&alice, |sats| {
        vec![
            Output::new(payee.clone(), Amount::from_sat(30_000_000)),
            Output::new(change.clone(), Amount::from_sat(sats - 30_000_000)),
        ]
    });
    mine(&node, 1, &da);

    let report = scan_wallet(&gateway_for(&node), "alice");
    let reuse = reuse_correction(&report, &reused);
    assert!(
        reuse.starts_with("Generate a fresh address for every payment received."),
        "{reuse}"
    );
}
