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
    let reused = pay_with_change_back_to_input(&node, &alice);

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
