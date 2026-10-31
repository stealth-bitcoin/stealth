// Determinism tests: two scans of the same wallet history must produce
// byte-identical serialized reports, regardless of HashMap/HashSet seeds.
//
// Runs entirely in memory; no bitcoind node required.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{
    Address, Amount, Network, PubkeyHash, ScriptBuf, Txid, WPubkeyHash, WitnessProgram,
    WitnessVersion,
};
use stealth_engine::config::DetectorThresholds;
use stealth_engine::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, Utxo, WalletHistory,
    WalletTxCategory, WalletTxEntry,
};
use stealth_engine::{TxGraph, VulnerabilityType};

// ─── builders ───────────────────────────────────────────────────────────────

fn txid(n: u64) -> Txid {
    format!("{:0<64x}", n).parse().expect("valid txid hex")
}

fn parse_addr(script: ScriptBuf) -> Address<NetworkUnchecked> {
    let checked =
        Address::from_script(&script, Network::Regtest).expect("script encodes to an address");
    checked
        .to_string()
        .parse::<Address<NetworkUnchecked>>()
        .expect("valid regtest address string")
}

fn wpkh(seed: u8) -> Address<NetworkUnchecked> {
    parse_addr(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
        [seed; 20],
    )))
}

fn pkh(seed: u8) -> Address<NetworkUnchecked> {
    parse_addr(ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(
        [seed; 20],
    )))
}

fn tr(seed: u8) -> Address<NetworkUnchecked> {
    let program = WitnessProgram::new(WitnessVersion::V1, &[seed; 32]).expect("32-byte v1 program");
    parse_addr(ScriptBuf::new_witness_program(&program))
}

fn vin(prev: Txid, vout: u32) -> TxInputRef {
    TxInputRef {
        previous_txid: prev,
        previous_vout: vout,
        sequence: 0xffff_fffd,
        coinbase: false,
    }
}

fn out(n: u32, addr: &Address<NetworkUnchecked>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address: Some(addr.clone()),
        value: Amount::from_sat(sats),
        script_type: DescriptorType::P2wpkh,
    }
}

fn tx(id: Txid, vins: Vec<TxInputRef>, vouts: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: id,
        vin: vins,
        vout: vouts,
        version: 2,
        locktime: 0,
        vsize: 200,
        confirmations: 3,
    }
}

fn recv(id: Txid, addr: &Address<NetworkUnchecked>, sats: u64, conf: u32) -> WalletTxEntry {
    WalletTxEntry {
        txid: id,
        address: Some(addr.clone()),
        category: WalletTxCategory::Receive,
        amount: Amount::from_sat(sats),
        confirmations: conf,
        blockheight: 100,
    }
}

fn sent(id: Txid) -> WalletTxEntry {
    WalletTxEntry {
        txid: id,
        address: None,
        category: WalletTxCategory::Send,
        amount: Amount::from_sat(0),
        confirmations: 2,
        blockheight: 110,
    }
}

fn utxo(id: Txid, vout: u32, addr: &Address<NetworkUnchecked>, sats: u64, conf: u32) -> Utxo {
    Utxo {
        txid: id,
        vout,
        address: Some(addr.clone()),
        amount: Amount::from_sat(sats),
        confirmations: conf,
        script_type: DescriptorType::P2wpkh,
    }
}

// ─── synthetic wallet history ───────────────────────────────────────────────
//
// A deliberately messy wallet: reused addresses, dust (received and spent),
// a consolidation, mixed script types, a peel chain, toxic change, an
// exchange-like batch deposit, and a tainted merge. Rich enough that every
// HashSet/HashMap iteration in the detectors has more than one element.

fn build_history() -> WalletHistory {
    // Ours
    let w: Vec<Address<NetworkUnchecked>> = (1u8..=17).map(wpkh).collect();
    let c1 = wpkh(18);
    let c2 = wpkh(19);
    let c3 = wpkh(20);
    let t0 = tr(21);
    let p0 = pkh(22);
    // Externals
    let e: Vec<Address<NetworkUnchecked>> = (160u8..=166).map(wpkh).collect();
    let ep1 = wpkh(170);
    let ep2 = wpkh(171);
    let ep3 = wpkh(172);
    let xpa = wpkh(180);
    let xe: Vec<Address<NetworkUnchecked>> = (181u8..=185).map(wpkh).collect();

    let f1 = txid(0x21);
    let f2 = txid(0x22);
    let f3 = txid(0x23);
    let f4 = txid(0x24);
    let f5 = txid(0x25);
    let f6 = txid(0x26);
    let d1 = txid(0x27);
    let d2 = txid(0x28);
    let f7 = txid(0x29);
    let c1x = txid(0x2A);
    let s3 = txid(0x2B);
    let s1 = txid(0x2C);
    let s5 = txid(0x2D);
    let s6 = txid(0x2E);
    let s4 = txid(0x2F);
    let f8 = txid(0x30);
    let p1x = txid(0x31);
    let p2x = txid(0x32);
    let p3x = txid(0x33);
    let f9 = txid(0x34);
    let x1 = txid(0x35);
    let xp = txid(0x36);
    let f10 = txid(0x37);

    let txs = vec![
        // Funding from external sources (grandparents are phantom txids).
        tx(
            f1,
            vec![vin(txid(0x11), 0), vin(txid(0x12), 0)],
            vec![out(0, &w[0], 50_000_000), out(1, &e[0], 3_000_000)],
        ),
        tx(f2, vec![vin(txid(0x13), 1)], vec![out(0, &w[0], 7_000_000)]),
        tx(
            f3,
            vec![vin(txid(0x13), 0)],
            vec![out(0, &w[1], 20_000_000)],
        ),
        tx(f4, vec![vin(txid(0x14), 0)], vec![out(0, &w[1], 4_000_000)]),
        tx(
            f5,
            vec![vin(txid(0x15), 0)],
            vec![out(0, &w[2], 30_000_000)],
        ),
        tx(f6, vec![vin(txid(0x16), 0)], vec![out(0, &p0, 25_000_000)]),
        tx(
            d1,
            vec![vin(txid(0x17), 0)],
            vec![out(0, &w[3], 800), out(1, &e[1], 5_000_000)],
        ),
        tx(d2, vec![vin(txid(0x18), 0)], vec![out(0, &w[5], 900)]),
        tx(
            f7,
            vec![vin(txid(0x19), 0), vin(txid(0x1A), 0)],
            vec![out(0, &t0, 15_000_000)],
        ),
        tx(
            f8,
            vec![vin(txid(0x1B), 0)],
            vec![out(0, &w[10], 100_000_000)],
        ),
        tx(
            f9,
            vec![vin(txid(0x1C), 0)],
            vec![out(0, &w[11], 12_345_678)],
        ),
        tx(
            f10,
            vec![vin(txid(0x12), 3)],
            vec![out(0, &w[13], 10_000_000), out(1, &w[14], 300_000)],
        ),
        // Consolidation of three of our UTXOs (mixed script types).
        tx(
            c1x,
            vec![vin(f2, 0), vin(f4, 0), vin(f7, 0)],
            vec![out(0, &w[4], 25_900_000)],
        ),
        // Dust spent alongside a normal input.
        tx(
            s3,
            vec![vin(d1, 0), vin(f5, 0)],
            vec![out(0, &e[2], 28_000_000), out(1, &w[6], 1_987_654)],
        ),
        // Two-input send with one unnecessary input.
        tx(
            s1,
            vec![vin(f1, 0), vin(f3, 0)],
            vec![out(0, &e[3], 10_000_000), out(1, &w[7], 59_899_999)],
        ),
        // Payment leaving toxic change...
        tx(
            s5,
            vec![vin(f6, 0)],
            vec![out(0, &e[4], 24_990_000), out(1, &w[8], 5_000)],
        ),
        // ...later merged with a much larger UTXO.
        tx(
            s6,
            vec![vin(s5, 1), vin(s1, 1)],
            vec![out(0, &e[5], 59_000_000), out(1, &w[9], 800_000)],
        ),
        // Fully deterministic input→output links.
        tx(
            s4,
            vec![vin(f10, 0), vin(f10, 1)],
            vec![out(0, &e[6], 9_900_000), out(1, &w[15], 250_000)],
        ),
        // Peel chain: P1 → P2 → P3.
        tx(
            p1x,
            vec![vin(f8, 0)],
            vec![out(0, &ep1, 9_000_000), out(1, &c1, 90_500_000)],
        ),
        tx(
            p2x,
            vec![vin(p1x, 1)],
            vec![out(0, &ep2, 8_000_000), out(1, &c2, 82_000_000)],
        ),
        tx(
            p3x,
            vec![vin(p2x, 1)],
            vec![out(0, &ep3, 7_000_000), out(1, &c3, 74_500_000)],
        ),
        // Exchange-like batch withdrawal paying us.
        tx(xp, vec![vin(txid(0x1D), 0)], vec![out(0, &xpa, 63_000_000)]),
        tx(
            x1,
            vec![vin(xp, 0)],
            vec![
                out(0, &w[12], 10_000_000),
                out(1, &xe[0], 9_500_000),
                out(2, &xe[1], 10_500_000),
                out(3, &xe[2], 11_000_000),
                out(4, &xe[3], 9_000_000),
                out(5, &xe[4], 12_000_000),
            ],
        ),
    ];
    let transactions: HashMap<Txid, DecodedTransaction> =
        txs.into_iter().map(|t| (t.txid, t)).collect();

    let wallet_txs = vec![
        recv(f1, &w[0], 50_000_000, 40),
        recv(f2, &w[0], 7_000_000, 38),
        recv(f3, &w[1], 20_000_000, 36),
        recv(f4, &w[1], 4_000_000, 34),
        recv(f5, &w[2], 30_000_000, 32),
        recv(f6, &p0, 25_000_000, 30),
        recv(d1, &w[3], 800, 28),
        recv(d2, &w[5], 900, 26),
        recv(f7, &t0, 15_000_000, 24),
        recv(f8, &w[10], 100_000_000, 22),
        recv(f9, &w[11], 12_345_678, 150),
        recv(f10, &w[13], 10_000_000, 20),
        recv(x1, &w[12], 10_000_000, 3),
        sent(c1x),
        sent(s3),
        sent(s1),
        sent(s5),
        sent(s6),
        sent(s4),
        sent(p1x),
        sent(p2x),
        sent(p3x),
    ];

    let utxos = vec![
        utxo(c1x, 0, &w[4], 25_900_000, 5),
        utxo(d2, 0, &w[5], 900, 8),
        utxo(s6, 1, &w[9], 800_000, 2),
        utxo(p3x, 1, &c3, 74_500_000, 1),
        utxo(f9, 0, &w[11], 12_345_678, 150),
        utxo(x1, 0, &w[12], 10_000_000, 3),
    ];

    let mut derived_addresses: HashSet<Address<NetworkUnchecked>> = w.iter().cloned().collect();
    derived_addresses.extend([c1, c2, c3, t0, p0]);
    let internal_addresses: HashSet<Address<NetworkUnchecked>> = HashSet::from([w[7].clone()]);

    WalletHistory {
        wallet_txs,
        utxos,
        transactions,
        internal_addresses,
        derived_addresses,
    }
}

fn scan(history: &WalletHistory) -> stealth_engine::Report {
    let risky: HashSet<Txid> = HashSet::from([txid(0x21)]);
    let exchange: HashSet<Txid> = HashSet::from([txid(0x35)]);
    let graph = TxGraph::from_wallet_history(history.clone());
    graph.detect_all(
        &DetectorThresholds::default(),
        Some(&risky),
        Some(&exchange),
    )
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[test]
fn synthetic_scenario_triggers_detectors() {
    let history = build_history();
    let report = scan(&history);
    let present: HashSet<VulnerabilityType> = report
        .findings
        .iter()
        .map(|f| f.vulnerability_type)
        .collect();
    for expected in [
        VulnerabilityType::AddressReuse,
        VulnerabilityType::Cioh,
        VulnerabilityType::Dust,
        VulnerabilityType::DustSpending,
        VulnerabilityType::ChangeDetection,
        VulnerabilityType::Consolidation,
        VulnerabilityType::ScriptTypeMixing,
        VulnerabilityType::ClusterMerge,
        VulnerabilityType::UtxoAgeSpread,
        VulnerabilityType::ExchangeOrigin,
        VulnerabilityType::TaintedUtxoMerge,
        VulnerabilityType::BehavioralFingerprint,
        VulnerabilityType::PeelChain,
        VulnerabilityType::DeterministicLink,
        VulnerabilityType::UnnecessaryInput,
        VulnerabilityType::ToxicChange,
    ] {
        assert!(present.contains(&expected), "missing finding: {expected}");
    }
    assert!(!report.warnings.is_empty(), "expected at least one warning");
}

#[test]
fn report_serialization_is_deterministic() {
    let history = build_history();
    let serialized: Vec<String> = (0..5)
        .map(|_| serde_json::to_string(&scan(&history)).expect("report serializes to JSON"))
        .collect();
    for (i, s) in serialized.iter().enumerate().skip(1) {
        assert_eq!(
            &serialized[0], s,
            "serialized report {} differs from the first run",
            i
        );
    }
}

#[test]
fn address_reuse_correction_recommends_silent_payments() {
    let history = build_history();
    let report = scan(&history);
    let finding = report
        .findings
        .iter()
        .find(|f| f.vulnerability_type == VulnerabilityType::AddressReuse)
        .expect("expected an AddressReuse finding");
    let correction = finding
        .correction
        .as_deref()
        .expect("AddressReuse finding has no correction");
    assert!(
        correction.contains("Silent Payments"),
        "AddressReuse correction does not mention Silent Payments: {correction}"
    );
    assert!(
        correction.contains("sp1"),
        "AddressReuse correction does not mention an sp1 address: {correction}"
    );
}

#[test]
fn script_type_mixing_correction_notes_silent_payments_prerequisite() {
    let history = build_history();
    let report = scan(&history);
    let finding = report
        .findings
        .iter()
        .find(|f| f.vulnerability_type == VulnerabilityType::ScriptTypeMixing)
        .expect("expected a ScriptTypeMixing finding");
    let correction = finding
        .correction
        .as_deref()
        .expect("ScriptTypeMixing finding has no correction");
    assert!(
        correction.contains("Silent Payments"),
        "ScriptTypeMixing correction does not mention Silent Payments: {correction}"
    );
}

#[test]
fn cioh_and_consolidation_corrections_recommend_payjoin() {
    let history = build_history();
    let report = scan(&history);
    for vtype in [VulnerabilityType::Cioh, VulnerabilityType::Consolidation] {
        let finding = report
            .findings
            .iter()
            .find(|f| f.vulnerability_type == vtype)
            .unwrap_or_else(|| panic!("expected a {vtype} finding"));
        let correction = finding
            .correction
            .as_deref()
            .unwrap_or_else(|| panic!("{vtype} finding has no correction"));
        assert!(
            correction.contains("Payjoin"),
            "{vtype} correction does not mention Payjoin: {correction}"
        );
    }
}

// ─── cluster merge: same chain vs distinct origins ──────────────────────────

fn spend_history(
    ours: &[Address<NetworkUnchecked>],
    receipts: &[Txid],
    spend: DecodedTransaction,
    txs: Vec<DecodedTransaction>,
) -> WalletHistory {
    let mut wallet_txs: Vec<WalletTxEntry> =
        receipts.iter().map(|r| recv(*r, &ours[0], 1, 5)).collect();
    wallet_txs.push(sent(spend.txid));
    let mut transactions: HashMap<Txid, DecodedTransaction> =
        txs.into_iter().map(|t| (t.txid, t)).collect();
    transactions.insert(spend.txid, spend);
    WalletHistory {
        wallet_txs,
        utxos: vec![],
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: ours.iter().cloned().collect(),
    }
}

fn cluster_merges(history: &WalletHistory) -> Vec<String> {
    TxGraph::from_wallet_history(history.clone())
        .detect_all(&DetectorThresholds::default(), None, None)
        .findings
        .into_iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::ClusterMerge)
        .map(|f| f.description)
        .collect()
}

#[test]
fn cluster_merge_ignores_the_mainnet_same_chain_spend() {
    // Mainnet shape of dfa822be…: `payer` funds `source`, and `child` spends `source:1`, also at `payer`.
    let (w1, w2) = (wpkh(201), wpkh(204));
    let payer = wpkh(202);
    let earlier = txid(0x500);
    let source = txid(0x501);
    let child = txid(0x502);
    let spend = txid(0x503);
    let txs = vec![
        tx(
            earlier,
            vec![vin(txid(0x5F0), 0)],
            vec![out(0, &payer, 1_100_000)],
        ),
        tx(
            source,
            vec![vin(earlier, 0)],
            vec![out(0, &w1, 400_000), out(1, &payer, 600_000)],
        ),
        tx(
            child,
            vec![vin(txid(0x5F2), 0), vin(source, 1)],
            vec![out(0, &w2, 500_000)],
        ),
    ];
    let history = spend_history(
        &[w1, w2],
        &[source, child],
        tx(
            spend,
            vec![vin(source, 0), vin(child, 0)],
            vec![out(0, &wpkh(203), 890_000)],
        ),
        txs,
    );
    assert_eq!(cluster_merges(&history), Vec::<String>::new());
}

fn two_receipts_paid_by(
    payer_a: &Address<NetworkUnchecked>,
    payer_b: &Address<NetworkUnchecked>,
) -> WalletHistory {
    let (w1, w2) = (wpkh(211), wpkh(212));
    let (pa, pb) = (txid(0x511), txid(0x512));
    let (fa, fb) = (txid(0x513), txid(0x514));
    let spend = txid(0x515);
    let txs = vec![
        tx(
            pa,
            vec![vin(txid(0x5F3), 0)],
            vec![out(0, payer_a, 900_000)],
        ),
        tx(
            pb,
            vec![vin(txid(0x5F4), 0)],
            vec![out(0, payer_b, 900_000)],
        ),
        tx(fa, vec![vin(pa, 0)], vec![out(0, &w1, 400_000)]),
        tx(fb, vec![vin(pb, 0)], vec![out(0, &w2, 400_000)]),
    ];
    spend_history(
        &[w1, w2],
        &[fa, fb],
        tx(
            spend,
            vec![vin(fa, 0), vin(fb, 0)],
            vec![out(0, &wpkh(213), 790_000)],
        ),
        txs,
    )
}

#[test]
fn cluster_merge_ignores_coins_paid_by_the_same_address() {
    let exchange = wpkh(214);
    let history = two_receipts_paid_by(&exchange, &exchange);
    assert_eq!(cluster_merges(&history), Vec::<String>::new());
}

#[test]
fn cluster_merge_still_flags_coins_from_distinct_origins() {
    let history = two_receipts_paid_by(&wpkh(214), &wpkh(215));
    assert_eq!(cluster_merges(&history).len(), 1);
}

#[test]
fn cluster_merge_counts_chains_not_inputs() {
    // Two inputs come from one funding tx, the third is a distinct origin.
    let w: Vec<Address<NetworkUnchecked>> = (224u8..=226).map(wpkh).collect();
    let source = txid(0x521);
    let other = txid(0x523);
    let spend = txid(0x524);
    let txs = vec![
        tx(
            source,
            vec![vin(txid(0x5F5), 0)],
            vec![out(0, &w[0], 400_000), out(1, &w[1], 500_000)],
        ),
        tx(
            other,
            vec![vin(txid(0x5F6), 0)],
            vec![out(0, &w[2], 300_000)],
        ),
    ];
    let history = spend_history(
        &w,
        &[source, other],
        tx(
            spend,
            vec![vin(source, 0), vin(source, 1), vin(other, 0)],
            vec![out(0, &wpkh(223), 1_190_000)],
        ),
        txs,
    );
    let merges = cluster_merges(&history);
    assert_eq!(merges.len(), 1);
    assert!(
        merges[0].ends_with("from 2 different funding chains"),
        "{}",
        merges[0]
    );
}

#[test]
fn cluster_merge_treats_coinbase_coins_as_one_origin() {
    let (w1, w2) = (wpkh(231), wpkh(232));
    let (ca, cb) = (txid(0x531), txid(0x532));
    let spend = txid(0x533);
    let coinbase = TxInputRef {
        previous_txid: Txid::all_zeros(),
        previous_vout: u32::MAX,
        sequence: 0xffff_ffff,
        coinbase: true,
    };
    let txs = vec![
        tx(ca, vec![coinbase.clone()], vec![out(0, &w1, 400_000)]),
        tx(cb, vec![coinbase], vec![out(0, &w2, 400_000)]),
    ];
    let history = spend_history(
        &[w1, w2],
        &[ca, cb],
        tx(
            spend,
            vec![vin(ca, 0), vin(cb, 0)],
            vec![out(0, &wpkh(233), 790_000)],
        ),
        txs,
    );
    assert_eq!(cluster_merges(&history), Vec::<String>::new());
}

#[test]
fn cluster_merge_ignores_coins_at_one_own_address() {
    // Coins at one address are already linked by it, whatever paid them.
    let w = wpkh(241);
    let funding: Vec<Txid> = (0x541..=0x543).map(txid).collect();
    let spend = txid(0x544);
    let txs = funding
        .iter()
        .zip(0x5F7u64..)
        .zip(242u8..)
        .flat_map(|((f, parent), payer)| {
            let p = tx(
                txid(parent),
                vec![vin(txid(parent + 0x10), 0)],
                vec![out(0, &wpkh(payer), 900_000)],
            );
            vec![
                p,
                tx(*f, vec![vin(txid(parent), 0)], vec![out(0, &w, 400_000)]),
            ]
        })
        .collect();
    let history = spend_history(
        std::slice::from_ref(&w),
        &funding,
        tx(
            spend,
            funding.iter().map(|f| vin(*f, 0)).collect(),
            vec![out(0, &wpkh(249), 1_190_000)],
        ),
        txs,
    );
    assert_eq!(cluster_merges(&history), Vec::<String>::new());
}

#[test]
fn cluster_merge_ignores_coins_from_one_funding_tx() {
    let (w1, w2) = (wpkh(101), wpkh(102));
    let funding = txid(0x551);
    let spend = txid(0x552);
    let txs = vec![tx(
        funding,
        vec![vin(txid(0x5FA), 0)],
        vec![out(0, &w1, 400_000), out(1, &w2, 400_000)],
    )];
    let history = spend_history(
        &[w1, w2],
        &[funding],
        tx(
            spend,
            vec![vin(funding, 0), vin(funding, 1)],
            vec![out(0, &wpkh(103), 790_000)],
        ),
        txs,
    );
    assert_eq!(cluster_merges(&history), Vec::<String>::new());
}

#[test]
fn cluster_merge_flags_a_counterparty_paid_from_the_same_batch() {
    // An exchange batch pays us and Alice; Alice later pays us from her output of that batch.
    let (x, y) = (wpkh(111), wpkh(112));
    let (exchange, alice) = (wpkh(113), wpkh(114));
    let (hot, batch, alice_pays) = (txid(0x561), txid(0x562), txid(0x563));
    let spend = txid(0x564);
    let txs = vec![
        tx(
            hot,
            vec![vin(txid(0x5FB), 0)],
            vec![out(0, &exchange, 2_000_000)],
        ),
        tx(
            batch,
            vec![vin(hot, 0)],
            vec![out(0, &x, 400_000), out(1, &alice, 1_500_000)],
        ),
        tx(alice_pays, vec![vin(batch, 1)], vec![out(0, &y, 400_000)]),
    ];
    let history = spend_history(
        &[x, y],
        &[batch, alice_pays],
        tx(
            spend,
            vec![vin(batch, 0), vin(alice_pays, 0)],
            vec![out(0, &wpkh(115), 790_000)],
        ),
        txs,
    );
    assert_eq!(cluster_merges(&history).len(), 1);
}

#[test]
fn cluster_merge_groups_inputs_linked_only_through_a_third() {
    // `a` and `c` share an own address, `c` and `b` share a payer; `a` and `b` share nothing.
    let (x, y) = (wpkh(121), wpkh(122));
    let (payer_a, payer_bc) = (wpkh(123), wpkh(124));
    let (pa, pb, pc) = (txid(0x571), txid(0x572), txid(0x573));
    let (fa, fb, fc) = (txid(0x574), txid(0x575), txid(0x576));
    let spend = txid(0x577);
    let txs = vec![
        tx(
            pa,
            vec![vin(txid(0x5FC), 0)],
            vec![out(0, &payer_a, 900_000)],
        ),
        tx(
            pb,
            vec![vin(txid(0x5FD), 0)],
            vec![out(0, &payer_bc, 900_000)],
        ),
        tx(
            pc,
            vec![vin(txid(0x5FE), 0)],
            vec![out(0, &payer_bc, 900_000)],
        ),
        tx(fa, vec![vin(pa, 0)], vec![out(0, &x, 400_000)]),
        tx(fb, vec![vin(pb, 0)], vec![out(0, &y, 400_000)]),
        tx(fc, vec![vin(pc, 0)], vec![out(0, &x, 400_000)]),
    ];
    let history = spend_history(
        &[x, y],
        &[fa, fb, fc],
        tx(
            spend,
            vec![vin(fa, 0), vin(fb, 0), vin(fc, 0)],
            vec![out(0, &wpkh(125), 1_190_000)],
        ),
        txs,
    );
    assert_eq!(cluster_merges(&history), Vec::<String>::new());
}
