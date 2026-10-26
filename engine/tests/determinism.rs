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
