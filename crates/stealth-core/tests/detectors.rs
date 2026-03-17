use std::collections::{HashMap, HashSet};

use stealth_core::config::AnalysisConfig;
use stealth_core::detectors::{
    DetectorContext, detect_address_reuse, detect_behavioral_fingerprint, detect_change_detection,
    detect_cioh, detect_cluster_merge, detect_consolidation, detect_dust, detect_dust_spending,
    detect_exchange_origin, detect_script_type_mixing, detect_tainted_utxo_merge,
    detect_utxo_age_spread,
};
use stealth_core::graph::TxGraph;
use stealth_core::model::{
    DecodedTransaction, DerivedAddress, DescriptorChainRole, DescriptorType, FindingKind,
    TxInputRef, TxOutput, Utxo, WalletHistory, WalletTxCategory, WalletTxEntry, WarningKind,
};

fn satoshis(value: u64) -> f64 {
    value as f64 / 100_000_000.0
}

fn our_address(
    address: &str,
    descriptor_type: DescriptorType,
    chain_role: DescriptorChainRole,
) -> DerivedAddress {
    DerivedAddress {
        address: address.to_string(),
        descriptor_type,
        chain_role,
        derivation_index: 0,
    }
}

fn wallet_entry(
    txid: &str,
    address: &str,
    category: WalletTxCategory,
    sats: u64,
    confirmations: u32,
) -> WalletTxEntry {
    WalletTxEntry {
        txid: txid.to_string(),
        address: address.to_string(),
        category,
        amount_btc: satoshis(sats),
        confirmations,
        blockheight: 0,
    }
}

fn tx(
    txid: &str,
    vin: Vec<TxInputRef>,
    vout: Vec<TxOutput>,
    confirmations: u32,
) -> DecodedTransaction {
    DecodedTransaction {
        txid: txid.to_string(),
        vin,
        vout,
        version: 2,
        locktime: 0,
        vsize: 200,
        confirmations,
    }
}

fn input(previous_txid: &str, previous_vout: u32) -> TxInputRef {
    TxInputRef {
        previous_txid: previous_txid.to_string(),
        previous_vout,
        sequence: 0xffff_fffd,
        coinbase: false,
    }
}

fn output(n: u32, address: &str, sats: u64, script_type: DescriptorType) -> TxOutput {
    TxOutput {
        n,
        address: address.to_string(),
        value_btc: satoshis(sats),
        script_type,
    }
}

fn utxo(
    txid: &str,
    vout: u32,
    address: &str,
    sats: u64,
    confirmations: u32,
    script_type: DescriptorType,
) -> Utxo {
    Utxo {
        txid: txid.to_string(),
        vout,
        address: address.to_string(),
        amount_btc: satoshis(sats),
        confirmations,
        script_type,
    }
}

fn graph(
    addresses: Vec<DerivedAddress>,
    wallet_txs: Vec<WalletTxEntry>,
    utxos: Vec<Utxo>,
    transactions: Vec<DecodedTransaction>,
) -> TxGraph {
    let history = WalletHistory {
        wallet_txs,
        utxos,
        transactions: transactions
            .into_iter()
            .map(|item| (item.txid.clone(), item))
            .collect::<HashMap<_, _>>(),
    };
    TxGraph::new(addresses, history)
}

fn context<'a>(
    graph: &'a TxGraph,
    config: &'a AnalysisConfig,
    known_exchange_txids: &'a HashSet<String>,
    known_risky_txids: &'a HashSet<String>,
) -> DetectorContext<'a> {
    DetectorContext {
        graph,
        config,
        known_exchange_txids,
        known_risky_txids,
    }
}

#[test]
fn address_reuse_is_detected() {
    let receive = our_address(
        "bcrt1qreceive",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let graph = graph(
        vec![receive.clone()],
        vec![
            wallet_entry(
                "reuse-1",
                &receive.address,
                WalletTxCategory::Receive,
                1_000_000,
                6,
            ),
            wallet_entry(
                "reuse-2",
                &receive.address,
                WalletTxCategory::Receive,
                2_000_000,
                5,
            ),
        ],
        Vec::new(),
        vec![
            tx(
                "reuse-1",
                Vec::new(),
                vec![output(
                    0,
                    &receive.address,
                    1_000_000,
                    DescriptorType::P2wpkh,
                )],
                6,
            ),
            tx(
                "reuse-2",
                Vec::new(),
                vec![output(
                    0,
                    &receive.address,
                    2_000_000,
                    DescriptorType::P2wpkh,
                )],
                5,
            ),
        ],
    );

    let config = AnalysisConfig::default();
    let known_exchange = HashSet::new();
    let known_risky = HashSet::new();
    let findings =
        detect_address_reuse(&context(&graph, &config, &known_exchange, &known_risky)).findings;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, FindingKind::AddressReuse);
}

#[test]
fn dust_current_and_historical_are_detected() {
    let strict = our_address(
        "bcrt1qdust",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let spent = our_address(
        "bcrt1qspent",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let graph = graph(
        vec![strict.clone(), spent.clone()],
        vec![
            wallet_entry(
                "dust-live",
                &strict.address,
                WalletTxCategory::Receive,
                546,
                3,
            ),
            wallet_entry(
                "dust-spent",
                &spent.address,
                WalletTxCategory::Receive,
                1_000,
                2,
            ),
        ],
        vec![utxo(
            "dust-live",
            0,
            &strict.address,
            546,
            3,
            DescriptorType::P2wpkh,
        )],
        vec![
            tx(
                "dust-live",
                Vec::new(),
                vec![output(0, &strict.address, 546, DescriptorType::P2wpkh)],
                3,
            ),
            tx(
                "dust-spent",
                Vec::new(),
                vec![output(0, &spent.address, 1_000, DescriptorType::P2wpkh)],
                2,
            ),
        ],
    );

    let config = AnalysisConfig::default();
    let known_exchange = HashSet::new();
    let known_risky = HashSet::new();
    let findings = detect_dust(&context(&graph, &config, &known_exchange, &known_risky)).findings;
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .any(|finding| finding.kind == FindingKind::Dust)
    );
}

#[test]
fn multi_input_heuristics_are_detected() {
    let a = our_address(
        "bcrt1qin1",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let b = our_address(
        "bcrt1qin2",
        DescriptorType::P2tr,
        DescriptorChainRole::External,
    );
    let change = our_address(
        "bcrt1qchange",
        DescriptorType::P2wpkh,
        DescriptorChainRole::Internal,
    );
    let transactions = vec![
        tx(
            "fund-a",
            vec![input("bob-parent", 0)],
            vec![output(0, &a.address, 50_000, DescriptorType::P2wpkh)],
            10,
        ),
        tx(
            "fund-b",
            vec![input("carol-parent", 0)],
            vec![output(0, &b.address, 60_000, DescriptorType::P2tr)],
            10,
        ),
        tx(
            "spend",
            vec![input("fund-a", 0), input("fund-b", 0)],
            vec![
                output(0, "mipcPayment", 1_000_000, DescriptorType::P2pkh),
                output(1, &change.address, 10_345, DescriptorType::P2wpkh),
            ],
            2,
        ),
    ];
    let graph = graph(
        vec![a.clone(), b.clone(), change.clone()],
        vec![
            wallet_entry("fund-a", &a.address, WalletTxCategory::Receive, 50_000, 10),
            wallet_entry("fund-b", &b.address, WalletTxCategory::Receive, 60_000, 10),
            wallet_entry("spend", &change.address, WalletTxCategory::Send, 10_345, 2),
        ],
        vec![utxo(
            "spend",
            1,
            &change.address,
            10_345,
            2,
            DescriptorType::P2wpkh,
        )],
        transactions,
    );

    let config = AnalysisConfig::default();
    let known_exchange = HashSet::new();
    let known_risky = HashSet::new();
    let ctx = context(&graph, &config, &known_exchange, &known_risky);
    assert_eq!(detect_cioh(&ctx).findings[0].kind, FindingKind::Cioh);
    assert_eq!(
        detect_change_detection(&ctx).findings[0].kind,
        FindingKind::ChangeDetection
    );
    assert_eq!(
        detect_script_type_mixing(&ctx).findings[0].kind,
        FindingKind::ScriptTypeMixing
    );
    assert_eq!(
        detect_cluster_merge(&ctx).findings[0].kind,
        FindingKind::ClusterMerge
    );
}

#[test]
fn consolidation_and_dust_spending_are_detected() {
    let dust_addr = our_address(
        "bcrt1qdustin",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let normal_addr = our_address(
        "bcrt1qnormal",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let consolidated = our_address(
        "bcrt1qconsolidated",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let transactions = vec![
        tx(
            "dust-fund",
            vec![input("miner-a", 0)],
            vec![output(0, &dust_addr.address, 1_000, DescriptorType::P2wpkh)],
            20,
        ),
        tx(
            "normal-fund",
            vec![input("miner-b", 0)],
            vec![output(
                0,
                &normal_addr.address,
                25_000,
                DescriptorType::P2wpkh,
            )],
            20,
        ),
        tx(
            "consolidation-parent",
            vec![input("src-1", 0), input("src-2", 0), input("src-3", 0)],
            vec![output(
                0,
                &consolidated.address,
                26_000,
                DescriptorType::P2wpkh,
            )],
            5,
        ),
        tx(
            "spend-dust",
            vec![input("dust-fund", 0), input("normal-fund", 0)],
            vec![output(0, "mipcRecipient", 20_000, DescriptorType::P2pkh)],
            2,
        ),
    ];
    let graph = graph(
        vec![dust_addr.clone(), normal_addr.clone(), consolidated.clone()],
        vec![
            wallet_entry(
                "dust-fund",
                &dust_addr.address,
                WalletTxCategory::Receive,
                1_000,
                20,
            ),
            wallet_entry(
                "normal-fund",
                &normal_addr.address,
                WalletTxCategory::Receive,
                25_000,
                20,
            ),
            wallet_entry(
                "consolidation-parent",
                &consolidated.address,
                WalletTxCategory::Receive,
                26_000,
                5,
            ),
            wallet_entry(
                "spend-dust",
                "mipcRecipient",
                WalletTxCategory::Send,
                20_000,
                2,
            ),
        ],
        vec![utxo(
            "consolidation-parent",
            0,
            &consolidated.address,
            26_000,
            5,
            DescriptorType::P2wpkh,
        )],
        transactions,
    );

    let config = AnalysisConfig::default();
    let known_exchange = HashSet::new();
    let known_risky = HashSet::new();
    let ctx = context(&graph, &config, &known_exchange, &known_risky);
    assert_eq!(
        detect_dust_spending(&ctx).findings[0].kind,
        FindingKind::DustSpending
    );
    assert_eq!(
        detect_consolidation(&ctx).findings[0].kind,
        FindingKind::Consolidation
    );
}

#[test]
fn age_spread_emits_finding_and_warning() {
    let old = our_address(
        "bcrt1qold",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let fresh = our_address(
        "bcrt1qfresh",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let graph = graph(
        vec![old.clone(), fresh.clone()],
        Vec::new(),
        vec![
            utxo(
                "old-utxo",
                0,
                &old.address,
                300_000,
                120,
                DescriptorType::P2wpkh,
            ),
            utxo(
                "fresh-utxo",
                0,
                &fresh.address,
                310_000,
                5,
                DescriptorType::P2wpkh,
            ),
        ],
        vec![
            tx(
                "old-utxo",
                Vec::new(),
                vec![output(0, &old.address, 300_000, DescriptorType::P2wpkh)],
                120,
            ),
            tx(
                "fresh-utxo",
                Vec::new(),
                vec![output(0, &fresh.address, 310_000, DescriptorType::P2wpkh)],
                5,
            ),
        ],
    );

    let config = AnalysisConfig::default();
    let known_exchange = HashSet::new();
    let known_risky = HashSet::new();
    let result = detect_utxo_age_spread(&context(&graph, &config, &known_exchange, &known_risky));
    assert_eq!(result.findings[0].kind, FindingKind::UtxoAgeSpread);
    assert_eq!(result.warnings[0].kind, WarningKind::DormantUtxos);
}

#[test]
fn exchange_origin_and_tainted_merge_are_detected() {
    let receive = our_address(
        "bcrt1qexchange",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let clean = our_address(
        "bcrt1qclean",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let tainted = our_address(
        "bcrt1qtainted",
        DescriptorType::P2wpkh,
        DescriptorChainRole::External,
    );
    let transactions = vec![
        tx(
            "exchange-batch",
            vec![input("exchange-hot", 0)],
            vec![
                output(0, &receive.address, 200_000, DescriptorType::P2wpkh),
                output(1, "bcrt1qsomeone1", 190_000, DescriptorType::P2wpkh),
                output(2, "bcrt1qsomeone2", 180_000, DescriptorType::P2wpkh),
                output(3, "bcrt1qsomeone3", 170_000, DescriptorType::P2wpkh),
                output(4, "bcrt1qsomeone4", 160_000, DescriptorType::P2wpkh),
            ],
            4,
        ),
        tx(
            "risky-source",
            vec![input("risky-parent", 0)],
            vec![output(0, &tainted.address, 80_000, DescriptorType::P2wpkh)],
            8,
        ),
        tx(
            "clean-source",
            vec![input("clean-parent", 0)],
            vec![output(0, &clean.address, 90_000, DescriptorType::P2wpkh)],
            8,
        ),
        tx(
            "merge-taint",
            vec![input("risky-source", 0), input("clean-source", 0)],
            vec![output(0, "mipcOut", 150_000, DescriptorType::P2pkh)],
            1,
        ),
    ];
    let graph = graph(
        vec![receive.clone(), clean.clone(), tainted.clone()],
        vec![
            wallet_entry(
                "exchange-batch",
                &receive.address,
                WalletTxCategory::Receive,
                200_000,
                4,
            ),
            wallet_entry(
                "risky-source",
                &tainted.address,
                WalletTxCategory::Receive,
                80_000,
                8,
            ),
            wallet_entry(
                "clean-source",
                &clean.address,
                WalletTxCategory::Receive,
                90_000,
                8,
            ),
            wallet_entry("merge-taint", "mipcOut", WalletTxCategory::Send, 150_000, 1),
        ],
        Vec::new(),
        transactions,
    );

    let known_exchange_txids = HashSet::from([String::from("exchange-batch")]);
    let known_risky_txids = HashSet::from([String::from("risky-source")]);
    let config = AnalysisConfig::default();
    let ctx = context(&graph, &config, &known_exchange_txids, &known_risky_txids);

    assert_eq!(
        detect_exchange_origin(&ctx).findings[0].kind,
        FindingKind::ExchangeOrigin
    );

    let taint_result = detect_tainted_utxo_merge(&ctx);
    assert_eq!(taint_result.findings[0].kind, FindingKind::TaintedUtxoMerge);
    assert_eq!(taint_result.warnings[0].kind, WarningKind::DirectTaint);
}

#[test]
fn behavioral_fingerprint_requires_consistent_patterns() {
    let in1 = our_address(
        "bcrt1qbeh1",
        DescriptorType::P2pkh,
        DescriptorChainRole::External,
    );
    let in2 = our_address(
        "bcrt1qbeh2",
        DescriptorType::P2pkh,
        DescriptorChainRole::External,
    );
    let change = our_address(
        "bcrt1qbehchange",
        DescriptorType::P2wpkh,
        DescriptorChainRole::Internal,
    );
    let transactions = vec![
        tx(
            "fund-1",
            vec![input("source-1", 0)],
            vec![output(0, &in1.address, 400_000, DescriptorType::P2pkh)],
            20,
        ),
        tx(
            "fund-2",
            vec![input("source-2", 0)],
            vec![output(0, &in2.address, 400_000, DescriptorType::P2pkh)],
            20,
        ),
        tx(
            "send-1",
            vec![input("fund-1", 0), input("fund-2", 0)],
            vec![
                output(0, "mipcDest1", 100_000, DescriptorType::P2pkh),
                output(1, &change.address, 20_000, DescriptorType::P2wpkh),
            ],
            3,
        ),
        tx(
            "send-2",
            vec![input("fund-1", 0), input("fund-2", 0)],
            vec![
                output(0, "mipcDest2", 200_000, DescriptorType::P2pkh),
                output(1, &change.address, 30_000, DescriptorType::P2wpkh),
            ],
            2,
        ),
        tx(
            "send-3",
            vec![input("fund-1", 0), input("fund-2", 0)],
            vec![
                output(0, "mipcDest3", 300_000, DescriptorType::P2pkh),
                output(1, &change.address, 40_000, DescriptorType::P2wpkh),
            ],
            1,
        ),
    ];
    let graph = graph(
        vec![in1.clone(), in2.clone(), change.clone()],
        vec![
            wallet_entry(
                "fund-1",
                &in1.address,
                WalletTxCategory::Receive,
                400_000,
                20,
            ),
            wallet_entry(
                "fund-2",
                &in2.address,
                WalletTxCategory::Receive,
                400_000,
                20,
            ),
            wallet_entry("send-1", &change.address, WalletTxCategory::Send, 20_000, 3),
            wallet_entry("send-2", &change.address, WalletTxCategory::Send, 30_000, 2),
            wallet_entry("send-3", &change.address, WalletTxCategory::Send, 40_000, 1),
        ],
        Vec::new(),
        transactions,
    );

    let config = AnalysisConfig::default();
    let known_exchange = HashSet::new();
    let known_risky = HashSet::new();
    let findings =
        detect_behavioral_fingerprint(&context(&graph, &config, &known_exchange, &known_risky))
            .findings;
    assert_eq!(findings[0].kind, FindingKind::BehavioralFingerprint);
}
