// Crash invariant: for any wallet history, `detect_all` returns a report
// without panicking, and every finding or warning carries a description.
//
// Runs entirely in memory; no bitcoind node required.

use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{
    Address, Amount, Network, PubkeyHash, ScriptBuf, ScriptHash, Txid, WPubkeyHash, WScriptHash,
    WitnessProgram, WitnessVersion,
};
use proptest::collection::{hash_set, vec};
use proptest::prelude::*;
use proptest::sample::subsequence;
use proptest::test_runner::FileFailurePersistence;
use stealth_engine::config::DetectorThresholds;
use stealth_engine::gateway::{
    DecodedTransaction, DescriptorType, TxInputRef, TxOutput, Utxo, WalletHistory,
    WalletTxCategory, WalletTxEntry,
};
use stealth_engine::{Report, TxGraph};

// Txid slots: 0..TX_SLOTS are generated transactions, the rest are phantoms
// (outpoints and wallet entries whose transaction is never provided).
const TX_SLOTS: u8 = 14;
const TXID_SPACE: u8 = 24;
const ADDR_POOL: usize = 14;
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
// Txid slots of the peel-chain and dust-attack modes, outside TXID_SPACE.
const PEEL_SLOT: u8 = 100;
const DUST_SLOT: u8 = 120;
const EXCHANGE_SLOT: u8 = 130;
const FINGERPRINT_SLOT: u8 = 140;
const LINK_SLOT: u8 = 170;
const EXACT_SLOT: u8 = 220;

// ─── builders ───────────────────────────────────────────────────────────────

fn txid(n: u8) -> Txid {
    Txid::from_byte_array([n; 32])
}

fn address(kind: u8, seed: u8, mainnet: bool) -> Address<NetworkUnchecked> {
    // Kinds 5 and 6 are non-standard for the engine: a P2A anchor and a v2 program.
    let program = |version, bytes: &[u8]| {
        let program = WitnessProgram::new(version, bytes).expect("valid witness program");
        ScriptBuf::new_witness_program(&program)
    };
    let script = match kind % 7 {
        0 => ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20])),
        1 => ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([seed; 20])),
        2 => ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([seed; 20])),
        3 => ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([seed; 32])),
        4 => program(WitnessVersion::V1, &[seed; 32]),
        5 => program(WitnessVersion::V1, &[0x4e, 0x73]),
        _ => program(WitnessVersion::V2, &[seed; 32]),
    };
    let network = if mainnet {
        Network::Bitcoin
    } else {
        Network::Regtest
    };
    Address::from_script(&script, network)
        .expect("witness or standard script encodes to an address")
        .to_string()
        .parse()
        .expect("address round-trips")
}

// ─── strategies ─────────────────────────────────────────────────────────────

fn sats() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => Just(0u64),
        2 => 1u64..=1_000,
        2 => 1_001u64..=10_000,
        // Exactly at the default dust, strict-dust and toxic-change thresholds.
        2 => prop::sample::select(vec![546u64, 547, 1_000, 1_001, 9_999, 10_000, 10_001]),
        4 => 1_000u64..=200_000_000,
        2 => (1u64..=2_000).prop_map(|k| k * 100_000),
        1 => (MAX_MONEY - 1_000_000)..=MAX_MONEY,
    ]
}

fn amount() -> impl Strategy<Value = Amount> {
    sats().prop_map(Amount::from_sat)
}

// One value shared by every output of a transaction, so zero medians are common.
fn uniform_amount() -> impl Strategy<Value = Option<Amount>> {
    let value = prop_oneof![
        3 => Just(0u64),
        1 => 1u64..=1_000,
        1 => (MAX_MONEY - 1_000_000)..=MAX_MONEY,
    ];
    prop_oneof![3 => Just(None), 1 => value.prop_map(|v| Some(Amount::from_sat(v)))]
}

fn confirmations() -> impl Strategy<Value = u32> {
    // 10 and 100 sit on the default age-spread and dormancy thresholds, 99 just below.
    prop_oneof![
        Just(0u32),
        1u32..200,
        prop::sample::select(vec![10u32, 99, 100, 110]),
        Just(u32::MAX),
        any::<u32>(),
    ]
}

fn addr_idx() -> impl Strategy<Value = Option<usize>> {
    prop_oneof![1 => Just(None), 9 => (0..ADDR_POOL).prop_map(Some)]
}

// Final, non-RBF, RBF, or anything.
fn sequence() -> impl Strategy<Value = u32> {
    prop_oneof![
        2 => Just(u32::MAX),
        2 => Just(0xffff_fffe),
        2 => Just(0xffff_fffd),
        1 => any::<u32>(),
    ]
}

// Risky/exchange tags, sometimes on the dust-attack transaction.
fn tagged_slot() -> impl Strategy<Value = u8> {
    prop_oneof![4 => txid_slot(), 1 => Just(DUST_SLOT)]
}

fn locktime() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0u32), any::<u32>()]
}

fn txid_slot() -> impl Strategy<Value = u8> {
    0..TXID_SPACE
}

fn script_type() -> impl Strategy<Value = DescriptorType> {
    prop_oneof![
        Just(DescriptorType::P2wpkh),
        Just(DescriptorType::P2tr),
        Just(DescriptorType::P2shP2wpkh),
        Just(DescriptorType::P2sh),
        Just(DescriptorType::P2pkh),
        Just(DescriptorType::Unknown),
    ]
}

fn category() -> impl Strategy<Value = WalletTxCategory> {
    prop_oneof![
        Just(WalletTxCategory::Send),
        Just(WalletTxCategory::Receive),
        Just(WalletTxCategory::Unknown),
    ]
}

#[derive(Debug, Clone)]
enum Prev {
    // A real output of the earlier tx at index `parent`, clamped to the previous one.
    Earlier { parent: u8, pick: u8, largest: bool },
    // Any slot: this tx, a later one (cycles) or a phantom.
    Anywhere { slot: u8, vout: u32 },
}

#[derive(Debug, Clone)]
struct InputSpec {
    prev: Prev,
    sequence: u32,
    coinbase: bool,
}

fn input() -> impl Strategy<Value = InputSpec> {
    let earlier = (
        prop_oneof![3 => Just(u8::MAX), 1 => 0..TX_SLOTS],
        any::<u8>(),
        any::<bool>(),
    )
        .prop_map(|(parent, pick, largest)| Prev::Earlier {
            parent,
            pick,
            largest,
        });
    let anywhere = (txid_slot(), prop_oneof![0u32..6, any::<u32>()])
        .prop_map(|(slot, vout)| Prev::Anywhere { slot, vout });
    (
        prop_oneof![8 => earlier, 2 => anywhere],
        sequence(),
        prop::bool::weighted(0.03),
    )
        .prop_map(|(prev, sequence, coinbase)| InputSpec {
            prev,
            sequence,
            coinbase,
        })
}

#[derive(Debug, Clone)]
struct OutputSpec {
    n: Option<u32>,
    addr: Option<usize>,
    value: Amount,
    script_type: DescriptorType,
}

fn output() -> impl Strategy<Value = OutputSpec> {
    (
        prop_oneof![19 => Just(None), 1 => (0u32..4).prop_map(Some)],
        addr_idx(),
        amount(),
        script_type(),
    )
        .prop_map(|(n, addr, value, script_type)| OutputSpec {
            n,
            addr,
            value,
            script_type,
        })
}

type WalletEntrySpec = (WalletTxCategory, Option<usize>, Amount, u32, u32);

fn wallet_entry() -> impl Strategy<Value = WalletEntrySpec> {
    (
        category(),
        addr_idx(),
        amount(),
        confirmations(),
        any::<u32>(),
    )
}

#[derive(Debug, Clone)]
struct TxSpec {
    dup_slot: Option<u8>,
    inner_slot: Option<u8>,
    inputs: Vec<InputSpec>,
    outputs: Vec<OutputSpec>,
    uniform: Option<Amount>,
    version: i32,
    locktime: u32,
    vsize: u32,
    confirmations: u32,
    wallet: Option<WalletEntrySpec>,
}

fn transaction() -> impl Strategy<Value = TxSpec> {
    let inputs = prop_oneof![
        1 => vec(input(), 0..1),
        5 => vec(input(), 1..=2),
        4 => vec(input(), 3..=4),
        1 => vec(input(), 0..40),
    ];
    let outputs = prop_oneof![
        2 => vec(output(), 0..2),
        4 => vec(output(), 2..=2),
        4 => vec(output(), 3..=4),
        1 => vec(output(), 0..40),
    ];
    (
        prop_oneof![19 => Just(None), 1 => (0..TX_SLOTS).prop_map(Some)],
        prop_oneof![19 => Just(None), 1 => txid_slot().prop_map(Some)],
        inputs,
        outputs,
        uniform_amount(),
        any::<i32>(),
        locktime(),
        prop_oneof![Just(0u32), 1u32..2_000, any::<u32>()],
        confirmations(),
        prop_oneof![1 => Just(None), 6 => wallet_entry().prop_map(Some)],
    )
        .prop_map(
            |(
                dup_slot,
                inner_slot,
                inputs,
                outputs,
                uniform,
                version,
                locktime,
                vsize,
                confirmations,
                wallet,
            )| TxSpec {
                dup_slot,
                inner_slot,
                inputs,
                outputs,
                uniform,
                version,
                locktime,
                vsize,
                confirmations,
                wallet,
            },
        )
}

#[derive(Debug, Clone)]
struct Scenario {
    pool: Vec<Address<NetworkUnchecked>>,
    txs: Vec<TxSpec>,
    wallet_txs: Vec<(u8, WalletEntrySpec)>,
    utxos: Vec<(u8, u32, Option<usize>, Amount, u32, DescriptorType)>,
    derived: HashSet<usize>,
    internal: HashSet<usize>,
    risky: Option<HashSet<u8>>,
    exchange: Option<HashSet<u8>>,
    peel: Option<PeelSpec>,
    dust_attack: Option<DustAttackSpec>,
    exchange_batch: Option<ExchangeBatchSpec>,
    fingerprint: Option<FingerprintSpec>,
    link: Option<LinkSpec>,
    exact: Option<ExactSpec>,
    // Wallet-wide sequence and locktime, applied to every transaction, and a
    // base age with an offset: every UTXO then has `base` or `base + offset`
    // confirmations (offset 9 or 10, around the age-spread threshold).
    style: (Option<u32>, Option<u32>, Option<(u32, u32)>),
}

// A funding tx then 2-8 hops, each paying a small share and sending the
// larger change output (ours) to the next hop.
#[derive(Debug, Clone)]
struct PeelSpec {
    start: u64,
    // (change address, payment address, payment share in permille)
    hops: Vec<(usize, usize, u64)>,
    // Same fee rate (sat/vB) on every hop.
    fee_rate: u64,
    // Payments rounded down to a multiple of 100k sats.
    round: bool,
}

fn peel() -> impl Strategy<Value = PeelSpec> {
    (
        1_000_000u64..=MAX_MONEY,
        vec((0..ADDR_POOL, 0..ADDR_POOL, 1u64..=220), 2..=8),
        prop_oneof![1 => Just(0u64), 3 => 1u64..=50],
        any::<bool>(),
    )
        .prop_map(|(start, hops, fee_rate, round)| PeelSpec {
            start,
            hops,
            fee_rate,
            round,
        })
}

// An external tx with 10-14 outputs to distinct addresses outside the pool
// (or, with `diversity_80`, 10 outputs whose last two repeat the first two,
// a diversity of exactly 0.8): the first `dust` are strict dust to us, the
// next one optionally dust-class (547-1000 sats) to us; the first `unspent`
// strict ones and, unless `class_spent`, the dust-class one are still UTXOs.
#[derive(Debug, Clone)]
struct DustAttackSpec {
    outputs: usize,
    diversity_80: bool,
    dust: usize,
    dust_sats: u64,
    class_sats: Option<u64>,
    class_spent: bool,
    unspent: usize,
}

fn dust_attack() -> impl Strategy<Value = DustAttackSpec> {
    (
        (10usize..=14, prop::bool::weighted(0.3)),
        5usize..=10,
        1u64..=546,
        prop::option::weighted(0.7, 547u64..=1_000),
        any::<bool>(),
        prop_oneof![1 => Just(0usize), 3 => 1usize..=10],
    )
        .prop_map(
            |((outputs, diversity_80), dust, dust_sats, class_sats, class_spent, unspent)| {
                DustAttackSpec {
                    outputs: if diversity_80 { 10 } else { outputs },
                    diversity_80,
                    dust,
                    dust_sats,
                    class_sats,
                    class_spent,
                    unspent,
                }
            },
        )
}

// An external batch paying 5-8 outputs to 1-6 pool addresses, the first
// ours; sometimes all outputs but the first are zero, so the median is 0.
// Few addresses keep the unique-recipient signal off, so the large input
// (input/median ratio) or the exchange tag decide the finding.
#[derive(Debug, Clone)]
struct ExchangeBatchSpec {
    addrs: Vec<usize>,
    outputs: Vec<u64>,
    // 0: unresolved input, 1: input funding the outputs exactly, 2: one large
    // input, 3: an input of exactly 10x the median output (the ratio cutoff).
    funding: u8,
    tagged: bool,
    // Pays only addresses outside the pool and is labelled a send: neither side ours.
    foreign: bool,
}

fn exchange_batch() -> impl Strategy<Value = ExchangeBatchSpec> {
    (
        prop_oneof![
            3 => subsequence((0..ADDR_POOL).collect::<Vec<_>>(), 1..=4),
            1 => subsequence((0..ADDR_POOL).collect::<Vec<_>>(), 5..=6),
        ],
        prop_oneof![
            3 => vec(100_000u64..=10_000_000, 5..=8),
            1 => (100_000u64..=10_000_000, 4usize..=7).prop_map(|(first, zeros)| {
                let mut outputs = vec![first];
                outputs.resize(zeros + 1, 0);
                outputs
            }),
        ],
        0u8..4,
        any::<bool>(),
        prop::bool::weighted(0.2),
    )
        .prop_map(
            |(addrs, outputs, funding, tagged, foreign)| ExchangeBatchSpec {
                addrs,
                outputs,
                funding,
                tagged,
                foreign,
            },
        )
}

// 3-6 sends whose behavioural patterns are each either present or actively
// avoided: round payments, uniform output count, mixed input script types,
// RBF (always or never), locktime (always set or always 0), fee rate.
// An isolated spec is the whole wallet, so a single pattern decides.
#[derive(Debug, Clone)]
struct FingerprintSpec {
    sends: usize,
    on: [bool; 6],
    // Exactly 3 of 5 payments round: 60%, right at the cutoff.
    round_60: bool,
    rbf_never: bool,
    locktime_zero: bool,
    isolated: bool,
}

fn fingerprint() -> impl Strategy<Value = FingerprintSpec> {
    let focused = (0usize..7, any::<bool>(), any::<bool>(), 3usize..=6).prop_map(
        |(focus, rbf_never, locktime_zero, sends)| {
            let mut on = [false; 6];
            let round_60 = focus == 6;
            if round_60 {
                on[1] = true;
            } else {
                on[focus] = true;
            }
            FingerprintSpec {
                sends: if round_60 { 5 } else { sends },
                on,
                round_60,
                rbf_never,
                locktime_zero,
                isolated: true,
            }
        },
    );
    let mixed = (any::<[bool; 6]>(), any::<bool>(), any::<bool>(), 3usize..=6).prop_map(
        |(on, rbf_never, locktime_zero, sends)| FingerprintSpec {
            sends,
            on,
            round_60: false,
            rbf_never,
            locktime_zero,
            isolated: false,
        },
    );
    prop_oneof![3 => focused, 2 => mixed]
}

fn add_fingerprint(
    f: &FingerprintSpec,
    transactions: &mut HashMap<Txid, DecodedTransaction>,
    wallet_txs: &mut Vec<WalletTxEntry>,
    derived: &mut HashSet<Address<NetworkUnchecked>>,
) {
    let [round, uniform, mixed, rbf, locktime, fee] = f.on;
    const FEE_RATES: [u64; 6] = [1, 20, 80, 3, 50, 7];
    for (i, &varying_rate) in FEE_RATES.iter().enumerate().take(f.sends) {
        let k = i as u8;
        let funding = txid(FINGERPRINT_SLOT + k);
        let id = txid(FINGERPRINT_SLOT + 10 + k);
        let owner = address(if mixed && i % 2 == 1 { 4 } else { 0 }, 210 + k, false);
        let change = address(0, 220 + k, false);
        derived.extend([owner.clone(), change.clone()]);
        let input = 50_000_000;
        transactions.insert(
            funding,
            plain_tx(funding, Vec::new(), vec![pay(0, &owner, input)]),
        );
        let is_round = round || (f.round_60 && i < 3);
        let payment = 1_000_000 * (i as u64 + 1) + if is_round { 0 } else { 1_234 };
        let mut vout = vec![pay(0, &address(0, 230 + k, false), payment)];
        if !uniform && i % 2 == 1 {
            vout.push(pay(1, &address(0, 240 + k, false), payment));
        }
        let rate = if fee { 10 } else { varying_rate };
        let paid: u64 = vout.iter().map(|o| o.value.to_sat()).sum();
        let n = vout.len() as u32;
        vout.push(pay(n, &change, input - paid - rate * 150));
        let sequence = match (rbf, f.rbf_never) {
            (true, true) => u32::MAX,
            (true, false) => 0xffff_fffd,
            (false, _) if i % 2 == 0 => u32::MAX,
            (false, _) => 0xffff_fffd,
        };
        let mut tx = plain_tx(id, vec![spend(funding, 0)], vout);
        tx.vin[0].sequence = sequence;
        tx.locktime = match (locktime, f.locktime_zero) {
            (true, true) => 0,
            (true, false) => 800_000 + i as u32,
            (false, _) if i % 2 == 0 => 0,
            (false, _) => 800_000,
        };
        transactions.insert(id, tx);
        wallet_txs.push(entry(id, WalletTxCategory::Send, None));
    }
}

// 1-8 sends of ours, each with funded inputs and values from a small set so
// the input-to-output mapping is often ambiguous: mostly 4x4 with some zero
// outputs (assignments need not be permutations), else 4x2-3 or 2-3 wide.
#[derive(Debug, Clone)]
struct LinkSpec {
    txs: Vec<(Vec<u64>, Vec<u64>)>,
}

fn link() -> impl Strategy<Value = LinkSpec> {
    // Mostly 100k multiples, sometimes dust or the band just above it.
    let value = || {
        prop_oneof![
            6 => prop::sample::select(vec![1u64, 2, 3, 4, 6]).prop_map(|v| v * 100_000),
            1 => 1u64..=1_000,
            1 => 1_001u64..=10_000,
        ]
    };
    let maybe_zero = move || prop_oneof![Just(0u64), value()];
    let tx = prop_oneof![
        3 => (vec(value(), 4..=4), vec(maybe_zero(), 4..=4)),
        1 => (vec(value(), 4..=4), vec(value(), 2..=3)),
        1 => (vec(value(), 2..=3), vec(value(), 2..=3)),
    ];
    vec(tx, 1..=8).prop_map(|txs| LinkSpec { txs })
}

fn add_link(
    l: &LinkSpec,
    transactions: &mut HashMap<Txid, DecodedTransaction>,
    wallet_txs: &mut Vec<WalletTxEntry>,
    derived: &mut HashSet<Address<NetworkUnchecked>>,
) {
    for (k, (inputs, outputs)) in l.txs.iter().enumerate() {
        let base = LINK_SLOT + 5 * k as u8;
        let mut vin = Vec::new();
        for (i, &v) in inputs.iter().enumerate() {
            let funding = txid(base + i as u8);
            let owner = address(0, 250 + i as u8, false);
            derived.insert(owner.clone());
            transactions.insert(
                funding,
                plain_tx(funding, Vec::new(), vec![pay(0, &owner, v)]),
            );
            vin.push(spend(funding, 0));
        }
        let vout = outputs
            .iter()
            .enumerate()
            .map(|(j, &v)| pay(j as u32, &address(0, 245 + j as u8, false), v))
            .collect();
        let id = txid(base + 4);
        transactions.insert(id, plain_tx(id, vin, vout));
        wallet_txs.push(entry(id, WalletTxCategory::Send, None));
    }
}

// Amounts sitting exactly on the equalities that decide findings: an input
// equal to payment + fee (unnecessary input), and toxic change of exactly
// 546 or 10,000 sats later merged with a 10,001-sat input, the only one
// above the toxic band.
#[derive(Debug, Clone)]
struct ExactSpec {
    toxic_low: bool,
}

fn exact() -> impl Strategy<Value = ExactSpec> {
    any::<bool>().prop_map(|toxic_low| ExactSpec { toxic_low })
}

fn add_exact(
    x: &ExactSpec,
    transactions: &mut HashMap<Txid, DecodedTransaction>,
    wallet_txs: &mut Vec<WalletTxEntry>,
    derived: &mut HashSet<Address<NetworkUnchecked>>,
) {
    let ours: Vec<_> = (150u8..157).map(|seed| address(1, seed, false)).collect();
    derived.extend(ours.iter().cloned());
    let external = |seed: u8| address(1, seed, false);
    let mut fund = |slot: u8, owner: &Address<NetworkUnchecked>, sats: u64| {
        let id = txid(EXACT_SLOT + slot);
        transactions.insert(id, plain_tx(id, Vec::new(), vec![pay(0, owner, sats)]));
        spend(id, 0)
    };
    let (a, b) = (fund(0, &ours[0], 501_000), fund(1, &ours[1], 300_000));
    let toxic = if x.toxic_low { 546 } else { 10_000 };
    let t1_in = fund(3, &ours[3], 1_000_000);
    let big = fund(5, &ours[5], 10_001);
    let mut send = |slot: u8, vin: Vec<TxInputRef>, vout: Vec<TxOutput>| {
        let id = txid(EXACT_SLOT + slot);
        transactions.insert(id, plain_tx(id, vin, vout));
        wallet_txs.push(entry(id, WalletTxCategory::Send, None));
        id
    };
    // Fee 1,000; payment + fee = 501,000, exactly the first input.
    send(
        2,
        vec![a, b],
        vec![pay(0, &external(160), 500_000), pay(1, &ours[2], 300_000)],
    );
    let t1 = send(
        4,
        vec![t1_in],
        vec![
            pay(0, &external(161), 1_000_000 - toxic - 1_000),
            pay(1, &ours[4], toxic),
        ],
    );
    send(
        6,
        vec![spend(t1, 1), big],
        vec![pay(0, &external(162), toxic + 10_001 - 500)],
    );
}

fn plain_tx(id: Txid, vin: Vec<TxInputRef>, vout: Vec<TxOutput>) -> DecodedTransaction {
    DecodedTransaction {
        txid: id,
        vin,
        vout,
        version: 2,
        locktime: 0,
        vsize: 150,
        confirmations: 10,
    }
}

fn spend(id: Txid, vout: u32) -> TxInputRef {
    TxInputRef {
        previous_txid: id,
        previous_vout: vout,
        sequence: 0xffff_fffd,
        coinbase: false,
    }
}

fn pay(n: u32, address: &Address<NetworkUnchecked>, sats: u64) -> TxOutput {
    TxOutput {
        n,
        address: Some(address.clone()),
        value: Amount::from_sat(sats),
        script_type: DescriptorType::infer_from_address(address),
    }
}

fn entry(
    id: Txid,
    category: WalletTxCategory,
    address: Option<&Address<NetworkUnchecked>>,
) -> WalletTxEntry {
    WalletTxEntry {
        txid: id,
        address: address.cloned(),
        category,
        amount: Amount::ZERO,
        confirmations: 10,
        blockheight: 100,
    }
}

fn scenario() -> impl Strategy<Value = Scenario> {
    let pool = vec((any::<u8>(), 0u8..8, prop::bool::weighted(0.1)), ADDR_POOL).prop_map(|specs| {
        specs
            .into_iter()
            .map(|(kind, seed, mainnet)| address(kind, seed, mainnet))
            .collect::<Vec<_>>()
    });
    let utxo = (
        txid_slot(),
        prop_oneof![0u32..6, any::<u32>()],
        addr_idx(),
        amount(),
        confirmations(),
        script_type(),
    );
    (
        pool,
        vec(transaction(), 0..=TX_SLOTS as usize),
        vec((txid_slot(), wallet_entry()), 0..6),
        vec(utxo, 0..12),
        hash_set(0..ADDR_POOL, 0..ADDR_POOL),
        hash_set(0..ADDR_POOL, 0..4),
        prop::option::of(hash_set(tagged_slot(), 0..5)),
        prop::option::of(hash_set(tagged_slot(), 0..5)),
        prop::option::weighted(0.25, peel()),
        (
            prop::option::weighted(0.15, dust_attack()),
            prop::option::weighted(0.25, exchange_batch()),
            prop::option::weighted(0.3, fingerprint()),
            prop::option::weighted(0.4, link()),
            prop::option::weighted(0.3, exact()),
        ),
        (
            prop::option::weighted(0.3, sequence()),
            prop::option::weighted(0.3, locktime()),
            prop::option::weighted(
                0.2,
                (
                    prop_oneof![Just(0u32), Just(89u32), Just(90u32), 0u32..1_000],
                    prop_oneof![Just(9u32), Just(10u32)],
                ),
            ),
        ),
    )
        .prop_map(
            |(
                pool,
                txs,
                wallet_txs,
                utxos,
                derived,
                internal,
                risky,
                exchange,
                peel,
                (dust_attack, exchange_batch, fingerprint, link, exact),
                style,
            )| Scenario {
                pool,
                txs,
                wallet_txs,
                utxos,
                derived,
                internal,
                risky,
                exchange,
                peel,
                dust_attack,
                exchange_batch,
                fingerprint,
                link,
                exact,
                style,
            },
        )
}

fn wallet_tx(id: Txid, e: &WalletEntrySpec, pool: &[Address<NetworkUnchecked>]) -> WalletTxEntry {
    let &(category, a, amount, confirmations, blockheight) = e;
    WalletTxEntry {
        txid: id,
        address: a.map(|i| pool[i].clone()),
        category,
        amount,
        confirmations,
        blockheight,
    }
}

fn build(s: &Scenario) -> WalletHistory {
    if let Some(f) = s.fingerprint.as_ref().filter(|f| f.isolated) {
        let mut history = WalletHistory {
            wallet_txs: Vec::new(),
            utxos: Vec::new(),
            transactions: HashMap::new(),
            internal_addresses: HashSet::new(),
            derived_addresses: HashSet::new(),
            ranged_addresses: HashSet::new(),
        };
        add_fingerprint(
            f,
            &mut history.transactions,
            &mut history.wallet_txs,
            &mut history.derived_addresses,
        );
        return history;
    }
    let addr = |i: Option<usize>| i.map(|i| s.pool[i].clone());
    let phantom = |n: u8| txid(TX_SLOTS + n % (TXID_SPACE - TX_SLOTS));
    let mut transactions = HashMap::new();
    let mut wallet_txs = Vec::new();
    // Key and outputs of every transaction built so far, in order.
    let mut made: Vec<(Txid, Vec<TxOutput>)> = Vec::new();
    for (k, t) in s.txs.iter().enumerate() {
        let key = txid(t.dup_slot.unwrap_or(k as u8));
        let vin = t
            .inputs
            .iter()
            .map(|i| {
                let (previous_txid, previous_vout) = match i.prev {
                    Prev::Anywhere { slot, vout } => (txid(slot), vout),
                    Prev::Earlier {
                        parent,
                        pick,
                        largest,
                    } => {
                        let parent = made
                            .get(usize::from(parent).min(k.saturating_sub(1)))
                            .filter(|(_, outs)| !outs.is_empty());
                        match parent {
                            Some((id, outs)) => {
                                let out = if largest {
                                    outs.iter().max_by_key(|o| o.value)
                                } else {
                                    outs.get(pick as usize % outs.len())
                                };
                                (*id, out.map_or(0, |o| o.n))
                            }
                            None => (phantom(pick), pick as u32),
                        }
                    }
                };
                TxInputRef {
                    previous_txid,
                    previous_vout,
                    sequence: i.sequence,
                    coinbase: i.coinbase,
                }
            })
            .collect();
        let vout: Vec<TxOutput> = t
            .outputs
            .iter()
            .enumerate()
            .map(|(pos, o)| TxOutput {
                n: o.n.unwrap_or(pos as u32),
                address: addr(o.addr),
                value: t.uniform.unwrap_or(o.value),
                script_type: o.script_type,
            })
            .collect();
        if let Some(e) = &t.wallet {
            wallet_txs.push(wallet_tx(key, e, &s.pool));
        }
        made.push((key, vout.clone()));
        // A duplicate slot overwrites the earlier transaction under that txid.
        transactions.insert(
            key,
            DecodedTransaction {
                txid: t.inner_slot.map_or(key, txid),
                vin,
                vout,
                version: t.version,
                locktime: t.locktime,
                vsize: t.vsize,
                confirmations: t.confirmations,
            },
        );
    }
    wallet_txs.extend(
        s.wallet_txs
            .iter()
            .map(|(slot, e)| wallet_tx(txid(*slot), e, &s.pool)),
    );
    let mut derived: HashSet<Address<NetworkUnchecked>> =
        s.derived.iter().map(|&i| s.pool[i].clone()).collect();
    if let Some(p) = &s.peel {
        let funding = txid(PEEL_SLOT);
        let mut owner = &s.pool[p.hops[0].0];
        transactions.insert(
            funding,
            plain_tx(
                funding,
                vec![spend(txid(DUST_SLOT + 1), 0)],
                vec![pay(0, owner, p.start)],
            ),
        );
        wallet_txs.push(entry(funding, WalletTxCategory::Receive, Some(owner)));
        derived.insert(owner.clone());
        let (mut parent, mut parent_vout, mut value) = (funding, 0, p.start);
        for (i, &(change, payee, permille)) in p.hops.iter().enumerate() {
            let id = txid(PEEL_SLOT + 1 + i as u8);
            let mut payment = value / 1_000 * permille;
            if p.round {
                payment -= payment % 100_000;
            }
            let fee = (p.fee_rate * 150).min(value / 100);
            value -= payment + fee;
            owner = &s.pool[change];
            derived.insert(owner.clone());
            transactions.insert(
                id,
                plain_tx(
                    id,
                    vec![spend(parent, parent_vout)],
                    vec![pay(0, &s.pool[payee], payment), pay(1, owner, value)],
                ),
            );
            wallet_txs.push(entry(id, WalletTxCategory::Send, None));
            (parent, parent_vout) = (id, 1);
        }
    }
    let mut utxos: Vec<Utxo> = s
        .utxos
        .iter()
        .map(
            |&(slot, vout, a, amount, confirmations, script_type)| Utxo {
                txid: txid(slot),
                vout,
                address: addr(a),
                amount,
                confirmations,
                script_type,
            },
        )
        .collect();
    if let Some(d) = &s.dust_attack {
        let id = txid(DUST_SLOT);
        let mut vout = Vec::new();
        let recipient = |n: usize| {
            let n = if d.diversity_80 && n >= 8 { n - 8 } else { n };
            address(n as u8 % 5, 100 + n as u8, false)
        };
        for n in 0..d.outputs {
            let address = &recipient(n);
            let (value, ours) = match (n.cmp(&d.dust), d.class_sats) {
                (std::cmp::Ordering::Less, _) => (d.dust_sats, true),
                (std::cmp::Ordering::Equal, Some(class)) => (class, true),
                _ => (5_000_000, false),
            };
            if ours {
                derived.insert(address.clone());
                if n < d.unspent.min(d.dust) || (n == d.dust && !d.class_spent) {
                    utxos.push(Utxo {
                        txid: txid(DUST_SLOT),
                        vout: n as u32,
                        address: Some(address.clone()),
                        amount: Amount::from_sat(value),
                        confirmations: 10,
                        script_type: DescriptorType::infer_from_address(address),
                    });
                }
            }
            vout.push(pay(n as u32, address, value));
        }
        // Funded by an address outside the pool, so the input resolves and is not ours.
        let funding = txid(DUST_SLOT + 2);
        let sender = address(0, 200, false);
        transactions.insert(
            funding,
            plain_tx(funding, Vec::new(), vec![pay(0, &sender, 1_000_000_000)]),
        );
        transactions.insert(id, plain_tx(id, vec![spend(funding, 0)], vout));
        wallet_txs.push(entry(id, WalletTxCategory::Receive, Some(&recipient(0))));
    }
    if let Some(e) = &s.exchange_batch {
        let id = txid(EXCHANGE_SLOT);
        let vout: Vec<TxOutput> = e
            .outputs
            .iter()
            .enumerate()
            .map(|(n, &v)| {
                let payee = if e.foreign {
                    address(0, 190 + (n % e.addrs.len()) as u8, false)
                } else {
                    s.pool[e.addrs[n % e.addrs.len()]].clone()
                };
                pay(n as u32, &payee, v)
            })
            .collect();
        let total: u64 = e.outputs.iter().sum();
        let vin = match e.funding {
            0 => vec![spend(txid(EXCHANGE_SLOT + 2), 0)],
            n => {
                let funding = txid(EXCHANGE_SLOT + 1);
                let mut sorted = e.outputs.clone();
                sorted.sort_unstable();
                let value = match n {
                    1 => total + 1_000,
                    2 => total * 100,
                    _ => 10 * sorted[sorted.len() / 2],
                };
                let sender = address(0, 201, false);
                transactions.insert(
                    funding,
                    plain_tx(funding, Vec::new(), vec![pay(0, &sender, value)]),
                );
                vec![spend(funding, 0)]
            }
        };
        transactions.insert(id, plain_tx(id, vin, vout));
        if e.foreign {
            wallet_txs.push(entry(id, WalletTxCategory::Send, None));
        } else {
            let ours = &s.pool[e.addrs[0]];
            derived.insert(ours.clone());
            wallet_txs.push(entry(id, WalletTxCategory::Receive, Some(ours)));
        }
    }
    if let Some(f) = &s.fingerprint {
        add_fingerprint(f, &mut transactions, &mut wallet_txs, &mut derived);
    }
    if let Some(l) = &s.link {
        add_link(l, &mut transactions, &mut wallet_txs, &mut derived);
    }
    if let Some(x) = &s.exact {
        add_exact(x, &mut transactions, &mut wallet_txs, &mut derived);
    }
    for tx in transactions.values_mut() {
        if let Some(sequence) = s.style.0 {
            tx.vin.iter_mut().for_each(|i| i.sequence = sequence);
        }
        if let Some(locktime) = s.style.1 {
            tx.locktime = locktime;
        }
    }
    if let Some((base, offset)) = s.style.2 {
        for u in &mut utxos {
            u.confirmations = base + if u.confirmations % 2 == 0 { 0 } else { offset };
        }
    }
    WalletHistory {
        wallet_txs,
        utxos,
        transactions,
        internal_addresses: s.internal.iter().map(|&i| s.pool[i].clone()).collect(),
        ranged_addresses: derived.clone(),
        derived_addresses: derived,
    }
}

fn thresholds() -> impl Strategy<Value = DetectorThresholds> {
    let ratio = || prop_oneof![Just(0.0f64), Just(f64::NAN), Just(-1.0f64), 0.0f64..2.0];
    let small = || prop_oneof![Just(0usize), 1usize..12];
    (
        (amount(), amount(), amount(), amount(), amount()),
        (small(), small(), small(), small(), small()),
        (any::<u32>(), any::<u32>(), ratio(), ratio(), ratio()),
        // Bounded: the peel-chain walk runs up to `max_hops` steps.
        (
            0u32..64,
            prop_oneof![4 => 0u32..10, 1 => any::<u32>()],
            prop_oneof![4 => 0u32..10, 1 => any::<u32>()],
        ),
    )
        .prop_map(
            |(
                (dust, strict_dust, normal_input_min, toxic_change_lower, toxic_change_upper),
                (
                    consolidation_min_inputs,
                    consolidation_max_outputs,
                    exchange_batch_min_outputs,
                    dust_attack_min_outputs,
                    dust_attack_min_dust_outputs,
                ),
                (
                    utxo_age_spread_blocks,
                    dormant_utxo_blocks,
                    dust_attack_diversity,
                    peel_chain_ratio,
                    low_ambiguity_cutoff,
                ),
                (peel_chain_max_hops, peel_chain_min_hops, peel_chain_critical_hops),
            )| DetectorThresholds {
                dust,
                strict_dust,
                normal_input_min,
                consolidation_min_inputs,
                consolidation_max_outputs,
                utxo_age_spread_blocks,
                dormant_utxo_blocks,
                exchange_batch_min_outputs,
                dust_attack_min_outputs,
                dust_attack_min_dust_outputs,
                dust_attack_diversity,
                toxic_change_lower,
                toxic_change_upper,
                peel_chain_max_hops,
                peel_chain_min_hops,
                peel_chain_critical_hops,
                peel_chain_ratio,
                low_ambiguity_cutoff,
            },
        )
}

fn scan(s: &Scenario, thresholds: &DetectorThresholds) -> Report {
    let slots = |set: &Option<HashSet<u8>>| {
        set.as_ref()
            .map(|set| set.iter().map(|&n| txid(n)).collect::<HashSet<_>>())
    };
    let risky = slots(&s.risky);
    let mut exchange = slots(&s.exchange);
    if s.exchange_batch.as_ref().is_some_and(|e| e.tagged) {
        exchange
            .get_or_insert_with(HashSet::new)
            .insert(txid(EXCHANGE_SLOT));
    }
    TxGraph::from_wallet_history(build(s)).detect_all(thresholds, risky.as_ref(), exchange.as_ref())
}

fn assert_described(report: &Report) -> Result<(), TestCaseError> {
    for f in report.findings.iter().chain(&report.warnings) {
        prop_assert!(
            !f.description.trim().is_empty(),
            "{} has an empty description",
            f.vulnerability_type
        );
    }
    Ok(())
}

// ─── properties ─────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn detect_all_never_panics_on_any_history(s in scenario()) {
        let report = scan(&s, &DetectorThresholds::default());
        assert_described(&report)?;
    }

    #[test]
    fn detect_all_never_panics_with_degenerate_thresholds(
        s in scenario(),
        thresholds in thresholds(),
    ) {
        let report = scan(&s, &thresholds);
        assert_described(&report)?;
    }
}

#[test]
fn empty_history_yields_an_empty_report() {
    let history = WalletHistory {
        wallet_txs: Vec::new(),
        utxos: Vec::new(),
        transactions: HashMap::new(),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
        ranged_addresses: HashSet::new(),
    };
    let report = TxGraph::from_wallet_history(history).detect_all(
        &DetectorThresholds::default(),
        None,
        None,
    );
    assert!(report.findings.is_empty() && report.warnings.is_empty());
    assert!(report.summary.analyzed_nothing);
}
