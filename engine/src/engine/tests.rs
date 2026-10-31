//! Unit tests for the analysis engine, against an in-memory gateway.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, OutPoint, Txid};

use crate::engine::{merge_chain_history, AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};
use crate::error::AnalysisError;
use crate::gateway::{
    BlockchainGateway, DecodedTransaction, DescriptorType, ResolvedDescriptor, TxFetchResults,
    TxInputRef, TxOutput, Utxo, UtxoSetResults, WalletHistory, WalletTxCategory, WalletTxEntry,
};
use crate::types::VulnerabilityType;

const ADDR: &str = "bcrt1q8ns65y2arcy6yh7wgjquhs04h4d0p66laks2hk";

fn addr() -> Address<NetworkUnchecked> {
    ADDR.parse().expect("address")
}

fn txid(n: u32) -> Txid {
    format!("{n:064x}").parse().expect("txid")
}

fn payment(n: u32) -> DecodedTransaction {
    DecodedTransaction {
        txid: txid(n),
        vin: vec![TxInputRef {
            previous_txid: txid(1000 + n),
            previous_vout: 0,
            sequence: 0xffff_ffff,
            coinbase: false,
        }],
        vout: vec![TxOutput {
            n: 0,
            address: Some(addr()),
            value: Amount::from_sat(50_000),
            script_type: DescriptorType::P2wpkh,
        }],
        version: 2,
        locktime: 0,
        vsize: 110,
        confirmations: 10,
    }
}

fn receive(n: u32) -> WalletTxEntry {
    WalletTxEntry {
        txid: txid(n),
        address: Some(addr()),
        category: WalletTxCategory::Receive,
        amount: Amount::from_sat(50_000),
        confirmations: 10,
        blockheight: 100 + n,
    }
}

fn unspent(n: u32) -> Utxo {
    Utxo {
        txid: txid(n),
        vout: 0,
        address: Some(addr()),
        amount: Amount::from_sat(50_000),
        confirmations: 10,
        script_type: DescriptorType::P2wpkh,
    }
}

/// What the node knows about the address: `payments` transactions paid it,
/// `still_unspent` of them are unspent.
fn chain_history(payments: u32, still_unspent: u32) -> WalletHistory {
    WalletHistory {
        wallet_txs: (1..=payments).map(receive).collect(),
        utxos: (1..=still_unspent).map(unspent).collect(),
        transactions: (1..=payments).map(|n| (txid(n), payment(n))).collect(),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([addr()]),
        ranged_addresses: HashSet::new(),
    }
}

fn pasted() -> UtxoInput {
    UtxoInput {
        txid: txid(1),
        vout: 0,
        value: None,
        address: None,
    }
}

struct FakeGateway {
    transactions: HashMap<Txid, DecodedTransaction>,
    broken: HashSet<Txid>,
    normalize_error: Option<AnalysisError>,
    txindex: Result<bool, AnalysisError>,
    history: Result<WalletHistory, AnalysisError>,
    scanned: RefCell<Vec<String>>,
    persisted: RefCell<Vec<bool>>,
    unspent: Result<HashSet<OutPoint>, String>,
    failing: HashSet<OutPoint>,
    asked: RefCell<Vec<OutPoint>>,
    batches: RefCell<Vec<Vec<Txid>>>,
    vanished: HashSet<Txid>,
    fail_batches: bool,
    calls: RefCell<Vec<&'static str>>,
}

impl FakeGateway {
    fn new(history: Result<WalletHistory, AnalysisError>) -> Self {
        Self {
            transactions: HashMap::from([(txid(1), payment(1))]),
            broken: HashSet::new(),
            normalize_error: None,
            txindex: Ok(false),
            history,
            scanned: RefCell::new(Vec::new()),
            persisted: RefCell::new(Vec::new()),
            unspent: Ok(HashSet::new()),
            failing: HashSet::new(),
            asked: RefCell::new(Vec::new()),
            batches: RefCell::new(Vec::new()),
            vanished: HashSet::new(),
            fail_batches: false,
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl BlockchainGateway for FakeGateway {
    fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError> {
        match &self.normalize_error {
            Some(error) => Err(error.clone()),
            None => Ok(descriptor.to_owned()),
        }
    }

    fn derive_addresses(
        &self,
        _: &ResolvedDescriptor,
    ) -> Result<Vec<Address<NetworkUnchecked>>, AnalysisError> {
        Ok(vec![addr()])
    }

    fn scan_descriptors(
        &self,
        descriptors: &[ResolvedDescriptor],
        persist: bool,
    ) -> Result<WalletHistory, AnalysisError> {
        self.persisted.borrow_mut().push(persist);
        self.scanned
            .borrow_mut()
            .extend(descriptors.iter().map(|d| d.desc.clone()));
        self.history.clone()
    }

    fn list_wallet_descriptors(&self, _: &str) -> Result<Vec<ResolvedDescriptor>, AnalysisError> {
        Ok(Vec::new())
    }

    fn scan_wallet(&self, _: &str) -> Result<WalletHistory, AnalysisError> {
        Err(AnalysisError::EnvironmentUnavailable("not used".into()))
    }

    fn known_wallet_txids(&self, _: &[String]) -> Result<HashSet<Txid>, AnalysisError> {
        Ok(HashSet::new())
    }

    fn txindex_synced(&self) -> Result<bool, AnalysisError> {
        self.txindex.clone()
    }

    fn get_transaction(&self, txid: Txid) -> Result<DecodedTransaction, AnalysisError> {
        if self.broken.contains(&txid) {
            return Err(AnalysisError::EnvironmentUnavailable(format!("bad {txid}")));
        }
        if self.vanished.contains(&txid) {
            return Err(AnalysisError::EnvironmentUnavailable(format!(
                "gone {txid}"
            )));
        }
        self.transactions
            .get(&txid)
            .cloned()
            .ok_or_else(|| AnalysisError::TransactionNotFound(format!("unknown {txid}")))
    }

    fn get_transactions(&self, txids: &[Txid]) -> Result<TxFetchResults, AnalysisError> {
        self.batches.borrow_mut().push(txids.to_vec());
        self.calls.borrow_mut().push("getrawtransaction");
        if self.fail_batches {
            return Err(AnalysisError::EnvironmentUnavailable(
                "getrawtransaction: timeout".into(),
            ));
        }
        // As the trait's default: only a tx the node cannot find stays per tx.
        txids
            .iter()
            .map(|&txid| match self.get_transaction(txid) {
                Err(error @ AnalysisError::TransactionNotFound(_)) => Ok((txid, Err(error))),
                fetched => Ok((txid, Ok(fetched?))),
            })
            .collect()
    }

    fn outputs_in_utxo_set(&self, outpoints: &[OutPoint]) -> Result<UtxoSetResults, AnalysisError> {
        self.asked.borrow_mut().extend_from_slice(outpoints);
        self.calls.borrow_mut().push("gettxout");
        let unspent = self
            .unspent
            .clone()
            .map_err(AnalysisError::EnvironmentUnavailable)?;
        Ok(outpoints
            .iter()
            .map(|op| {
                if self.failing.contains(op) {
                    (
                        *op,
                        Err(AnalysisError::EnvironmentUnavailable(
                            "gettxout: busy".into(),
                        )),
                    )
                } else {
                    (*op, Ok(unspent.contains(op)))
                }
            })
            .collect())
    }
}

fn scan(gateway: &FakeGateway) -> crate::types::Report {
    AnalysisEngine::new(gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted()]))
        .expect("utxo scan")
}

fn address_reuse(report: &crate::types::Report) -> Option<&crate::types::Finding> {
    report
        .findings
        .iter()
        .find(|f| f.vulnerability_type == VulnerabilityType::AddressReuse)
}

#[test]
fn a_pasted_output_counts_its_address_reuse_from_the_chain() {
    let gateway = FakeGateway::new(Ok(chain_history(12, 1)));
    let report = scan(&gateway);
    let reuse = address_reuse(&report).expect("address reuse finding");
    assert!(
        reuse.description.contains("reused across 12 transactions"),
        "{}",
        reuse.description
    );
    assert_eq!(report.stats.addresses_without_history, 0);
}

#[test]
fn the_address_history_comes_through_the_single_address_scan_path() {
    let gateway = FakeGateway::new(Ok(chain_history(12, 1)));
    scan(&gateway);
    assert_eq!(
        gateway.scanned.borrow().as_slice(),
        [format!("addr({ADDR})")]
    );
}

#[test]
fn an_address_whose_history_the_node_cannot_serve_is_counted_not_fatal() {
    let gateway = FakeGateway::new(Err(AnalysisError::HistoryUnavailable(
        "Method not found".into(),
    )));
    let report = scan(&gateway);
    assert_eq!(report.stats.addresses_without_history, 1);
    assert!(address_reuse(&report).is_none());
    assert_eq!(report.stats.transactions_analyzed, 1);
}

#[test]
fn the_utxo_set_stays_what_was_pasted() {
    let gateway = FakeGateway::new(Ok(chain_history(12, 5)));
    let report = scan(&gateway);
    assert_eq!(report.stats.utxos_current, 1);
}

#[test]
fn the_node_entry_replaces_the_pasted_one_instead_of_doubling_it() {
    let mut history = chain_history(1, 1);
    merge_chain_history(&mut history, chain_history(12, 1));
    assert_eq!(history.wallet_txs.len(), 12);
    assert_eq!(history.transactions.len(), 12);
}

#[test]
fn a_pasted_output_the_node_did_not_return_is_kept() {
    let mut history = chain_history(1, 1);
    merge_chain_history(&mut history, chain_history(0, 0));
    assert_eq!(history.wallet_txs.len(), 1);
}

#[test]
fn an_output_missing_from_the_node_history_is_still_analyzed() {
    let gateway = FakeGateway::new(Ok(chain_history(0, 0)));
    let report = scan(&gateway);
    assert_eq!(report.stats.transactions_analyzed, 1);
    assert!(!report.summary.analyzed_nothing);
}

#[test]
fn utxo_mode_never_keeps_a_cache_wallet_for_its_addresses() {
    let gateway = FakeGateway::new(Ok(chain_history(3, 1)));
    let settings = EngineSettings {
        persist_scan_wallet: true,
        ..EngineSettings::default()
    };
    AnalysisEngine::new(&gateway, settings)
        .analyze(ScanTarget::Utxos(vec![pasted()]))
        .expect("utxo scan");
    assert_eq!(gateway.persisted.borrow().as_slice(), [false]);
}

#[test]
fn an_ancestor_the_node_cannot_find_is_skipped() {
    let gateway = FakeGateway::new(Ok(chain_history(1, 1)));
    let fetched = gateway.get_transactions(&[txid(1001)]).expect("lookup");
    assert!(matches!(
        fetched[0].1,
        Err(AnalysisError::TransactionNotFound(_))
    ));
    scan(&gateway);
}

#[test]
fn an_ancestor_with_invalid_data_fails_the_scan() {
    let mut gateway = FakeGateway::new(Ok(chain_history(1, 1)));
    gateway.broken.insert(txid(1001));
    let result = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted()]));
    assert!(result.is_err());
}

#[test]
fn invalid_data_in_the_address_history_fails_the_scan() {
    let bad = AnalysisError::EnvironmentUnavailable("invalid amount -1 BTC in listunspent".into());
    let gateway = FakeGateway::new(Err(bad.clone()));
    let result = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted()]));
    assert_eq!(result.err(), Some(bad));
}

#[test]
fn a_pasted_output_the_node_cannot_find_is_named_in_the_error() {
    let gateway = FakeGateway::new(Ok(chain_history(1, 1)));
    let missing = UtxoInput {
        txid: txid(7),
        vout: 3,
        value: None,
        address: None,
    };
    let error = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![missing]))
        .expect_err("an unknown pasted output must fail the scan");
    assert!(
        matches!(error, AnalysisError::TransactionNotFound(_)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains(&format!("{}:3", txid(7))),
        "{error}"
    );
}

// ─── dust outside the pasted outputs ────────────────────────────────────────

const DUST_PARENT: u32 = 77;
const DUST_CHILD: u32 = 78;

/// Two 600-sat outputs (:0, :1) at the address, as in mainnet 69ab…5f6c.
fn dust_parent() -> DecodedTransaction {
    let dust = |n| TxOutput {
        n,
        address: Some(addr()),
        value: Amount::from_sat(600),
        script_type: DescriptorType::P2wpkh,
    };
    DecodedTransaction {
        vout: vec![dust(0), dust(1)],
        ..payment(DUST_PARENT)
    }
}

/// Spends `:0` of the dust parent alongside a larger coin.
fn dust_child() -> DecodedTransaction {
    let mut tx = payment(DUST_CHILD);
    tx.vin.push(TxInputRef {
        previous_txid: txid(DUST_PARENT),
        previous_vout: 0,
        sequence: 0xffff_ffff,
        coinbase: false,
    });
    tx
}

/// Only `:1` is pasted; the address history comes from `history`.
fn dust_scan(gateway: &mut FakeGateway) -> crate::types::Report {
    gateway
        .transactions
        .insert(txid(DUST_PARENT), dust_parent());
    let pasted = UtxoInput {
        txid: txid(DUST_PARENT),
        vout: 1,
        value: None,
        address: None,
    };
    AnalysisEngine::new(&*gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted]))
        .expect("utxo scan")
}

fn dust_status(report: &crate::types::Report, vout: u64) -> Option<String> {
    let parent = txid(DUST_PARENT).to_string();
    report
        .findings
        .iter()
        .filter(|f| f.vulnerability_type == VulnerabilityType::Dust)
        .filter_map(|f| f.details.as_ref())
        .find(|d| d["txid"].as_str() == Some(parent.as_str()) && d["vout"].as_u64() == Some(vout))
        .and_then(|d| d["status"].as_str().map(str::to_owned))
}

fn without_history() -> FakeGateway {
    FakeGateway::new(Err(AnalysisError::HistoryUnavailable(
        "wallet support is disabled".into(),
    )))
}

#[test]
fn dust_spent_on_chain_outside_the_history_is_reported_spent() {
    let mut gateway = without_history();
    gateway.unspent = Ok(HashSet::from([OutPoint::new(txid(DUST_PARENT), 1)]));
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("spent"));
    assert_eq!(dust_status(&report, 1).as_deref(), Some("unspent"));
}

#[test]
fn pasted_dust_spent_on_chain_is_reported_spent() {
    let mut gateway = without_history();
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 1).as_deref(), Some("spent"));
    let pasted = report
        .findings
        .iter()
        .find(|f| {
            f.details
                .as_ref()
                .is_some_and(|d| d["vout"].as_u64() == Some(1))
        })
        .expect("pasted dust finding");
    assert!(
        pasted.description.contains("pasted as unspent"),
        "{}",
        pasted.description
    );
    assert!(gateway
        .asked
        .borrow()
        .contains(&OutPoint::new(txid(DUST_PARENT), 1)));
}

#[test]
fn pasted_dust_the_node_cannot_check_stays_as_pasted() {
    let mut gateway = without_history();
    gateway.unspent = Err("node unreachable".into());
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 1).as_deref(), Some("unspent"));
}

#[test]
fn a_pasted_output_the_node_fails_on_is_named_in_the_error() {
    let mut gateway = FakeGateway::new(Ok(chain_history(1, 1)));
    gateway.broken.insert(txid(1));
    let error = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted()]))
        .expect_err("a node error on a pasted output must fail the scan");
    assert!(
        error.to_string().contains(&format!("{}:0", txid(1))),
        "{error}"
    );
}

#[test]
fn an_address_history_the_node_cannot_look_up_is_counted_not_fatal() {
    let gateway = FakeGateway::new(Err(AnalysisError::TransactionNotFound(
        "No such mempool transaction. Use -txindex".into(),
    )));
    let report = scan(&gateway);
    assert_eq!(report.stats.addresses_without_history, 1);
}

#[test]
fn a_descriptor_scan_still_fails_on_a_wallet_tx_the_node_cannot_find() {
    let missing = AnalysisError::TransactionNotFound("No such mempool transaction".into());
    let gateway = FakeGateway::new(Err(missing.clone()));
    let result = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Descriptor(format!("addr({ADDR})")));
    assert_eq!(result.err(), Some(missing));
}

#[test]
fn a_node_error_while_normalizing_the_address_history_keeps_its_variant() {
    let mut gateway = FakeGateway::new(Ok(chain_history(1, 1)));
    let busy = AnalysisError::EnvironmentUnavailable("Loading block index...".into());
    gateway.normalize_error = Some(busy.clone());
    let result = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted()]));
    assert_eq!(result.err(), Some(busy));
}

#[test]
fn a_wallet_tx_a_synced_txindex_cannot_find_fails_the_utxo_scan() {
    let missing = AnalysisError::TransactionNotFound("evicted".into());
    let mut gateway = FakeGateway::new(Err(missing.clone()));
    gateway.txindex = Ok(true);
    let result = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted()]));
    assert_eq!(result.err(), Some(missing));
}

#[test]
fn a_call_the_whitelist_forbids_during_the_address_history_is_counted_not_fatal() {
    let gateway = FakeGateway::new(Err(AnalysisError::RpcForbidden {
        method: "listunspent".into(),
        detail: String::new(),
    }));
    let report = scan(&gateway);
    assert_eq!(report.stats.addresses_without_history, 1);
}

#[test]
fn a_failed_index_probe_fails_the_utxo_scan() {
    let mut gateway = FakeGateway::new(Err(AnalysisError::TransactionNotFound("gone".into())));
    let busy = AnalysisError::EnvironmentUnavailable("getindexinfo: Loading".into());
    gateway.txindex = Err(busy.clone());
    let result = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted()]));
    assert_eq!(result.err(), Some(busy));
}

const XPUB: &str = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";
const PUBKEY: &str = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd";
const PUBKEY2: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

fn ranged(descriptor: &str) -> bool {
    crate::descriptor::is_ranged(descriptor)
}

#[test]
fn a_single_script_descriptor_is_not_ranged() {
    for d in [
        format!("addr({ADDR})"),
        "raw(0014e0a63d7b9c3a6a5b2c1d0e9f8a7b6c5d4e3f2a1b)".to_owned(),
        format!("wpkh({PUBKEY})"),
        format!("pkh({PUBKEY})#8fhd9pwu"),
        format!("tr({PUBKEY})"),
        format!("combo({PUBKEY})"),
        format!("wsh(multi(1,{PUBKEY},{PUBKEY2}))"),
        format!("wpkh({XPUB}/0/5)"),
    ] {
        assert!(!ranged(&d), "{d}");
    }
}

#[test]
fn a_wildcard_descriptor_is_ranged() {
    for d in [
        format!("wpkh({XPUB}/0/*)"),
        format!("wpkh({XPUB}/1/*')#qwer"),
        format!("wsh(multi(1,{XPUB}/0/*,{PUBKEY}))"),
    ] {
        assert!(ranged(&d), "{d}");
    }
}

#[test]
fn dust_unspent_on_chain_but_not_pasted_is_reported_unspent() {
    let mut gateway = without_history();
    gateway.unspent = Ok(HashSet::from([OutPoint::new(txid(DUST_PARENT), 0)]));
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unspent"));
}

#[test]
fn dust_whose_status_the_node_cannot_give_is_reported_unknown() {
    let mut gateway = without_history();
    gateway.unspent = Err("node unreachable".into());
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unknown"));
    let unknown = report
        .findings
        .iter()
        .find(|f| {
            f.details
                .as_ref()
                .is_some_and(|d| d["status"].as_str() == Some("unknown"))
        })
        .expect("unknown dust finding");
    assert_eq!(unknown.severity, crate::types::Severity::Low);
}

#[test]
fn dust_whose_spend_is_in_the_history_needs_no_node_call() {
    let history = WalletHistory {
        wallet_txs: vec![
            WalletTxEntry {
                txid: txid(DUST_PARENT),
                ..receive(DUST_PARENT)
            },
            WalletTxEntry {
                txid: txid(DUST_CHILD),
                address: None,
                category: WalletTxCategory::Send,
                ..receive(DUST_CHILD)
            },
        ],
        utxos: Vec::new(),
        transactions: HashMap::from([
            (txid(DUST_PARENT), dust_parent()),
            (txid(DUST_CHILD), dust_child()),
        ]),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([addr()]),
        ranged_addresses: HashSet::new(),
    };
    let mut gateway = FakeGateway::new(Ok(history));
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("spent"));
    assert_eq!(
        gateway.asked.borrow().as_slice(),
        [OutPoint::new(txid(DUST_PARENT), 1)],
        "only the pasted coin is asked; the confirmed spend of :0 settles it"
    );
}

/// A descriptor scan whose history holds the dust parent (with
/// `parent_confirmations`), the wallet listing `listed` of its outputs, and,
/// when given, a child spending `:0`.
fn dust_descriptor_scan(
    gateway: &mut FakeGateway,
    listed: &[u32],
    parent_confirmations: u32,
    child_confirmations: Option<u32>,
) -> crate::types::Report {
    let parent = DecodedTransaction {
        confirmations: parent_confirmations,
        ..dust_parent()
    };
    gateway
        .transactions
        .entry(txid(DUST_PARENT))
        .or_insert_with(|| parent.clone());
    let mut transactions = HashMap::from([(txid(DUST_PARENT), parent)]);
    let mut wallet_txs = vec![receive(DUST_PARENT)];
    if let Some(confirmations) = child_confirmations {
        transactions.insert(
            txid(DUST_CHILD),
            DecodedTransaction {
                confirmations,
                ..dust_child()
            },
        );
        wallet_txs.push(WalletTxEntry {
            address: None,
            category: WalletTxCategory::Send,
            ..receive(DUST_CHILD)
        });
    }
    gateway.history = Ok(WalletHistory {
        wallet_txs,
        utxos: listed
            .iter()
            .map(|&vout| Utxo {
                vout,
                amount: Amount::from_sat(600),
                ..unspent(DUST_PARENT)
            })
            .collect(),
        transactions,
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([addr()]),
        ranged_addresses: HashSet::new(),
    });
    AnalysisEngine::new(&*gateway, EngineSettings::default())
        .analyze(ScanTarget::Descriptor(format!("addr({ADDR})")))
        .expect("descriptor scan")
}

#[test]
fn dust_absent_from_the_utxo_set_with_its_creating_tx_gone_is_unknown() {
    let mut gateway = without_history();
    gateway.vanished.insert(txid(DUST_PARENT));
    let report = dust_descriptor_scan(&mut gateway, &[], 0, None);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unknown"));
    assert_eq!(dust_status(&report, 1).as_deref(), Some("unknown"));
}

#[test]
fn dust_absent_from_the_utxo_set_with_its_creating_tx_still_in_the_mempool_is_unknown() {
    let mut gateway = without_history();
    gateway.transactions.insert(
        txid(DUST_PARENT),
        DecodedTransaction {
            confirmations: 0,
            ..dust_parent()
        },
    );
    let report = dust_descriptor_scan(&mut gateway, &[], 0, None);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unknown"));
}

#[test]
fn dust_absent_from_the_utxo_set_with_its_creating_tx_confirmed_since_is_spent() {
    let mut gateway = without_history();
    gateway.transactions.insert(
        txid(DUST_PARENT),
        DecodedTransaction {
            confirmations: 1,
            ..dust_parent()
        },
    );
    let report = dust_descriptor_scan(&mut gateway, &[], 0, None);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("spent"));
    assert_eq!(
        gateway.batches.borrow().as_slice(),
        [vec![txid(DUST_PARENT)]],
        "one batched lookup per unconfirmed creating tx"
    );
}

#[test]
fn dust_whose_own_answer_fails_is_unknown_while_the_rest_are_answered() {
    let mut gateway = without_history();
    gateway.failing = HashSet::from([OutPoint::new(txid(DUST_PARENT), 0)]);
    gateway.unspent = Ok(HashSet::from([OutPoint::new(txid(DUST_PARENT), 1)]));
    let report = dust_descriptor_scan(&mut gateway, &[], 10, None);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unknown"));
    assert_eq!(dust_status(&report, 1).as_deref(), Some("unspent"));
}

#[test]
fn dust_spent_by_an_unconfirmed_tx_that_was_replaced_is_unspent() {
    let mut gateway = without_history();
    gateway.unspent = Ok(HashSet::from([
        OutPoint::new(txid(DUST_PARENT), 0),
        OutPoint::new(txid(DUST_PARENT), 1),
    ]));
    let report = dust_descriptor_scan(&mut gateway, &[], 10, Some(0));
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unspent"));
    assert!(gateway
        .asked
        .borrow()
        .contains(&OutPoint::new(txid(DUST_PARENT), 0)));
}

#[test]
fn dust_spent_by_a_confirmed_tx_needs_no_node_call() {
    let mut gateway = without_history();
    let report = dust_descriptor_scan(&mut gateway, &[], 10, Some(3));
    assert_eq!(dust_status(&report, 0).as_deref(), Some("spent"));
    assert_eq!(
        gateway.asked.borrow().as_slice(),
        [OutPoint::new(txid(DUST_PARENT), 1)]
    );
}

#[test]
fn dust_spent_by_an_unconfirmed_tx_without_a_node_answer_is_unknown() {
    let mut failing_output = without_history();
    failing_output.failing = HashSet::from([OutPoint::new(txid(DUST_PARENT), 0)]);
    let mut failing_call = without_history();
    failing_call.unspent = Err("node unreachable".into());
    for gateway in [&mut failing_output, &mut failing_call] {
        let report = dust_descriptor_scan(gateway, &[], 10, Some(0));
        assert_eq!(dust_status(&report, 0).as_deref(), Some("unknown"));
    }
}

#[test]
fn pasted_dust_with_a_confirmed_spend_in_the_history_is_spent_without_asking() {
    let child = DecodedTransaction {
        vin: vec![TxInputRef {
            previous_txid: txid(DUST_PARENT),
            previous_vout: 1,
            sequence: 0xffff_ffff,
            coinbase: false,
        }],
        ..payment(DUST_CHILD)
    };
    let history = WalletHistory {
        wallet_txs: vec![
            receive(DUST_PARENT),
            WalletTxEntry {
                address: None,
                category: WalletTxCategory::Send,
                ..receive(DUST_CHILD)
            },
        ],
        utxos: Vec::new(),
        transactions: HashMap::from([
            (txid(DUST_PARENT), dust_parent()),
            (txid(DUST_CHILD), child),
        ]),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([addr()]),
        ranged_addresses: HashSet::new(),
    };
    let mut gateway = FakeGateway::new(Ok(history));
    gateway.unspent = Err("node unreachable".into());
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 1).as_deref(), Some("spent"));
    assert!(!gateway
        .asked
        .borrow()
        .contains(&OutPoint::new(txid(DUST_PARENT), 1)));
}

#[test]
fn a_descriptor_scan_does_not_look_up_wallet_listed_dust() {
    let mut gateway = without_history();
    let report = dust_descriptor_scan(&mut gateway, &[1], 10, None);
    assert_eq!(dust_status(&report, 1).as_deref(), Some("unspent"));
    assert_eq!(
        gateway.asked.borrow().as_slice(),
        [OutPoint::new(txid(DUST_PARENT), 0)]
    );
}

#[test]
fn unconfirmed_dust_listed_by_the_address_history_is_unspent_without_asking() {
    let parent = DecodedTransaction {
        confirmations: 0,
        ..dust_parent()
    };
    let listed = |vout| Utxo {
        vout,
        amount: Amount::from_sat(600),
        confirmations: 0,
        ..unspent(DUST_PARENT)
    };
    let history = WalletHistory {
        wallet_txs: vec![receive(DUST_PARENT)],
        utxos: vec![listed(0), listed(1)],
        transactions: HashMap::from([(txid(DUST_PARENT), parent.clone())]),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::from([addr()]),
        ranged_addresses: HashSet::new(),
    };
    let mut gateway = FakeGateway::new(Ok(history));
    gateway.transactions.insert(txid(DUST_PARENT), parent);
    let report = dust_scan(&mut gateway);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unspent"));
    let freeze = report
        .findings
        .iter()
        .find(|f| {
            f.details
                .as_ref()
                .is_some_and(|d| d["vout"].as_u64() == Some(0))
        })
        .and_then(|f| f.correction.clone())
        .unwrap_or_default();
    assert!(freeze.contains("freeze"), "{freeze}");
    assert!(gateway.asked.borrow().is_empty());
}

#[test]
fn the_creating_tx_is_checked_before_the_utxo_set() {
    let mut gateway = without_history();
    let report = dust_descriptor_scan(&mut gateway, &[], 10, None);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("spent"));
    assert_eq!(
        gateway.calls.borrow().as_slice(),
        ["getrawtransaction", "gettxout"]
    );
}

#[test]
fn dust_whose_creating_tx_left_the_chain_is_unknown() {
    let mut reorged = without_history();
    reorged.transactions.insert(
        txid(DUST_PARENT),
        DecodedTransaction {
            confirmations: 0,
            ..dust_parent()
        },
    );
    let mut gone = without_history();
    gone.vanished.insert(txid(DUST_PARENT));
    for gateway in [&mut reorged, &mut gone] {
        let report = dust_descriptor_scan(gateway, &[], 10, None);
        assert_eq!(dust_status(&report, 0).as_deref(), Some("unknown"));
    }
}

#[test]
fn pasted_dust_whose_creating_tx_is_unconfirmed_is_not_called_spent() {
    let mut gateway = without_history();
    gateway.transactions.insert(
        txid(DUST_PARENT),
        DecodedTransaction {
            confirmations: 0,
            ..dust_parent()
        },
    );
    let pasted = UtxoInput {
        txid: txid(DUST_PARENT),
        vout: 1,
        value: None,
        address: None,
    };
    let report = AnalysisEngine::new(&gateway, EngineSettings::default())
        .analyze(ScanTarget::Utxos(vec![pasted]))
        .expect("utxo scan");
    assert_eq!(dust_status(&report, 1).as_deref(), Some("unspent"));
}

#[test]
fn a_failed_creating_tx_lookup_still_reports_present_dust_unspent() {
    let mut gateway = without_history();
    gateway.fail_batches = true;
    gateway.unspent = Ok(HashSet::from([OutPoint::new(txid(DUST_PARENT), 1)]));
    let report = dust_descriptor_scan(&mut gateway, &[], 10, None);
    assert_eq!(dust_status(&report, 0).as_deref(), Some("unknown"));
    assert_eq!(dust_status(&report, 1).as_deref(), Some("unspent"));
    let freeze = report
        .findings
        .iter()
        .find(|f| {
            f.details
                .as_ref()
                .is_some_and(|d| d["vout"].as_u64() == Some(1))
        })
        .and_then(|f| f.correction.clone())
        .unwrap_or_default();
    assert!(freeze.contains("freeze"), "{freeze}");
}
