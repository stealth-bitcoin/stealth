//! Unit tests for the analysis engine, against an in-memory gateway.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Txid};

use crate::engine::{merge_chain_history, AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};
use crate::error::AnalysisError;
use crate::gateway::{
    BlockchainGateway, DecodedTransaction, DescriptorType, ResolvedDescriptor, TxInputRef,
    TxOutput, Utxo, WalletHistory, WalletTxCategory, WalletTxEntry,
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
        self.transactions
            .get(&txid)
            .cloned()
            .ok_or_else(|| AnalysisError::TransactionNotFound(format!("unknown {txid}")))
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
