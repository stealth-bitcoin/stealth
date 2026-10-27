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
    history: Result<WalletHistory, String>,
    scanned: RefCell<Vec<String>>,
}

impl FakeGateway {
    fn new(history: Result<WalletHistory, String>) -> Self {
        Self {
            transactions: HashMap::from([(txid(1), payment(1))]),
            history,
            scanned: RefCell::new(Vec::new()),
        }
    }
}

impl BlockchainGateway for FakeGateway {
    fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError> {
        Ok(descriptor.to_owned())
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
    ) -> Result<WalletHistory, AnalysisError> {
        self.scanned
            .borrow_mut()
            .extend(descriptors.iter().map(|d| d.desc.clone()));
        self.history
            .clone()
            .map_err(AnalysisError::EnvironmentUnavailable)
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

    fn get_transaction(&self, txid: Txid) -> Result<DecodedTransaction, AnalysisError> {
        self.transactions
            .get(&txid)
            .cloned()
            .ok_or_else(|| AnalysisError::EnvironmentUnavailable(format!("unknown {txid}")))
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
    let gateway = FakeGateway::new(Err("wallet support is disabled".into()));
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
