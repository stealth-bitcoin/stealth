use std::collections::{HashMap, HashSet};

use stealth_core::config::AnalysisConfig;
use stealth_core::engine::{AnalysisEngine, EngineSettings, ScanTarget};
use stealth_core::error::AnalysisError;
use stealth_core::gateway::BlockchainGateway;
use stealth_core::model::{
    DecodedTransaction, DescriptorType, ResolvedDescriptor, TxOutput, WalletHistory,
    WalletTxCategory, WalletTxEntry,
};

#[derive(Default)]
struct MockGateway {
    normalized: HashMap<String, String>,
    derived: HashMap<String, Vec<String>>,
    descriptor_history: Option<WalletHistory>,
    wallet_descriptors: HashMap<String, Vec<ResolvedDescriptor>>,
    wallet_history: HashMap<String, WalletHistory>,
    known_wallet_txids: HashMap<String, HashSet<String>>,
}

impl BlockchainGateway for MockGateway {
    fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError> {
        self.normalized.get(descriptor).cloned().ok_or_else(|| {
            AnalysisError::DescriptorNormalization {
                descriptor: descriptor.to_string(),
                message: "missing normalization fixture".into(),
            }
        })
    }

    fn derive_addresses(
        &self,
        descriptor: &ResolvedDescriptor,
    ) -> Result<Vec<String>, AnalysisError> {
        self.derived.get(&descriptor.desc).cloned().ok_or_else(|| {
            AnalysisError::EnvironmentUnavailable("missing derivation fixture".into())
        })
    }

    fn scan_descriptors(
        &self,
        _descriptors: &[ResolvedDescriptor],
    ) -> Result<WalletHistory, AnalysisError> {
        self.descriptor_history
            .clone()
            .ok_or(AnalysisError::AnalysisEmpty)
    }

    fn list_wallet_descriptors(
        &self,
        wallet_name: &str,
    ) -> Result<Vec<ResolvedDescriptor>, AnalysisError> {
        self.wallet_descriptors
            .get(wallet_name)
            .cloned()
            .ok_or_else(|| AnalysisError::EnvironmentUnavailable("wallet not found".into()))
    }

    fn scan_wallet(&self, wallet_name: &str) -> Result<WalletHistory, AnalysisError> {
        self.wallet_history
            .get(wallet_name)
            .cloned()
            .ok_or(AnalysisError::AnalysisEmpty)
    }

    fn known_wallet_txids(
        &self,
        wallet_names: &[String],
    ) -> Result<HashSet<String>, AnalysisError> {
        Ok(wallet_names
            .iter()
            .filter_map(|wallet_name| self.known_wallet_txids.get(wallet_name))
            .flat_map(|txids| txids.iter().cloned())
            .collect())
    }
}

fn satoshis(value: u64) -> f64 {
    value as f64 / 100_000_000.0
}

fn descriptor(desc: &str, internal: bool) -> ResolvedDescriptor {
    ResolvedDescriptor {
        desc: desc.to_string(),
        internal,
        active: true,
        range_end: 50,
    }
}

fn history_for_address_reuse(address: &str) -> WalletHistory {
    WalletHistory {
        wallet_txs: vec![
            WalletTxEntry {
                txid: "tx-1".into(),
                address: address.into(),
                category: WalletTxCategory::Receive,
                amount_btc: satoshis(100_000),
                confirmations: 6,
                blockheight: 0,
            },
            WalletTxEntry {
                txid: "tx-2".into(),
                address: address.into(),
                category: WalletTxCategory::Receive,
                amount_btc: satoshis(200_000),
                confirmations: 5,
                blockheight: 0,
            },
        ],
        utxos: Vec::new(),
        transactions: HashMap::from([
            (
                "tx-1".into(),
                DecodedTransaction {
                    txid: "tx-1".into(),
                    vin: Vec::new(),
                    vout: vec![TxOutput {
                        n: 0,
                        address: address.into(),
                        value_btc: satoshis(100_000),
                        script_type: DescriptorType::P2wpkh,
                    }],
                    version: 2,
                    locktime: 0,
                    vsize: 100,
                    confirmations: 6,
                },
            ),
            (
                "tx-2".into(),
                DecodedTransaction {
                    txid: "tx-2".into(),
                    vin: Vec::new(),
                    vout: vec![TxOutput {
                        n: 0,
                        address: address.into(),
                        value_btc: satoshis(200_000),
                        script_type: DescriptorType::P2wpkh,
                    }],
                    version: 2,
                    locktime: 0,
                    vsize: 100,
                    confirmations: 5,
                },
            ),
        ]),
    }
}

#[test]
fn descriptor_scan_normalizes_derives_and_reports_findings() {
    let normalized_external = "normalized:wpkh(xpub/0/*)";
    let normalized_internal = "normalized:wpkh(xpub/1/*)";
    let address = "bcrt1qengine";
    let gateway = MockGateway {
        normalized: HashMap::from([
            ("wpkh(xpub/0/*)".into(), normalized_external.into()),
            ("wpkh(xpub/1/*)".into(), normalized_internal.into()),
        ]),
        derived: HashMap::from([
            (normalized_external.into(), vec![address.into()]),
            (normalized_internal.into(), vec!["bcrt1qchange".into()]),
        ]),
        descriptor_history: Some(history_for_address_reuse(address)),
        ..MockGateway::default()
    };
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());

    let report = engine
        .analyze(ScanTarget::Descriptors(vec!["wpkh(xpub/0/*)#abcd".into()]))
        .expect("analysis should succeed");

    assert_eq!(report.summary.findings, 1);
    assert_eq!(
        report.findings[0].kind,
        stealth_core::model::FindingKind::AddressReuse
    );
    assert_eq!(report.stats.addresses_derived, 2);
}

#[test]
fn wallet_scan_uses_existing_wallet_descriptors() {
    let address = "bcrt1qwallet";
    let wallet_name = "alice";
    let gateway = MockGateway {
        derived: HashMap::from([
            ("normalized:wpkh(wallet/0/*)".into(), vec![address.into()]),
            (
                "normalized:wpkh(wallet/1/*)".into(),
                vec!["bcrt1qwalletchange".into()],
            ),
        ]),
        wallet_descriptors: HashMap::from([(
            wallet_name.into(),
            vec![
                descriptor("normalized:wpkh(wallet/0/*)", false),
                descriptor("normalized:wpkh(wallet/1/*)", true),
            ],
        )]),
        wallet_history: HashMap::from([(wallet_name.into(), history_for_address_reuse(address))]),
        ..MockGateway::default()
    };
    let engine = AnalysisEngine::new(&gateway, EngineSettings::default());

    let report = engine
        .analyze(ScanTarget::WalletName(wallet_name.into()))
        .expect("wallet analysis should succeed");

    assert_eq!(report.summary.findings, 1);
    assert_eq!(report.stats.transactions_analyzed, 2);
}

#[test]
fn empty_history_returns_typed_error() {
    let gateway = MockGateway {
        normalized: HashMap::from([
            ("wpkh(xpub/0/*)".into(), "normalized:wpkh(xpub/0/*)".into()),
            ("wpkh(xpub/1/*)".into(), "normalized:wpkh(xpub/1/*)".into()),
        ]),
        derived: HashMap::from([
            (
                "normalized:wpkh(xpub/0/*)".into(),
                vec!["bcrt1qnone".into()],
            ),
            (
                "normalized:wpkh(xpub/1/*)".into(),
                vec!["bcrt1qnonechange".into()],
            ),
        ]),
        descriptor_history: Some(WalletHistory {
            wallet_txs: Vec::new(),
            utxos: Vec::new(),
            transactions: HashMap::new(),
        }),
        ..MockGateway::default()
    };
    let engine = AnalysisEngine::new(
        &gateway,
        EngineSettings {
            analysis: AnalysisConfig::default(),
            known_exchange_wallets: Vec::new(),
            known_risky_wallets: Vec::new(),
        },
    );

    let error = engine
        .analyze(ScanTarget::Descriptors(vec!["wpkh(xpub/0/*)".into()]))
        .expect_err("analysis should fail");

    assert_eq!(error, AnalysisError::AnalysisEmpty);
}
