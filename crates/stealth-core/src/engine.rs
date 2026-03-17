use crate::config::AnalysisConfig;
use crate::descriptor::normalize_descriptors;
use crate::detectors::{DetectorContext, run_all};
use crate::error::AnalysisError;
use crate::gateway::BlockchainGateway;
use crate::graph::TxGraph;
use crate::model::{
    AnalysisReport, DerivedAddress, DescriptorChainRole, DescriptorType, ResolvedDescriptor,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSettings {
    pub analysis: AnalysisConfig,
    pub known_exchange_wallets: Vec<String>,
    pub known_risky_wallets: Vec<String>,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            analysis: AnalysisConfig::default(),
            known_exchange_wallets: Vec::new(),
            known_risky_wallets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTarget {
    Descriptors(Vec<String>),
    WalletName(String),
}

pub struct AnalysisEngine<'a, G> {
    gateway: &'a G,
    settings: EngineSettings,
}

impl<'a, G> AnalysisEngine<'a, G>
where
    G: BlockchainGateway,
{
    pub fn new(gateway: &'a G, settings: EngineSettings) -> Self {
        Self { gateway, settings }
    }

    pub fn analyze(&self, target: ScanTarget) -> Result<AnalysisReport, AnalysisError> {
        let (descriptors, history) = match target {
            ScanTarget::Descriptors(raw_descriptors) => {
                if raw_descriptors.is_empty() {
                    return Err(AnalysisError::EmptyDescriptor);
                }
                let descriptors = normalize_descriptors(
                    &raw_descriptors,
                    self.settings.analysis.derivation_range_end,
                    self.gateway,
                )?;
                let history = self.gateway.scan_descriptors(&descriptors)?;
                (descriptors, history)
            }
            ScanTarget::WalletName(wallet_name) => {
                let descriptors = self.gateway.list_wallet_descriptors(&wallet_name)?;
                let history = self.gateway.scan_wallet(&wallet_name)?;
                (descriptors, history)
            }
        };

        if history.wallet_txs.is_empty() {
            return Err(AnalysisError::AnalysisEmpty);
        }

        let derived_addresses = self.derive_all_addresses(&descriptors)?;
        let graph = TxGraph::new(derived_addresses.clone(), history);
        let known_exchange_txids = self
            .gateway
            .known_wallet_txids(&self.settings.known_exchange_wallets)?;
        let known_risky_txids = self
            .gateway
            .known_wallet_txids(&self.settings.known_risky_wallets)?;

        let detector_result = run_all(&DetectorContext {
            graph: &graph,
            config: &self.settings.analysis,
            known_exchange_txids: &known_exchange_txids,
            known_risky_txids: &known_risky_txids,
        });

        Ok(AnalysisReport::new(
            graph.our_txids().count(),
            derived_addresses.len(),
            detector_result.findings,
            detector_result.warnings,
        ))
    }

    fn derive_all_addresses(
        &self,
        descriptors: &[ResolvedDescriptor],
    ) -> Result<Vec<DerivedAddress>, AnalysisError> {
        let mut addresses = Vec::new();

        for descriptor in descriptors {
            let descriptor_type = DescriptorType::from_descriptor(&descriptor.desc);
            let chain_role = if descriptor.internal {
                DescriptorChainRole::Internal
            } else {
                DescriptorChainRole::External
            };
            let derived = self.gateway.derive_addresses(descriptor)?;
            addresses.extend(derived.into_iter().enumerate().map(|(index, address)| {
                DerivedAddress {
                    address,
                    descriptor_type,
                    chain_role,
                    derivation_index: index as u32,
                }
            }));
        }

        Ok(addresses)
    }
}
