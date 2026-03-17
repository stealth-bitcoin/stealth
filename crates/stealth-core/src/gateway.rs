use std::collections::HashSet;

use crate::descriptor::DescriptorNormalizer;
use crate::error::AnalysisError;
use crate::model::{ResolvedDescriptor, WalletHistory};

pub trait BlockchainGateway {
    fn normalize_descriptor(&self, descriptor: &str) -> Result<String, AnalysisError>;
    fn derive_addresses(
        &self,
        descriptor: &ResolvedDescriptor,
    ) -> Result<Vec<String>, AnalysisError>;
    fn scan_descriptors(
        &self,
        descriptors: &[ResolvedDescriptor],
    ) -> Result<WalletHistory, AnalysisError>;
    fn list_wallet_descriptors(
        &self,
        wallet_name: &str,
    ) -> Result<Vec<ResolvedDescriptor>, AnalysisError>;
    fn scan_wallet(&self, wallet_name: &str) -> Result<WalletHistory, AnalysisError>;
    fn known_wallet_txids(&self, wallet_names: &[String])
    -> Result<HashSet<String>, AnalysisError>;
}

impl<T> DescriptorNormalizer for T
where
    T: BlockchainGateway + ?Sized,
{
    fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError> {
        self.normalize_descriptor(descriptor)
    }
}
