use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Txid};
use serde::{Deserialize, Serialize};

use crate::config::AnalysisConfig;
use crate::error::{AnalysisError, HistoryOf};
use crate::progress::ScanProgress;

/// What to scan.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    Descriptor(String),
    Descriptors(Vec<String>),
    Utxos(Vec<UtxoInput>),
}

/// A raw UTXO to analyse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInput {
    pub txid: Txid,
    pub vout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Amount>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::types::serde_addr_opt"
    )]
    pub address: Option<Address<NetworkUnchecked>>,
}

/// Top-level settings for the analysis engine, combining detector config
/// with optional known-wallet hooks used by taint and exchange detectors.
#[derive(Debug, Clone, Default)]
pub struct EngineSettings {
    pub config: AnalysisConfig,
    pub known_risky_txids: Option<HashSet<Txid>>,
    pub known_exchange_txids: Option<HashSet<Txid>>,
    pub ownership_descriptors: Vec<String>,
    /// Reuse a deterministic watch-only wallet across scans of the same
    /// descriptors. When set, the first descriptor scan imports and keeps
    /// the wallet so later scans only pay Core's incremental catch-up.
    /// Defaults to `false`: a throwaway wallet is created and discarded.
    pub persist_scan_wallet: bool,
    /// Optional sink that receives phase transitions and rescan progress.
    pub progress: Option<ScanProgress>,
    /// How many transactions of the user's own history a scan loads unasked.
    pub history_limit: HistoryLimit,
}

/// Wallet transactions a scan loads before it stops to ask.
pub const DEFAULT_MAX_WALLET_TXS: u64 = 5_000;

/// Answers whether to go on loading a history of `tx_count` transactions,
/// above `limit`.
pub type AskToGoOn = Arc<dyn Fn(HistoryOf, u64, u64) -> bool + Send + Sync>;

/// The most transactions of the user's own history a scan loads, counted
/// after the rescan and before any of them is fetched. A history above the
/// limit fails the scan with [`AnalysisError::HistoryTooLarge`], unless
/// `ask` says to go on.
#[derive(Clone)]
pub struct HistoryLimit {
    /// `None` lifts the limit.
    pub max_txs: Option<u64>,
    pub ask: Option<AskToGoOn>,
    /// Whose history the count is of, for the question and the error.
    pub of: HistoryOf,
}

impl HistoryLimit {
    pub fn unlimited() -> Self {
        Self {
            max_txs: None,
            ask: None,
            of: HistoryOf::Wallet,
        }
    }

    pub fn at_most(max_txs: u64) -> Self {
        Self {
            max_txs: Some(max_txs),
            ask: None,
            of: HistoryOf::Wallet,
        }
    }

    pub fn check(&self, tx_count: u64) -> Result<(), AnalysisError> {
        match self.max_txs {
            Some(limit) if tx_count > limit => {
                if self
                    .ask
                    .as_ref()
                    .is_some_and(|ask| ask(self.of, tx_count, limit))
                {
                    Ok(())
                } else {
                    Err(AnalysisError::HistoryTooLarge {
                        of: self.of,
                        tx_count,
                        limit,
                    })
                }
            }
            _ => Ok(()),
        }
    }
}

impl Default for HistoryLimit {
    fn default() -> Self {
        Self::at_most(DEFAULT_MAX_WALLET_TXS)
    }
}

impl fmt::Debug for HistoryLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryLimit")
            .field("max_txs", &self.max_txs)
            .field("ask", &self.ask.is_some())
            .field("of", &self.of)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limit_lets_5000_through_and_stops_5001() {
        let limit = HistoryLimit::default();
        assert_eq!(limit.check(5_000), Ok(()));
        assert_eq!(
            limit.check(5_001),
            Err(AnalysisError::HistoryTooLarge {
                of: HistoryOf::Wallet,
                tx_count: 5_001,
                limit: 5_000
            })
        );
    }

    #[test]
    fn a_lifted_limit_lets_any_history_through() {
        assert_eq!(HistoryLimit::unlimited().check(u64::MAX), Ok(()));
    }

    #[test]
    fn above_the_limit_the_answer_decides_and_is_told_the_count_and_the_limit() {
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&asked);
        let mut limit = HistoryLimit::at_most(3);
        limit.of = HistoryOf::PastedAddresses;
        limit.ask = Some(Arc::new(move |of, tx_count, limit| {
            assert_eq!(of, HistoryOf::PastedAddresses);
            seen.lock().unwrap().push((tx_count, limit));
            tx_count < 10
        }));
        assert_eq!(limit.check(3), Ok(()));
        assert_eq!(limit.check(5), Ok(()));
        assert!(limit.check(10).is_err());
        assert_eq!(*asked.lock().unwrap(), vec![(5, 3), (10, 3)]);
    }

    #[test]
    fn the_error_names_the_count_and_the_limit() {
        let message = AnalysisError::HistoryTooLarge {
            of: HistoryOf::Wallet,
            tx_count: 12_345,
            limit: 5_000,
        }
        .to_string();
        assert!(
            message.starts_with("this scan's history holds 12345 transactions"),
            "{message}"
        );
        assert!(message.contains("limit of 5000"), "{message}");
    }

    #[test]
    fn a_utxo_scan_stop_names_the_pasted_outputs_addresses() {
        let mut limit = HistoryLimit::at_most(3);
        limit.of = HistoryOf::PastedAddresses;
        let message = limit.check(5).expect_err("above the limit").to_string();
        assert!(
            message
                .starts_with("the history of the pasted outputs' addresses holds 5 transactions"),
            "{message}"
        );
    }
}
