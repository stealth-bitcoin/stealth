//! # stealth-engine
//!
//! Detects Bitcoin UTXO privacy vulnerabilities by analysing a wallet's
//! transaction history through a [`BlockchainGateway`](gateway::BlockchainGateway).
//!
//! The canonical execution path is:
//!
//! ```text
//! AnalysisEngine  +  BlockchainGateway  →  Report
//! ```
//!
//! Construct an [`AnalysisEngine`] with a concrete gateway implementation,
//! then call [`AnalysisEngine::analyze`] with a [`ScanTarget`].
//!
//! Results are returned as a structured [`Report`] that can be serialised
//! to JSON.
//!
//! ## Detected vulnerabilities
//!
//! | # | Vulnerability | Default severity |
//! |---|---------------|------------------|
//! | 1 | Address reuse | HIGH |
//! | 2 | Common-input-ownership heuristic (CIOH) | HIGH – CRITICAL |
//! | 3 | Dust UTXO reception | MEDIUM – HIGH |
//! | 4 | Dust spent alongside normal inputs | HIGH |
//! | 5 | Identifiable change outputs | MEDIUM |
//! | 6 | UTXOs born from consolidation transactions | MEDIUM |
//! | 7 | Mixed script types in inputs | HIGH |
//! | 8 | Cross-origin cluster merge | HIGH |
//! | 9 | UTXO age / lookback-depth spread | LOW |
//! | 10 | Exchange-origin batch withdrawal | MEDIUM |
//! | 11 | Tainted UTXO merge | HIGH |
//! | 12 | Behavioural fingerprinting | MEDIUM |

pub use stealth_model::config;
pub use stealth_model::descriptor;
mod detect;
pub mod engine;
pub use stealth_model::error;
pub use stealth_model::gateway;
mod graph;
pub use stealth_model::types;

pub use engine::{AnalysisEngine, EngineSettings, ScanTarget, UtxoInput};
pub use graph::TxGraph;
pub use stealth_model::types::*;
