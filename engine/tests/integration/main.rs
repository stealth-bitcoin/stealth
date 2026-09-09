//! Integration tests for stealth-engine.
//!
//! Each test spins up a fresh regtest Bitcoin Core via `corepc-node`,
//! reproduces one or more privacy vulnerabilities, then runs the
//! detector through the canonical `AnalysisEngine` + `BitcoinCoreRpc`
//! gateway path to verify it fires the expected finding(s).
//!
//! Tests are grouped by the feature they exercise; shared setup lives
//! in `common`.

mod common;

mod address_reuse;
mod behavior;
mod change;
mod dust;
mod gateway;
mod linkage;
mod origins;
mod progress;
mod scanning;
mod utxo_mode;
mod xpub;
