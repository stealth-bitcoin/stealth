use std::collections::HashSet;

use bitcoin::Amount;

/// Identifies a specific detector for enable/disable configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorId {
    AddressReuse,
    Cioh,
    Dust,
    DustSpending,
    ChangeDetection,
    Consolidation,
    ScriptTypeMixing,
    ClusterMerge,
    UtxoAgeSpread,
    ExchangeOrigin,
    TaintedUtxoMerge,
    BehavioralFingerprint,
    DustAttack,
    PeelChain,
    DeterministicLink,
    UnnecessaryInput,
    ToxicChange,
}

/// Numeric thresholds used by the detectors.
///
/// `Eq` is intentionally not derived — `f64` does not implement `Eq`. Use
/// `PartialEq` for comparisons.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectorThresholds {
    pub dust: Amount,
    pub strict_dust: Amount,
    pub normal_input_min: Amount,
    pub consolidation_min_inputs: usize,
    pub consolidation_max_outputs: usize,
    pub utxo_age_spread_blocks: u32,
    pub dormant_utxo_blocks: u32,
    pub exchange_batch_min_outputs: usize,
    pub dust_attack_min_outputs: usize,
    pub dust_attack_min_dust_outputs: usize,
    /// Minimum unique-address-to-output ratio for a transaction to be
    /// classified as a dust attack.
    pub dust_attack_diversity: f64,
    /// Lower bound (inclusive) on values considered "toxic change".
    pub toxic_change_lower: Amount,
    pub toxic_change_upper: Amount,
    /// Maximum hops to trace forward when looking for a peel chain. A safety
    /// bound well above real chains; a chain cut by it is marked truncated.
    pub peel_chain_max_hops: u32,
    /// Minimum hop count required to emit a peel-chain finding.
    pub peel_chain_min_hops: u32,
    /// Hop count at which a peel chain escalates to `Critical`.
    pub peel_chain_critical_hops: u32,
    /// Maximum small/large output ratio that still looks like a peel.
    pub peel_chain_ratio: f64,
    /// Strict upper bound (exclusive) on the `ambiguity` value that
    /// triggers a deterministic-link warning. Transactions with
    /// `ambiguity >= low_ambiguity_cutoff` emit nothing.
    pub low_ambiguity_cutoff: f64,
}

impl Default for DetectorThresholds {
    fn default() -> Self {
        Self {
            dust: Amount::from_sat(1_000),
            strict_dust: Amount::from_sat(546),
            normal_input_min: Amount::from_sat(10_000),
            consolidation_min_inputs: 3,
            consolidation_max_outputs: 2,
            utxo_age_spread_blocks: 10,
            dormant_utxo_blocks: 100,
            exchange_batch_min_outputs: 5,
            dust_attack_min_outputs: 10,
            dust_attack_min_dust_outputs: 5,
            dust_attack_diversity: 0.8,
            toxic_change_lower: Amount::from_sat(546),
            toxic_change_upper: Amount::from_sat(10_000),
            peel_chain_max_hops: 1_000,
            peel_chain_min_hops: 2,
            peel_chain_critical_hops: 4,
            peel_chain_ratio: 0.3,
            low_ambiguity_cutoff: 0.4,
        }
    }
}

/// Top-level analysis configuration.
///
/// `Eq` is intentionally not derived — `DetectorThresholds` carries
/// `f64` fields that only implement `PartialEq`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisConfig {
    pub derivation_range_end: u32,
    pub thresholds: DetectorThresholds,
    pub enabled_detectors: HashSet<DetectorId>,
    /// Maximum ancestor-fetch depth when resolving UTXO history.
    /// `0` means only UTXO's own tx; `2` (the default)
    pub max_ancestor_depth: u32,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            derivation_range_end: 999,
            thresholds: DetectorThresholds::default(),
            enabled_detectors: HashSet::from([
                DetectorId::AddressReuse,
                DetectorId::Cioh,
                DetectorId::Dust,
                DetectorId::DustSpending,
                DetectorId::ChangeDetection,
                DetectorId::Consolidation,
                DetectorId::ScriptTypeMixing,
                DetectorId::ClusterMerge,
                DetectorId::UtxoAgeSpread,
                DetectorId::ExchangeOrigin,
                DetectorId::TaintedUtxoMerge,
                DetectorId::BehavioralFingerprint,
                DetectorId::DustAttack,
                DetectorId::PeelChain,
                DetectorId::DeterministicLink,
                DetectorId::UnnecessaryInput,
                DetectorId::ToxicChange,
            ]),
            max_ancestor_depth: 2,
        }
    }
}
