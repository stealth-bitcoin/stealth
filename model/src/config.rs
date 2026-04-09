use bitcoin::Amount;

/// Numeric thresholds used by the detectors.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub toxic_change_upper: Amount,
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
            toxic_change_upper: Amount::from_sat(10_000),
        }
    }
}

/// Top-level analysis configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisConfig {
    pub derivation_range_end: u32,
    pub thresholds: DetectorThresholds,
    /// Maximum ancestor-fetch depth when resolving UTXO history.
    /// `0` means only UTXO's own tx; `2` (the default)
    pub max_ancestor_depth: u32,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            derivation_range_end: 999,
            thresholds: DetectorThresholds::default(),
            max_ancestor_depth: 2,
        }
    }
}
