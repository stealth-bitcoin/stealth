use std::collections::HashSet;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorThresholds {
    pub dust_sats: u64,
    pub strict_dust_sats: u64,
    pub normal_input_min_sats: u64,
    pub consolidation_min_inputs: usize,
    pub consolidation_max_outputs: usize,
    pub utxo_age_spread_blocks: u32,
    pub dormant_utxo_blocks: u32,
    pub exchange_batch_outputs: usize,
}

impl Default for DetectorThresholds {
    fn default() -> Self {
        Self {
            dust_sats: 1_000,
            strict_dust_sats: 546,
            normal_input_min_sats: 10_000,
            consolidation_min_inputs: 3,
            consolidation_max_outputs: 2,
            utxo_age_spread_blocks: 10,
            dormant_utxo_blocks: 100,
            exchange_batch_outputs: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisConfig {
    pub derivation_range_end: u32,
    pub thresholds: DetectorThresholds,
    pub enabled_detectors: HashSet<DetectorId>,
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
            ]),
        }
    }
}
