pub mod config;
pub mod descriptor;
pub mod detectors;
pub mod engine;
pub mod error;
pub mod gateway;
pub mod graph;
pub mod model;

#[cfg(test)]
mod tests {
    use crate::descriptor::{DescriptorNormalizer, normalize_descriptors};
    use crate::model::{
        AnalysisReport, Finding, FindingDetails, FindingKind, Severity, Warning, WarningDetails,
        WarningKind,
    };
    use serde_json::json;

    #[test]
    fn normalizes_checksums_and_infers_change_descriptor_pair() {
        struct RecordingNormalizer;

        impl DescriptorNormalizer for RecordingNormalizer {
            fn normalize(&self, descriptor: &str) -> Result<String, crate::error::AnalysisError> {
                Ok(format!("normalized:{descriptor}"))
            }
        }

        let normalized = normalize_descriptors(
            &[String::from("wpkh([abcd/84h/1h/0h]tpub123/0/*)#checksum")],
            777,
            &RecordingNormalizer,
        )
        .expect("descriptor normalization should succeed");

        assert_eq!(normalized.len(), 2);
        assert_eq!(
            normalized[0].desc,
            "normalized:wpkh([abcd/84h/1h/0h]tpub123/0/*)"
        );
        assert!(!normalized[0].internal);
        assert_eq!(
            normalized[1].desc,
            "normalized:wpkh([abcd/84h/1h/0h]tpub123/1/*)"
        );
        assert!(normalized[1].internal);
        assert_eq!(normalized[1].range_end, 777);
    }

    #[test]
    fn report_summary_tracks_clean_state_and_counts() {
        let finding = Finding {
            kind: FindingKind::AddressReuse,
            severity: Severity::High,
            description: "address reused".into(),
            details: FindingDetails::Generic(json!({"address":"bcrt1qexample"})),
            correction: Some("use a fresh address".into()),
        };
        let warning = Warning {
            kind: WarningKind::DormantUtxos,
            severity: Severity::Low,
            description: "dormant coins".into(),
            details: WarningDetails::Generic(json!({"count":1})),
        };

        let report = AnalysisReport::new(12, 34, vec![finding], vec![warning]);

        assert_eq!(report.summary.findings, 1);
        assert_eq!(report.summary.warnings, 1);
        assert!(!report.summary.clean);
        assert_eq!(report.stats.transactions_analyzed, 12);
        assert_eq!(report.stats.addresses_derived, 34);
    }

    #[test]
    fn empty_report_is_marked_clean() {
        let report = AnalysisReport::new(0, 0, Vec::new(), Vec::new());
        assert!(report.summary.clean);
    }
}
