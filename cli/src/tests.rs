//! Unit tests for the CLI binary.

mod args {
    use crate::*;

    fn to_args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cache_wallet_flag_is_opt_in() {
        let default = parse_scan_args(&to_args(&["--descriptor", "wpkh(x/0/*)"])).unwrap();
        assert!(!default.cache_wallet, "cache must be off by default");

        let enabled =
            parse_scan_args(&to_args(&["--descriptor", "wpkh(x/0/*)", "--cache-wallet"])).unwrap();
        assert!(enabled.cache_wallet, "--cache-wallet must enable the cache");
    }
}

mod settings {
    use crate::*;

    #[test]
    fn the_cache_flag_reaches_the_engine() {
        let opts = ScanOpts {
            cache_wallet: true,
            ..ScanOpts::default()
        };
        assert!(
            opts.engine_settings()
                .expect("settings")
                .persist_scan_wallet
        );
        assert!(
            !ScanOpts::default()
                .engine_settings()
                .expect("settings")
                .persist_scan_wallet
        );
    }
}

mod exit_codes {
    use crate::*;

    fn summary(clean: bool, analyzed_nothing: bool, findings: usize) -> Summary {
        Summary {
            findings,
            warnings: 0,
            clean,
            analyzed_nothing,
        }
    }

    #[test]
    fn a_clean_scan_exits_successfully() {
        assert!(scan_succeeded(&summary(true, false, 0)));
    }

    #[test]
    fn an_empty_scan_exits_successfully() {
        assert!(scan_succeeded(&summary(false, true, 0)));
    }

    #[test]
    fn findings_fail_the_scan_even_when_nothing_was_analyzed() {
        assert!(!scan_succeeded(&summary(false, true, 1)));
    }

    #[test]
    fn findings_fail_the_scan() {
        assert!(!scan_succeeded(&summary(false, false, 3)));
    }
}

mod empty_report {
    use crate::*;

    fn summary(analyzed_nothing: bool, findings: usize, warnings: usize) -> Summary {
        Summary {
            findings,
            warnings,
            clean: false,
            analyzed_nothing,
        }
    }

    #[test]
    fn an_empty_scan_with_nothing_to_report_is_empty() {
        assert!(is_empty_report(&summary(true, 0, 0)));
    }

    #[test]
    fn findings_outrank_the_empty_notice() {
        assert!(!is_empty_report(&summary(true, 1, 0)));
    }

    #[test]
    fn warnings_outrank_the_empty_notice() {
        assert!(!is_empty_report(&summary(true, 0, 1)));
    }

    #[test]
    fn a_scan_that_analyzed_something_is_not_empty() {
        assert!(!is_empty_report(&summary(false, 0, 0)));
    }
}

mod ownership {
    use crate::*;

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("stealth-cli-test-{}-{name}", std::process::id()));
        fs::write(&path, contents).expect("write temp file");
        path
    }

    #[test]
    fn utxos_with_descriptors_is_ownership_context() {
        let utxos = temp_file(
            "utxos.json",
            r#"[{"txid": "d0bf39108641739b186eb18f2992320fa679b4b3ffe787c5ee1f677d1cc1784d", "vout": 0}]"#,
        );
        let descriptors = temp_file("descs.json", r#"["wpkh(x/0/*)"]"#);
        let opts = ScanOpts {
            utxos_file: Some(utxos),
            descriptors_file: Some(descriptors),
            ..ScanOpts::default()
        };

        let target = opts.scan_target().expect("combined input must be accepted");
        assert!(matches!(target, ScanTarget::Utxos(ref u) if u.len() == 1));
        assert_eq!(
            opts.ownership_descriptors()
                .expect("ownership descriptors must load"),
            vec!["wpkh(x/0/*)".to_owned()]
        );
    }
}

mod ordering {
    use crate::*;
    use stealth_engine::types::{Finding, Severity, VulnerabilityType};

    fn finding(vtype: VulnerabilityType, severity: Severity, description: &str) -> Finding {
        Finding {
            vulnerability_type: vtype,
            severity,
            description: description.to_owned(),
            details: None,
            correction: None,
        }
    }

    fn descriptions(list: &[Finding]) -> Vec<&str> {
        by_severity(list)
            .into_iter()
            .map(|f| f.description.as_str())
            .collect()
    }

    #[test]
    fn the_worst_finding_prints_first() {
        let list = vec![
            finding(VulnerabilityType::UtxoAgeSpread, Severity::Low, "spread"),
            finding(VulnerabilityType::Cioh, Severity::Critical, "cioh"),
            finding(VulnerabilityType::AddressReuse, Severity::High, "reuse"),
        ];
        assert_eq!(descriptions(&list), ["cioh", "reuse", "spread"]);
    }

    #[test]
    fn equal_severities_keep_the_engine_order() {
        let list = vec![
            finding(VulnerabilityType::DormantUtxos, Severity::Low, "dormant"),
            finding(
                VulnerabilityType::ChangeDetection,
                Severity::Medium,
                "change",
            ),
            finding(
                VulnerabilityType::Consolidation,
                Severity::Medium,
                "consolidation",
            ),
        ];
        assert_eq!(descriptions(&list), ["change", "consolidation", "dormant"]);
    }

    fn report(findings: Vec<Finding>, warnings: Vec<Finding>) -> stealth_engine::Report {
        let stats = stealth_engine::types::Stats {
            transactions_analyzed: 3,
            addresses_seen: 3,
            utxos_current: 1,
            addresses_without_history: 0,
        };
        stealth_engine::Report::new(stats, findings, warnings)
    }

    fn position(text: &str, needle: &str) -> usize {
        text.find(needle)
            .unwrap_or_else(|| panic!("{needle:?} missing from:\n{text}"))
    }

    #[test]
    fn the_text_report_keeps_its_shape() {
        let text = text_report(&report(
            vec![finding(VulnerabilityType::Cioh, Severity::Critical, "cioh")],
            vec![finding(
                VulnerabilityType::DormantUtxos,
                Severity::Low,
                "dormant",
            )],
        ));
        assert_eq!(
            text,
            "Scanned 3 transactions, 3 addresses, 1 current UTXOs\n\n\
             Findings (1):\n  [CRITICAL] CIOH: cioh\n\n\
             Warnings (1):\n  [LOW] DORMANT_UTXOS: dormant\n"
        );
    }

    #[test]
    fn an_empty_report_keeps_its_shape() {
        let stats = stealth_engine::types::Stats {
            transactions_analyzed: 0,
            addresses_seen: 1,
            utxos_current: 0,
            addresses_without_history: 0,
        };
        let text = text_report(&stealth_engine::Report::new(stats, Vec::new(), Vec::new()));
        assert_eq!(
            text,
            "Scanned 0 transactions, 1 addresses, 0 current UTXOs\n\n\
             No transactions found for this input.\n\
             Nothing was analyzed — this can mean an unused address, purely off-chain \
             (e.g. Lightning) history, or a node still catching up to the chain tip.\n"
        );
    }

    #[test]
    fn a_clean_report_keeps_its_shape() {
        let text = text_report(&report(Vec::new(), Vec::new()));
        assert_eq!(
            text,
            "Scanned 3 transactions, 3 addresses, 1 current UTXOs\n\nNo privacy issues found.\n"
        );
    }

    #[test]
    fn the_text_report_names_the_history_the_node_could_not_serve() {
        let stats = stealth_engine::types::Stats {
            transactions_analyzed: 2,
            addresses_seen: 2,
            utxos_current: 2,
            addresses_without_history: 2,
        };
        let text = text_report(&stealth_engine::Report::new(
            stats,
            vec![finding(VulnerabilityType::Dust, Severity::Medium, "dust")],
            Vec::new(),
        ));
        assert!(
            text.contains("could not serve the chain history of 2 addresses"),
            "{text}"
        );
        assert!(
            position(&text, "could not serve") < position(&text, "Findings (1):"),
            "the caveat comes before the findings it qualifies:\n{text}"
        );
    }

    #[test]
    fn a_clean_verdict_over_unserved_history_still_carries_the_caveat() {
        let stats = stealth_engine::types::Stats {
            transactions_analyzed: 2,
            addresses_seen: 1,
            utxos_current: 2,
            addresses_without_history: 1,
        };
        let text = text_report(&stealth_engine::Report::new(stats, Vec::new(), Vec::new()));
        assert!(text.contains("No privacy issues found."), "{text}");
        assert!(
            text.contains("could not serve the chain history of 1 address;"),
            "{text}"
        );
    }

    #[test]
    fn a_findings_only_report_ends_with_its_blank_line() {
        let text = text_report(&report(
            vec![finding(VulnerabilityType::Cioh, Severity::Critical, "cioh")],
            Vec::new(),
        ));
        assert!(
            text.ends_with("Findings (1):\n  [CRITICAL] CIOH: cioh\n\n"),
            "{text:?}"
        );
    }

    #[test]
    fn a_warnings_only_report_ends_with_its_last_line() {
        let text = text_report(&report(
            Vec::new(),
            vec![finding(
                VulnerabilityType::DormantUtxos,
                Severity::Low,
                "dormant",
            )],
        ));
        assert!(
            text.ends_with("Warnings (1):\n  [LOW] DORMANT_UTXOS: dormant\n"),
            "{text:?}"
        );
    }

    #[test]
    fn the_text_report_prints_findings_worst_first() {
        let text = text_report(&report(
            vec![
                finding(VulnerabilityType::UtxoAgeSpread, Severity::Low, "spread"),
                finding(VulnerabilityType::Cioh, Severity::Critical, "cioh"),
            ],
            Vec::new(),
        ));
        assert!(position(&text, "[CRITICAL] CIOH") < position(&text, "[LOW] UTXO_AGE_SPREAD"));
    }

    #[test]
    fn the_text_report_prints_warnings_worst_first() {
        let text = text_report(&report(
            Vec::new(),
            vec![
                finding(VulnerabilityType::DormantUtxos, Severity::Low, "dormant"),
                finding(VulnerabilityType::TaintedUtxoMerge, Severity::High, "taint"),
            ],
        ));
        assert!(position(&text, "[HIGH] TAINTED") < position(&text, "[LOW] DORMANT"));
    }
}
