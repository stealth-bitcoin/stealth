//! Unit tests for the CLI binary.

mod args {
    use crate::*;

    fn to_args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_rescan_since() {
        let opts = parse_scan_args(&to_args(&[
            "--utxos",
            "u.json",
            "--rescan-since",
            "1700000000",
        ]))
        .unwrap();
        assert_eq!(opts.rescan_since, Some(1_700_000_000));
    }

    #[test]
    fn rejects_non_numeric_rescan_since() {
        assert!(parse_scan_args(&to_args(&["--rescan-since", "yesterday"])).is_err());
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
