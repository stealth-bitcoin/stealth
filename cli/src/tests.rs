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

mod rpc_auth {
    use crate::*;

    fn temp_cookie(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("stealth-cli-{}-{name}.cookie", std::process::id()));
        std::fs::write(&path, "__cookie__:secret").unwrap();
        path
    }

    #[test]
    fn explicit_user_and_pass_win_over_a_cookie() {
        let cookie = temp_cookie("explicit");
        let auth = select_rpc_auth(Some("u".into()), Some("p".into()), Some(cookie.clone()));
        std::fs::remove_file(&cookie).unwrap();
        assert_eq!(auth, Ok(RpcAuth::UserPass("u".into(), "p".into())));
    }

    #[test]
    fn a_cookie_is_handed_over_as_a_path() {
        let cookie = temp_cookie("given");
        let auth = select_rpc_auth(Some("u".into()), None, Some(cookie.clone()));
        std::fs::remove_file(&cookie).unwrap();
        assert_eq!(auth, Ok(RpcAuth::CookieFile(cookie)));
    }

    #[test]
    fn an_unreadable_cookie_fails_up_front() {
        assert!(select_rpc_auth(None, None, Some(PathBuf::from("/nowhere/.cookie"))).is_err());
    }

    #[test]
    fn nothing_configured_means_no_auth() {
        assert_eq!(select_rpc_auth(None, None, None), Ok(RpcAuth::None));
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
            conflicted_txids: Vec::new(),
            mempool_conflicted_txids: Vec::new(),
            abandoned_txids: Vec::new(),
            unavailable_txids: Vec::new(),
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
            conflicted_txids: Vec::new(),
            mempool_conflicted_txids: Vec::new(),
            abandoned_txids: Vec::new(),
            unavailable_txids: Vec::new(),
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
            conflicted_txids: Vec::new(),
            mempool_conflicted_txids: Vec::new(),
            abandoned_txids: Vec::new(),
            unavailable_txids: Vec::new(),
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
            conflicted_txids: Vec::new(),
            mempool_conflicted_txids: Vec::new(),
            abandoned_txids: Vec::new(),
            unavailable_txids: Vec::new(),
        };
        let text = text_report(&stealth_engine::Report::new(stats, Vec::new(), Vec::new()));
        assert!(text.contains("No privacy issues found."), "{text}");
        assert!(
            text.contains("could not serve the chain history of 1 address;"),
            "{text}"
        );
    }

    const CONFLICTED: &str = "515ef5fdbfaebe7e5819b68a302739e92d7485517893b8fd3f7706e5496b2ccb";

    #[test]
    fn the_text_report_names_each_conflicted_tx_it_left_out() {
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.conflicted_txids = vec![CONFLICTED.parse().unwrap()];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 1 transaction Core reports as conflicted: it, or a transaction \
                 it depends on, conflicts with another one, so it is not part of the wallet's \
                 history. It may still have been seen by the network before it became conflicted; \
                 Stealth does not analyze it.\n  {CONFLICTED}\n"
            )),
            "{text}"
        );
        assert!(
            position(&text, CONFLICTED) < position(&text, "No privacy issues found."),
            "the note comes before the verdict:\n{text}"
        );
    }

    #[test]
    fn the_conflicted_note_counts_several() {
        let other = "a179853216e3e6c3bee813fb7f16c5cf4b81a85e974ebd8a99f45ebd13add7ab";
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.conflicted_txids = vec![CONFLICTED.parse().unwrap(), other.parse().unwrap()];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 2 transactions Core reports as conflicted: each, or a transaction \
                 it depends on, conflicts with another one, so they are not part of the wallet's \
                 history. They may still have been seen by the network before they became \
                 conflicted; Stealth does not analyze them.\n  {CONFLICTED}\n  {other}\n"
            )),
            "{text}"
        );
    }

    #[test]
    fn a_scan_whose_every_tx_was_conflicted_gives_no_empty_scan_hint() {
        let stats = stealth_engine::types::Stats {
            transactions_analyzed: 0,
            addresses_seen: 1,
            utxos_current: 0,
            addresses_without_history: 0,
            conflicted_txids: vec![CONFLICTED.parse().unwrap()],
            mempool_conflicted_txids: Vec::new(),
            abandoned_txids: Vec::new(),
            unavailable_txids: Vec::new(),
        };
        let text = text_report(&stealth_engine::Report::new(stats, Vec::new(), Vec::new()));
        assert!(text.contains(CONFLICTED), "{text}");
        assert!(
            text.ends_with(&format!(
                "  {CONFLICTED}\n\nNothing else was left to analyze.\n"
            )),
            "{text}"
        );
        assert!(!text.contains("No transactions found"), "{text}");
        assert!(!text.contains("unused address"), "{text}");
    }

    const REPLACEMENT: &str = "a179853216e3e6c3bee813fb7f16c5cf4b81a85e974ebd8a99f45ebd13add7ab";

    fn replaced(txid: &str, by: &str) -> stealth_engine::types::MempoolConflict {
        stealth_engine::types::MempoolConflict {
            txid: txid.parse().unwrap(),
            conflicts_with: by.parse().unwrap(),
        }
    }

    #[test]
    fn the_text_report_names_a_replaced_tx_and_its_replacement() {
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.mempool_conflicted_txids = vec![replaced(CONFLICTED, REPLACEMENT)];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 1 transaction that conflicts, or depends on one that conflicts, with \
                 a transaction in the mempool. It may still confirm; until then it is not part \
                 of the history the wallet sees. It may still have been seen by the network \
                 before the conflicting one reached the mempool; Stealth does not analyze it.\n  \
                 {CONFLICTED}: it, or a transaction it depends on, conflicts with {REPLACEMENT}, \
                 which is in the mempool and not confirmed yet\n"
            )),
            "{text}"
        );
        assert!(
            position(&text, REPLACEMENT) < position(&text, "No privacy issues found."),
            "{text}"
        );
    }

    #[test]
    fn a_descendant_of_a_tx_in_conflict_with_the_mempool_is_not_said_to_conflict_itself() {
        // A payment double-spent in the mempool, and a child spending its change.
        let child = "f5561a23e573423aeb6d9200aaf74db3ac73c83fae52f5261520d28506dadcd9";
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.mempool_conflicted_txids = vec![
            replaced(CONFLICTED, REPLACEMENT),
            replaced(child, REPLACEMENT),
        ];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "  {child}: it, or a transaction it depends on, conflicts with {REPLACEMENT}, \
                 which is in the mempool and not confirmed yet\n"
            )),
            "{text}"
        );
        assert!(!text.contains(&format!("{child} conflicts with")), "{text}");
    }

    #[test]
    fn the_replaced_note_counts_several() {
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.mempool_conflicted_txids = vec![
            replaced(CONFLICTED, REPLACEMENT),
            replaced(REPLACEMENT, CONFLICTED),
        ];
        let text = text_report(&clean);
        assert!(
            text.contains(
                "Left out 2 transactions that conflict, or depend on ones that conflict, with \
                 transactions in the mempool. They may still confirm; until then they are not \
                 part of the history the wallet sees. They may still have been seen by the \
                 network before the conflicting ones reached the mempool; Stealth does not \
                 analyze them.\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_text_report_names_abandoned_txs() {
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.abandoned_txids = vec![CONFLICTED.parse().unwrap()];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 1 transaction that was abandoned in the wallet. It may still confirm; \
                 until then it is not part of the history the wallet sees. It may still have been seen by the network before it was \
                 abandoned; Stealth does not analyze it.\n  {CONFLICTED}\n"
            )),
            "{text}"
        );
        clean
            .stats
            .abandoned_txids
            .push(REPLACEMENT.parse().unwrap());
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 2 transactions that were abandoned in the wallet. They may still \
                 confirm; until then they are not part of the history the wallet sees. They may still have been seen by the network before \
                 they were abandoned; Stealth does not analyze them.\n  {CONFLICTED}\n  \
                 {REPLACEMENT}\n"
            )),
            "{text}"
        );
    }

    #[test]
    fn a_scan_whose_every_tx_was_replaced_or_abandoned_gives_no_empty_scan_hint() {
        for (mempool_conflicted_txids, abandoned_txids) in [
            (vec![replaced(CONFLICTED, REPLACEMENT)], Vec::new()),
            (Vec::new(), vec![CONFLICTED.parse().unwrap()]),
        ] {
            let stats = stealth_engine::types::Stats {
                transactions_analyzed: 0,
                addresses_seen: 1,
                utxos_current: 0,
                addresses_without_history: 0,
                conflicted_txids: Vec::new(),
                mempool_conflicted_txids,
                abandoned_txids,
                unavailable_txids: Vec::new(),
            };
            let text = text_report(&stealth_engine::Report::new(stats, Vec::new(), Vec::new()));
            assert!(text.contains(CONFLICTED), "{text}");
            assert!(
                text.ends_with("\n\nNothing else was left to analyze.\n"),
                "{text}"
            );
            assert!(!text.contains("No transactions found"), "{text}");
        }
    }

    #[test]
    fn the_text_report_names_unconfirmed_txs_the_node_no_longer_has() {
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.unavailable_txids = vec![CONFLICTED.parse().unwrap()];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 1 transaction that is unconfirmed and that this node no longer has (it \
                 may have been replaced or double-spent, expired or been evicted from the \
                 mempool, never been broadcast, or depend on a transaction that was). It may \
                 still confirm unless a conflicting transaction is mined; until then it is not \
                 part of the history the wallet sees. Stealth does not analyze it.\n  \
                 {CONFLICTED}\n"
            )),
            "{text}"
        );
        clean
            .stats
            .unavailable_txids
            .push(REPLACEMENT.parse().unwrap());
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 2 transactions that are unconfirmed and that this node no longer has \
                 (they may have been replaced or double-spent, expired or been evicted from the \
                 mempool, never been broadcast, or depend on a transaction that was). They may \
                 still confirm unless a conflicting transaction is mined; until then they are not \
                 part of the history the wallet sees. Stealth does not analyze them.\n  \
                 {CONFLICTED}\n  {REPLACEMENT}\n"
            )),
            "{text}"
        );
    }

    #[test]
    fn a_scan_whose_every_tx_was_unavailable_gives_no_empty_scan_hint() {
        let mut stats = report(Vec::new(), Vec::new()).stats;
        stats.transactions_analyzed = 0;
        stats.unavailable_txids = vec![CONFLICTED.parse().unwrap()];
        let text = text_report(&stealth_engine::Report::new(stats, Vec::new(), Vec::new()));
        assert!(
            text.ends_with("\n\nNothing else was left to analyze.\n"),
            "{text}"
        );
        assert!(!text.contains("No transactions found"), "{text}");
    }

    #[test]
    fn a_report_without_conflicted_txs_has_no_note() {
        let text = text_report(&report(Vec::new(), Vec::new()));
        assert!(!text.contains("conflicted"), "{text}");
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
