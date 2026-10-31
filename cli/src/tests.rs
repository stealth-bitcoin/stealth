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
            orphaned_txids: Vec::new(),
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
            orphaned_txids: Vec::new(),
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
            orphaned_txids: Vec::new(),
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
            orphaned_txids: Vec::new(),
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
                 history. It can only come back if a reorg removes the conflicting block. If it \
                 was broadcast, it may have been seen by the network before it became \
                 conflicted; Stealth does not analyze it.\n  {CONFLICTED}\n"
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
                 history. They can only come back if a reorg removes the block or blocks holding the \
                 conflicting transactions. If they were broadcast, they may have been seen by the network before they became \
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
            orphaned_txids: Vec::new(),
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
                 of the history the wallet sees. If it was broadcast, it may have been seen by \
                 the network before the conflicting one reached the mempool; Stealth does not \
                 analyze it.\n  \
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
                 part of the history the wallet sees. If they were broadcast, they may have been \
                 seen by the network before the conflicting ones reached the mempool; Stealth \
                 does not analyze them.\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn several_left_out_against_one_mempool_tx_name_it_in_the_singular() {
        // A raw double spend and the child of the payment it replaced, or a double bump.
        let child = "f5561a23e573423aeb6d9200aaf74db3ac73c83fae52f5261520d28506dadcd9";
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.mempool_conflicted_txids = vec![
            replaced(CONFLICTED, REPLACEMENT),
            replaced(child, REPLACEMENT),
        ];
        let text = text_report(&clean);
        assert!(
            text.contains(
                "Left out 2 transactions that conflict, or depend on ones that conflict, with \
                 a transaction in the mempool. They may still confirm; until then they are not \
                 part of the history the wallet sees. If they were broadcast, they may have been \
                 seen by the network before the conflicting one reached the mempool; Stealth \
                 does not analyze them.\n"
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
                "Left out 1 transaction that was abandoned in the wallet, by hand or by Core \
                 after a reorg removed a coinbase it depends on. It may still confirm, unless it \
                 depends on a coinbase a reorg removed; until then it is not part of the history \
                 the wallet sees. If it was broadcast, it \
                 may have been seen by the network before it was abandoned; Stealth does not \
                 analyze it.\n  {CONFLICTED}\n"
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
                "Left out 2 transactions that were abandoned in the wallet, by hand or by Core \
                 after a reorg removed a coinbase they depend on. They may still confirm, unless \
                 they depend on a coinbase a reorg removed; until then they are not part of the \
                 history the wallet sees. If they \
                 were broadcast, they may have been seen by the network before they were \
                 abandoned; Stealth does not analyze them.\n  {CONFLICTED}\n  {REPLACEMENT}\n"
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
                orphaned_txids: Vec::new(),
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
    fn the_text_report_names_unconfirmed_txs_the_node_does_not_have() {
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.unavailable_txids = vec![CONFLICTED.parse().unwrap()];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 1 transaction that is unconfirmed and that this node does not have (it \
                 may have been replaced or double-spent, expired or been evicted from the \
                 mempool, never been broadcast, or depend on a transaction that was). It may \
                 still confirm, unless it or a transaction it depends on has a conflicting \
                 transaction mined; until then it is not part of the history the wallet sees. Stealth does not analyze it.\n  \
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
                "Left out 2 transactions that are unconfirmed and that this node does not have \
                 (they may have been replaced or double-spent, expired or been evicted from the \
                 mempool, never been broadcast, or depend on a transaction that was). They may \
                 still confirm, unless they or a transaction they depend on has a conflicting \
                 transaction mined; until then they are not part of the history the wallet sees. Stealth does not analyze them.\n  \
                 {CONFLICTED}\n  {REPLACEMENT}\n"
            )),
            "{text}"
        );
    }

    #[test]
    fn the_text_report_names_orphaned_coinbases() {
        let mut clean = report(Vec::new(), Vec::new());
        clean.stats.orphaned_txids = vec![CONFLICTED.parse().unwrap()];
        let text = text_report(&clean);
        assert!(
            text.contains(&format!(
                "Left out 1 transaction that is a coinbase from a block no longer in the chain. \
                 It can only come back if a reorg restores that block; until then it is not \
                 part of the history the wallet sees. Stealth does not analyze it.\n  \
                 {CONFLICTED}\n"
            )),
            "{text}"
        );
        clean
            .stats
            .orphaned_txids
            .push(REPLACEMENT.parse().unwrap());
        let text = text_report(&clean);
        assert!(
            text.contains(
                "Left out 2 transactions that are coinbases from blocks no longer in the chain. \
                 They can only come back if a reorg restores those blocks; until then they are \
                 not part of the history the wallet sees. Stealth does not analyze them.\n"
            ),
            "{text}"
        );
        let mut empty = clean.stats.clone();
        empty.transactions_analyzed = 0;
        let text = text_report(&stealth_engine::Report::new(empty, Vec::new(), Vec::new()));
        assert!(
            text.ends_with("\n\nNothing else was left to analyze.\n"),
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

mod history_limit {
    use crate::*;
    use stealth_engine::error::{AnalysisError, HistoryOf};

    fn to_args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn limit_of(parts: &[&str]) -> Option<u64> {
        parse_scan_args(&to_args(parts))
            .expect("flags")
            .engine_settings()
            .expect("settings")
            .history_limit
            .max_txs
    }

    #[test]
    fn the_default_limit_is_5000() {
        assert_eq!(limit_of(&["--descriptor", "wpkh(x/0/*)"]), Some(5_000));
    }

    #[test]
    fn max_txs_sets_the_limit() {
        assert_eq!(
            limit_of(&["--descriptor", "wpkh(x/0/*)", "--max-txs", "3"]),
            Some(3)
        );
    }

    #[test]
    fn no_limits_lifts_it() {
        assert_eq!(
            limit_of(&["--descriptor", "wpkh(x/0/*)", "--no-limits"]),
            None
        );
    }

    #[test]
    fn max_txs_needs_a_whole_number() {
        for value in ["many", "1.5", "-3"] {
            assert!(
                parse_scan_args(&to_args(&["--max-txs", value])).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn max_txs_and_no_limits_do_not_go_together() {
        let error = parse_scan_args(&to_args(&["--max-txs", "3", "--no-limits"]))
            .expect_err("conflicting flags");
        assert!(error.contains("--max-txs"), "{error}");
        assert!(error.contains("--no-limits"), "{error}");
    }

    #[test]
    fn a_stop_names_the_count_and_the_flags_that_go_on() {
        let message = scan_error(AnalysisError::HistoryTooLarge {
            of: HistoryOf::Wallet,
            tx_count: 12_345,
            limit: 5_000,
        });
        assert!(message.contains("12345 transactions"), "{message}");
        assert!(message.contains("limit of 5000"), "{message}");
        assert!(
            message.ends_with(
                "; to scan it anyway, pass --no-limits, or --max-txs with at least 12345, \
                 higher if the history may grow"
            ),
            "{message}"
        );
    }

    #[test]
    fn a_utxo_stop_names_the_addresses_of_the_outputs_in_the_utxo_file() {
        let message = scan_error(AnalysisError::HistoryTooLarge {
            of: HistoryOf::PastedAddresses,
            tx_count: 12_345,
            limit: 5_000,
        });
        assert!(
            message.starts_with(
                "the history of the addresses of the outputs in the UTXO file holds 12345 \
                 transactions, more than the limit of 5000"
            ),
            "{message}"
        );
        assert!(!message.contains("pasted"), "{message}");
        assert!(message.contains("--no-limits"), "{message}");
    }

    #[test]
    fn a_wallet_stop_keeps_the_shared_wording() {
        let error = AnalysisError::HistoryTooLarge {
            of: HistoryOf::Wallet,
            tx_count: 12_345,
            limit: 5_000,
        };
        assert!(scan_error(error.clone()).starts_with(&error.to_string()));
    }

    #[test]
    fn any_other_error_keeps_its_message() {
        let error = AnalysisError::EnvironmentUnavailable("down".into());
        assert_eq!(scan_error(error.clone()), error.to_string());
    }

    fn answer_about(of: HistoryOf, typed: &str) -> (bool, String) {
        let mut shown = Vec::new();
        show_question(of, 12_345, 5_000, &mut shown);
        (is_yes(typed), String::from_utf8(shown).expect("utf-8"))
    }

    fn answer(typed: &str) -> (bool, String) {
        answer_about(HistoryOf::Wallet, typed)
    }

    #[test]
    fn the_prompt_names_whose_history_it_counted() {
        let (_, wallet) = answer_about(HistoryOf::Wallet, "n\n");
        assert!(
            wallet.starts_with("This wallet's history holds 12345"),
            "{wallet}"
        );
        let (_, pasted) = answer_about(HistoryOf::PastedAddresses, "n\n");
        assert!(
            pasted.starts_with(
                "The history of the addresses of the outputs in the UTXO file holds 12345"
            ),
            "{pasted}"
        );
    }

    /// The asker installed for a terminal, reading `typed` and writing nowhere.
    fn asked_with(typed: &'static str) -> HistoryLimit {
        let interrupts = Arc::new(Interrupts::default());
        HistoryLimit {
            ask: Some(terminal_ask(
                move || typed.as_bytes(),
                io::sink,
                interrupts,
                || true,
                || {},
            )),
            ..HistoryLimit::at_most(3)
        }
    }

    /// A reader that blocks until the test ends.
    struct Silent(std::sync::mpsc::Receiver<()>);

    impl io::Read for Silent {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn an_interrupt_while_the_question_waits_is_a_no() {
        let interrupts = Arc::new(Interrupts::default());
        let (_keep_blocked, silence) = std::sync::mpsc::channel::<()>();
        let silence = std::sync::Mutex::new(Some(silence));
        let limit = HistoryLimit {
            ask: Some(terminal_ask(
                move || {
                    let silence = silence.lock().unwrap().take().expect("asked once");
                    io::BufReader::new(Silent(silence))
                },
                io::sink,
                Arc::clone(&interrupts),
                || true,
                || {},
            )),
            ..HistoryLimit::at_most(3)
        };
        let asking = std::thread::spawn(move || limit.check(5));
        while !interrupts.waiting_for_an_answer() {
            std::thread::yield_now();
        }
        assert!(
            !interrupts.interrupt(),
            "an answered interrupt does not exit"
        );
        assert!(asking.join().unwrap().is_err());
        assert!(interrupts.interrupt(), "the next interrupt exits");
    }

    #[test]
    fn an_interrupt_outside_the_question_exits_at_once() {
        assert!(Interrupts::default().interrupt());
    }

    fn interrupts_after_answering(typed: &'static str) -> Arc<Interrupts> {
        let interrupts = Arc::new(Interrupts::default());
        let limit = HistoryLimit {
            ask: Some(terminal_ask(
                move || typed.as_bytes(),
                io::sink,
                Arc::clone(&interrupts),
                || true,
                || {},
            )),
            ..HistoryLimit::at_most(3)
        };
        let _ = limit.check(5);
        interrupts
    }

    #[test]
    fn after_a_typed_no_the_next_interrupt_exits() {
        assert!(interrupts_after_answering("n\n").interrupt());
    }

    #[test]
    fn an_interrupt_after_the_typed_yes_won_exits() {
        let interrupts = Interrupts::default();
        let (reply, _answer) = std::sync::mpsc::channel();
        interrupts.begin_asking(reply);
        assert!(interrupts.answer(), "the typed answer came first");
        assert!(interrupts.interrupt(), "an interrupt in the gap exits");
    }

    #[test]
    fn a_typed_answer_after_the_interrupt_won_is_dropped() {
        let interrupts = Interrupts::default();
        let (reply, answer) = std::sync::mpsc::channel();
        interrupts.begin_asking(reply);
        assert!(!interrupts.interrupt());
        assert!(!interrupts.answer(), "the interrupt answered first");
        assert!(matches!(answer.try_recv(), Ok(Reply::Interrupted)));
        assert!(interrupts.interrupt(), "the next interrupt exits");
    }

    #[test]
    fn after_a_yes_an_interrupt_exits_at_once() {
        assert!(interrupts_after_answering("y\n").interrupt());
    }

    #[test]
    fn only_a_terminal_on_both_stdin_and_stderr_is_asked() {
        assert!(should_ask(true, true, true));
        assert!(!should_ask(true, false, true));
        assert!(!should_ask(false, true, true));
        assert!(!should_ask(false, false, true));
    }

    #[test]
    fn typed_ahead_input_is_dropped_before_the_question_shows() {
        struct Log(Arc<std::sync::Mutex<Vec<&'static str>>>);
        impl io::Write for Log {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().push("shown");
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (shown, dropped) = (Arc::clone(&events), Arc::clone(&events));
        let limit = HistoryLimit {
            ask: Some(terminal_ask(
                || "n\n".as_bytes(),
                move || Log(Arc::clone(&shown)),
                Arc::new(Interrupts::default()),
                || true,
                move || dropped.lock().unwrap().push("dropped"),
            )),
            ..HistoryLimit::at_most(3)
        };
        let _ = limit.check(5);
        assert_eq!(events.lock().unwrap().first(), Some(&"dropped"));
    }

    #[test]
    fn the_scan_is_interruptible_only_once_the_handler_is_installed() {
        assert!(install_interrupt_handler(false, || true));
        assert!(
            !install_interrupt_handler(false, || false),
            "installing failed"
        );
        assert!(
            !install_interrupt_handler(true, || panic!("an ignored SIGINT gets no handler")),
            "SIGINT ignored"
        );
    }

    #[test]
    fn a_scan_whose_interrupt_is_ignored_is_not_asked() {
        assert!(!should_ask(true, true, false));
    }

    /// A terminal that records being read, and answers with an empty line.
    struct Watched(Arc<std::sync::atomic::AtomicBool>);

    impl io::Read for Watched {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
    }

    #[test]
    fn a_scan_sent_to_the_background_before_the_question_is_refused_unasked() {
        let in_the_foreground = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let probe = Arc::clone(&in_the_foreground);
        let shown = Arc::new(std::sync::Mutex::new(Vec::new()));
        let screen = Arc::clone(&shown);
        let read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let touched = Arc::clone(&read);
        struct Shared(Arc<std::sync::Mutex<Vec<u8>>>);
        impl io::Write for Shared {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let limit = HistoryLimit {
            ask: Some(terminal_ask(
                move || io::BufReader::new(Watched(Arc::clone(&touched))),
                move || Shared(Arc::clone(&screen)),
                Arc::new(Interrupts::default()),
                move || probe.load(std::sync::atomic::Ordering::Relaxed),
                || {},
            )),
            ..HistoryLimit::at_most(3)
        };
        // Started in the foreground, then put in the background during the rescan.
        in_the_foreground.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(limit.check(5).is_err());
        assert!(shown.lock().unwrap().is_empty(), "nothing is asked");
        assert!(
            !read.load(std::sync::atomic::Ordering::Relaxed),
            "the terminal is not read"
        );
    }

    #[test]
    fn the_terminal_asker_goes_on_only_on_a_yes() {
        assert_eq!(asked_with("y\n").check(5), Ok(()));
        for typed in ["n\n", "\n", ""] {
            assert!(asked_with(typed).check(5).is_err(), "{typed:?}");
        }
    }

    #[test]
    fn the_prompt_says_how_many_txs_and_what_loading_them_costs() {
        let (_, shown) = answer("n\n");
        assert!(shown.contains("12345 transactions"), "{shown}");
        assert!(shown.contains("limit of 5000"), "{shown}");
        assert!(shown.contains("take long"), "{shown}");
        assert!(shown.contains("load on the node"), "{shown}");
        assert!(shown.contains("[y/N]"), "{shown}");
    }

    #[test]
    fn only_a_yes_goes_on() {
        for typed in ["y\n", "Y\n", "yes\n", " YES \n"] {
            assert!(answer(typed).0, "{typed:?}");
        }
        for typed in ["\n", "n\n", "no\n", "", "sure\n"] {
            assert!(!answer(typed).0, "{typed:?}");
        }
    }

    #[test]
    fn a_terminal_gets_asked_and_a_pipe_does_not() {
        let opts = ScanOpts::default();
        let ask: AskToGoOn = Arc::new(|_, _, _| true);
        assert!(opts.history_limit(Some(ask)).ask.is_some());
        assert!(opts.history_limit(None).ask.is_none());
    }

    #[test]
    fn with_the_limit_lifted_nobody_is_asked() {
        let opts = ScanOpts {
            no_limits: true,
            ..ScanOpts::default()
        };
        let ask: AskToGoOn = Arc::new(|_, _, _| true);
        assert!(opts.history_limit(Some(ask)).ask.is_none());
    }
}

mod usage {
    use crate::*;

    #[test]
    fn max_txs_says_whose_history_it_limits() {
        let text = usage();
        let flag = text.find("--max-txs <N>").expect("--max-txs in the help");
        let entry = &text[flag..text[flag..]
            .find("--no-limits")
            .map_or(text.len(), |end| flag + end)];
        let entry = entry.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(entry.contains("the wallet's history"), "{entry}");
        assert!(
            entry.contains(
                "in UTXO mode, the history of the addresses of the outputs in the UTXO file"
            ),
            "{entry}"
        );
        assert!(
            entry.contains(
                "only when run in the foreground with stdin and stderr on a terminal and \
                 Ctrl-C not ignored"
            ),
            "{entry}"
        );
    }
}
