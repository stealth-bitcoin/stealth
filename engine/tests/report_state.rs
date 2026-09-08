// In-memory report-state tests: an empty wallet history must be reported
// as "analyzed nothing", distinct from a scanned-and-clean wallet.

use std::collections::{HashMap, HashSet};

use stealth_engine::config::DetectorThresholds;
use stealth_engine::gateway::WalletHistory;
use stealth_engine::TxGraph;

fn empty_history() -> WalletHistory {
    WalletHistory {
        wallet_txs: Vec::new(),
        utxos: Vec::new(),
        transactions: HashMap::new(),
        internal_addresses: HashSet::new(),
        derived_addresses: HashSet::new(),
    }
}

#[test]
fn empty_history_reports_analyzed_nothing_not_clean() {
    let graph = TxGraph::from_wallet_history(empty_history());
    let report = graph.detect_all(&DetectorThresholds::default(), None, None);

    assert_eq!(report.stats.transactions_analyzed, 0);
    assert!(
        report.summary.analyzed_nothing,
        "0 transactions analyzed must set analyzed_nothing"
    );
    assert!(
        !report.summary.clean,
        "nothing analyzed is not a clean history"
    );
}
