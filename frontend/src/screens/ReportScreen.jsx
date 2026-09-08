import FindingCard from '../components/FindingCard'
import styles from './ReportScreen.module.css'

function truncateDescriptor(desc) {
  if (!desc || desc.length <= 80) return desc
  return `${desc.slice(0, 80)}…`
}

export default function ReportScreen({ report, descriptor, onReset }) {
  const { stats, findings, warnings, summary } = report

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        {/* Nav */}
        <div className={styles.header}>
          <div className={styles.nav}>
            <div className={styles.wordmark}>
              STEAL<span>TH</span>
            </div>
            <button className={styles.backButton} onClick={onReset}>
              ← Analyze Another Wallet
            </button>
          </div>

          <div className={styles.descriptorBox}>
            <span className={styles.descriptorLabel}>Analyzed descriptor</span>
            <div className={styles.descriptorValue}>
              {truncateDescriptor(descriptor)}
            </div>
          </div>
        </div>

        {/* Summary bar */}
        <div className={styles.summaryBar}>
          <div className={`${styles.summaryCard} ${styles.vulnerable}`}>
            <div className={styles.summaryNumber}>{summary.findings}</div>
            <div className={styles.summaryLabel}>Findings</div>
          </div>
          <div className={`${styles.summaryCard} ${styles.warn}`}>
            <div className={styles.summaryNumber}>{summary.warnings}</div>
            <div className={styles.summaryLabel}>Warnings</div>
          </div>
          <div className={`${styles.summaryCard} ${styles.total}`}>
            <div className={styles.summaryNumber}>{stats.transactions_analyzed}</div>
            <div className={styles.summaryLabel}>Txs Analyzed</div>
          </div>
        </div>

        {/* Nothing-analyzed banner */}
        {summary.analyzed_nothing && (
          <div className={styles.emptyBanner}>
            <strong>No transactions found for this input.</strong>
            <p className={styles.emptyHint}>
              Nothing was analyzed. This can mean an unused address, a wallet whose
              activity predates the scan window, purely off-chain history (e.g.
              Lightning), or a node still catching up to the chain tip.
            </p>
          </div>
        )}

        {/* Clean banner */}
        {summary.clean && (
          <div className={styles.cleanBanner}>
            No privacy issues found — this wallet has a clean history.
          </div>
        )}

        {/* Findings */}
        {findings.length > 0 && (
          <>
            <div className={styles.listHeader}>
              <span className={styles.listTitle}>Findings</span>
            </div>
            <div className={styles.findingList}>
              {findings.map((f, i) => (
                <FindingCard key={i} finding={f} />
              ))}
            </div>
          </>
        )}

        {/* Warnings */}
        {warnings.length > 0 && (
          <>
            <div className={styles.listHeader} style={{ marginTop: 28 }}>
              <span className={styles.listTitle}>Warnings</span>
            </div>
            <div className={styles.findingList}>
              {warnings.map((w, i) => (
                <FindingCard key={i} finding={w} />
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
