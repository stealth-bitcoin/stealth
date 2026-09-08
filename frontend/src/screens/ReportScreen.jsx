import { useState } from 'react'
import FindingCard from '../components/FindingCard'
import styles from './ReportScreen.module.css'

function truncateDescriptor(desc) {
  if (!desc || desc.length <= 80) return desc
  return `${desc.slice(0, 80)}…`
}

const KIND_LABELS = {
  address: 'Analyzed address',
  xpub: 'Analyzed xpub',
  utxos: 'Analyzed UTXO set',
  descriptor: 'Analyzed descriptor',
}

const GROUP_SUMMARIES = {
  ADDRESS_REUSE: (n) => `${n} addresses were reused across transactions`,
  CIOH: (n) => `${n} transactions merge your inputs (common-input-ownership)`,
  DUST: (n) => `${n} dust UTXOs detected`,
  DUST_SPENDING: (n) => `${n} transactions spend dust alongside normal inputs`,
  CHANGE_DETECTION: (n) => `${n} transactions have identifiable change outputs`,
  CONSOLIDATION: (n) => `${n} UTXOs were born from input consolidations`,
  SCRIPT_TYPE_MIXING: (n) => `${n} transactions mix input script types`,
  CLUSTER_MERGE: (n) => `${n} transactions merge separate funding chains`,
  EXCHANGE_ORIGIN: (n) => `${n} transactions look like exchange batch withdrawals`,
  TAINTED_UTXO_MERGE: (n) => `${n} transactions merge tainted and clean inputs`,
  DIRECT_TAINT: (n) => `${n} transactions come directly from a risky source`,
  PEEL_CHAIN: (n) => `${n} peel chains detected`,
  DETERMINISTIC_LINK: (n) => `${n} transactions have guessable input→output links`,
  UNNECESSARY_INPUT: (n) => `${n} transactions include unnecessary inputs`,
  TOXIC_CHANGE: (n) => `${n} toxic change outputs were later merged`,
}

function groupSummary(type, count) {
  const fn = GROUP_SUMMARIES[type]
  if (fn) return fn(count)
  const label = String(type ?? 'finding').toLowerCase().replace(/_/g, ' ')
  return `${count} ${label} findings`
}

function groupByType(list) {
  const order = []
  const byType = new Map()
  for (const f of list) {
    if (!byType.has(f.type)) {
      byType.set(f.type, [])
      order.push(f.type)
    }
    byType.get(f.type).push(f)
  }
  return order.map((type) => ({ type, items: byType.get(type) }))
}

function FindingGroup({ type, items }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={styles.group}>
      <button className={styles.groupHeader} onClick={() => setOpen((o) => !o)}>
        <span className={styles.groupSummary}>{groupSummary(type, items.length)}</span>
        <span className={`${styles.chevron} ${open ? styles.open : ''}`}>›</span>
      </button>
      {open && (
        <div className={styles.groupItems}>
          {items.map((f, i) => (
            <FindingCard key={i} finding={f} />
          ))}
        </div>
      )}
    </div>
  )
}

function FindingList({ list }) {
  return (
    <div className={styles.findingList}>
      {groupByType(list).map((group, i) =>
        group.items.length > 1 ? (
          <FindingGroup key={i} type={group.type} items={group.items} />
        ) : (
          <FindingCard key={i} finding={group.items[0]} />
        ),
      )}
    </div>
  )
}

export default function ReportScreen({ report, descriptor, kind, onReset }) {
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
            <span className={styles.descriptorLabel}>
              {KIND_LABELS[kind] ?? 'Analyzed descriptor'}
            </span>
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

        {/* Single-address scope note */}
        {kind === 'address' && (
          <div className={styles.scopeNote}>
            This audit covers only this single address. To review your whole wallet,
            scan its xpub or output descriptor instead — an address alone reveals
            nothing about your other addresses or change outputs.
          </div>
        )}

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
            <FindingList list={findings} />
          </>
        )}

        {/* Warnings */}
        {warnings.length > 0 && (
          <>
            <div className={styles.listHeader} style={{ marginTop: 28 }}>
              <span className={styles.listTitle}>Warnings</span>
            </div>
            <FindingList list={warnings} />
          </>
        )}
      </div>
    </div>
  )
}
