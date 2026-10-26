import { useState } from 'react'
import FindingCard from '../components/FindingCard'
import VulnerabilityBadge from '../components/VulnerabilityBadge'
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
  // Historical, already-spent dust is a DUST finding too.
  DUST: (n) => `${n} dust outputs detected`,
  DUST_SPENDING: (n) => `${n} transactions spend dust alongside normal inputs`,
  CHANGE_DETECTION: (n) => `${n} transactions have identifiable change outputs`,
  CONSOLIDATION: (n) => `${n} UTXOs were born from input consolidations`,
  SCRIPT_TYPE_MIXING: (n) => `${n} transactions mix input script types`,
  CLUSTER_MERGE: (n) => `${n} transactions merge separate funding chains`,
  EXCHANGE_ORIGIN: (n) => `${n} transactions look like exchange batch withdrawals`,
  TAINTED_UTXO_MERGE: (n) => `${n} transactions merge tainted and clean inputs`,
  DIRECT_TAINT: (n) => `${n} transactions come directly from a risky source`,
  // One chain emits a finding per qualifying hop, so this counts findings.
  PEEL_CHAIN: (n) => `${n} peel-chain findings`,
  DETERMINISTIC_LINK: (n) => `${n} transactions have guessable input→output links`,
  UNNECESSARY_INPUT: (n) => `${n} transactions include unnecessary inputs`,
  TOXIC_CHANGE: (n) => `${n} toxic change outputs were later merged`,
}

function groupSummary(type, count, noun) {
  const fn = GROUP_SUMMARIES[type]
  if (fn) return fn(count)
  const label = String(type ?? '').toLowerCase().replace(/_/g, ' ').trim()
  return `${count} ${label} ${noun}s`.replace(/\s+/g, ' ')
}

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

// Severities vary inside one type, so a collapsed group must carry the worst.
function worstSeverity(items) {
  let worst = null
  for (const f of items) {
    if (!worst || (SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[worst] ?? 0)) {
      worst = f.severity
    }
  }
  return worst
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

function FindingGroup({ type, items, noun }) {
  const severity = worstSeverity(items)
  const [open, setOpen] = useState(severity === 'CRITICAL')
  return (
    <div className={styles.group}>
      <button className={styles.groupHeader} onClick={() => setOpen((o) => !o)}>
        <VulnerabilityBadge type={type} severity={severity} />
        <span className={styles.groupSummary}>{groupSummary(type, items.length, noun)}</span>
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

function FindingList({ list, noun = 'finding' }) {
  return (
    <div className={styles.findingList}>
      {groupByType(list).map((group, i) =>
        group.items.length > 1 ? (
          <FindingGroup key={i} type={group.type} items={group.items} noun={noun} />
        ) : (
          <FindingCard key={i} finding={group.items[0]} />
        ),
      )}
    </div>
  )
}

// The web UI always imports from genesis, so a scan window is never the cause.
function emptyHint(kind) {
  if (kind === 'utxos') {
    return 'Nothing was analyzed. None of the UTXO references you pasted could be ' +
      'resolved to an output this node can read: check that each vout exists in ' +
      'its transaction and belongs to a standard, addressable script.'
  }
  if (kind === 'address') {
    return 'Nothing was analyzed. This address has never appeared on-chain, or the ' +
      'node is still catching up to the chain tip.'
  }
  return 'Nothing was analyzed. This can mean a wallet that was never used, purely ' +
    'off-chain history (e.g. Lightning), a descriptor that derives different ' +
    'addresses than the ones you funded, or a node still catching up to the ' +
    'chain tip.'
}

// The classifier calls anything with parentheses a descriptor, so a pasted
// addr(...) arrives here as one despite being a single-address scan.
function effectiveKind(kind, descriptor) {
  if (kind === 'descriptor' && /^\s*addr\(/i.test(descriptor ?? '')) return 'address'
  return kind
}

export default function ReportScreen({ report, descriptor, kind: rawKind, onReset }) {
  const { stats, findings, warnings, summary } = report
  const kind = effectiveKind(rawKind, descriptor)

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
            scan its xpub or output descriptor instead: one address gives this scan
            no visibility into your other addresses or your change outputs.
          </div>
        )}

        {/* Nothing-analyzed banner */}
        {summary.analyzed_nothing && (
          <div className={styles.emptyBanner}>
            <strong>No transactions found for this input.</strong>
            <p className={styles.emptyHint}>{emptyHint(kind)}</p>
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
            <FindingList list={warnings} noun="warning" />
          </>
        )}
      </div>
    </div>
  )
}
