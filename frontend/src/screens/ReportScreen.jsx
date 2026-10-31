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
  CIOH: (n) => `${n} transactions merge coins from several of your addresses (common-input-ownership)`,
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

function FindingGroup({ type, items, severity, noun }) {
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

const worstFirst = (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)

// The engine emits findings by detector; the reader goes top-down.
function FindingList({ list, noun = 'finding' }) {
  const groups = groupByType(list)
    .map((group) => {
      const items = [...group.items].sort(worstFirst)
      return { ...group, items, severity: items[0].severity }
    })
    .sort(worstFirst)
  return (
    <div className={styles.findingList}>
      {groups.map((group) =>
        group.items.length > 1 ? (
          <FindingGroup
            key={group.type}
            type={group.type}
            items={group.items}
            severity={group.severity}
            noun={noun}
          />
        ) : (
          <FindingCard key={group.type} finding={group.items[0]} />
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

// Why a note's transactions were left out, for one and for several; a settled
// one is out of the history for good, the others may still confirm.
const LEFT_OUT = {
  conflicted: {
    settled: true,
    one: 'Core reports as conflicted: it, or a transaction it depends on, conflicts with another one',
    many: 'Core reports as conflicted: each, or a transaction it depends on, conflicts with another one',
    beforeOne: 'it became conflicted',
    beforeMany: 'they became conflicted',
    // It may never have been broadcast.
    ifBroadcast: true,
    comesBackOne: 'It can only come back if a reorg removes the conflicting block',
    comesBackMany: 'They can only come back if a reorg removes the conflicting blocks',
  },
  mempoolConflicted: {
    settled: false,
    one: 'that conflicts, or depends on one that conflicts, with a transaction in the mempool',
    many: 'that conflict, or depend on ones that conflict, with transactions in the mempool',
    beforeOne: 'the conflicting one reached the mempool',
    beforeMany: 'the conflicting ones reached the mempool',
    // A wallet tx may be double-spent before it was ever broadcast.
    ifBroadcast: true,
  },
  // Several left out against one mempool tx.
  mempoolConflictedWithOne: {
    settled: false,
    one: 'that conflicts, or depends on one that conflicts, with a transaction in the mempool',
    many: 'that conflict, or depend on ones that conflict, with a transaction in the mempool',
    beforeOne: 'the conflicting one reached the mempool',
    beforeMany: 'the conflicting one reached the mempool',
    ifBroadcast: true,
  },
  abandoned: {
    settled: false,
    // Core abandons the descendants of a coinbase a reorg removed.
    one: 'that was abandoned in the wallet, by hand or by Core after a reorg removed a coinbase it depends on',
    many: 'that were abandoned in the wallet, by hand or by Core after a reorg removed a coinbase they depend on',
    beforeOne: 'it was abandoned',
    beforeMany: 'they were abandoned',
    ifBroadcast: true,
    unlessOne: 'it depends on a coinbase a reorg removed',
    unlessMany: 'they depend on a coinbase a reorg removed',
  },
  // A tx never broadcast was not seen, so this note says nothing about the network.
  unavailable: {
    settled: false,
    one: 'that is unconfirmed and that this node does not have (it may have been replaced or double-spent, expired or been evicted from the mempool, never been broadcast, or depend on a transaction that was)',
    many: 'that are unconfirmed and that this node does not have (they may have been replaced or double-spent, expired or been evicted from the mempool, never been broadcast, or depend on a transaction that was)',
    beforeOne: null,
    beforeMany: null,
    // What would stop it from confirming.
    unlessOne: 'it or a transaction it depends on has a conflicting transaction mined',
    unlessMany: 'they or a transaction they depend on has a conflicting transaction mined',
  },
  orphaned: {
    settled: false,
    one: 'that is a coinbase from a block no longer in the chain',
    many: 'that are coinbases from blocks no longer in the chain',
    beforeOne: null,
    beforeMany: null,
    // It cannot confirm as it stands; this is how it could come back.
    comesBackOne: 'It can only come back if a reorg restores that block',
    comesBackMany: 'They can only come back if a reorg restores those blocks',
  },
}

// "may still confirm", with what would stop it when the reason says.
function mayConfirm(reason, one) {
  const unless = one ? reason.unlessOne : reason.unlessMany
  return unless ? `may still confirm, unless ${unless}` : 'may still confirm'
}

// Whether the transactions are out for good, may still confirm, or could come back.
function standing(reason, one) {
  const part = one ? 'it is' : 'they are'
  const comesBack = one ? reason.comesBackOne : reason.comesBackMany
  if (reason.settled) {
    return `, so ${part} not part of the wallet's history.${comesBack ? ` ${comesBack}.` : ''}`
  }
  if (comesBack) return `. ${comesBack}; until then ${part} not part of the history the wallet sees.`
  return `. ${one ? 'It' : 'They'} ${mayConfirm(reason, one)}; until then ${part} not part of the history the wallet sees.`
}

// What the network may have seen, hedged when the tx may never have been broadcast.
function seenBefore(reason, one) {
  const before = one ? reason.beforeOne : reason.beforeMany
  if (reason.ifBroadcast) {
    const [it, was] = one ? ['it', 'was'] : ['they', 'were']
    return `If ${it} ${was} broadcast, ${it} may have been seen by the network before ${before}; `
  }
  return `${one ? 'It' : 'They'} may still have been seen by the network before ${before}; `
}

function LeftOutNote({ items, reason }) {
  if (items.length === 0) return null
  const one = items.length === 1
  return (
    <div className={styles.scopeNote}>
      <p className={styles.noteText}>
        Left out {items.length} {one ? 'transaction' : 'transactions'}{' '}
        {one ? reason.one : reason.many}
        {standing(reason, one)}{' '}
        {reason.beforeOne && seenBefore(reason, one)}
        Stealth does not analyze {one ? 'it' : 'them'}.
      </p>
      <ul className={styles.txidList}>
        {items.map((item) => (
          <li key={item} className={styles.txid}>{item}</li>
        ))}
      </ul>
    </div>
  )
}

export default function ReportScreen({ report, descriptor, kind: rawKind, onReset }) {
  const { stats, findings, warnings, summary } = report
  const kind = effectiveKind(rawKind, descriptor)
  const conflicted = stats.conflicted_txids ?? []
  const inMempoolConflict = (stats.mempool_conflicted_txids ?? []).map(
    (r) => `${r.txid}: it, or a transaction it depends on, conflicts with ${r.conflicts_with}, which is in the mempool and not confirmed yet`,
  )
  // The conflicting side counts the mempool txs, not the txs left out.
  const conflicting = new Set((stats.mempool_conflicted_txids ?? []).map((r) => r.conflicts_with))
  const mempoolReason =
    conflicting.size === 1 ? LEFT_OUT.mempoolConflictedWithOne : LEFT_OUT.mempoolConflicted
  const abandoned = stats.abandoned_txids ?? []
  const unavailable = stats.unavailable_txids ?? []
  const orphaned = stats.orphaned_txids ?? []
  const anyLeftOut =
    conflicted.length +
      inMempoolConflict.length +
      abandoned.length +
      unavailable.length +
      orphaned.length >
    0
  const emptyScan = summary.analyzed_nothing && findings.length === 0 && warnings.length === 0

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

        {/* History the node could not serve */}
        {stats.addresses_without_history > 0 && (
          <div className={styles.scopeNote}>
            The node could not serve the chain history of {stats.addresses_without_history}{' '}
            {stats.addresses_without_history === 1 ? 'address' : 'addresses'} behind these
            outputs; the counts for {stats.addresses_without_history === 1 ? 'it' : 'them'} cover
            only the outputs you pasted.
          </div>
        )}

        {/* Wallet transactions left out */}
        <LeftOutNote items={conflicted} reason={LEFT_OUT.conflicted} />
        <LeftOutNote items={inMempoolConflict} reason={mempoolReason} />
        <LeftOutNote items={abandoned} reason={LEFT_OUT.abandoned} />
        <LeftOutNote items={unavailable} reason={LEFT_OUT.unavailable} />
        <LeftOutNote items={orphaned} reason={LEFT_OUT.orphaned} />

        {/* Nothing-analyzed banner; the notes above already say why, when they are shown */}
        {emptyScan && anyLeftOut && (
          <div className={styles.emptyBanner}>
            <strong>Nothing else was left to analyze.</strong>
          </div>
        )}
        {emptyScan && !anyLeftOut && (
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
