import { useState } from 'react'
import styles from './LoadingScreen.module.css'

const PHASE_LABELS = {
  pending: 'Starting scan',
  rescanning: "Scanning the chain for your wallet's history",
  loading_history: 'Loading history',
  analyzing: 'Analyzing privacy patterns',
}

const CHAIN_SCAN_KINDS = ['descriptor', 'xpub', 'address']

export default function LoadingScreen({ text, kind, state, progress, onCancel }) {
  const [cancelling, setCancelling] = useState(false)

  const safeText = text ?? ''
  const shortText = safeText.length > 48 ? `${safeText.slice(0, 48)}…` : safeText
  const isChainScan = CHAIN_SCAN_KINDS.includes(kind)
  const label = PHASE_LABELS[state] ?? PHASE_LABELS.pending
  const hasProgress = state === 'rescanning' && typeof progress === 'number'
  const percent = hasProgress ? Math.round(Math.min(Math.max(progress, 0), 1) * 100) : null

  async function handleCancel() {
    if (!onCancel || cancelling) return
    setCancelling(true)
    try {
      await onCancel()
    } catch (err) {
      console.error('Cancel failed:', err)
      setCancelling(false)
    }
  }

  return (
    <div className={styles.root}>
      <div className={styles.scanner}>
        <div className={styles.ring} />
        <div className={styles.ring2} />
        <div className={styles.ring3} />
        <div className={styles.logoMark}>
          ST<span>LT</span>H
        </div>
      </div>

      <div className={styles.status}>
        <div key={label} className={styles.statusText}>
          {label}<span className={styles.dots}>...</span>
        </div>
        <div className={styles.descriptor}>{shortText}</div>
        {isChainScan && (
          <div className={styles.note}>
            Full chain scan. On an indexed node this typically takes a few minutes.
          </div>
        )}
      </div>

      <div className={styles.footer}>
        <div
          className={styles.progressBar}
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent ?? undefined}
        >
          {percent !== null ? (
            <div className={styles.progressFill} style={{ width: `${percent}%` }} />
          ) : (
            <div className={styles.progressIndeterminate} />
          )}
        </div>
        {percent !== null && <div className={styles.progressPercent}>{percent}%</div>}
        <button
          type="button"
          className={styles.cancelButton}
          onClick={handleCancel}
          disabled={cancelling}
        >
          {cancelling ? 'Cancelling' : 'Cancel'}
        </button>
      </div>
    </div>
  )
}
