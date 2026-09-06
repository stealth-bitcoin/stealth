import { useState } from 'react'
import styles from './InputScreen.module.css'
import { classifyInput } from '../lib/inputClassifier'
import { buildScanRequest } from '../lib/buildScanRequest'

const PLACEHOLDER = 'Paste a descriptor, xpub, address, or a list of UTXOs (txid:vout per line)'

const BADGES = {
  descriptor: 'Descriptor',
  xpub: 'Extended public key',
  address: 'Address',
  private: 'Private key',
  unknown: 'Not recognized',
}

export default function InputScreen({ onAnalyze }) {
  const [text, setText] = useState('')

  const classified = classifyInput(text)
  const { kind } = classified
  const showBadge = text.trim().length > 0
  const blocked = !text.trim() || kind === 'unknown' || kind === 'private'

  function handleSubmit(e) {
    e.preventDefault()
    if (blocked) return
    onAnalyze({
      body: buildScanRequest(classified),
      kind,
      text: classified.value,
    })
  }

  return (
    <div className={styles.root}>
      <div className={styles.container}>
        <div className={styles.wordmark}>
          <div className={styles.logo}>
            STEAL<span>TH</span>
          </div>
          <div className={styles.tagline}>Bitcoin Wallet Privacy Analyzer</div>
        </div>

        <form className={styles.card} onSubmit={handleSubmit}>
          <div className={styles.labelRow}>
            <label className={styles.label} htmlFor="wallet-input">
              Wallet Input
            </label>
            {showBadge && (
              <span className={styles.badge} data-kind={kind}>
                {kind === 'utxos' ? `UTXO list (${classified.utxos.length})` : BADGES[kind]}
              </span>
            )}
          </div>
          <textarea
            id="wallet-input"
            className={styles.textarea}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={PLACEHOLDER}
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
          />

          {kind === 'private' && (
            <p className={`${styles.warning} ${styles.warningDanger}`}>
              This looks like a PRIVATE key. Never paste private keys; use the public xpub.
            </p>
          )}

          <button
            type="submit"
            className={styles.button}
            disabled={blocked}
          >
            Analyze Wallet
          </button>
          <p className={styles.hint}>
            Supports descriptors like <code>wpkh(...)</code>, <code>xpub</code>/<code>tpub</code> keys,
            addresses, and <code>txid:vout</code> lists
          </p>
        </form>
      </div>
    </div>
  )
}
