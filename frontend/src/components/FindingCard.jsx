import { useState } from 'react'
import styles from './FindingCard.module.css'
import VulnerabilityBadge from './VulnerabilityBadge'

function TxRow({ txid }) {
  if (!txid) return null
  return (
    <div className={styles.txRow}>
      <span className={styles.txLabel}>txid</span>
      <span className={styles.txHash}>{txid.slice(0, 10)}…{txid.slice(-10)}</span>
    </div>
  )
}

function AddressRow({ item }) {
  const { address, role, amount_btc, sats, script_type, ours } = item
  const tag = role ?? (script_type ? `${script_type}${ours != null ? (ours ? ' ·ours' : ' ·ext') : ''}` : null)
  const amount = amount_btc != null ? `${amount_btc} BTC` : sats != null ? `${sats} sats` : null
  return (
    <div className={styles.addrRow}>
      <span className={styles.addrHash}>{address}</span>
      {tag && <span className={styles.addrTag}>{tag}</span>}
      {amount && <span className={styles.addrAmount}>{amount}</span>}
    </div>
  )
}

function AddrGroup({ label, items }) {
  if (!items?.length) return null
  return (
    <div className={styles.listGroup}>
      <div className={styles.groupLabel}>{label}</div>
      {items.map((item, i) => <AddressRow key={i} item={item} />)}
    </div>
  )
}

function StringList({ label, items }) {
  if (!items?.length) return null
  return (
    <div className={styles.listGroup}>
      <div className={styles.groupLabel}>{label}</div>
      <ul className={styles.strList}>
        {items.map((s, i) => <li key={i}>{s}</li>)}
      </ul>
    </div>
  )
}

function ScalarGroup({ data }) {
  const entries = Object.entries(data).filter(([, v]) => typeof v !== 'object')
  if (!entries.length) return null
  return (
    <dl className={styles.kvList}>
      {entries.map(([k, v]) => (
        <div key={k} className={styles.kvRow}>
          <dt className={styles.kvKey}>{k.replace(/_/g, ' ')}</dt>
          <dd className={styles.kvVal}>{String(v)}</dd>
        </div>
      ))}
    </dl>
  )
}

function DetailsPanel({ details }) {
  if (!details || !Object.keys(details).length) return null

  const skip = new Set()
  const parts = []

  if (details.txid) {
    parts.push(<TxRow key="txid" txid={details.txid} />)
    skip.add('txid')
  }

  if (typeof details.address === 'string') {
    parts.push(
      <div key="address" className={styles.addrRow}>
        <span className={styles.addrHash}>{details.address}</span>
      </div>
    )
    skip.add('address')
  }

  const addrFields = [
    'our_addresses', 'change_outputs', 'received_outputs',
    'dust_inputs', 'normal_inputs', 'tainted_inputs', 'clean_inputs', 'inputs',
  ]
  for (const f of addrFields) {
    if (Array.isArray(details[f]) && details[f].length) {
      parts.push(<AddrGroup key={f} label={f.replace(/_/g, ' ')} items={details[f]} />)
      skip.add(f)
    }
  }

  if (Array.isArray(details.chains)) {
    details.chains.forEach((inputs, i) => {
      const rows = (Array.isArray(inputs) ? inputs : []).map(({ address, funding_txid, funding_vout }) => ({
        address,
        role: `${String(funding_txid).slice(0, 10)}…:${funding_vout}`,
      }))
      parts.push(<AddrGroup key={`chain-${i}`} label={`chain ${i + 1}`} items={rows} />)
    })
    skip.add('chains')
  }

  for (const f of ['reasons', 'patterns', 'signals', 'script_types']) {
    if (Array.isArray(details[f]) && details[f].length) {
      parts.push(<StringList key={f} label={f} items={details[f]} />)
      skip.add(f)
    }
  }

  const rest = Object.fromEntries(Object.entries(details).filter(([k]) => !skip.has(k)))
  if (Object.keys(rest).length) {
    parts.push(<ScalarGroup key="kv" data={rest} />)
  }

  return <div className={styles.details}>{parts}</div>
}

function CorrectionPanel({ text }) {
  if (!text) return null
  return (
    <div className={styles.correction}>
      <div className={styles.correctionLabel}>How to fix</div>
      <p className={styles.correctionText}>{text}</p>
    </div>
  )
}

export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)

  return (
    <div className={styles.card}>
      <button className={styles.header} onClick={() => setOpen(o => !o)}>
        <div className={styles.left}>
          <VulnerabilityBadge type={finding.type} severity={finding.severity} />
          <span className={styles.description}>{finding.description}</span>
        </div>
        <span className={`${styles.chevron} ${open ? styles.open : ''}`}>›</span>
      </button>
      {open && (
        <>
          <DetailsPanel details={finding.details} />
          <CorrectionPanel text={finding.correction} />
        </>
      )}
    </div>
  )
}
