export const analyzeWallet = async (body) => {
  const res = await fetch('/api/wallet/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error('Analysis failed')
  return res.json()
}

export const startScan = async (body) => {
  const res = await fetch('/api/wallet/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`Failed to start scan (HTTP ${res.status})`)
  const { scan_id: scanId } = await res.json()
  return scanId
}

export const getScan = async (id) => {
  const res = await fetch(`/api/wallet/scans/${id}`)
  if (!res.ok) throw new Error(`Failed to fetch scan status (HTTP ${res.status})`)
  return res.json()
}

export const cancelScan = async (id) => {
  const res = await fetch(`/api/wallet/scans/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(`Failed to cancel scan (HTTP ${res.status})`)
}
