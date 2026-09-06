export function buildScanRequest(classified) {
  const { kind, value } = classified
  if (kind === 'utxos') return { utxos: classified.utxos }
  if (kind !== 'descriptor' && kind !== 'xpub' && kind !== 'address') {
    throw new Error(`Cannot build a scan request from ${kind} input`)
  }
  return { descriptor: kind === 'address' ? `addr(${value})` : value }
}
