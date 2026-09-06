import { describe, it, expect, vi, afterEach } from 'vitest'
import { analyzeWallet, startScan, getScan, cancelScan } from './walletService'

afterEach(() => vi.unstubAllGlobals())

function stubFetch(response) {
  const fetchMock = vi.fn().mockResolvedValue(response)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('analyzeWallet', () => {
  it('POSTs the prepared body verbatim', async () => {
    const fetchMock = stubFetch({ ok: true, json: () => Promise.resolve({ findings: [] }) })

    const body = { descriptor: 'wpkh(abc)' }
    const result = await analyzeWallet(body)

    expect(fetchMock).toHaveBeenCalledWith('/api/wallet/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    expect(result).toEqual({ findings: [] })
  })

  it('POSTs a utxos body untouched', async () => {
    const fetchMock = stubFetch({ ok: true, json: () => Promise.resolve({}) })

    const body = { utxos: [{ txid: 'a'.repeat(64), vout: 0 }] }
    await analyzeWallet(body)

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(body)
  })

  it('throws when the response is not ok', async () => {
    stubFetch({ ok: false })
    await expect(analyzeWallet({ descriptor: 'x' })).rejects.toThrow('Analysis failed')
  })
})

describe('startScan', () => {
  it('POSTs the body to /api/wallet/scans and returns the scan_id', async () => {
    const fetchMock = stubFetch({
      ok: true,
      status: 202,
      json: () => Promise.resolve({ scan_id: 'scan-42' }),
    })

    const body = { descriptor: 'wpkh(abc)' }
    const scanId = await startScan(body)

    expect(fetchMock).toHaveBeenCalledWith('/api/wallet/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    expect(scanId).toBe('scan-42')
  })

  it('throws on an HTTP error', async () => {
    stubFetch({ ok: false, status: 400 })
    await expect(startScan({ descriptor: 'x' })).rejects.toThrow(/failed to start/i)
  })
})

describe('getScan', () => {
  it('GETs /api/wallet/scans/{id} and returns the job', async () => {
    const job = { state: 'rescanning', progress: 0.42, report: null, error: null }
    const fetchMock = stubFetch({ ok: true, json: () => Promise.resolve(job) })

    const result = await getScan('scan-42')

    expect(fetchMock).toHaveBeenCalledWith('/api/wallet/scans/scan-42')
    expect(result).toEqual(job)
  })

  it('throws on an HTTP error', async () => {
    stubFetch({ ok: false, status: 404 })
    await expect(getScan('scan-42')).rejects.toThrow(/failed to fetch scan/i)
  })
})

describe('cancelScan', () => {
  it('DELETEs /api/wallet/scans/{id} without reading a body', async () => {
    const json = vi.fn()
    const fetchMock = stubFetch({ ok: true, status: 204, json })

    await cancelScan('scan-42')

    expect(fetchMock).toHaveBeenCalledWith('/api/wallet/scans/scan-42', { method: 'DELETE' })
    expect(json).not.toHaveBeenCalled()
  })

  it('throws on an HTTP error', async () => {
    stubFetch({ ok: false, status: 500 })
    await expect(cancelScan('scan-42')).rejects.toThrow(/failed to cancel/i)
  })
})
