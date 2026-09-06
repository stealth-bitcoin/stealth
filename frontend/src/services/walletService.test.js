import { describe, it, expect, vi, afterEach } from 'vitest'
import { startScan, getScan, cancelScan } from './walletService'

afterEach(() => vi.unstubAllGlobals())

function stubFetch(response) {
  const fetchMock = vi.fn().mockResolvedValue(response)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

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
