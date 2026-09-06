// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, act } from '@testing-library/react'
import App from './App'
import { startScan, getScan, cancelScan } from './services/walletService'

vi.mock('./services/walletService', () => ({
  startScan: vi.fn(),
  getScan: vi.fn(),
  cancelScan: vi.fn(),
}))

beforeEach(() => {
  vi.useFakeTimers()
  startScan.mockResolvedValue('scan-1')
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.resetAllMocks()
})

const XPUB = 'xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw'
const DESC = `wpkh(${XPUB}/0/*)`
const SHORT_DESC = `${DESC.slice(0, 48)}…`
const REPORT = {
  stats: { transactions_analyzed: 7 },
  findings: [],
  warnings: [],
  summary: { findings: 0, warnings: 0, clean: true },
}

const job = (state, extra = {}) => ({ state, progress: null, report: null, error: null, ...extra })

function queueJobs(...jobs) {
  for (const j of jobs) getScan.mockResolvedValueOnce(j)
}

async function submitScan() {
  fireEvent.change(screen.getByPlaceholderText(/paste a descriptor/i), {
    target: { value: DESC },
  })
  fireEvent.click(screen.getByRole('button', { name: /analyze/i }))
  await act(async () => {})
}

const tick = (ms = 1000) => act(() => vi.advanceTimersByTimeAsync(ms))

describe('App scan flow', () => {
  it('starts a scan, polls every second, and shows the report when done', async () => {
    queueJobs(job('rescanning', { progress: 0.5 }), job('done', { progress: 1, report: REPORT }))
    render(<App />)

    await submitScan()
    expect(startScan).toHaveBeenCalledWith({ descriptor: DESC })
    expect(screen.getByText(SHORT_DESC)).toBeTruthy()

    await tick(999)
    expect(getScan).not.toHaveBeenCalled()
    await tick(1)
    expect(getScan).toHaveBeenCalledWith('scan-1')
    expect(screen.getByText(SHORT_DESC)).toBeTruthy()

    await tick()
    expect(screen.getByText(/no privacy issues found/i)).toBeTruthy()
  })

  it('stops polling once the job is done', async () => {
    queueJobs(job('done', { report: REPORT }))
    render(<App />)
    await submitScan()
    await tick()
    expect(getScan).toHaveBeenCalledTimes(1)
    await tick(3000)
    expect(getScan).toHaveBeenCalledTimes(1)
  })

  it('keeps polling through the intermediate states', async () => {
    queueJobs(job('pending'), job('rescanning'), job('loading_history'), job('analyzing'))
    render(<App />)
    await submitScan()
    await tick(4000)
    expect(getScan).toHaveBeenCalledTimes(4)
    expect(screen.getByText(SHORT_DESC)).toBeTruthy()
  })

  it('returns to the input screen with a friendly message when the scan fails', async () => {
    queueJobs(job('failed', { error: 'Descriptor is invalid' }))
    render(<App />)
    await submitScan()
    await tick()
    expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toBe('Scan failed: Descriptor is invalid')
  })

  it('falls back to a generic message when a failed job has no error string', async () => {
    queueJobs(job('failed'))
    render(<App />)
    await submitScan()
    await tick()
    expect(screen.getByRole('alert').textContent).toBe('Scan failed. Please try again.')
  })

  it('returns to the input screen without an error when the scan is cancelled', async () => {
    queueJobs(job('cancelled'))
    render(<App />)
    await submitScan()
    await tick()
    expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('shows a friendly message when the scan cannot start', async () => {
    startScan.mockRejectedValue(new Error('HTTP 500'))
    render(<App />)
    await submitScan()
    expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toMatch(/could not start the scan/i)
    expect(getScan).not.toHaveBeenCalled()
  })

  it('clears the previous error when a new scan is submitted', async () => {
    queueJobs(job('failed', { error: 'boom' }))
    render(<App />)
    await submitScan()
    await tick()
    expect(screen.getByRole('alert')).toBeTruthy()

    queueJobs(job('rescanning'))
    await submitScan()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByText(SHORT_DESC)).toBeTruthy()
  })

  it('tolerates a transient polling failure and keeps going', async () => {
    getScan.mockRejectedValueOnce(new Error('network blip'))
    render(<App />)
    await submitScan()
    await tick()
    queueJobs(job('done', { report: REPORT }))
    await tick()
    expect(screen.getByText(/no privacy issues found/i)).toBeTruthy()
  })

  it('gives up with a friendly message after repeated polling failures', async () => {
    getScan.mockRejectedValue(new Error('backend gone'))
    render(<App />)
    await submitScan()
    await tick(5000)
    expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toMatch(/lost connection/i)
    const calls = getScan.mock.calls.length
    await tick(3000)
    expect(getScan.mock.calls.length).toBe(calls)
  })

  it('stops polling when unmounted', async () => {
    queueJobs(job('rescanning'))
    const { unmount } = render(<App />)
    await submitScan()
    await tick()
    expect(getScan).toHaveBeenCalledTimes(1)
    unmount()
    await tick(3000)
    expect(getScan).toHaveBeenCalledTimes(1)
  })
})
