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

  it('cancels the running scan from the loading screen', async () => {
    queueJobs(job('rescanning'))
    cancelScan.mockResolvedValue()
    render(<App />)
    await submitScan()
    await tick()

    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    await act(async () => {})
    expect(cancelScan).toHaveBeenCalledWith('scan-1')

    queueJobs(job('cancelled'))
    await tick()
    expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('sends a cancel clicked before the scan id arrived once it does', async () => {
    let resolveStart
    startScan.mockReturnValue(new Promise((resolve) => { resolveStart = resolve }))
    cancelScan.mockResolvedValue()
    render(<App />)
    await submitScan()

    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    await act(async () => {})
    expect(cancelScan).not.toHaveBeenCalled()

    await act(async () => resolveStart('scan-1'))
    expect(cancelScan).toHaveBeenCalledWith('scan-1')
    expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
    await tick(3000)
    expect(getScan).not.toHaveBeenCalled()
  })

  it('sends a cancel clicked after the id arrived but before the screen re-rendered', async () => {
    let resolveStart
    startScan.mockReturnValue(new Promise((resolve) => { resolveStart = resolve }))
    cancelScan.mockResolvedValue()
    render(<App />)
    await submitScan()
    const cancel = screen.getByRole('button', { name: /^cancel$/i })

    // The id lands outside act, so the click still runs the handler of the render before it.
    resolveStart('scan-1')
    // One microtask runs the code after startScan; React re-renders a microtask later.
    await Promise.resolve()
    // A plain DOM click, not wrapped in act, so no pending render is flushed first.
    cancel.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await act(async () => {})
    expect(cancelScan).toHaveBeenCalledWith('scan-1')
  })

  it('keeps following the scan when the early cancel cannot be sent', async () => {
    let resolveStart
    startScan.mockReturnValue(new Promise((resolve) => { resolveStart = resolve }))
    cancelScan.mockRejectedValue(new Error('HTTP 500'))
    render(<App />)
    await submitScan()
    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    await act(async () => {})

    await act(async () => resolveStart('scan-1'))
    expect(screen.getByRole('button', { name: /^cancel$/i }).disabled).toBe(false)
    queueJobs(job('done', { report: REPORT }))
    await tick()
    expect(getScan).toHaveBeenCalledWith('scan-1')
    expect(screen.getByText(/no privacy issues found/i)).toBeTruthy()
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

  describe('a history above the limit', () => {
    const tooLarge = () =>
      job('failed', {
        error: 'analysis failed: the wallet history holds 12345 transactions',
        limit_exceeded: { tx_count: 12345, limit: 5000 },
      })

    it('asks before loading it instead of failing the scan', async () => {
      queueJobs(tooLarge())
      render(<App />)
      await submitScan()
      await tick()
      expect(screen.getByRole('alertdialog').textContent).toMatch(/12,345 transactions/)
      expect(screen.queryByRole('alert')).toBeNull()
      expect(screen.queryByPlaceholderText(/paste a descriptor/i)).toBeNull()
      await tick(3000)
      expect(getScan).toHaveBeenCalledTimes(1)
    })

    it('sends the scan again with the limit lifted when told to scan anyway', async () => {
      queueJobs(tooLarge())
      render(<App />)
      await submitScan()
      await tick()

      startScan.mockResolvedValue('scan-2')
      fireEvent.click(screen.getByRole('button', { name: /scan anyway/i }))
      await act(async () => {})
      expect(startScan).toHaveBeenLastCalledWith({ descriptor: DESC, no_limits: true })
      expect(screen.queryByRole('alertdialog')).toBeNull()

      queueJobs(job('done', { report: REPORT }))
      await tick()
      expect(getScan).toHaveBeenLastCalledWith('scan-2')
      expect(screen.getByText(/no privacy issues found/i)).toBeTruthy()
    })

    it('honours a cancel sent before the poll saw the stop', async () => {
      queueJobs(job('rescanning'))
      cancelScan.mockResolvedValue()
      render(<App />)
      await submitScan()
      await tick()

      fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
      await act(async () => {})
      queueJobs(tooLarge())
      await tick()
      expect(screen.queryByRole('alertdialog')).toBeNull()
      expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
      expect(screen.queryByRole('alert')).toBeNull()
    })

    it('forgets a cancel sent for an earlier scan', async () => {
      queueJobs(job('rescanning'))
      cancelScan.mockResolvedValue()
      render(<App />)
      await submitScan()
      await tick()
      fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
      await act(async () => {})
      queueJobs(job('cancelled'))
      await tick()
      expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()

      startScan.mockResolvedValue('scan-2')
      queueJobs(tooLarge())
      await submitScan()
      await tick()
      expect(screen.getByRole('alertdialog').textContent).toMatch(/12,345 transactions/)
    })

    it('shows the confirm step when the cancel request failed', async () => {
      queueJobs(job('rescanning'))
      cancelScan.mockRejectedValue(new Error('HTTP 500'))
      render(<App />)
      await submitScan()
      await tick()
      fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
      await act(async () => {})

      queueJobs(tooLarge())
      await tick()
      expect(screen.getByRole('alertdialog').textContent).toMatch(/12,345 transactions/)
    })

    it('lets the scan sent again from the confirm step be cancelled', async () => {
      queueJobs(tooLarge())
      cancelScan.mockResolvedValue()
      render(<App />)
      await submitScan()
      await tick()

      startScan.mockResolvedValue('scan-2')
      fireEvent.click(screen.getByRole('button', { name: /scan anyway/i }))
      await act(async () => {})
      const cancel = screen.getByRole('button', { name: /^cancel$/i })
      expect(cancel.disabled).toBe(false)
      fireEvent.click(cancel)
      await act(async () => {})
      expect(cancelScan).toHaveBeenCalledWith('scan-2')
    })

    it('goes back to the input without sending anything when cancelled', async () => {
      queueJobs(tooLarge())
      render(<App />)
      await submitScan()
      await tick()

      fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
      await act(async () => {})
      expect(screen.getByPlaceholderText(/paste a descriptor/i)).toBeTruthy()
      expect(screen.queryByRole('alert')).toBeNull()
      expect(startScan).toHaveBeenCalledTimes(1)
      expect(cancelScan).not.toHaveBeenCalled()
    })
  })
})
