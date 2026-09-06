// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, act } from '@testing-library/react'
import LoadingScreen from './LoadingScreen'

afterEach(cleanup)

const NOTE = /Full chain scan\. On an indexed node this typically takes a few minutes\./i

describe('LoadingScreen', () => {
  it('labels each backend phase honestly', () => {
    const phases = [
      ['pending', /starting scan/i],
      ['rescanning', /scanning the chain for your wallet's history/i],
      ['loading_history', /loading history/i],
      ['analyzing', /analyzing privacy patterns/i],
    ]
    for (const [state, label] of phases) {
      const { unmount } = render(<LoadingScreen state={state} />)
      expect(screen.getByText(label)).toBeTruthy()
      unmount()
    }
  })

  it('shows the real percentage and bar width while rescanning', () => {
    render(<LoadingScreen state="rescanning" progress={0.42} />)
    expect(screen.getByText('42%')).toBeTruthy()
    const bar = screen.getByRole('progressbar')
    expect(bar.getAttribute('aria-valuenow')).toBe('42')
    expect(bar.firstChild.style.width).toBe('42%')
  })

  it('falls back to an indeterminate bar when progress is null', () => {
    render(<LoadingScreen state="rescanning" progress={null} />)
    expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBeNull()
    expect(screen.queryByText(/\d+%/)).toBeNull()
  })

  it('shows no percentage outside the rescanning phase', () => {
    render(<LoadingScreen state="analyzing" progress={0.9} />)
    expect(screen.queryByText('90%')).toBeNull()
    expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBeNull()
  })

  it('shows the full-chain-scan note for descriptor, xpub, and address scans', () => {
    for (const kind of ['descriptor', 'xpub', 'address']) {
      const { unmount } = render(<LoadingScreen text="abc" kind={kind} />)
      expect(screen.getByText(NOTE)).toBeTruthy()
      unmount()
    }
  })

  it('does not show the note for utxo scans', () => {
    render(<LoadingScreen text="deadbeef:0" kind="utxos" />)
    expect(screen.queryByText(NOTE)).toBeNull()
  })

  it('calls onCancel and disables the button while cancelling', async () => {
    let resolveCancel
    const onCancel = vi.fn(() => new Promise((resolve) => { resolveCancel = resolve }))
    render(<LoadingScreen state="rescanning" onCancel={onCancel} />)

    const button = screen.getByRole('button', { name: /^cancel$/i })
    expect(button.disabled).toBe(false)
    fireEvent.click(button)
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(button.disabled).toBe(true)
    expect(button.textContent).toBe('Cancelling')
    fireEvent.click(button)
    expect(onCancel).toHaveBeenCalledTimes(1)
    await act(async () => resolveCancel())
  })

  it('re-enables the cancel button when cancelling fails', async () => {
    const onCancel = vi.fn().mockRejectedValue(new Error('nope'))
    render(<LoadingScreen onCancel={onCancel} />)
    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    await act(async () => {})
    const button = screen.getByRole('button', { name: /^cancel$/i })
    expect(button.disabled).toBe(false)
  })

  it('ignores cancel clicks when no onCancel handler is given', () => {
    render(<LoadingScreen />)
    expect(() => fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))).not.toThrow()
  })

  it('shows the truncated input text', () => {
    render(<LoadingScreen text={'a'.repeat(60)} kind="descriptor" />)
    expect(screen.getByText(`${'a'.repeat(48)}…`)).toBeTruthy()
  })

  it('renders without any props instead of crashing', () => {
    expect(() => render(<LoadingScreen />)).not.toThrow()
    expect(screen.getByText(/starting scan/i)).toBeTruthy()
    expect(screen.queryByText(NOTE)).toBeNull()
  })

  it('tolerates a null text prop', () => {
    expect(() => render(<LoadingScreen text={null} kind="descriptor" />)).not.toThrow()
  })
})
