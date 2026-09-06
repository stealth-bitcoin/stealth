// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import InputScreen from './InputScreen'

afterEach(cleanup)

const XPUB = 'xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw'
const DESC = `wpkh(${XPUB}/0/*)`
const TXID = 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'

function setup(onAnalyze = vi.fn()) {
  render(<InputScreen onAnalyze={onAnalyze} />)
  return onAnalyze
}

function type(value) {
  fireEvent.change(screen.getByPlaceholderText(/paste a descriptor, xpub, address/i), {
    target: { value },
  })
}

describe('InputScreen', () => {
  it('renders a single textarea accepting all input formats', () => {
    setup()
    expect(screen.getByPlaceholderText(
      'Paste a descriptor, xpub, address, or a list of UTXOs (txid:vout per line)'
    )).toBeTruthy()
  })

  it('shows a Descriptor badge without any birth date field or rescan warning', () => {
    setup()
    type(DESC)
    expect(screen.getByText('Descriptor')).toBeTruthy()
    expect(screen.queryByLabelText(/birth date/i)).toBeNull()
    expect(screen.queryByText(/without a birth date/i)).toBeNull()
  })

  it('never renders a birth date input for xpub or address kinds', () => {
    setup()
    type(XPUB)
    expect(screen.getByText('Extended public key')).toBeTruthy()
    expect(screen.queryByLabelText(/birth date/i)).toBeNull()
    type('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
    expect(screen.getByText('Address')).toBeTruthy()
    expect(screen.queryByLabelText(/birth date/i)).toBeNull()
    expect(screen.queryByText(/without a birth date/i)).toBeNull()
  })

  it('blocks private keys with a red badge and an explicit warning', () => {
    const onAnalyze = setup()
    type('xprv' + XPUB.slice(4))
    expect(screen.getByText('Private key')).toBeTruthy()
    expect(screen.getByText(/never paste private keys.*public xpub/i)).toBeTruthy()
    const button = screen.getByRole('button', { name: /analyze/i })
    expect(button.disabled).toBe(true)
    fireEvent.click(button)
    expect(onAnalyze).not.toHaveBeenCalled()
  })

  it('blocks a descriptor containing an xprv', () => {
    setup()
    type(`wpkh(xprv${XPUB.slice(4)}/0/*)`)
    expect(screen.getByText('Private key')).toBeTruthy()
    expect(screen.getByRole('button', { name: /analyze/i }).disabled).toBe(true)
  })

  it('disables the submit button for unrecognized input', () => {
    setup()
    type('hello world')
    expect(screen.getByText('Not recognized')).toBeTruthy()
    expect(screen.getByRole('button', { name: /analyze/i }).disabled).toBe(true)
  })

  it('submits a descriptor body without rescan_since', () => {
    const onAnalyze = setup()
    type(DESC)
    fireEvent.click(screen.getByRole('button', { name: /analyze/i }))
    expect(onAnalyze).toHaveBeenCalledWith({
      body: { descriptor: DESC },
      kind: 'descriptor',
      text: DESC,
    })
  })

  it('submits a utxos body without rescan_since', () => {
    const onAnalyze = setup()
    type(`${TXID}:0`)
    fireEvent.click(screen.getByRole('button', { name: /analyze/i }))
    expect(onAnalyze).toHaveBeenCalledWith({
      body: { utxos: [{ txid: TXID, vout: 0 }] },
      kind: 'utxos',
      text: `${TXID}:0`,
    })
  })
})
