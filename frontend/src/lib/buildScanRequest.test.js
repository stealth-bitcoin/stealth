import { describe, it, expect } from 'vitest'
import { buildScanRequest } from './buildScanRequest'

const XPUB = 'xpub6CatWdiZynkCminahu8Gmr7FAVnQXBTSMaBxn6qmBNkdm9tDkFzWmjmDrLBCQSTa7BHgpEjCXzMTCyDsQLSmcGYJHBB7cTwpqLNRKGP47uw'
const DESC = `wpkh(${XPUB}/0/*)`
const ADDR = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
const TXID = 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'
const UTXOS = [{ txid: TXID, vout: 0 }]

describe('buildScanRequest', () => {
  it('sends utxos as-is', () => {
    expect(buildScanRequest({ kind: 'utxos', value: `${TXID}:0`, utxos: UTXOS }))
      .toEqual({ utxos: UTXOS })
  })

  it('wraps an address in addr()', () => {
    expect(buildScanRequest({ kind: 'address', value: ADDR }))
      .toEqual({ descriptor: `addr(${ADDR})` })
  })

  it('sends a descriptor verbatim', () => {
    expect(buildScanRequest({ kind: 'descriptor', value: DESC }))
      .toEqual({ descriptor: DESC })
  })

  it('sends an xpub verbatim in the descriptor field', () => {
    expect(buildScanRequest({ kind: 'xpub', value: XPUB }))
      .toEqual({ descriptor: XPUB })
  })

  it('never includes rescan_since, even when a legacy birth date argument is passed', () => {
    expect(buildScanRequest({ kind: 'descriptor', value: DESC }, '2021-03-15'))
      .toEqual({ descriptor: DESC })
    expect(buildScanRequest({ kind: 'xpub', value: XPUB }, '2017-01-01'))
      .toEqual({ descriptor: XPUB })
    expect(buildScanRequest({ kind: 'address', value: ADDR }, '2017-01-01'))
      .toEqual({ descriptor: `addr(${ADDR})` })
    expect(buildScanRequest({ kind: 'utxos', value: `${TXID}:0`, utxos: UTXOS }, '2021-03-15'))
      .toEqual({ utxos: UTXOS })
  })

  it('throws for unknown input', () => {
    expect(() => buildScanRequest({ kind: 'unknown', value: 'mystery' }))
      .toThrow(/unknown/)
  })

  it('throws for private keys', () => {
    expect(() => buildScanRequest({ kind: 'private', value: 'xprv123' }))
      .toThrow(/private/)
  })
})
