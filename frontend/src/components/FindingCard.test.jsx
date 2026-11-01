// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import FindingCard from './FindingCard'

afterEach(cleanup)

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)

const clusterMerge = {
  type: 'CLUSTER_MERGE',
  severity: 'HIGH',
  description: 'TX ... merges UTXOs from 2 different funding chains',
  details: {
    txid: 'c'.repeat(64),
    chains: [
      [
        { funding_txid: A, funding_vout: 0, address: 'bcrt1qfirst' },
        { funding_txid: A, funding_vout: 1, address: 'bcrt1qsecond' },
      ],
      [{ funding_txid: B, funding_vout: 3, address: 'bcrt1qthird' }],
    ],
  },
}

describe('FindingCard', () => {
  it('lists the inputs of each funding chain under its own heading', () => {
    render(<FindingCard finding={clusterMerge} />)
    fireEvent.click(screen.getByRole('button'))
    const first = screen.getByText('chain 1').parentElement
    const second = screen.getByText('chain 2').parentElement
    expect(first.textContent).toContain('bcrt1qfirst')
    expect(first.textContent).toContain('bcrt1qsecond')
    expect(first.textContent).toContain(`${A.slice(0, 10)}…:1`)
    expect(second.textContent).toContain('bcrt1qthird')
    expect(second.textContent).toContain(`${B.slice(0, 10)}…:3`)
    expect(second.textContent).not.toContain('bcrt1qfirst')
  })

  it('lists every input address of the parent of a dust coin', () => {
    const parents = Array.from({ length: 7 }, (_, i) => `bcrt1qparent${i}`)
    render(
      <FindingCard
        finding={{
          type: 'DUST',
          severity: 'HIGH',
          description: 'Dust UTXO ... and 2 more are yours, this is small change of your own spend',
          details: { status: 'unspent', origin: 'possibly_own_change', parent_input_addresses: parents },
        }}
      />
    )
    fireEvent.click(screen.getByRole('button'))
    const group = screen.getByText('parent input addresses').parentElement
    for (const address of parents) {
      expect(group.textContent).toContain(address)
    }
    expect(screen.getByText('possibly_own_change')).toBeTruthy()
  })
})
