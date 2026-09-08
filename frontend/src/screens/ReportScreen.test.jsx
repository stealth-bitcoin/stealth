// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import ReportScreen from './ReportScreen'

afterEach(cleanup)

function makeReport({ txs = 0, findings = [], warnings = [], clean = false } = {}) {
  return {
    stats: { transactions_analyzed: txs, addresses_seen: 0, utxos_current: 0 },
    findings,
    warnings,
    summary: {
      findings: findings.length,
      warnings: warnings.length,
      clean,
      analyzed_nothing: txs === 0,
    },
  }
}

const finding = (type, description, extra = {}) => ({
  type,
  severity: 'MEDIUM',
  description,
  ...extra,
})

describe('ReportScreen — nothing analyzed vs clean', () => {
  it('shows a "nothing found" message when no transactions were analyzed', () => {
    render(<ReportScreen report={makeReport({ txs: 0 })} descriptor="addr(bc1qexample)" kind="address" onReset={() => {}} />)
    expect(screen.getByText(/no transactions found for this input/i)).toBeTruthy()
    expect(screen.queryByText(/clean history/i)).toBeNull()
    expect(screen.getByText(/unused address|off-chain|behind|catching up|lightning/i)).toBeTruthy()
  })

  it('shows the clean banner when transactions were analyzed with no findings', () => {
    render(<ReportScreen report={makeReport({ txs: 7, clean: true })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.getByText(/clean history/i)).toBeTruthy()
    expect(screen.queryByText(/no transactions found for this input/i)).toBeNull()
  })
})

describe('ReportScreen — single-address scope note', () => {
  it('warns that only one address was audited for an address scan', () => {
    render(<ReportScreen report={makeReport({ txs: 3 })} descriptor="addr(bc1qexample)" kind="address" onReset={() => {}} />)
    expect(screen.getByText(/only this single address/i)).toBeTruthy()
    expect(screen.getByText(/xpub/i)).toBeTruthy()
  })

  it('does not show the scope note for an xpub scan', () => {
    render(<ReportScreen report={makeReport({ txs: 3 })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.queryByText(/only this single address/i)).toBeNull()
  })
})

describe('ReportScreen — grouped findings', () => {
  const exchangeFindings = [
    finding('EXCHANGE_ORIGIN', 'TX aaa looks like an exchange batch withdrawal'),
    finding('EXCHANGE_ORIGIN', 'TX bbb looks like an exchange batch withdrawal'),
    finding('EXCHANGE_ORIGIN', 'TX ccc looks like an exchange batch withdrawal'),
  ]

  it('collapses repeated findings of one type into a single counted card', () => {
    render(
      <ReportScreen
        report={makeReport({ txs: 9, findings: exchangeFindings })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.getByText(/3 transactions look like exchange batch withdrawals/i)).toBeTruthy()
    // The individual finding descriptions stay hidden until the group is expanded.
    expect(screen.queryByText('TX aaa looks like an exchange batch withdrawal')).toBeNull()
  })

  it('reveals the individual findings when the group is expanded', () => {
    render(
      <ReportScreen
        report={makeReport({ txs: 9, findings: exchangeFindings })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    fireEvent.click(screen.getByText(/3 transactions look like exchange batch withdrawals/i))
    expect(screen.getByText('TX aaa looks like an exchange batch withdrawal')).toBeTruthy()
    expect(screen.getByText('TX ccc looks like an exchange batch withdrawal')).toBeTruthy()
  })

  it('renders a lone finding as a normal card, not a group', () => {
    render(
      <ReportScreen
        report={makeReport({ txs: 4, findings: [finding('ADDRESS_REUSE', 'Address bc1q reused across 2 transactions')] })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.getByText('Address bc1q reused across 2 transactions')).toBeTruthy()
  })
})

describe('ReportScreen — header label follows the input kind', () => {
  const cases = [
    ['address', 'Analyzed address'],
    ['xpub', 'Analyzed xpub'],
    ['utxos', 'Analyzed UTXO set'],
    ['descriptor', 'Analyzed descriptor'],
  ]
  for (const [kind, label] of cases) {
    it(`labels a ${kind} scan as "${label}"`, () => {
      render(<ReportScreen report={makeReport({ txs: 3 })} descriptor="x" kind={kind} onReset={() => {}} />)
      expect(screen.getByText(label)).toBeTruthy()
    })
  }
})
