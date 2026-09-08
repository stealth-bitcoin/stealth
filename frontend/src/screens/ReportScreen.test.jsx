// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
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
