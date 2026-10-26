// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import ReportScreen from './ReportScreen'

afterEach(cleanup)

// Mirrors Report::new in model/src/types.rs: a scan is clean only when it
// analyzed something and found nothing.
function makeReport({ txs = 0, findings = [], warnings = [] } = {}) {
  const analyzedNothing = txs === 0
  return {
    stats: { transactions_analyzed: txs, addresses_seen: 0, utxos_current: 0 },
    findings,
    warnings,
    summary: {
      findings: findings.length,
      warnings: warnings.length,
      clean: !analyzedNothing && findings.length === 0 && warnings.length === 0,
      analyzed_nothing: analyzedNothing,
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
    render(<ReportScreen report={makeReport({ txs: 7 })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
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

  it('shows the scope note for an addr() descriptor, which is one address', () => {
    render(<ReportScreen report={makeReport({ txs: 3 })} descriptor="addr(bc1qexample)" kind="descriptor" onReset={() => {}} />)
    expect(screen.getByText(/only this single address/i)).toBeTruthy()
    expect(screen.getByText('Analyzed address')).toBeTruthy()
  })

  it('does not show the scope note for a multi-address descriptor', () => {
    render(<ReportScreen report={makeReport({ txs: 3 })} descriptor="wpkh([ab/84h]tpub.../0/*)" kind="descriptor" onReset={() => {}} />)
    expect(screen.queryByText(/only this single address/i)).toBeNull()
    expect(screen.getByText('Analyzed descriptor')).toBeTruthy()
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

describe('ReportScreen — a collapsed group still carries its severity', () => {
  const dustFindings = [
    finding('DUST', 'Dust UTXO at bc1qaaa (600 sats, P2WPKH, unspent)', { severity: 'CRITICAL' }),
    finding('DUST', 'Historical dust output at bc1qbbb (450 sats, already spent)', { severity: 'LOW' }),
  ]

  it('shows the worst severity of the group on the group header', () => {
    render(
      <ReportScreen
        report={makeReport({ txs: 5, findings: dustFindings })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    const [header] = screen.getAllByText('Dust')
    expect(header.className).toMatch(/critical/i)
  })

  it('does not hide a CRITICAL finding behind a closed group', () => {
    render(
      <ReportScreen
        report={makeReport({ txs: 5, findings: dustFindings })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.getByText('Dust UTXO at bc1qaaa (600 sats, P2WPKH, unspent)')).toBeTruthy()
  })

  it('keeps a group with no CRITICAL member collapsed', () => {
    render(
      <ReportScreen
        report={makeReport({
          txs: 5,
          findings: [
            finding('DUST', 'Dust UTXO at bc1qaaa (600 sats, P2WPKH, unspent)', { severity: 'HIGH' }),
            finding('DUST', 'Historical dust output at bc1qbbb (450 sats, already spent)', { severity: 'LOW' }),
          ],
        })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.queryByText('Dust UTXO at bc1qaaa (600 sats, P2WPKH, unspent)')).toBeNull()
    expect(screen.getByText('Dust').className).toMatch(/high/i)
  })
})

describe('ReportScreen — group summaries describe what the findings are', () => {
  it('calls grouped dust findings outputs, not current UTXOs', () => {
    render(
      <ReportScreen
        report={makeReport({
          txs: 5,
          findings: [
            finding('DUST', 'Dust UTXO at bc1qaaa (600 sats, P2WPKH, unspent)'),
            finding('DUST', 'Historical dust output at bc1qbbb (450 sats, already spent)'),
          ],
        })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.getByText('2 dust outputs detected')).toBeTruthy()
    expect(screen.queryByText(/dust UTXOs detected/i)).toBeNull()
  })

  it('counts peel-chain findings rather than claiming distinct chains', () => {
    render(
      <ReportScreen
        report={makeReport({
          txs: 5,
          findings: [
            finding('PEEL_CHAIN', 'Peel chain detected from TX aaa: 3 hops'),
            finding('PEEL_CHAIN', 'Peel chain detected from TX bbb: 2 hops'),
          ],
        })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.getByText('2 peel-chain findings')).toBeTruthy()
    expect(screen.queryByText(/peel chains detected/i)).toBeNull()
  })

  // A detector type with no entry in the summary table falls back to a
  // generated sentence. New detectors land here before they get a phrasing.
  it('calls grouped warnings warnings, not findings', () => {
    render(
      <ReportScreen
        report={makeReport({
          txs: 5,
          warnings: [
            finding('FUTURE_HEURISTIC', 'TX aaa matched a new heuristic'),
            finding('FUTURE_HEURISTIC', 'TX bbb matched a new heuristic'),
          ],
        })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.getByText('2 future heuristic warnings')).toBeTruthy()
    expect(screen.queryByText(/future heuristic findings/i)).toBeNull()
  })

  it('calls grouped findings findings', () => {
    render(
      <ReportScreen
        report={makeReport({
          txs: 5,
          findings: [
            finding('FUTURE_HEURISTIC', 'TX aaa matched a new heuristic'),
            finding('FUTURE_HEURISTIC', 'TX bbb matched a new heuristic'),
          ],
        })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(screen.getByText('2 future heuristic findings')).toBeTruthy()
  })
})

describe('ReportScreen — the empty-scan hint fits the input', () => {
  it('explains an empty UTXO-list scan by unresolved references', () => {
    render(<ReportScreen report={makeReport({ txs: 0 })} descriptor="aaa:0" kind="utxos" onReset={() => {}} />)
    expect(screen.getByText(/none of the UTXO references you pasted could be resolved/i)).toBeTruthy()
    // A bad txid or a node without txindex fails the scan outright, so it
    // never reaches this screen; advising on it here would mislead.
    expect(screen.queryByText(/txindex/i)).toBeNull()
  })

  it('never blames a scan window, which the web UI does not have', () => {
    for (const kind of ['address', 'xpub', 'utxos', 'descriptor']) {
      cleanup()
      render(<ReportScreen report={makeReport({ txs: 0 })} descriptor="x" kind={kind} onReset={() => {}} />)
      expect(screen.queryByText(/scan window|rescan window|birth/i)).toBeNull()
    }
  })
})

describe('ReportScreen — the scope note does not overclaim', () => {
  it('limits the claim to what this scan can see', () => {
    render(<ReportScreen report={makeReport({ txs: 3 })} descriptor="addr(bc1q)" kind="address" onReset={() => {}} />)
    expect(screen.getByText(/gives this scan no visibility/i)).toBeTruthy()
    expect(screen.queryByText(/reveals nothing about your other addresses/i)).toBeNull()
  })
})
