// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import ReportScreen from './ReportScreen'

afterEach(cleanup)

// Mirrors Report::new in model/src/types.rs: a scan is clean only when it
// analyzed something and found nothing.
function makeReport({ txs = 0, findings = [], warnings = [], unserved = 0, conflicted = [], replaced = [], abandoned = [], unavailable = [], orphaned = [] } = {}) {
  const analyzedNothing = txs === 0
  return {
    stats: { transactions_analyzed: txs, addresses_seen: 0, utxos_current: 0, addresses_without_history: unserved, conflicted_txids: conflicted, mempool_conflicted_txids: replaced, abandoned_txids: abandoned, unavailable_txids: unavailable, orphaned_txids: orphaned },
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

  it('never claims nothing was analyzed above a list of findings', () => {
    const report = makeReport({ txs: 0 })
    report.findings = [finding('DUST', 'Dust UTXO at bc1qaaa (600 sats, P2WPKH, unspent)')]
    report.summary.findings = 1
    render(<ReportScreen report={report} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.queryByText(/no transactions found for this input/i)).toBeNull()
    expect(screen.getByText('Dust UTXO at bc1qaaa (600 sats, P2WPKH, unspent)')).toBeTruthy()
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

  it('says CIOH merges coins from several of your addresses', () => {
    render(
      <ReportScreen
        report={makeReport({
          txs: 5,
          findings: [
            finding('CIOH', 'TX aaa merges 2 of your addresses: 2 of its 2 inputs are yours (100% ownership)'),
            finding('CIOH', 'TX bbb merges 3 of your addresses: 3 of its 5 inputs are yours (60% ownership)'),
          ],
        })}
        descriptor="wpkh(x/0/*)"
        kind="xpub"
        onReset={() => {}}
      />,
    )
    expect(
      screen.getByText('2 transactions merge coins from several of your addresses (common-input-ownership)'),
    ).toBeTruthy()
    expect(screen.queryByText(/merge your inputs/i)).toBeNull()
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

describe('ReportScreen — rows are ordered by severity, worst first', () => {
  // The engine emits findings by detector, so a LOW row can precede a CRITICAL one.
  const mixed = [
    finding('UTXO_AGE_SPREAD', 'UTXO age spread of 15 blocks between oldest and newest', { severity: 'LOW' }),
    finding('CHANGE_DETECTION', 'TX aaa has identifiable change output(s)', { severity: 'MEDIUM' }),
    finding('CHANGE_DETECTION', 'TX bbb has identifiable change output(s)', { severity: 'MEDIUM' }),
    finding('CONSOLIDATION', 'UTXO ccc:1 born from a 3-input consolidation', { severity: 'MEDIUM' }),
    finding('PEEL_CHAIN', 'Peel chain of 4 hops starting at TX ddd', { severity: 'CRITICAL' }),
    finding('PEEL_CHAIN', 'Peel chain of 2 hops starting at TX eee', { severity: 'HIGH' }),
  ]

  function rowTexts(section) {
    const title = screen.getAllByText(section === 'warnings' ? 'Warnings' : 'Findings').find((el) => /listTitle/.test(el.className))
    const list = title.closest('[class*=listHeader]').nextElementSibling
    return [...list.children].map((el) => el.querySelector('button').textContent)
  }

  it('puts the most severe row first, whatever order the engine emitted', () => {
    render(<ReportScreen report={makeReport({ txs: 9, findings: mixed })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    const rows = rowTexts('findings')
    expect(rows[0]).toMatch(/peel-chain/i)
    expect(rows[rows.length - 1]).toMatch(/age spread/i)
  })

  it('keeps the engine order between rows of equal severity', () => {
    render(<ReportScreen report={makeReport({ txs: 9, findings: mixed })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    const rows = rowTexts('findings')
    expect(rows[1]).toMatch(/change outputs/i)
    expect(rows[2]).toMatch(/consolidation/i)
  })

  it('orders the findings inside an expanded group the same way', () => {
    const chain = [
      finding('PEEL_CHAIN', 'Peel chain of 2 hops starting at TX aaa', { severity: 'HIGH' }),
      finding('PEEL_CHAIN', 'Peel chain of 4 hops starting at TX bbb', { severity: 'CRITICAL' }),
    ]
    render(<ReportScreen report={makeReport({ txs: 9, findings: chain })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    const inner = [...document.querySelectorAll('[class*=groupItems] [class*=description]')].map((e) => e.textContent)
    expect(inner[0]).toMatch(/4 hops/)
  })

  it('orders the warnings the same way', () => {
    const warnings = [
      finding('DORMANT_UTXOS', '4 UTXO(s) have ≥100 confirmations', { severity: 'LOW' }),
      finding('TAINTED_UTXO_MERGE', 'TX fff merges tainted and clean inputs', { severity: 'HIGH' }),
    ]
    render(<ReportScreen report={makeReport({ txs: 9, findings: mixed, warnings })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(rowTexts('warnings')[0]).toMatch(/tainted/i)
  })
})

describe('ReportScreen — history the node could not serve', () => {
  const two = '8f792eb1a5e79c35628ddfac918321b945f63adabdf43e0a567cd4e3ecb55e65:0\n0d6b4d403d2f139a6c92f2e3fcf67d591ba4fff593cfc8e03e79fbc2eb019dd4:0'
  const reuse = finding('ADDRESS_REUSE', 'Address bc1q reused across 2 transactions')

  it('says how many addresses fell back to the pasted outputs', () => {
    render(<ReportScreen report={makeReport({ txs: 2, findings: [reuse], unserved: 1 })} descriptor={two} kind="utxos" onReset={() => {}} />)
    expect(screen.getByText(/could not serve the chain history of 1 address\b/i)).toBeTruthy()
  })

  it('pluralizes the addresses', () => {
    render(<ReportScreen report={makeReport({ txs: 2, findings: [reuse], unserved: 2 })} descriptor={two} kind="utxos" onReset={() => {}} />)
    expect(screen.getByText(/could not serve the chain history of 2 addresses/i)).toBeTruthy()
  })

  it('says nothing when the chain history came through', () => {
    render(<ReportScreen report={makeReport({ txs: 2, findings: [reuse] })} descriptor={two} kind="utxos" onReset={() => {}} />)
    expect(screen.queryByText(/could not serve/i)).toBeNull()
    expect(screen.queryByText(/you pasted/i)).toBeNull()
  })
})

describe('ReportScreen — conflicted transactions left out', () => {
  const original = '515ef5fdbfaebe7e5819b68a302739e92d7485517893b8fd3f7706e5496b2ccb'
  const other = 'a179853216e3e6c3bee813fb7f16c5cf4b81a85e974ebd8a99f45ebd13add7ab'

  it('names the conflicted transaction and says why it was left out', () => {
    render(<ReportScreen report={makeReport({ txs: 2, conflicted: [original] })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.getByText(/left out 1 transaction core reports as conflicted: it, or a transaction it depends on, conflicts with another one, so it is not part of the wallet's history\. it can only come back if a reorg removes the conflicting block\. if it was broadcast, it may have been seen by the network before it became conflicted; stealth does not analyze it\./i)).toBeTruthy()
    expect(screen.getByText(original)).toBeTruthy()
  })

  it('names every one of several', () => {
    render(<ReportScreen report={makeReport({ txs: 2, conflicted: [original, other] })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.getByText(/left out 2 transactions core reports as conflicted: each, or a transaction it depends on, conflicts with another one, so they are not part of the wallet's history\. they can only come back if a reorg removes the conflicting blocks\. if they were broadcast, they may have been seen by the network before they became conflicted; stealth does not analyze them\./i)).toBeTruthy()
    expect(screen.getByText(original)).toBeTruthy()
    expect(screen.getByText(other)).toBeTruthy()
  })

  it('gives no empty-scan hint when every transaction was left out', () => {
    render(<ReportScreen report={makeReport({ txs: 0, conflicted: [original] })} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.getByText(original)).toBeTruthy()
    expect(screen.getByText(/nothing else was left to analyze/i)).toBeTruthy()
    expect(screen.queryByText(/no transactions found for this input/i)).toBeNull()
    expect(screen.queryByText(/unused|off-chain|catching up/i)).toBeNull()
  })

  it('says nothing when no transaction was left out, or the report predates the field', () => {
    const report = makeReport({ txs: 2 })
    render(<ReportScreen report={report} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.queryByText(/conflicted/i)).toBeNull()
    cleanup()
    delete report.stats.conflicted_txids
    render(<ReportScreen report={report} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)
    expect(screen.queryByText(/conflicted/i)).toBeNull()
  })
})

describe('ReportScreen — replaced and abandoned transactions left out', () => {
  const original = '515ef5fdbfaebe7e5819b68a302739e92d7485517893b8fd3f7706e5496b2ccb'
  const other = 'a179853216e3e6c3bee813fb7f16c5cf4b81a85e974ebd8a99f45ebd13add7ab'
  const show = (report) => render(<ReportScreen report={report} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)

  it('names a replaced transaction and the replacement not confirmed yet', () => {
    show(makeReport({ txs: 2, replaced: [{ txid: original, conflicts_with: other }] }))
    expect(screen.getByText(/left out 1 transaction that conflicts, or depends on one that conflicts, with a transaction in the mempool\. it may still confirm; until then it is not part of the history the wallet sees\. it may still have been seen by the network before the conflicting one reached the mempool; stealth does not analyze it\./i)).toBeTruthy()
    expect(screen.getByText(`${original}: it, or a transaction it depends on, conflicts with ${other}, which is in the mempool and not confirmed yet`)).toBeTruthy()
  })

  it('does not say a descendant conflicts with the mempool tx itself', () => {
    const child = 'f5561a23e573423aeb6d9200aaf74db3ac73c83fae52f5261520d28506dadcd9'
    show(makeReport({ txs: 2, replaced: [{ txid: original, conflicts_with: other }, { txid: child, conflicts_with: other }] }))
    expect(screen.getByText(`${child}: it, or a transaction it depends on, conflicts with ${other}, which is in the mempool and not confirmed yet`)).toBeTruthy()
    expect(screen.queryByText(new RegExp(`^${child} conflicts with`))).toBeNull()
  })

  it('names a single conflicting transaction in the singular for several left out', () => {
    const child = 'f5561a23e573423aeb6d9200aaf74db3ac73c83fae52f5261520d28506dadcd9'
    show(makeReport({ txs: 2, replaced: [{ txid: original, conflicts_with: other }, { txid: child, conflicts_with: other }] }))
    expect(screen.getByText(/left out 2 transactions that conflict, or depend on ones that conflict, with a transaction in the mempool\. they may still confirm; until then they are not part of the history the wallet sees\. they may still have been seen by the network before the conflicting one reached the mempool; stealth does not analyze them\./i)).toBeTruthy()
  })

  it('counts several replaced transactions', () => {
    show(makeReport({ txs: 2, replaced: [{ txid: original, conflicts_with: other }, { txid: other, conflicts_with: original }] }))
    expect(screen.getByText(/left out 2 transactions that conflict, or depend on ones that conflict, with transactions in the mempool\. they may still confirm; until then they are not part of the history the wallet sees\. they may still have been seen by the network before the conflicting ones reached the mempool; stealth does not analyze them\./i)).toBeTruthy()
  })

  it('names abandoned transactions', () => {
    show(makeReport({ txs: 2, abandoned: [original] }))
    expect(screen.getByText(/left out 1 transaction that was abandoned in the wallet, by hand or by core after a reorg removed a coinbase it depends on\. it may still confirm, unless it depends on a coinbase a reorg removed; until then it is not part of the history the wallet sees\. if it was broadcast, it may have been seen by the network before it was abandoned; stealth does not analyze it\./i)).toBeTruthy()
    expect(screen.getByText(original)).toBeTruthy()
    cleanup()
    show(makeReport({ txs: 2, abandoned: [original, other] }))
    expect(screen.getByText(/left out 2 transactions that were abandoned in the wallet, by hand or by core after a reorg removed a coinbase they depend on\. they may still confirm, unless they depend on a coinbase a reorg removed; until then they are not part of the history the wallet sees\. if they were broadcast, they may have been seen by the network before they were abandoned; stealth does not analyze them\./i)).toBeTruthy()
  })

  it('gives no empty-scan hint when every transaction was replaced or abandoned', () => {
    for (const report of [
      makeReport({ txs: 0, replaced: [{ txid: original, conflicts_with: other }] }),
      makeReport({ txs: 0, abandoned: [original] }),
    ]) {
      show(report)
      expect(screen.getByText(/nothing else was left to analyze/i)).toBeTruthy()
      expect(screen.queryByText(/no transactions found for this input/i)).toBeNull()
      cleanup()
    }
  })

  it('says nothing when the report predates the fields', () => {
    const report = makeReport({ txs: 2 })
    delete report.stats.conflicted_txids
    delete report.stats.mempool_conflicted_txids
    delete report.stats.abandoned_txids
    delete report.stats.unavailable_txids
    delete report.stats.orphaned_txids
    show(report)
    // Words from each of the five notes.
    expect(screen.queryByText(/left out|conflict|in the mempool|abandoned|does not have|coinbase/i)).toBeNull()
  })
})

describe('ReportScreen — unconfirmed transactions the node does not have', () => {
  const original = '515ef5fdbfaebe7e5819b68a302739e92d7485517893b8fd3f7706e5496b2ccb'
  const other = 'a179853216e3e6c3bee813fb7f16c5cf4b81a85e974ebd8a99f45ebd13add7ab'
  const show = (report) => render(<ReportScreen report={report} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)

  it('names one and says why it was left out', () => {
    show(makeReport({ txs: 2, unavailable: [original] }))
    expect(screen.getByText(/left out 1 transaction that is unconfirmed and that this node does not have \(it may have been replaced or double-spent, expired or been evicted from the mempool, never been broadcast, or depend on a transaction that was\)\. it may still confirm, unless it or a transaction it depends on has a conflicting transaction mined; until then it is not part of the history the wallet sees\. stealth does not analyze it\./i)).toBeTruthy()
    expect(screen.getByText(original)).toBeTruthy()
  })

  it('counts several', () => {
    show(makeReport({ txs: 2, unavailable: [original, other] }))
    expect(screen.getByText(/left out 2 transactions that are unconfirmed and that this node does not have \(they may have been replaced or double-spent, expired or been evicted from the mempool, never been broadcast, or depend on a transaction that was\)\. they may still confirm, unless they or a transaction they depend on has a conflicting transaction mined; until then they are not part of the history the wallet sees\. stealth does not analyze them\./i)).toBeTruthy()
    expect(screen.getByText(other)).toBeTruthy()
  })

  it('gives no empty-scan hint when every transaction was left out this way', () => {
    show(makeReport({ txs: 0, unavailable: [original] }))
    expect(screen.getByText(/nothing else was left to analyze/i)).toBeTruthy()
    expect(screen.queryByText(/no transactions found for this input/i)).toBeNull()
  })

  it('says nothing when the report predates the field', () => {
    const report = makeReport({ txs: 2 })
    delete report.stats.unavailable_txids
    show(report)
    expect(screen.queryByText(/does not have/i)).toBeNull()
  })
})

describe('ReportScreen — coinbases from blocks no longer in the chain', () => {
  const original = '515ef5fdbfaebe7e5819b68a302739e92d7485517893b8fd3f7706e5496b2ccb'
  const other = 'a179853216e3e6c3bee813fb7f16c5cf4b81a85e974ebd8a99f45ebd13add7ab'
  const show = (report) => render(<ReportScreen report={report} descriptor="wpkh(x/0/*)" kind="xpub" onReset={() => {}} />)

  it('names one and says how it could come back', () => {
    show(makeReport({ txs: 2, orphaned: [original] }))
    expect(screen.getByText(/left out 1 transaction that is a coinbase from a block no longer in the chain\. it can only come back if a reorg restores that block; until then it is not part of the history the wallet sees\. stealth does not analyze it\./i)).toBeTruthy()
    expect(screen.getByText(original)).toBeTruthy()
  })

  it('counts several', () => {
    show(makeReport({ txs: 2, orphaned: [original, other] }))
    expect(screen.getByText(/left out 2 transactions that are coinbases from blocks no longer in the chain\. they can only come back if a reorg restores those blocks; until then they are not part of the history the wallet sees\. stealth does not analyze them\./i)).toBeTruthy()
  })

  it('gives no empty-scan hint when every transaction was left out this way', () => {
    show(makeReport({ txs: 0, orphaned: [original] }))
    expect(screen.getByText(/nothing else was left to analyze/i)).toBeTruthy()
  })
})
