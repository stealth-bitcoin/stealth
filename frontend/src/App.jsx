import { useState, useEffect, useRef } from 'react'
import InputScreen from './screens/InputScreen'
import LoadingScreen from './screens/LoadingScreen'
import ReportScreen from './screens/ReportScreen'
import ErrorBoundary from './components/ErrorBoundary'
import { startScan, getScan, cancelScan } from './services/walletService'

const POLL_INTERVAL_MS = 1000
const MAX_POLL_FAILURES = 5

export default function App() {
  const [screen, setScreen] = useState('input')
  const [scan, setScan] = useState(null)
  const [scanId, setScanIdState] = useState(null)
  // Read by handleCancel, which a click can run before the render that sees a new id.
  const currentScanId = useRef(null)
  const [job, setJob] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const [limitExceeded, setLimitExceeded] = useState(null)
  const pollFailures = useRef(0)
  const cancelSent = useRef(false)
  // A cancel clicked before startScan returned the id, settled once it is sent.
  const cancelWaiting = useRef(null)

  function setScanId(id) {
    currentScanId.current = id
    setScanIdState(id)
  }

  useEffect(() => {
    if (!scanId) return undefined
    let active = true
    pollFailures.current = 0

    const interval = setInterval(async () => {
      let next
      try {
        next = await getScan(scanId)
      } catch (err) {
        console.error('Scan polling failed:', err)
        if (active && ++pollFailures.current >= MAX_POLL_FAILURES) {
          setError('Lost connection to the scanner. Please try again.')
          setScreen('input')
          setScanId(null)
        }
        return
      }
      if (!active) return
      pollFailures.current = 0
      setJob(next)
      if (next.state === 'done') {
        setReport(next.report)
        setScreen('report')
        setScanId(null)
      } else if (next.state === 'failed' && next.limit_exceeded && cancelSent.current) {
        // The user already asked to stop; there is nothing left to confirm.
        setScreen('input')
        setScanId(null)
      } else if (next.state === 'failed' && next.limit_exceeded) {
        setLimitExceeded(next.limit_exceeded)
        setScanId(null)
      } else if (next.state === 'failed') {
        setError(next.error ? `Scan failed: ${next.error}` : 'Scan failed. Please try again.')
        setScreen('input')
        setScanId(null)
      } else if (next.state === 'cancelled') {
        setScreen('input')
        setScanId(null)
      }
    }, POLL_INTERVAL_MS)

    return () => {
      active = false
      clearInterval(interval)
    }
  }, [scanId])

  async function handleAnalyze(nextScan) {
    setScan(nextScan)
    setJob(null)
    setReport(null)
    setError(null)
    setLimitExceeded(null)
    cancelSent.current = false
    cancelWaiting.current = null
    setScreen('loading')
    let id
    try {
      id = await startScan(nextScan.body)
    } catch (err) {
      console.error('Failed to start scan:', err)
      setError('Could not start the scan. Please try again.')
      setScreen('input')
      cancelWaiting.current?.resolve()
      cancelWaiting.current = null
      return
    }
    const waiting = cancelWaiting.current
    if (!waiting) {
      setScanId(id)
      return
    }
    cancelWaiting.current = null
    try {
      await cancelScan(id)
      waiting.resolve()
      setScreen('input')
    } catch (err) {
      // The job runs on; keep following it so the user can cancel again.
      cancelSent.current = false
      waiting.reject(err)
      setScanId(id)
    }
  }

  function handleCancel() {
    cancelSent.current = true
    const id = currentScanId.current
    if (!id) {
      return new Promise((resolve, reject) => {
        cancelWaiting.current = { resolve, reject }
      })
    }
    return cancelScan(id).catch((err) => {
      cancelSent.current = false
      throw err
    })
  }

  function handleScanAnyway() {
    return handleAnalyze({ ...scan, body: { ...scan.body, no_limits: true } })
  }

  function handleReset() {
    setScreen('input')
    setScan(null)
    setScanId(null)
    setJob(null)
    setReport(null)
    setError(null)
    setLimitExceeded(null)
  }

  function renderScreen() {
    if (screen === 'loading') {
      return (
        <LoadingScreen
          text={scan?.text}
          kind={scan?.kind}
          state={job?.state}
          progress={job?.progress}
          onCancel={handleCancel}
          limitExceeded={limitExceeded}
          onScanAnyway={handleScanAnyway}
          onDismiss={handleReset}
        />
      )
    }
    if (screen === 'report') return <ReportScreen report={report} descriptor={scan?.text} kind={scan?.kind} onReset={handleReset} />
    return <InputScreen onAnalyze={handleAnalyze} error={error} />
  }

  return <ErrorBoundary onReset={handleReset}>{renderScreen()}</ErrorBoundary>
}
