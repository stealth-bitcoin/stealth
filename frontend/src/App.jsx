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
  const [scanId, setScanId] = useState(null)
  const [job, setJob] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const pollFailures = useRef(0)

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
    setScreen('loading')
    try {
      setScanId(await startScan(nextScan.body))
    } catch (err) {
      console.error('Failed to start scan:', err)
      setError('Could not start the scan. Please try again.')
      setScreen('input')
    }
  }

  function handleReset() {
    setScreen('input')
    setScan(null)
    setScanId(null)
    setJob(null)
    setReport(null)
    setError(null)
  }

  function renderScreen() {
    if (screen === 'loading') {
      return <LoadingScreen text={scan?.text} kind={scan?.kind} state={job?.state} progress={job?.progress} />
    }
    if (screen === 'report') return <ReportScreen report={report} descriptor={scan?.text} onReset={handleReset} />
    return <InputScreen onAnalyze={handleAnalyze} error={error} />
  }

  return <ErrorBoundary onReset={handleReset}>{renderScreen()}</ErrorBoundary>
}
