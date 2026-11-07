import React, { useState, useRef, useEffect, useCallback } from 'react'
import { AnimatePresence } from 'framer-motion'
import Intro from './components/Intro'
import Navbar from './components/Navbar'
import Hero from './components/Hero'
import WorkflowStory from './components/WorkflowStory'
import Dashboard from './components/Dashboard'
import FindingsExplorer from './components/FindingsExplorer'
import ResourceExplorer from './components/ResourceExplorer'
import Reports from './components/Reports'
import ToastContainer from './components/Toast'

const CATS = ['Email', 'JWT', 'AWS Key', 'Internal IP', 'API Endpoint']

// LocalStorage history helpers
const loadHistory = () => {
  try {
    return JSON.parse(localStorage.getItem('jlh_history') || '[]')
  } catch {
    return []
  }
}

const saveHistory = hist => {
  try {
    localStorage.setItem('jlh_history', JSON.stringify(hist))
  } catch {}
}

async function fetchScanApi(targetUrl) {
  let response
  try {
    response = await fetch('/api/scan?url=' + encodeURIComponent(targetUrl))
  } catch (netErr) {
    throw new Error(
      'Unable to connect to the JSLeakHunter Python backend at /api/scan. ' +
      'Please ensure the backend is running (`python js.py --web`) on http://127.0.0.1:5000.'
    )
  }

  let data
  try {
    data = await response.json()
  } catch {
    throw new Error(`Invalid response received from scanner backend (HTTP ${response.status}).`)
  }

  if (!data || data.status !== 'success') {
    const errorMsg = data?.message || `Scan failed with status code ${response.status}.`
    throw new Error(errorMsg)
  }

  return data
}

function normalizeScanData(data) {
  const perFile = Array.isArray(data.resources) ? data.resources : null
  const items = []
  let nextId = 1

  const pushFinding = (category, value, resourceUrl) => {
    items.push({
      id: nextId++,
      cat: category,
      value: String(value),
      resource: resourceUrl || null
    })
  }

  if (perFile) {
    perFile.forEach(res => {
      CATS.forEach(cat => {
        const matches = (res.findings || {})[cat] || []
        matches.forEach(val => pushFinding(cat, val, res.url))
      })
    })
  } else {
    CATS.forEach(cat => {
      const matches = (data.findings || {})[cat] || []
      matches.forEach(val => pushFinding(cat, val, null))
    })
  }

  const counts = Object.fromEntries(
    CATS.map(cat => [cat, ((data.findings || {})[cat] || []).length])
  )

  const perFileCountMap = {}
  if (perFile) {
    perFile.forEach(res => {
      perFileCountMap[res.url] = CATS.reduce(
        (sum, cat) => sum + (((res.findings || {})[cat] || []).length),
        0
      )
    })
  }

  const resources = (data.js_files || []).map(url => ({
    url,
    count: perFile ? (perFileCountMap[url] ?? 0) : null
  }))

  return {
    target: data.target,
    total: data.total_findings ?? items.length,
    counts,
    items,
    resources,
    grouped: !!perFile,
    time: Date.now()
  }
}

export default function App() {
  const [showIntro, setShowIntro] = useState(true)
  const [scanResult, setScanResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [history, setHistory] = useState(loadHistory)
  const [toasts, setToasts] = useState([])
  const scanInputRef = useRef(null)

  const addToast = useCallback((message, type = 'info') => {
    const id = Math.random().toString(36).slice(2)
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 3200)
  }, [])

  const handleScan = async (url) => {
    setLoading(true)
    setError('')
    try {
      addToast(`Initiating scan on ${url}…`, 'info')
      const rawData = await fetchScanApi(url)
      const normalized = normalizeScanData(rawData)
      setScanResult(normalized)

      // Update history in browser
      const newEntry = {
        target: normalized.target,
        time: normalized.time,
        js: normalized.resources.length,
        total: normalized.total
      }
      const updatedHist = [newEntry, ...loadHistory()].slice(0, 40)
      saveHistory(updatedHist)
      setHistory(updatedHist)

      addToast(`Scan complete: ${normalized.total} sensitive findings in ${normalized.resources.length} scripts`, 'success')

      // Smooth scroll to findings section
      setTimeout(() => {
        document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' })
      }, 300)
    } catch (err) {
      setError(err.message)
      addToast(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleCopyClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
      addToast('Copied to clipboard', 'success')
    } catch {
      addToast('Clipboard copy failed — browser permission denied', 'error')
    }
  }

  const handleClearHistory = () => {
    saveHistory([])
    setHistory([])
    addToast('Local scan history cleared', 'info')
  }

  return (
    <div className="app-layout">
      {/* Cinematic Intro Animation */}
      <AnimatePresence>
        {showIntro && (
          <Intro key="intro-loader" onDone={() => setShowIntro(false)} />
        )}
      </AnimatePresence>

      {/* Global Navbar */}
      <Navbar onQuickScanFocus={() => scanInputRef.current?.focus()} />

      <main className="app-main-content">
        {/* Hero Section with Target Input */}
        <Hero
          onScan={handleScan}
          loading={loading}
          error={error}
          inputRef={scanInputRef}
        />

        {/* GSAP Scroll Story Section */}
        <WorkflowStory />

        {/* Real Metrics & Category Dashboard */}
        <Dashboard
          hist={history}
          res={scanResult}
          onClearHistory={handleClearHistory}
          onRescan={handleScan}
        />

        {/* Findings Explorer */}
        <FindingsExplorer
          res={scanResult}
          onCopy={handleCopyClipboard}
        />

        {/* JavaScript Resources Explorer */}
        <ResourceExplorer
          res={scanResult}
          onCopy={handleCopyClipboard}
        />

        {/* Professional Reports Section */}
        <Reports
          res={scanResult}
          onNotify={addToast}
        />
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <div className="container footer-container">
          <div className="footer-left">
            <span className="footer-brand">JS<span className="text-gradient">LEAK</span>HUNTER</span>
            <span className="footer-version mono">v2.0 Hardened</span>
          </div>
          <div className="footer-disclaimer">
            Passive reconnaissance scanner. Only audit systems and resources with explicit written authorization.
          </div>
        </div>
      </footer>

      {/* Toast Notification Container */}
      <ToastContainer toasts={toasts} />
    </div>
  )
}
