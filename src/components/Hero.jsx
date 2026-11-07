import React, { useState, useRef, useEffect } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { SearchIcon, ShieldIcon, AlertIcon, TerminalIcon, GlobeIcon } from './Icons'

export default function Hero({ onScan, loading, error, inputRef }) {
  const [targetUrl, setTargetUrl] = useState('')
  const [validationWarning, setValidationWarning] = useState('')
  const localInputRef = useRef(null)
  const actualRef = inputRef || localInputRef
  const rm = useReducedMotion()
  const heroRef = useRef(null)

  // Cursor follow glow
  const handleMouseMove = e => {
    if (rm || !heroRef.current) return
    const rect = heroRef.current.getBoundingClientRect()
    heroRef.current.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`)
    heroRef.current.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`)
  }

  const validateTarget = input => {
    const val = input.trim()
    if (!val) {
      setValidationWarning('')
      return true
    }
    if (val.startsWith('file:') || val.startsWith('gopher:') || val.startsWith('ftp:')) {
      setValidationWarning('Only HTTP and HTTPS target URLs are permitted.')
      return false
    }
    setValidationWarning('')
    return true
  }

  const handleInputChange = e => {
    const val = e.target.value
    setTargetUrl(val)
    validateTarget(val)
  }

  const handleSubmit = e => {
    e.preventDefault()
    const trimmed = targetUrl.trim()
    if (!trimmed || loading) return
    if (!validateTarget(trimmed)) return
    onScan(trimmed)
  }

  const handleSetSample = url => {
    setTargetUrl(url)
    setValidationWarning('')
    actualRef.current?.focus()
  }

  return (
    <section id="top" className="hero-section" ref={heroRef} onMouseMove={handleMouseMove}>
      <div className="hero-glow-layer" aria-hidden="true" />
      <div className="container hero-container">
        
        {/* Top Tagline Badge */}
        <motion.div
          className="hero-badge"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <ShieldIcon size={14} className="badge-shield-icon" />
          <span>PASSIVE RECONNAISSANCE • ZERO-INTRUSION AUDITING</span>
        </motion.div>

        {/* Main Headline */}
        <motion.h1
          className="hero-headline"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.1 }}
        >
          Inspect client-side scripts.<br />
          <span className="text-gradient">Detect critical exposures.</span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          className="hero-subtitle"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.2 }}
        >
          JSLeakHunter statically analyses public JavaScript assets for leaked credentials,
          AWS access keys, JWT tokens, internal IP disclosures, and private API endpoints.
        </motion.p>

        {/* Main Scanner Input Bar */}
        <motion.div
          className="hero-scanner-box glass-panel"
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.3 }}
        >
          <form className="scan-input-form" onSubmit={handleSubmit}>
            <div className="input-prefix-icon">
              <GlobeIcon size={18} />
            </div>
            <input
              ref={actualRef}
              type="text"
              className="scan-url-input mono"
              placeholder="Enter target URL (e.g. https://example.com)"
              value={targetUrl}
              onChange={handleInputChange}
              disabled={loading}
              aria-label="Target Website URL to Scan"
              autoComplete="off"
              spellCheck="false"
            />
            {targetUrl && !loading && (
              <button
                type="button"
                className="input-clear-btn"
                onClick={() => {
                  setTargetUrl('')
                  setValidationWarning('')
                  actualRef.current?.focus()
                }}
                aria-label="Clear target input"
              >
                ✕
              </button>
            )}
            <motion.button
              type="submit"
              className="btn btn-primary scan-submit-btn"
              disabled={loading || !targetUrl.trim()}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {loading ? (
                <>
                  <span className="spinner-icon" aria-hidden="true" />
                  <span>Scanning Assets…</span>
                </>
              ) : (
                <>
                  <SearchIcon size={16} />
                  <span>Scan Target</span>
                </>
              )}
            </motion.button>
          </form>

          {/* Quick Demo Helper Links */}
          <div className="hero-quick-helpers">
            <span className="helper-label">Quick suggestions:</span>
            <button
              type="button"
              className="chip-btn"
              onClick={() => handleSetSample('https://example.com')}
            >
              example.com
            </button>
            <button
              type="button"
              className="chip-btn"
              onClick={() => handleSetSample('https://httpbin.org')}
            >
              httpbin.org
            </button>
          </div>
        </motion.div>

        {/* Validation or API Error Alerts */}
        {(validationWarning || error) && (
          <motion.div
            className="hero-alert-banner"
            role="alert"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <AlertIcon size={18} className="alert-icon-svg" />
            <div className="alert-text">
              <strong>Scan Error:</strong> {validationWarning || error}
            </div>
          </motion.div>
        )}

        {/* Security & Authorization Disclaimer */}
        <div className="hero-authorization-note">
          <TerminalIcon size={14} className="note-icon" />
          <span>
            Authorized security assessments only. Never scan targets without explicit prior written authorization.
          </span>
        </div>

      </div>
    </section>
  )
}

