import React, { useState, useRef, useEffect } from 'react'
import { motion, useInView, useReducedMotion, animate } from 'framer-motion'
import { CATEGORY_INFO } from '../utils/security'
import { ShieldIcon, FileCodeIcon, TerminalIcon, AlertIcon, TrashIcon, ArrowRightIcon } from './Icons'

const CATS = ['Email', 'JWT', 'AWS Key', 'Internal IP', 'API Endpoint']

// Animated Counter component
function AnimatedStat({ value }) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  const rm = useReducedMotion()
  const [displayVal, setDisplayVal] = useState(0)

  useEffect(() => {
    if (!inView) return
    if (rm) {
      setDisplayVal(value)
      return
    }
    const controls = animate(0, value, {
      duration: 1.2,
      ease: 'easeOut',
      onUpdate: latest => setDisplayVal(Math.round(latest))
    })
    return () => controls.stop()
  }, [inView, value, rm])

  return <span ref={ref}>{displayVal}</span>
}

export default function Dashboard({ hist, res, onClearHistory, onRescan }) {
  const [showClearConfirm, setShowClearConfirm] = useState(false)
  const rm = useReducedMotion()

  const aggregate = hist.reduce(
    (acc, item) => ({
      files: acc.files + (item.js || 0),
      findings: acc.findings + (item.total || 0)
    }),
    { files: 0, findings: 0 }
  )

  const highImpactCount = res
    ? (res.counts['AWS Key'] || 0) + (res.counts['JWT'] || 0)
    : 0

  const maxCategoryCount = Math.max(1, ...CATS.map(c => res?.counts[c] || 0))

  return (
    <section id="dashboard" className="dashboard-section">
      <div className="container">
        <div className="section-header">
          <span className="section-pill">OVERVIEW & TELEMETRY</span>
          <h2 className="section-title">
            Security <span className="text-gradient">Dashboard</span>
          </h2>
          <p className="section-subtitle">
            Real-time analytics for the current target and local session audit history.
          </p>
        </div>

        {/* 4 KPI Metric Cards */}
        <div className="kpi-grid">
          <motion.div
            className="kpi-card glass-panel"
            whileHover={{ y: -4 }}
            transition={{ duration: 0.2 }}
          >
            <div className="kpi-icon-wrap blue">
              <FileCodeIcon size={20} />
            </div>
            <div className="kpi-body">
              <div className="kpi-value mono">
                <AnimatedStat value={res ? res.resources.length : aggregate.files} />
              </div>
              <div className="kpi-label">
                {res ? 'JS Files Discovered' : 'Historical JS Files'}
              </div>
            </div>
          </motion.div>

          <motion.div
            className="kpi-card glass-panel"
            whileHover={{ y: -4 }}
            transition={{ duration: 0.2 }}
          >
            <div className="kpi-icon-wrap cyan">
              <TerminalIcon size={20} />
            </div>
            <div className="kpi-body">
              <div className="kpi-value mono">
                <AnimatedStat value={res ? res.total : aggregate.findings} />
              </div>
              <div className="kpi-label">
                {res ? 'Total Sensitive Findings' : 'Historical Findings'}
              </div>
            </div>
          </motion.div>

          <motion.div
            className="kpi-card glass-panel"
            whileHover={{ y: -4 }}
            transition={{ duration: 0.2 }}
          >
            <div className="kpi-icon-wrap red">
              <AlertIcon size={20} />
            </div>
            <div className="kpi-body">
              <div className="kpi-value mono">
                <AnimatedStat value={highImpactCount} />
              </div>
              <div className="kpi-label">High-Risk Credentials</div>
            </div>
          </motion.div>

          <motion.div
            className="kpi-card glass-panel"
            whileHover={{ y: -4 }}
            transition={{ duration: 0.2 }}
          >
            <div className="kpi-icon-wrap green">
              <ShieldIcon size={20} />
            </div>
            <div className="kpi-body">
              <div className="kpi-value mono">
                <AnimatedStat value={hist.length} />
              </div>
              <div className="kpi-label">Audit Scans Performed</div>
            </div>
          </motion.div>
        </div>

        {/* 2-Column Split: Category Chart + Recent Scans */}
        <div className="dashboard-grid-2">
          
          {/* Category Distribution Chart */}
          <div className="glass-panel chart-panel">
            <div className="panel-header">
              <h3 className="panel-title">Findings by Category</h3>
              {res && (
                <span className="badge badge-cyan mono">
                  {res.total} total detections
                </span>
              )}
            </div>

            {!res ? (
              <div className="empty-chart-state">
                <TerminalIcon size={28} className="empty-icon" />
                <p>Run a scan above to view category telemetry.</p>
              </div>
            ) : (
              <div className="bars">
                {CATS.map(category => {
                  const count = res.counts[category] || 0
                  const pct = Math.round((count / maxCategoryCount) * 100)
                  const info = CATEGORY_INFO[category]
                  return (
                    <div key={category} className="category-row">
                      <div className="cat-name-box">
                        <span className="cat-indicator" style={{ backgroundColor: info?.color || '#3b82f6' }} />
                        <span className="cat-label">{category}</span>
                      </div>
                      <div className="track">
                        <motion.div
                          className="fill"
                          style={{ backgroundColor: info?.color || '#3b82f6' }}
                          initial={{ width: 0 }}
                          whileInView={{ width: `${pct}%` }}
                          viewport={{ once: true }}
                          transition={{ duration: 0.8, ease: 'easeOut' }}
                        />
                      </div>
                      <span className="cat-count mono">{count}</span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Recent Scans Session Log */}
          <div className="glass-panel history-panel">
            <div className="panel-header">
              <h3 className="panel-title">Recent Session Audits</h3>
              {hist.length > 0 && (
                <button
                  className="btn btn-xs btn-outline"
                  onClick={() => setShowClearConfirm(true)}
                  aria-label="Clear scan history"
                >
                  <TrashIcon size={12} />
                  <span>Clear</span>
                </button>
              )}
            </div>

            {hist.length === 0 ? (
              <div className="empty-chart-state">
                <FileCodeIcon size={28} className="empty-icon" />
                <p>No scans recorded in this browser session.</p>
              </div>
            ) : (
              <div className="history-list">
                {hist.slice(0, 5).map((item, idx) => (
                  <div key={idx} className="history-item">
                    <div className="history-meta">
                      <span className="history-url mono">{item.target}</span>
                      <span className="history-details">
                        {new Date(item.time).toLocaleTimeString()} • {item.js} JS files • {item.total} findings
                      </span>
                    </div>
                    {onRescan && (
                      <button
                        className="btn-icon-rescan"
                        onClick={() => onRescan(item.target)}
                        title="Re-run scan on this target"
                        aria-label={`Re-run scan on ${item.target}`}
                      >
                        <ArrowRightIcon size={14} />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>

        {/* Clear History Modal */}
        {showClearConfirm && (
          <div className="modal-backdrop" onClick={() => setShowClearConfirm(false)}>
            <div
              className="modal-box glass-panel"
              onClick={e => e.stopPropagation()}
              role="dialog"
              aria-modal="true"
              aria-labelledby="clear-title"
            >
              <h3 id="clear-title" className="modal-title">Clear Local Session History?</h3>
              <p className="modal-text">
                This removes recorded scan statistics from your browser's local storage.
                The scanner backend retains no persistent logs.
              </p>
              <div className="modal-actions">
                <button
                  className="btn btn-danger"
                  onClick={() => {
                    onClearHistory()
                    setShowClearConfirm(false)
                  }}
                >
                  Confirm Clear
                </button>
                <button
                  className="btn btn-outline"
                  onClick={() => setShowClearConfirm(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

      </div>
    </section>
  )
}

