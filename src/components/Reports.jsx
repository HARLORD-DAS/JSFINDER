import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { generateCSVReport, generateJSONReport } from '../utils/security'
import { DownloadIcon, FileCodeIcon, TerminalIcon, ShieldIcon, CheckIcon } from './Icons'

const CATS = ['Email', 'JWT', 'AWS Key', 'Internal IP', 'API Endpoint']

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function Reports({ res, onNotify }) {
  const [modalOpen, setModalOpen] = useState(false)

  const handleDownloadJSON = () => {
    if (!res) return
    const content = generateJSONReport(res)
    const filename = `jsleakhunter-report-${new Date().toISOString().slice(0, 10)}.json`
    downloadFile(filename, content, 'application/json;charset=utf-8;')
    onNotify?.('JSON audit report downloaded', 'success')
  }

  const handleDownloadCSV = () => {
    if (!res) return
    const content = generateCSVReport(res)
    const filename = `jsleakhunter-report-${new Date().toISOString().slice(0, 10)}.csv`
    downloadFile(filename, content, 'text/csv;charset=utf-8;')
    onNotify?.('CSV audit report downloaded (formula hardened)', 'success')
  }

  return (
    <section id="reports" className="reports-section">
      <div className="container">
        <div className="section-header">
          <span className="section-pill">AUDIT EXPORT & COMPLIANCE</span>
          <h2 className="section-title">
            Security <span className="text-gradient">Report</span>
          </h2>
          <p className="section-subtitle">
            Export genuine reconnaissance telemetry in industry-standard JSON and CSV formats.
          </p>
        </div>

        {!res ? (
          <div className="glass-panel empty-state-box">
            <DownloadIcon size={36} className="empty-state-icon" />
            <h3 className="empty-state-title">No Report Data Available</h3>
            <p className="empty-state-desc">
              Run a scan on a target URL to generate and export security reports.
            </p>
          </div>
        ) : (
          <div className="reports-grid">
            
            {/* Executive Summary Card */}
            <motion.div
              className="glass-panel report-card"
              initial={{ opacity: 0, y: 15 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <div className="card-top-header">
                <ShieldIcon size={20} className="report-shield-icon" />
                <h3 className="report-card-title">Executive Summary</h3>
              </div>
              <div className="summary-fields">
                <div className="summary-field">
                  <span className="field-label">Target Asset:</span>
                  <span className="field-value mono">{res.target}</span>
                </div>
                <div className="summary-field">
                  <span className="field-label">Scan Timestamp:</span>
                  <span className="field-value">{new Date(res.time).toUTCString()}</span>
                </div>
                <div className="summary-field">
                  <span className="field-label">Scripts Discovered:</span>
                  <span className="field-value mono">{res.resources.length} files</span>
                </div>
                <div className="summary-field">
                  <span className="field-label">Total Findings:</span>
                  <span className="field-value mono text-highlight">{res.total}</span>
                </div>
              </div>
            </motion.div>

            {/* Category Breakdown Card */}
            <motion.div
              className="glass-panel report-card"
              initial={{ opacity: 0, y: 15 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.1 }}
            >
              <div className="card-top-header">
                <TerminalIcon size={20} className="report-terminal-icon" />
                <h3 className="report-card-title">Category Breakdown</h3>
              </div>
              <div className="report-breakdown-list">
                {CATS.map(category => (
                  <div key={category} className="breakdown-row">
                    <span className="breakdown-cat">{category}</span>
                    <span className="breakdown-count mono">{res.counts[category] || 0}</span>
                  </div>
                ))}
              </div>
            </motion.div>

            {/* Export Actions Card */}
            <motion.div
              className="glass-panel report-card"
              initial={{ opacity: 0, y: 15 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.2 }}
            >
              <div className="card-top-header">
                <DownloadIcon size={20} className="report-download-icon" />
                <h3 className="report-card-title">Export Options</h3>
              </div>
              <p className="export-desc">
                Download structured data for import into ticketing systems, SIEMs, or spreadsheets.
              </p>
              <div className="export-buttons-group">
                <button className="btn btn-primary btn-block" onClick={handleDownloadJSON}>
                  <FileCodeIcon size={16} />
                  <span>Download JSON Report</span>
                </button>
                <button className="btn btn-outline btn-block" onClick={handleDownloadCSV}>
                  <DownloadIcon size={16} />
                  <span>Download CSV (Sanitized)</span>
                </button>
                <button className="btn btn-ghost btn-block" onClick={() => setModalOpen(true)}>
                  <span>Preview Full Report Modal</span>
                </button>
              </div>
            </motion.div>

          </div>
        )}

        {/* Modal: Full Report Preview */}
        {modalOpen && res && (
          <div className="modal-backdrop" onClick={() => setModalOpen(false)}>
            <div
              className="modal-box modal-wide glass-panel"
              onClick={e => e.stopPropagation()}
              role="dialog"
              aria-modal="true"
            >
              <div className="modal-header">
                <h3 className="modal-title">JSLeakHunter Assessment Report</h3>
                <button className="btn-close-modal" onClick={() => setModalOpen(false)}>✕</button>
              </div>
              <div className="modal-body print-preview">
                <div className="report-doc-header">
                  <h4>Target: {res.target}</h4>
                  <p>Audit Time: {new Date(res.time).toUTCString()}</p>
                  <p>Discovered Scripts: {res.resources.length} | Total Exposures: {res.total}</p>
                </div>
                <hr className="report-divider" />
                <h5>Discovered Assets ({res.resources.length})</h5>
                <ul className="report-doc-list mono">
                  {res.resources.map(r => (
                    <li key={r.url}>{r.url}</li>
                  ))}
                </ul>
                <h5>Consolidated Exposures ({res.items.length})</h5>
                <div className="report-table-wrap">
                  <table className="report-doc-table">
                    <thead>
                      <tr>
                        <th>Category</th>
                        <th>Value</th>
                        <th>Resource File</th>
                      </tr>
                    </thead>
                    <tbody>
                      {res.items.map(item => (
                        <tr key={item.id}>
                          <td><span className="badge badge-info">{item.cat}</span></td>
                          <td className="mono break-all">{item.value}</td>
                          <td className="mono break-all">{item.resource || 'Global / Unassigned'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="report-disclaimer-box">
                  <strong>Disclaimer:</strong> JSLeakHunter is a passive heuristic scanner.
                  Detected patterns should be verified independently in a controlled, authorized environment.
                </div>
              </div>
              <div className="modal-actions">
                <button className="btn btn-primary" onClick={handleDownloadJSON}>
                  Export JSON
                </button>
                <button className="btn btn-outline" onClick={() => window.print()}>
                  Print Report
                </button>
                <button className="btn btn-outline" onClick={() => setModalOpen(false)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        )}

      </div>
    </section>
  )
}

