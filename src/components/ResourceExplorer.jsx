import React, { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { safeExternalUrl, getDomainInfo, CATEGORY_INFO } from '../utils/security'
import { FileCodeIcon, SearchIcon, ExternalLinkIcon, CopyIcon, CheckIcon, ChevronDownIcon, GlobeIcon } from './Icons'

export default function ResourceExplorer({ res, onCopy }) {
  const [searchFilter, setSearchFilter] = useState('')
  const [onlyWithFindings, setOnlyWithFindings] = useState(false)
  const [expandedUrl, setExpandedUrl] = useState(null)
  const [copiedUrl, setCopiedUrl] = useState(null)

  const handleCopy = (url) => {
    onCopy(url)
    setCopiedUrl(url)
    setTimeout(() => setCopiedUrl(null), 2000)
  }

  const resourceList = useMemo(() => {
    if (!res || !Array.isArray(res.resources)) return []
    return res.resources.filter(r => {
      const matchSearch = !searchFilter || r.url.toLowerCase().includes(searchFilter.toLowerCase())
      const matchFindings = !onlyWithFindings || (r.count !== null && r.count > 0)
      return matchSearch && matchFindings
    })
  }, [res, searchFilter, onlyWithFindings])

  return (
    <section id="resources" className="resources-section">
      <div className="container">
        <div className="section-header">
          <span className="section-pill">RESOURCE ENUMERATION</span>
          <h2 className="section-title">
            JavaScript <span className="text-gradient">Resources</span>
          </h2>
          <p className="section-subtitle">
            External and inline-linked JavaScript files discovered on the target page.
          </p>
        </div>

        {!res ? (
          <div className="glass-panel empty-state-box">
            <FileCodeIcon size={36} className="empty-state-icon" />
            <h3 className="empty-state-title">No JavaScript Assets Loaded</h3>
            <p className="empty-state-desc">
              Execute a scan above to discover scripts referenced on the target website.
            </p>
          </div>
        ) : res.resources.length === 0 ? (
          <div className="glass-panel empty-state-box">
            <FileCodeIcon size={36} className="empty-state-icon" />
            <h3 className="empty-state-title">No External JavaScript Found</h3>
            <p className="empty-state-desc">
              The target HTML page does not reference any external JavaScript files via &lt;script src&gt;.
            </p>
          </div>
        ) : (
          <div className="resources-wrapper">
            
            {/* Toolbar */}
            <div className="glass-panel findings-toolbar">
              <div className="toolbar-search-box">
                <SearchIcon size={16} className="search-box-icon" />
                <input
                  type="text"
                  className="toolbar-search-input"
                  placeholder="Filter scripts by URL or domain…"
                  value={searchFilter}
                  onChange={e => setSearchFilter(e.target.value)}
                  aria-label="Filter JavaScript resources"
                />
                {searchFilter && (
                  <button
                    className="search-clear-btn"
                    onClick={() => setSearchFilter('')}
                    aria-label="Clear filter"
                  >
                    ✕
                  </button>
                )}
              </div>

              {res.grouped && (
                <div className="toolbar-actions">
                  <button
                    className={`btn btn-sm ${onlyWithFindings ? 'btn-primary' : 'btn-outline'}`}
                    onClick={() => setOnlyWithFindings(prev => !prev)}
                    aria-pressed={onlyWithFindings}
                  >
                    <span>With Findings Only</span>
                  </button>
                </div>
              )}
            </div>

            {/* Resources List Grid */}
            {resourceList.length === 0 ? (
              <div className="glass-panel empty-state-box">
                <SearchIcon size={32} className="empty-state-icon" />
                <h3 className="empty-state-title">No Matching Resources</h3>
                <p className="empty-state-desc">
                  No JavaScript assets matched your search or findings criteria.
                </p>
              </div>
            ) : (
              <div className="resources-grid">
                <AnimatePresence>
                  {resourceList.map(item => {
                    const domainInfo = getDomainInfo(item.url, res.target)
                    const isExpanded = expandedUrl === item.url
                    const isCopied = copiedUrl === item.url
                    const safeHref = safeExternalUrl(item.url)

                    // Find findings for this resource
                    const fileItems = res.grouped
                      ? res.items.filter(i => i.resource === item.url)
                      : []

                    return (
                      <motion.div
                        key={item.url}
                        layout
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.98 }}
                        className="glass-panel resource-card"
                      >
                        <div className="resource-card-top">
                          <div className="resource-domain-meta">
                            <span
                              className={`domain-badge ${
                                domainInfo.isFirstParty ? 'first-party' : 'third-party'
                              }`}
                            >
                              <GlobeIcon size={12} />
                              <span>{domainInfo.isFirstParty ? '1st Party' : '3rd Party / CDN'}</span>
                            </span>
                            <span className="domain-name mono">{domainInfo.domain}</span>
                          </div>

                          {item.count !== null && (
                            <span
                              className={`badge ${
                                item.count > 0 ? 'badge-danger' : 'badge-neutral'
                              } mono`}
                            >
                              {item.count} {item.count === 1 ? 'finding' : 'findings'}
                            </span>
                          )}
                        </div>

                        {/* Script URL */}
                        <div className="resource-url-box mono" title={item.url}>
                          {item.url}
                        </div>

                        {/* Card Actions */}
                        <div className="resource-card-actions">
                          <button
                            className="btn btn-xs btn-outline"
                            onClick={() => handleCopy(item.url)}
                            aria-label="Copy script URL"
                          >
                            {isCopied ? <CheckIcon size={12} /> : <CopyIcon size={12} />}
                            <span>{isCopied ? 'Copied' : 'Copy URL'}</span>
                          </button>

                          {safeHref !== '#' && (
                            <a
                              href={safeHref}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="btn btn-xs btn-outline external-link"
                              aria-label="Open script in new tab"
                            >
                              <ExternalLinkIcon size={12} />
                              <span>Inspect Script</span>
                            </a>
                          )}

                          {res.grouped && fileItems.length > 0 && (
                            <button
                              className="btn btn-xs btn-primary ml-auto"
                              onClick={() => setExpandedUrl(isExpanded ? null : item.url)}
                              aria-expanded={isExpanded}
                            >
                              <span>{isExpanded ? 'Hide' : 'View'} Findings ({fileItems.length})</span>
                              <ChevronDownIcon size={12} className={isExpanded ? 'rotate-180' : ''} />
                            </button>
                          )}
                        </div>

                        {/* Expanded Findings inside this resource */}
                        <AnimatePresence>
                          {isExpanded && fileItems.length > 0 && (
                            <motion.div
                              className="resource-findings-drawer"
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                            >
                              <h4 className="drawer-title">Findings inside this script:</h4>
                              <div className="drawer-items">
                                {fileItems.map(f => {
                                  const info = CATEGORY_INFO[f.cat] || {}
                                  return (
                                    <div key={f.id} className="drawer-finding-row">
                                      <span
                                        className={`badge ${info.badgeClass || 'badge-neutral'}`}
                                      >
                                        {f.cat}
                                      </span>
                                      <span className="drawer-finding-val mono">{f.value}</span>
                                    </div>
                                  )
                                })}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    )
                  })}
                </AnimatePresence>
              </div>
            )}

          </div>
        )}

      </div>
    </section>
  )
}

