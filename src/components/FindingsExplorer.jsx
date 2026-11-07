import React, { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CATEGORY_INFO } from '../utils/security'
import { SearchIcon, CopyIcon, CheckIcon, ChevronDownIcon, TerminalIcon, FileCodeIcon } from './Icons'

const CATS = ['Email', 'JWT', 'AWS Key', 'Internal IP', 'API Endpoint']

export default function FindingsExplorer({ res, onCopy }) {
  const [activeCategory, setActiveCategory] = useState('All')
  const [searchQuery, setSearchQuery] = useState('')
  const [groupByResource, setGroupByResource] = useState(false)
  const [expandedId, setExpandedId] = useState(null)
  const [copiedId, setCopiedId] = useState(null)
  const [sortBy, setSortBy] = useState('default') // 'default' | 'alpha' | 'cat' | 'len'

  const handleCopyValue = (id, text) => {
    onCopy(text)
    setCopiedId(id)
    setTimeout(() => {
      setCopiedId(null)
    }, 2000)
  }

  // Filtered and sorted finding items
  const filteredList = useMemo(() => {
    if (!res || !Array.isArray(res.items)) return []
    let list = res.items.filter(item => {
      const matchCat = activeCategory === 'All' || item.cat === activeCategory
      const query = searchQuery.toLowerCase().trim()
      const matchQuery =
        !query ||
        item.value.toLowerCase().includes(query) ||
        item.cat.toLowerCase().includes(query) ||
        (item.resource && item.resource.toLowerCase().includes(query))
      return matchCat && matchQuery
    })

    if (sortBy === 'alpha') {
      list = [...list].sort((a, b) => a.value.localeCompare(b.value))
    } else if (sortBy === 'cat') {
      list = [...list].sort((a, b) => a.cat.localeCompare(b.cat))
    } else if (sortBy === 'len') {
      list = [...list].sort((a, b) => b.value.length - a.value.length)
    }

    return list
  }, [res, activeCategory, searchQuery, sortBy])

  // Grouped by resource map
  const groupedResources = useMemo(() => {
    if (!groupByResource || !res) return null
    const map = new Map()
    filteredList.forEach(item => {
      const key = item.resource || 'Global / Unattributed'
      if (!map.has(key)) map.set(key, [])
      map.get(key).push(item)
    })
    return Array.from(map.entries())
  }, [groupByResource, res, filteredList])

  return (
    <section id="findings" className="findings-section">
      <div className="container">
        <div className="section-header">
          <span className="section-pill">STATIC HEURISTIC RESULTS</span>
          <h2 className="section-title">
            Findings <span className="text-gradient">Explorer</span>
          </h2>
          <p className="section-subtitle">
            Inspect discovered tokens, endpoints, and identifiers with genuine per-script attribution.
          </p>
        </div>

        {!res ? (
          <div className="glass-panel empty-state-box">
            <TerminalIcon size={36} className="empty-state-icon" />
            <h3 className="empty-state-title">No Scan Performed Yet</h3>
            <p className="empty-state-desc">
              Enter a website URL above and click "Scan Target" to analyze JavaScript files for exposures.
            </p>
          </div>
        ) : (
          <div className="findings-wrapper">
            
            {/* Filter Tools Toolbar */}
            <div className="glass-panel findings-toolbar">
              {/* Search Bar */}
              <div className="toolbar-search-box">
                <SearchIcon size={16} className="search-box-icon" />
                <input
                  type="text"
                  className="toolbar-search-input"
                  placeholder="Filter findings by text, token, or file…"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  aria-label="Filter findings"
                />
                {searchQuery && (
                  <button
                    className="search-clear-btn"
                    onClick={() => setSearchQuery('')}
                    aria-label="Clear search filter"
                  >
                    ✕
                  </button>
                )}
              </div>

              {/* Group by Resource Toggle (only if backend has per-resource data) */}
              <div className="toolbar-actions">
                {res.grouped && (
                  <button
                    className={`btn btn-sm ${groupByResource ? 'btn-primary' : 'btn-outline'}`}
                    onClick={() => setGroupByResource(prev => !prev)}
                    aria-pressed={groupByResource}
                  >
                    <FileCodeIcon size={14} />
                    <span>Group by Script</span>
                  </button>
                )}

                {/* Sort Dropdown */}
                <select
                  className="toolbar-select"
                  value={sortBy}
                  onChange={e => setSortBy(e.target.value)}
                  aria-label="Sort findings"
                >
                  <option value="default">Sort: Default</option>
                  <option value="alpha">Sort: Value (A-Z)</option>
                  <option value="cat">Sort: Category</option>
                  <option value="len">Sort: Length</option>
                </select>
              </div>
            </div>

            {/* Category Filter Pills */}
            <div className="category-pills-bar">
              <button
                className={`category-pill ${activeCategory === 'All' ? 'active' : ''}`}
                onClick={() => setActiveCategory('All')}
              >
                <span>All Categories</span>
                <span className="pill-count mono">{res.total}</span>
              </button>

              {CATS.map(cat => {
                const count = res.counts[cat] || 0
                const isActive = activeCategory === cat
                const info = CATEGORY_INFO[cat]
                return (
                  <button
                    key={cat}
                    className={`category-pill ${isActive ? 'active' : ''}`}
                    onClick={() => setActiveCategory(cat)}
                  >
                    <span
                      className="pill-dot"
                      style={{ backgroundColor: info?.color || '#3b82f6' }}
                    />
                    <span>{cat}</span>
                    <span className="pill-count mono">{count}</span>
                  </button>
                )
              })}
            </div>

            {/* Finding Items List */}
            {filteredList.length === 0 ? (
              <div className="glass-panel empty-state-box">
                <SearchIcon size={32} className="empty-state-icon" />
                <h3 className="empty-state-title">
                  {res.total === 0
                    ? 'No Sensitive Findings Detected'
                    : 'No Findings Match Your Filter'}
                </h3>
                <p className="empty-state-desc">
                  {res.total === 0
                    ? 'The analyzed JavaScript assets did not expose any patterns matching emails, JWTs, AWS keys, internal IPs, or API routes.'
                    : 'Try clearing the search query or selecting "All Categories" to see all scan results.'}
                </p>
                {searchQuery && (
                  <button
                    className="btn btn-sm btn-outline"
                    onClick={() => {
                      setSearchQuery('')
                      setActiveCategory('All')
                    }}
                  >
                    Reset Filters
                  </button>
                )}
              </div>
            ) : groupByResource && groupedResources ? (
              /* Grouped by Script View */
              <div className="grouped-findings-container">
                {groupedResources.map(([resourcePath, items]) => (
                  <div key={resourcePath} className="glass-panel resource-group-block">
                    <div className="resource-group-header">
                      <div className="group-header-left">
                        <FileCodeIcon size={16} className="group-file-icon" />
                        <span className="group-resource-url mono">{resourcePath}</span>
                      </div>
                      <span className="badge badge-info mono">{items.length} findings</span>
                    </div>
                    <div className="group-items-list">
                      {items.map(item => (
                        <FindingCard
                          key={item.id}
                          item={item}
                          isExpanded={expandedId === item.id}
                          isCopied={copiedId === item.id}
                          onToggleExpand={() =>
                            setExpandedId(prev => (prev === item.id ? null : item.id))
                          }
                          onCopy={() => handleCopyValue(item.id, item.value)}
                        />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              /* Flat Findings List */
              <div className="flat-findings-list">
                <AnimatePresence mode="popLayout">
                  {filteredList.map(item => (
                    <FindingCard
                      key={item.id}
                      item={item}
                      isExpanded={expandedId === item.id}
                      isCopied={copiedId === item.id}
                      onToggleExpand={() =>
                        setExpandedId(prev => (prev === item.id ? null : item.id))
                      }
                      onCopy={() => handleCopyValue(item.id, item.value)}
                    />
                  ))}
                </AnimatePresence>
              </div>
            )}

          </div>
        )}

      </div>
    </section>
  )
}

function FindingCard({ item, isExpanded, isCopied, onToggleExpand, onCopy }) {
  const info = CATEGORY_INFO[item.cat] || {}

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.98 }}
      className="glass-panel finding-card"
    >
      <div className="finding-card-header" onClick={onToggleExpand}>
        <div className="card-header-main">
          <span
            className={`badge ${info.badgeClass || 'badge-neutral'}`}
            style={{ borderColor: info.color }}
          >
            {item.cat}
          </span>
          <div className="finding-value-box mono">
            {/* Safe rendering: plain text child, no innerHTML */}
            <span className="finding-value-text">{item.value}</span>
          </div>
        </div>

        <div className="card-header-actions" onClick={e => e.stopPropagation()}>
          <button
            className={`btn-icon-copy ${isCopied ? 'copied' : ''}`}
            onClick={onCopy}
            title="Copy value to clipboard"
            aria-label="Copy finding value"
          >
            {isCopied ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
            <span className="copy-label">{isCopied ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            className="btn-icon-chevron"
            onClick={onToggleExpand}
            aria-expanded={isExpanded}
            aria-label="Toggle details"
          >
            <motion.div
              animate={{ rotate: isExpanded ? 180 : 0 }}
              transition={{ duration: 0.2 }}
            >
              <ChevronDownIcon size={16} />
            </motion.div>
          </button>
        </div>
      </div>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            className="finding-card-details"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="details-grid">
              <div className="detail-item">
                <span className="detail-label">Risk Classification:</span>
                <span className="detail-val" style={{ color: info.color || '#3b82f6', fontWeight: 600 }}>
                  {info.severity || 'Information'}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Discovered In:</span>
                <span className="detail-val mono">
                  {item.resource || 'Global page scan (attribution unavailable)'}
                </span>
              </div>
              <div className="detail-item full-width">
                <span className="detail-label">Security Context:</span>
                <p className="detail-context-desc">
                  {info.description || 'Static regex match detected in JavaScript source code.'}
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

