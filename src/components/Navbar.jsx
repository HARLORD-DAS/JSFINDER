import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import { ShieldIcon, TerminalIcon } from './Icons'

const NAV_ITEMS = [
  { id: 'top', label: 'Scanner' },
  { id: 'workflow', label: 'Workflow' },
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'findings', label: 'Findings' },
  { id: 'resources', label: 'Resources' },
  { id: 'reports', label: 'Reports' },
]

export default function Navbar({ onQuickScanFocus }) {
  const [scrolled, setScrolled] = useState(false)
  const [activeId, setActiveId] = useState('top')
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const rm = useReducedMotion()

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    handleScroll()
    window.addEventListener('scroll', handleScroll, { passive: true })

    const observer = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id)
          }
        })
      },
      { rootMargin: '-40% 0px -50% 0px' }
    )

    NAV_ITEMS.forEach(item => {
      const el = document.getElementById(item.id)
      if (el) observer.observe(el)
    })

    return () => {
      window.removeEventListener('scroll', handleScroll)
      observer.disconnect()
    }
  }, [])

  const scrollTo = id => {
    setMobileMenuOpen(false)
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: rm ? 'auto' : 'smooth' })
    }
  }

  return (
    <header className={`navbar-header ${scrolled ? 'scrolled' : ''}`}>
      <div className="navbar-container">
        {/* Brand Logo */}
        <button
          className="navbar-brand"
          onClick={() => scrollTo('top')}
          aria-label="JSLeakHunter Home"
        >
          <div className="brand-icon-box">
            <ShieldIcon size={20} className="brand-shield" />
          </div>
          <div className="brand-text">
            <span className="brand-title">JS<span className="brand-accent">LEAK</span>HUNTER</span>
            <span className="brand-tagline">EXPOSURE AUDITOR</span>
          </div>
        </button>

        {/* Desktop Navigation Links */}
        <nav className="navbar-nav desktop-only" aria-label="Main Navigation">
          {NAV_ITEMS.map(item => {
            const isActive = activeId === item.id
            return (
              <button
                key={item.id}
                className={`nav-link ${isActive ? 'active' : ''}`}
                onClick={() => scrollTo(item.id)}
                aria-current={isActive ? 'true' : undefined}
              >
                {item.label}
                {isActive && (
                  <motion.div
                    layoutId="navbar-active-indicator"
                    className="nav-active-pill"
                    transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                  />
                )}
              </button>
            )
          })}
        </nav>

        {/* Right CTA & Mobile Toggle */}
        <div className="navbar-actions">
          <button
            className="btn btn-sm btn-outline desktop-only"
            onClick={() => {
              scrollTo('top')
              onQuickScanFocus?.()
            }}
          >
            <TerminalIcon size={14} />
            <span>New Scan</span>
          </button>

          {/* Mobile Menu Toggle */}
          <button
            className="mobile-menu-toggle mobile-only"
            onClick={() => setMobileMenuOpen(prev => !prev)}
            aria-expanded={mobileMenuOpen}
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? '✕' : '☰'}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            className="mobile-drawer mobile-only"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
          >
            <div className="mobile-drawer-content">
              {NAV_ITEMS.map(item => (
                <button
                  key={item.id}
                  className={`mobile-nav-link ${activeId === item.id ? 'active' : ''}`}
                  onClick={() => scrollTo(item.id)}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  )
}

