import React, { useState, useEffect } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { ShieldIcon, TerminalIcon } from './Icons'

export default function Intro({ onDone }) {
  const rm = useReducedMotion()
  const [phase, setPhase] = useState('hold') // 'hold' -> 'split' -> 'done'

  useEffect(() => {
    if (rm) {
      onDone()
      return
    }
    const t1 = setTimeout(() => setPhase('split'), 1700)
    const t2 = setTimeout(() => {
      setPhase('done')
      onDone()
    }, 2700)
    return () => {
      clearTimeout(t1)
      clearTimeout(t2)
    }
  }, [rm, onDone])

  if (phase === 'done') return null

  const splitting = phase === 'split'

  return (
    <div className="intro-container" aria-hidden="true">
      {/* Left Shutter Panel */}
      <motion.div
        className="intro-panel intro-panel-left"
        animate={{ x: splitting ? '-100%' : '0%' }}
        transition={{ duration: 0.95, ease: [0.76, 0, 0.24, 1] }}
      >
        <div className="intro-half-content right-align">
          <div className="intro-badge">
            <ShieldIcon size={16} />
            <span>SECURITY AUDIT</span>
          </div>
          <div className="intro-word-left">JSLEAK</div>
        </div>
      </motion.div>

      {/* Right Shutter Panel */}
      <motion.div
        className="intro-panel intro-panel-right"
        animate={{ x: splitting ? '100%' : '0%' }}
        transition={{ duration: 0.95, ease: [0.76, 0, 0.24, 1] }}
      >
        <div className="intro-half-content left-align">
          <div className="intro-badge cyan">
            <TerminalIcon size={16} />
            <span>V2.0 HARDENED</span>
          </div>
          <div className="intro-word-right">HUNTER</div>
        </div>
      </motion.div>

      {/* Center Laser Seam */}
      <motion.div
        className="intro-seam"
        animate={{ opacity: splitting ? 0 : [0.4, 1, 0.6] }}
        transition={{ duration: 1.2, repeat: Infinity, ease: 'easeInOut' }}
      />

      {/* Center Glow Aura */}
      <motion.div
        className="intro-aura"
        animate={{ opacity: splitting ? 0 : 0.8, scale: splitting ? 1.4 : 1 }}
        transition={{ duration: 0.4 }}
      />

      {/* Skip Button */}
      <button
        className="intro-skip-btn"
        onClick={onDone}
        aria-label="Skip introductory animation"
      >
        Skip Intro →
      </button>
    </div>
  )
}

