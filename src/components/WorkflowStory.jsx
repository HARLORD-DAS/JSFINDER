import React, { useRef, useLayoutEffect } from 'react'
import { useReducedMotion } from 'framer-motion'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { ShieldIcon, SearchIcon, FileCodeIcon, TerminalIcon, CheckIcon } from './Icons'

gsap.registerPlugin(ScrollTrigger)

const STAGES = [
  {
    step: '01',
    title: 'SSRF & Protocol Guard',
    desc: 'The target URL protocol is verified (HTTP/HTTPS only). DNS resolution confirms the destination address is strictly public and not in private, loopback, or cloud metadata ranges.',
    icon: ShieldIcon,
    tag: 'Pre-flight Validation'
  },
  {
    step: '02',
    title: 'HTML & Script Discovery',
    desc: 'The web page is parsed for <script src> elements. Relative script references are resolved into absolute URLs and filtered against malicious schemes and data URIs.',
    icon: SearchIcon,
    tag: 'Resource Identification'
  },
  {
    step: '03',
    title: 'Bounded Safe Fetching',
    desc: 'Discovered JavaScript assets are retrieved with strict connection and read timeouts. Bounded streaming prevents memory exhaustion and validates content types.',
    icon: FileCodeIcon,
    tag: 'Safe Ingestion'
  },
  {
    step: '04',
    title: 'Regex Heuristic Analysis',
    desc: 'JavaScript source code is matched against specialized patterns for AWS Access Keys, JWTs, RFC 1918 internal IP addresses, REST/internal API routes, and developer emails.',
    icon: TerminalIcon,
    tag: 'Exposure Detection'
  },
  {
    step: '05',
    title: 'Attribution & Consolidation',
    desc: 'Matches are de-duplicated and attributed per-file and per-category. Summary statistics are compiled ready for interactive exploration and CSV/JSON export.',
    icon: CheckIcon,
    tag: 'Report Compilation'
  }
]

export default function WorkflowStory() {
  const containerRef = useRef(null)
  const rm = useReducedMotion()

  useLayoutEffect(() => {
    if (rm) return

    const ctx = gsap.context(() => {
      const cards = gsap.utils.toArray('.workflow-card')
      gsap.set(cards, { opacity: 0.25, y: 30, scale: 0.96 })

      const tl = gsap.timeline({
        scrollTrigger: {
          trigger: containerRef.current,
          start: 'top top',
          end: '+=200%',
          pin: true,
          scrub: 0.7
        }
      })

      cards.forEach((card, idx) => {
        tl.to(card, {
          opacity: 1,
          y: 0,
          scale: 1,
          duration: 1,
          ease: 'power2.out'
        }).to(
          '.workflow-progress-bar',
          {
            scaleX: (idx + 1) / cards.length,
            duration: 1,
            ease: 'none'
          },
          '<'
        )
      })
    }, containerRef)

    return () => ctx.revert()
  }, [rm])

  return (
    <section id="workflow" className="workflow-section" ref={containerRef}>
      <div className="container workflow-container">
        <div className="section-header text-center">
          <span className="section-pill">ANALYSIS LIFECYCLE</span>
          <h2 className="section-title">
            How a scan <span className="text-gradient">operates</span>
          </h2>
          <p className="section-subtitle">
            JSLeakHunter performs zero-intrusion passive evaluation through five systematic stages.
          </p>
        </div>

        {/* Workflow Step Cards */}
        <div className="workflow-grid">
          {STAGES.map((s, idx) => {
            const IconComponent = s.icon
            return (
              <div key={s.step} className="workflow-card glass-panel">
                <div className="card-top-meta">
                  <span className="step-number mono">{s.step}</span>
                  <span className="step-badge">{s.tag}</span>
                </div>
                <div className="card-icon-wrap">
                  <IconComponent size={22} />
                </div>
                <h3 className="card-title">{s.title}</h3>
                <p className="card-desc">{s.desc}</p>
              </div>
            )
          })}
        </div>

        {/* Scroll Progress Bar (for GSAP scrub) */}
        {!rm && (
          <div className="workflow-progress-track">
            <div className="workflow-progress-bar" />
          </div>
        )}
      </div>
    </section>
  )
}

