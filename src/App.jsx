import { useState, useEffect, useLayoutEffect, useRef, useMemo, createContext, useContext } from 'react'
import { motion, AnimatePresence, useInView, useReducedMotion, animate } from 'framer-motion'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
gsap.registerPlugin(ScrollTrigger)

const CATS = ['Email', 'JWT', 'AWS Key', 'Internal IP', 'API Endpoint']
const NAV = [['top', 'Home'], ['workflow', 'Workflow'], ['dashboard', 'Dashboard'], ['findings', 'Findings'], ['resources', 'Resources'], ['reports', 'Reports']]
const ToastCtx = createContext(() => {})
const useToast = () => useContext(ToastCtx)

// ---- data layer: talks to the real Python backend (GET /api/scan?url=) ----
const loadHist = () => { try { return JSON.parse(localStorage.getItem('jlh_history') || '[]') } catch { return [] } }
const saveHist = h => { try { localStorage.setItem('jlh_history', JSON.stringify(h)) } catch {} }

async function runScan(url) {
  const r = await fetch('/api/scan?url=' + encodeURIComponent(url))
  const d = await r.json().catch(() => null)
  if (!d || d.status !== 'success') throw new Error((d && d.message) || `Scan failed (HTTP ${r.status})`)
  return d
}

function normalize(d) {
  const per = Array.isArray(d.resources) ? d.resources : null // optional per-file data (see README)
  const items = []
  let n = 0
  const add = (c, v, resource) => items.push({ id: n++, cat: c, value: String(v), resource })
  if (per) per.forEach(r => CATS.forEach(c => ((r.findings || {})[c] || []).forEach(v => add(c, v, r.url))))
  else CATS.forEach(c => ((d.findings || {})[c] || []).forEach(v => add(c, v, null)))
  const counts = Object.fromEntries(CATS.map(c => [c, ((d.findings || {})[c] || []).length]))
  const perCount = {}
  if (per) per.forEach(r => { perCount[r.url] = CATS.reduce((a, c) => a + (((r.findings || {})[c] || []).length), 0) })
  const resources = (d.js_files || []).map(u => ({ url: u, count: per ? perCount[u] ?? 0 : null }))
  return { target: d.target, total: d.total_findings ?? items.length, counts, items, resources, grouped: !!per, time: Date.now() }
}

// ---- export helpers (real scanner results only) ----
const csvCell = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"' }
const toCSV = r => ['target,resource,category,value', ...r.items.map(i => [r.target, i.resource || '', i.cat, i.value].map(csvCell).join(','))].join('\n')
const toJSON = r => JSON.stringify({ target: r.target, scanned_at: new Date(r.time).toISOString(), js_files: r.resources.map(x => x.url), total_findings: r.total, counts: r.counts, findings: r.items.map(({ cat, value, resource }) => ({ category: cat, value, resource })) }, null, 2)
function save(name, text, type) {
  const u = URL.createObjectURL(new Blob([text], { type }))
  const a = document.createElement('a'); a.href = u; a.download = name; a.click()
  setTimeout(() => URL.revokeObjectURL(u), 500)
}

// ---- small shared pieces ----
function Count({ to }) {
  const ref = useRef(null), inView = useInView(ref, { once: true }), rm = useReducedMotion(), [v, setV] = useState(0)
  useEffect(() => {
    if (!inView) return
    if (rm) { setV(to); return }
    const c = animate(0, to, { duration: 1.2, ease: 'easeOut', onUpdate: x => setV(Math.round(x)) })
    return () => c.stop()
  }, [inView, to, rm])
  return <span ref={ref}>{v}</span>
}
function useCopy() {
  const toast = useToast()
  return async t => { try { await navigator.clipboard.writeText(t); toast('Copied to clipboard') } catch { toast('Copy failed — clipboard unavailable', 'bad') } }
}
function Modal({ open, onClose, children }) {
  useEffect(() => { if (!open) return; const k = e => e.key === 'Escape' && onClose(); window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k) }, [open, onClose])
  return <AnimatePresence>{open && <motion.div className="ov" onClick={onClose} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
    <motion.div role="dialog" aria-modal="true" className="glass modal" onClick={e => e.stopPropagation()} initial={{ y: 24, scale: .96 }} animate={{ y: 0, scale: 1 }} exit={{ y: 24, scale: .96 }}>{children}</motion.div></motion.div>}</AnimatePresence>
}
const Empty = ({ children }) => <div className="glass empty">{children}</div>

// ---- A. cinematic intro ----
function Intro({ onDone }) {
  const rm = useReducedMotion(), [out, setOut] = useState(false)
  useEffect(() => { if (rm) { onDone(); return } const t = setTimeout(() => setOut(true), 2200); return () => clearTimeout(t) }, [rm])
  return <motion.div className="intro" exit={{ pointerEvents: 'none' }} transition={{ duration: .9 }} onAnimationComplete={() => out && onDone()}>
    <motion.div className="pn pl" animate={{ x: out ? '-101%' : 0 }} transition={{ duration: .8, ease: [.7, 0, .2, 1] }} />
    <motion.div className="pn pr" animate={{ x: out ? '101%' : 0 }} transition={{ duration: .8, ease: [.7, 0, .2, 1] }} onAnimationComplete={() => out && onDone()} />
    <motion.div className="scan" initial={{ top: '0%' }} animate={{ top: '100%' }} transition={{ duration: 1.8, ease: 'linear' }} />
    <motion.div className="logo" animate={{ opacity: out ? 0 : 1 }} initial={{ opacity: 0, letterSpacing: '.4em' }} whileInView={{ letterSpacing: '-.02em' }} transition={{ duration: 1.2 }}>
      <span>JS</span><span className="grad">LeakHunter</span></motion.div>
    <button className="btn ghost skip" onClick={onDone}>Skip intro</button>
  </motion.div>
}

// ---- H. navigation ----
function Nav() {
  const [s, setS] = useState(false), [act, setAct] = useState('top'), [open, setOpen] = useState(false), rm = useReducedMotion()
  useEffect(() => {
    const f = () => setS(window.scrollY > 20); f(); window.addEventListener('scroll', f, { passive: true })
    const io = new IntersectionObserver(es => es.forEach(e => e.isIntersecting && setAct(e.target.id)), { rootMargin: '-45% 0px -50% 0px' })
    NAV.forEach(([id]) => { const el = document.getElementById(id); el && io.observe(el) })
    return () => { window.removeEventListener('scroll', f); io.disconnect() }
  }, [])
  const go = id => { setOpen(false); document.getElementById(id)?.scrollIntoView({ behavior: rm ? 'auto' : 'smooth' }) }
  return <nav className={s ? 's' : ''} aria-label="Primary"><div className="wrap nav">
    <b className="mono" style={{ cursor: 'pointer' }} onClick={() => go('top')}>JS<span className="grad">LeakHunter</span></b>
    <div className="links">{NAV.map(([id, l]) => <button key={id} className={act === id ? 'a' : ''} aria-current={act === id ? 'true' : undefined} onClick={() => go(id)}>{l}{act === id && <motion.i layoutId="ul" className="ul" />}</button>)}</div>
    <button className="btn ghost burger" aria-expanded={open} aria-label="Menu" onClick={() => setOpen(o => !o)}>{open ? '✕' : '☰'}</button></div>
    <AnimatePresence>{open && <motion.div className="mob" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}>{NAV.map(([id, l]) => <button key={id} onClick={() => go(id)}>{l}</button>)}</motion.div>}</AnimatePresence></nav>
}

// ---- B. hero (functional scan input) ----
function Hero({ onScan, loading, error }) {
  const [url, setUrl] = useState(''), rm = useReducedMotion(), ref = useRef(null)
  const move = e => { if (rm || !ref.current) return; ref.current.style.setProperty('--mx', e.clientX + 'px'); ref.current.style.setProperty('--my', e.clientY + 'px') }
  const words = 'Find what your JavaScript gives away.'.split(' ')
  return <header id="top" className="hero" ref={ref} onPointerMove={move}><div className="glow" aria-hidden />
    <div className="wrap" style={{ position: 'relative' }}>
      <span className="tag mono">Passive • Static • Authorized use only</span>
      <h1>{words.map((w, i) => <motion.span key={i} style={{ display: 'inline-block', marginRight: '.25em' }} className={i > 2 ? 'grad' : ''} initial={{ y: 40, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: rm ? 0 : .1 * i, duration: .6 }}>{w}</motion.span>)}</h1>
      <p className="sub">JSLeakHunter fetches a page, discovers its JavaScript files and pattern-matches them for emails, JWTs, AWS key IDs, internal IPs and API endpoints.</p>
      <form className="row" onSubmit={e => { e.preventDefault(); if (url.trim() && !loading) onScan(url.trim()) }}>
        <input className="field mono" aria-label="Website URL" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} />
        <motion.button whileHover={{ scale: 1.03 }} whileTap={{ scale: .97 }} className="btn" disabled={loading || !url.trim()}>{loading && <i className="spin" />}{loading ? 'Scanning…' : 'Start Scan'}</motion.button></form>
      {error && <p className="err" role="alert">⚠ {error}</p>}
      <p className="sub" style={{ marginTop: 14 }}>Only scan sites you own or have written permission to assess.</p></div></header>
}

// ---- C. scroll storytelling (GSAP ScrollTrigger, pinned). Illustrative of the workflow, not live scan output. ----
const STEPS = [['Website submitted', 'You enter a URL; it is sent to /api/scan.'], ['JS discovered', 'The page HTML is parsed for <script src> files.'], ['Resources analysed', 'Each file is fetched and matched against 5 patterns.'], ['Exposures identified', 'Matches are de-duplicated per category.'], ['Findings presented', 'Results appear in the explorer and reports.']]
function Story() {
  const root = useRef(null), rm = useReducedMotion()
  useLayoutEffect(() => {
    if (rm) return
    const ctx = gsap.context(() => {
      const steps = gsap.utils.toArray('.step')
      gsap.set(steps, { opacity: .2, y: 20 })
      const tl = gsap.timeline({ scrollTrigger: { trigger: root.current, start: 'top top', end: '+=220%', pin: true, scrub: .6 } })
      steps.forEach((s, i) => tl.to(s, { opacity: 1, y: 0, duration: 1 }).to('.bar', { scaleX: (i + 1) / steps.length, duration: 1, ease: 'none' }, '<'))
    }, root)
    return () => ctx.revert()
  }, [rm])
  return <section id="workflow" className="story" ref={root}><div className="wrap" style={{ width: '100%' }}>
    <h2>How a scan <span className="grad">works</span></h2><p className="sub">Scroll through the five stages the Python engine performs.</p>
    <div className="steps">{STEPS.map(([t, d], i) => <div key={t} className="glass step"><b className="grad mono">0{i + 1}</b><h3 style={{ fontSize: '1.1rem', margin: '6px 0' }}>{t}</h3><p style={{ color: 'var(--mut)', margin: 0, fontSize: '.9rem' }}>{d}</p></div>)}</div>
    {!rm && <div className="prog"><div className="bar" /></div>}</div></section>
}

// ---- D. dashboard (real data: your scan history stored in this browser + latest backend result) ----
function Dashboard({ hist, res, clear }) {
  const [ask, setAsk] = useState(false)
  const totals = hist.reduce((a, h) => ({ js: a.js + h.js, f: a.f + h.total }), { js: 0, f: 0 })
  const max = Math.max(1, ...CATS.map(c => res?.counts[c] || 0))
  return <section id="dashboard"><div className="wrap"><h2>Security <span className="grad">dashboard</span></h2>
    <p className="sub">Totals are computed from scans you ran in this browser; the scanner itself keeps no history.</p>
    <div className="stats">{[['Total scans', hist.length], ['JS resources discovered', totals.js], ['Total findings', totals.f]].map(([l, n]) => <motion.div key={l} className="glass stat" whileHover={{ y: -4 }}><b><Count to={n} /></b><span>{l}</span></motion.div>)}</div>
    <div className="grid2" style={{ marginTop: 14 }}>
      <div className="glass bars"><h3>Latest scan by category</h3>{!res ? <p className="empty">Run a scan to see categories.</p> : CATS.map(c => <div key={c}><span>{c}</span><div className="track"><motion.div className="fill" initial={{ width: 0 }} whileInView={{ width: (res.counts[c] / max) * 100 + '%' }} viewport={{ once: true }} /></div><b>{res.counts[c]}</b></div>)}</div>
      <div className="glass"><div className="row" style={{ justifyContent: 'space-between' }}><h3>Recent scans</h3>{hist.length > 0 && <button className="chip" onClick={() => setAsk(true)}>Clear</button>}</div>
        {!hist.length ? <p className="empty">No scans yet.</p> : hist.slice(0, 6).map((h, i) => <div key={i} style={{ margin: '10px 0', wordBreak: 'break-all' }}><span className="mono">{h.target}</span><br /><small style={{ color: 'var(--mut)' }}>{new Date(h.time).toLocaleString()} · {h.js} JS · {h.total} findings</small></div>)}</div></div>
    <Modal open={ask} onClose={() => setAsk(false)}><h3>Clear scan history?</h3><p className="sub">This only removes the history stored in this browser.</p><div className="row"><button className="btn" onClick={() => { clear(); setAsk(false) }}>Clear</button><button className="btn ghost" onClick={() => setAsk(false)}>Cancel</button></div></Modal></div></section>
}

// ---- E. findings explorer ----
function Row({ it, open, setOpen, copy }) {
  const o = open === it.id
  return <motion.div layout initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: .96 }} className="glass">
    <button className="item" style={{ background: 'none', border: 0, padding: 0 }} aria-expanded={o} onClick={() => setOpen(o ? null : it.id)}>
      <div className="top"><span className="mono val">{it.value}</span><span className="tag">{it.cat}</span></div></button>
    <AnimatePresence>{o && <motion.div className="det" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} style={{ overflow: 'hidden' }}>
      <div>Category: {it.cat}</div><div>Found in: {it.resource || 'not reported by backend (see README to enable)'}</div>
      <button className="chip" style={{ marginTop: 8 }} onClick={() => copy(it.value)}>Copy value</button></motion.div>}</AnimatePresence></motion.div>
}
function Findings({ res }) {
  const [cat, setCat] = useState('All'), [q, setQ] = useState(''), [group, setGroup] = useState(false), [open, setOpen] = useState(null), copy = useCopy()
  const list = useMemo(() => res ? res.items.filter(i => (cat === 'All' || i.cat === cat) && (i.value + ' ' + (i.resource || '')).toLowerCase().includes(q.toLowerCase())) : [], [res, cat, q])
  const groups = useMemo(() => { const m = new Map(); list.forEach(i => { const k = i.resource || 'All findings'; m.set(k, [...(m.get(k) || []), i]) }); return [...m] }, [list])
  return <section id="findings"><div className="wrap"><h2>Findings <span className="grad">explorer</span></h2>
    <p className="sub">Severity is not assigned: the scanner only classifies matches by category, so none is invented here.</p>
    {!res ? <Empty>No results yet — start a scan above.</Empty> : <>
      <div className="tools"><input className="field" aria-label="Search findings" placeholder="Search findings…" value={q} onChange={e => setQ(e.target.value)} />
        {res.grouped && <button className="chip" aria-pressed={group} onClick={() => setGroup(g => !g)}>Group by resource</button>}</div>
      <div className="tools">{['All', ...CATS].map(c => <button key={c} className="chip" aria-pressed={cat === c} onClick={() => setCat(c)}>{c}{c !== 'All' && ` (${res.counts[c]})`}</button>)}</div>
      {!list.length ? <Empty>{res.total ? 'No findings match these filters.' : 'Scan complete — no sensitive findings detected.'}</Empty>
        : <div className="list">{(group && res.grouped ? groups : [['', list]]).map(([k, its]) => <div key={k} className="list">{k && <h3 className="mono" style={{ fontSize: '.9rem', wordBreak: 'break-all', color: 'var(--mut)' }}>{k}</h3>}
          <AnimatePresence mode="popLayout">{its.map(it => <Row key={it.id} it={it} open={open} setOpen={setOpen} copy={copy} />)}</AnimatePresence></div>)}</div>}</>}</div></section>
}

// ---- F. resource explorer ----
function Resources({ res }) {
  const [q, setQ] = useState(''), [open, setOpen] = useState(null), [only, setOnly] = useState(false), copy = useCopy()
  const list = res ? res.resources.filter(r => r.url.toLowerCase().includes(q.toLowerCase()) && (!only || r.count > 0)) : []
  return <section id="resources"><div className="wrap"><h2>JavaScript <span className="grad">resources</span></h2><p className="sub">Files discovered from the page's script tags.</p>
    {!res ? <Empty>No results yet.</Empty> : !res.resources.length ? <Empty>The page references no external JavaScript files.</Empty> : <>
      <div className="tools"><input className="field" aria-label="Search resources" placeholder="Filter by URL…" value={q} onChange={e => setQ(e.target.value)} />
        {res.grouped && <button className="chip" aria-pressed={only} onClick={() => setOnly(o => !o)}>With findings only</button>}</div>
      <div className="grid2"><AnimatePresence>{list.map(r => <motion.div layout key={r.url} className="glass" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} whileHover={{ y: -3 }}>
        <button style={{ all: 'unset', cursor: 'pointer', display: 'block', width: '100%' }} aria-expanded={open === r.url} onClick={() => setOpen(open === r.url ? null : r.url)}>
          <div className="mono val" style={{ fontSize: '.85rem' }}>{r.url}</div>{r.count !== null && <span className="tag" style={{ marginTop: 8, display: 'inline-block' }}>{r.count} findings</span>}</button>
        {open === r.url && <div className="det"><button className="chip" onClick={() => copy(r.url)}>Copy URL</button>{res.grouped && <div style={{ marginTop: 8 }}>{CATS.map(c => { const n = res.items.filter(i => i.resource === r.url && i.cat === c).length; return n ? <div key={c}>{c}: {n}</div> : null })}</div>}</div>}</motion.div>)}</AnimatePresence></div></>}</div></section>
}

// ---- G. reports ----
function Reports({ res }) {
  const toast = useToast()
  const dl = (kind) => { kind === 'json' ? save('jsleakhunter-report.json', toJSON(res), 'application/json') : save('jsleakhunter-report.csv', toCSV(res), 'text/csv'); toast(`${kind.toUpperCase()} report downloaded`) }
  return <section id="reports"><div className="wrap"><h2>Scan <span className="grad">report</span></h2><p className="sub">Exports contain exactly what the scanner returned.</p>
    {!res ? <Empty>Run a scan to generate a report.</Empty> : <div className="grid2">
      <motion.div className="glass" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}><h3>Summary</h3><p className="mono val">{res.target}</p><p>{res.resources.length} JS files · {res.total} findings</p><small style={{ color: 'var(--mut)' }}>{new Date(res.time).toLocaleString()}</small></motion.div>
      <motion.div className="glass" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: .1 }}><h3>Breakdown</h3>{CATS.map(c => <div key={c} className="row" style={{ justifyContent: 'space-between' }}><span>{c}</span><b>{res.counts[c]}</b></div>)}</motion.div>
      <motion.div className="glass" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: .2 }}><h3>Export</h3><div className="row"><button className="btn" onClick={() => dl('json')}>Download JSON</button><button className="btn ghost" onClick={() => dl('csv')}>Download CSV</button></div></motion.div></div>}</div></section>
}

// ---- app ----
export default function App() {
  const [intro, setIntro] = useState(true), [res, setRes] = useState(null), [loading, setLoading] = useState(false), [error, setError] = useState('')
  const [hist, setHist] = useState(loadHist), [toasts, setToasts] = useState([])
  const toast = (m, k) => { const id = Math.random(); setToasts(t => [...t, { id, m, k }]); setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 2500) }
  async function onScan(url) {
    setLoading(true); setError('')
    try {
      const r = normalize(await runScan(url)); setRes(r)
      const h = [{ target: r.target, time: r.time, js: r.resources.length, total: r.total }, ...loadHist()].slice(0, 50); saveHist(h); setHist(h)
      toast(`Scan complete — ${r.total} findings`)
      setTimeout(() => document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' }), 200)
    } catch (e) { setError(e.message); toast('Scan failed', 'bad') } finally { setLoading(false) }
  }
  return <ToastCtx.Provider value={toast}>
    <AnimatePresence>{intro && <Intro key="i" onDone={() => setIntro(false)} />}</AnimatePresence>
    <Nav /><main><Hero onScan={onScan} loading={loading} error={error} /><Story />
      <Dashboard hist={hist} res={res} clear={() => { saveHist([]); setHist([]) }} /><Findings res={res} /><Resources res={res} /><Reports res={res} /></main>
    <footer className="wrap" style={{ padding: '40px 20px', color: 'var(--mut)' }}>JSLeakHunter — passive scanning for authorized assessments only.</footer>
    <div className="toasts" aria-live="polite">{toasts.map(t => <motion.div key={t.id} className={'toast ' + (t.k || '')} initial={{ x: 40, opacity: 0 }} animate={{ x: 0, opacity: 1 }}>{t.m}</motion.div>)}</div>
  </ToastCtx.Provider>
}
