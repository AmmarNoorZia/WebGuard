import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Radar } from 'lucide-react'
import { useApp } from '../contexts/AppContext'
import { apiRequest } from '../lib/api'
import { useScanData } from '../lib/useScanData'
import { modules } from '../lib/constants'
import { EmptyState, SectionHeader } from '../components/Icons'
import ScanResult from '../components/ScanResult'

const scanOptions = {
  reflected: { label: 'Reflected XSS', endpoint: '/scans/xss',
    description: 'Tests /search?q with the existing same-origin demonstration script. Chrome checks the expected alert with CSP enabled.',
    progress: 'Testing the normal response, HTML reflection and browser execution. Please wait.' },
  stored: { label: 'Stored XSS', endpoint: '/scans/xss/stored',
    description: 'Saves a unique harmless comment, retrieves it independently, and verifies its JavaScript in a fresh Chrome context with CSP enabled. Removes only the scanner comment after testing.',
    progress: 'Submitting a test comment, retrieving saved content, checking browser execution and cleaning up. Please wait.' },
  dom: { label: 'DOM-Based XSS', endpoint: '/scans/xss/dom',
    description: 'Tests browser-only URL fragment input on /dom-xss. Fresh Chrome contexts compare a clean baseline with the controlled DOM input, using identical server HTML and CSP enabled.',
    progress: 'Checking the marker-free server page, clean browser baseline and fragment-to-DOM execution. Please wait.' },
}

export default function Scans() {
  const { targets, mode, loadingData, refresh } = useApp()
  const history = useScanData('/scans', 'scans')
  const [selectedId, setSelectedId] = useState('')
  const [scanType, setScanType] = useState('reflected')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [latest, setLatest] = useState(null)
  const targetId = selectedId || targets[0]?.id || ''
  const selectedScan = scanOptions[scanType]
  const label = selectedScan.label
  const run = async event => {
    event.preventDefault(); setBusy(true); setError(''); setLatest(null)
    try {
      const data = await apiRequest(selectedScan.endpoint, { method: 'POST', body: JSON.stringify({ target_id: targetId }) })
      setLatest(data.scan)
      await Promise.all([history.reload(), refresh()])
    } catch (err) { setError(err.message); if (err.scan) setLatest(err.scan) }
    finally { setBusy(false) }
  }
  return <>
    <div className="page-topline"><div><div className="eyebrow">SECURITY OPERATIONS</div><h1>Scan engine<span className="heading-dot">.</span></h1><p>Controlled Reflected, Stored and DOM-Based XSS testing for your authorized local websites.</p></div><Link className="btn btn-outline" to="/targets">Manage targets</Link></div>
    <div className="panel scan-controls"><h2>{label}</h2><p>{selectedScan.description}</p>
      <form className="form-stack" onSubmit={run}>
        <label>Scan type<select aria-label="Scan type" value={scanType} disabled={busy} onChange={e => setScanType(e.target.value)}>{Object.entries(scanOptions).map(([id, scan]) => <option key={id} value={id}>{scan.label}</option>)}</select></label>
        <label>Registered target<select aria-label="Registered target" value={targetId} disabled={busy || loadingData} onChange={e => setSelectedId(e.target.value)}><option value="" disabled>Select a target</option>{targets.map(t => <option key={t.id} value={t.id}>{t.name} — {t.url}</option>)}</select></label><p className="muted">Allowed: HTTP loopback ports 5001 and 5002. Register the root URL or /search without a query.</p><button className="btn btn-primary" disabled={busy || !targetId || mode === 'demo' || loadingData}>{busy ? 'Scanning with Chromium...' : `Run ${label} Scan`}</button></form>
      {mode === 'demo' && <p className="form-error">Sign in with your Supabase account to run and save real scans. Preview mode does not run tests.</p>}
      {busy && <p role="status">{selectedScan.progress}</p>}
      {error && <p className="form-error" role="alert">{error}</p>}
    </div>
    {latest && <ScanResult scan={latest}/>}
    <SectionHeader eyebrow="SAVED HISTORY" title="Scan results" action={<button className="btn btn-outline" disabled={history.loading || busy} onClick={history.reload}>Refresh</button>}/>
    {history.error && <p role="alert" className="form-error">{history.error}</p>}
    {history.loading && <p role="status">Loading saved scans...</p>}
    {history.items.filter(s => s.id !== latest?.id).map(s => <ScanResult key={s.id} scan={s}/>)}
    {!history.loading && !history.error && !history.items.length && !latest && <div className="panel"><EmptyState icon={Radar} title="No saved scans" text="Register a local lab website, sign in, and run the controlled test."/></div>}
    <SectionHeader eyebrow="MODULES" title="Implementation status"/>
    <div className="module-grid">{modules.map(m => <div className="panel module-card" key={m.id}><div className={`module-icon tone-${m.color}`}><m.icon size={22}/></div><h3>{m.id === 'xss' ? 'Reflected, Stored and DOM-Based XSS' : m.name}</h3><p>{m.id === 'xss' ? 'Implemented: browser-verified /search?q, /comments and /dom-xss tests' : 'Not implemented'}</p></div>)}</div>
    <div className="notice-strip"><div><strong>Scope of this module</strong><span>Each option runs one controlled XSS test. Cookie testing and other security modules are not implemented. Not detected does not prove a website has no XSS vulnerabilities.</span></div></div>
  </>
}
