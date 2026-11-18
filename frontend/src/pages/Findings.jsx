import React from 'react'
import { ShieldAlert } from 'lucide-react'
import { EmptyState } from '../components/Icons'
import ScanResult from '../components/ScanResult'
import { useScanData } from '../lib/useScanData'

export default function Findings() {
  const { items, loading, error, reload } = useScanData('/findings', 'findings')
  return <>
    <div className="page-topline"><div><div className="eyebrow">ASSESSMENT RESULTS</div><h1>Findings<span className="heading-dot">.</span></h1><p>Saved observations, including confirmed, not detected and inconclusive results.</p></div><button className="btn btn-outline" disabled={loading} onClick={reload}>Refresh</button></div>
    <div className="findings-summary">{['confirmed', 'not_detected', 'inconclusive'].map(status => <div className="panel severity-card" key={status}><span>{status.replaceAll('_', ' ')}</span><strong>{loading || error ? '—' : items.filter(f => f.detection_status === status).length}</strong><small>In the latest 100 saved observations</small></div>)}</div>
    {error && <p className="form-error" role="alert">{error}</p>}
    {loading && <p role="status">Loading saved results...</p>}
    {items.map(f => <ScanResult key={f.id} scan={{ id: f.scan_id, ...f.scan_runs }}/>) }
    {!loading && !error && !items.length && <div className="panel"><EmptyState icon={ShieldAlert} title="No saved results" text="Run a Reflected or Stored XSS scan to save evidence and recommended fixes here."/></div>}
  </>
}
