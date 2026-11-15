import React from 'react'
import { FileText } from 'lucide-react'
import { EmptyState } from '../components/Icons'
import { ReportButton } from '../components/ScanResult'
import { useScanData } from '../lib/useScanData'

export default function Reports() {
  const { items, loading, error, reload } = useScanData('/scans', 'scans')
  return <>
    <div className="page-topline"><div><div className="eyebrow">DOCUMENTATION</div><h1>Security reports<span className="heading-dot">.</span></h1><p>PDF reports generated from saved scan results and evidence.</p></div><button className="btn btn-outline" disabled={loading} onClick={reload}>Refresh</button></div>
    {error && <p className="form-error" role="alert">{error}</p>}
    {loading && <p role="status">Loading reports...</p>}
    {items.map(s => <article className="panel scan-result" key={s.id}><div className="scan-result-heading"><div><h3>{s.target_snapshot.name} — {s.result.title}</h3><p>{new Date(s.completed_at).toLocaleString()} · {s.result.status.replaceAll('_', ' ')}</p></div><ReportButton scanId={s.id}/></div><p>{s.result.affected_url}</p><p className="muted">Includes actual outcome, evidence, severity when applicable, mitigation and scope limitations. Inconclusive reports explain the verification blocker.</p></article>)}
    {!loading && !error && !items.length && <div className="panel"><EmptyState icon={FileText} title="No reports available" text="Run a scan first. Each saved attempt can be exported, including inconclusive attempts."/></div>}
  </>
}
