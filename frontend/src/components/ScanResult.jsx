import React, { useState } from 'react'
import { Download } from 'lucide-react'
import { downloadScanReport } from '../lib/api'

export function ReportButton({ scanId }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const download = async () => {
    setBusy(true); setError('')
    try { await downloadScanReport(scanId) } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }
  return <div><button className="btn btn-outline" disabled={busy} onClick={download}><Download size={16}/>{busy ? 'Preparing PDF...' : 'Download PDF'}</button>{error && <p role="alert" className="form-error">{error}</p>}</div>
}

export default function ScanResult({ scan }) {
  const r = scan.result
  const target = scan.target_snapshot
  return <article className="panel scan-result">
    <div className="scan-result-heading"><div><h3>{r.title}</h3><p>{target.name} · {new Date(r.completed_at).toLocaleString()}</p></div><span className={`detection-status ${r.status}`}>{r.status.replaceAll('_', ' ')}</span></div>
    <dl><dt>Target</dt><dd>{target.url}</dd><dt>Affected endpoint</dt><dd>{r.affected_url}</dd><dt>Severity</dt><dd>{r.severity || 'Not applicable'}</dd><dt>HTTP status</dt><dd>{r.http_status || 'No response'}</dd><dt>Outcome</dt><dd>{r.evidence.outcome}</dd></dl>
    {r.impact && <p><strong>Impact: </strong>{r.impact}</p>}
    {r.evidence.cleanup?.status === 'failed' && <p className="form-error" role="alert">Test comment cleanup failed: {r.evidence.cleanup.detail} Marker: {r.evidence.cleanup.marker}</p>}
    <details><summary>Evidence and reproducible request</summary><pre>{JSON.stringify(r.evidence, null, 2)}</pre><p>Tests completed: {r.tests.join(', ') || 'None'}</p></details>
    <p><strong>Recommended fix: </strong>{r.remediation}</p>
    <p className="muted">{r.limitation}</p>
    {scan.id ? <ReportButton scanId={scan.id}/> : <p className="form-error">This result has not been saved. PDF reporting is unavailable.</p>}
  </article>
}
