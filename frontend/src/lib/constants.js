import { DatabaseZap, CodeXml, ShieldCheck, Cookie, FileWarning } from 'lucide-react'

export const modules = [
  { id: 'sqli', name: 'SQL Injection', subtitle: 'Database input handling', icon: DatabaseZap, color: 'violet' },
  { id: 'xss', name: 'Cross-Site Scripting', subtitle: 'Unsafe browser output', icon: CodeXml, color: 'green' },
  { id: 'headers', name: 'Security Headers', subtitle: 'HTTP response safeguards', icon: ShieldCheck, color: 'blue' },
  { id: 'cookies', name: 'Cookie Security', subtitle: 'Session cookie attributes', icon: Cookie, color: 'amber' },
  { id: 'files', name: 'Sensitive Resources', subtitle: 'Accidentally exposed files', icon: FileWarning, color: 'rose' },
]
export const seedDemoTargets = [
  { id: 'demo-a', name: 'Test Website A', url: 'http://localhost:5001', environment: 'Vulnerable / secure mix', created_at: new Date().toISOString() },
  { id: 'demo-b', name: 'Test Website B', url: 'http://localhost:5002', environment: 'Vulnerable / secure mix', created_at: new Date().toISOString() },
]
export const formatDate = (value) => value ? new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '—'
export const shortHost = (url) => { try { return new URL(url).host } catch { return url } }
