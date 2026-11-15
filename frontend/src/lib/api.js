import { supabase } from './supabase'

export async function apiRequest(path, options = {}) {
  const { responseType, ...requestOptions } = options
  const { data: { session } } = await supabase.auth.getSession()
  if (!session?.access_token) throw new Error('Your session has expired. Please sign in again.')
  let response
  try {
    response = await fetch(`/api${path}`, {
      ...requestOptions,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.access_token}`,
        ...(options.headers || {}),
      },
    })
  } catch {
    throw new Error('Cannot reach the Flask API. Start the backend on port 5000.')
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}))
    const error = new Error(payload.error || `API request failed (${response.status})`)
    error.scan = payload.scan
    throw error
  }
  return responseType === 'blob' ? response.blob() : response.json()
}

export async function downloadScanReport(scanId) {
  const blob = await apiRequest(`/scans/${encodeURIComponent(scanId)}/report.pdf`, { responseType: 'blob' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `webguard-${scanId}.pdf`
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
