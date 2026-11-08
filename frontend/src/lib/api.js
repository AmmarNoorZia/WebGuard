import { supabase } from './supabase'

export async function apiRequest(path, options = {}) {
  const { data: { session } } = await supabase.auth.getSession()
  if (!session?.access_token) throw new Error('Your session has expired. Please sign in again.')
  let response
  try {
    response = await fetch(`/api${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.access_token}`,
        ...(options.headers || {}),
      },
    })
  } catch {
    throw new Error('Cannot reach the Flask API. Start the backend on port 5000.')
  }
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(payload.error || `API request failed (${response.status})`)
  return payload
}
