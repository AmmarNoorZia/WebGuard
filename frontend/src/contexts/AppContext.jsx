import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { supabase, supabaseConfigured } from '../lib/supabase'
import { apiRequest } from '../lib/api'
import { seedDemoTargets } from '../lib/constants'

const Context = createContext(null)
const readJSON = (key, fallback) => {
  try { const value = localStorage.getItem(key); return value ? JSON.parse(value) : fallback } catch { return fallback }
}
const normalizeLocalUrl = (input) => {
  const u = new URL(input)
  if (!['http:', 'https:'].includes(u.protocol) || !['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) || u.username || u.password || u.hash) {
    throw new Error('Only local test URLs (localhost / 127.0.0.1) are allowed.')
  }
  return u.toString().replace(/\/$/, '')
}

export function AppProvider({ children }) {
  const [theme, setTheme] = useState(() => localStorage.getItem('webguard-theme') || 'dark')
  const [mode, setMode] = useState(() => sessionStorage.getItem('webguard-mode') === 'demo' ? 'demo' : 'auth')
  const [user, setUser] = useState(null)
  const [loadingAuth, setLoadingAuth] = useState(true)
  const [targets, setTargets] = useState([])
  const [activity, setActivity] = useState([])
  const [loadingData, setLoadingData] = useState(false)
  const [toast, setToast] = useState(null)
  const notify = useCallback((message, type = 'success') => setToast({ message, type, id: Date.now() }), [])

  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('webguard-theme', theme) }, [theme])
  useEffect(() => {
    let active = true
    if (mode === 'demo') { setLoadingAuth(false); return () => { active = false } }
    if (!supabaseConfigured) { setLoadingAuth(false); return () => { active = false } }
    supabase.auth.getUser().then(({ data, error }) => {
      if (active) { setUser(error ? null : data.user); setLoadingAuth(false) }
    }).catch(() => { if (active) { setUser(null); setLoadingAuth(false) } })
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (active) {
        if (event === 'SIGNED_OUT') setUser(null)
        else if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED' || event === 'USER_UPDATED') setUser(session?.user || null)
      }
    })
    return () => { active = false; subscription.unsubscribe() }
  }, [mode])

  const refresh = useCallback(async () => {
    if (mode === 'demo') {
      setTargets(readJSON('webguard-demo-targets', seedDemoTargets))
      setActivity(readJSON('webguard-demo-activity', []))
      return
    }
    if (!user) { setTargets([]); setActivity([]); return }
    setLoadingData(true)
    try {
      const [t, a] = await Promise.all([apiRequest('/targets'), apiRequest('/activity')])
      setTargets(t.targets || []); setActivity(a.activity || [])
    } catch (err) { notify(err.message, 'error') }
    finally { setLoadingData(false) }
  }, [mode, user, notify])

  useEffect(() => { refresh() }, [refresh])
  useEffect(() => { if (!toast) return; const id = setTimeout(() => setToast(null), 4800); return () => clearTimeout(id) }, [toast])

  const startDemo = useCallback(() => {
    sessionStorage.setItem('webguard-mode', 'demo'); setMode('demo'); setLoadingAuth(false); setUser(null)
  }, [])
  const leaveDemo = useCallback(() => {
    sessionStorage.removeItem('webguard-mode'); setMode('auth'); setTargets([]); setActivity([]); setUser(null)
  }, [])
  const signOut = useCallback(async () => {
    if (mode === 'demo') { leaveDemo(); return }
    if (supabase) await supabase.auth.signOut()
    setUser(null); setTargets([]); setActivity([])
  }, [mode, leaveDemo])
  const addTarget = useCallback(async (values) => {
    const url = normalizeLocalUrl(values.url)
    if (!values.name?.trim() || values.name.trim().length > 80) throw new Error('Enter a name of at most 80 characters.')
    if (targets.some(t => t.url === url)) throw new Error('This URL is already in your workspace.')
    if (mode === 'demo') {
      const item = { id: `demo-${Date.now()}`, name: values.name.trim(), url, environment: values.environment || 'Local test', created_at: new Date().toISOString() }
      const next = [item, ...targets]; setTargets(next); localStorage.setItem('webguard-demo-targets', JSON.stringify(next))
      const events = [{ id: `event-${Date.now()}`, description: `Added target: ${item.name}`, event_type: 'target_added', created_at: new Date().toISOString() }, ...activity]
      setActivity(events); localStorage.setItem('webguard-demo-activity', JSON.stringify(events)); return item
    }
    const data = await apiRequest('/targets', { method: 'POST', body: JSON.stringify({ ...values, url }) })
    await refresh(); return data.target
  }, [targets, activity, mode, refresh])
  const removeTarget = useCallback(async (id) => {
    if (mode === 'demo') {
      const item = targets.find(t => t.id === id)
      const next = targets.filter(t => t.id !== id); setTargets(next); localStorage.setItem('webguard-demo-targets', JSON.stringify(next))
      const events = [{ id: `event-${Date.now()}`, description: `Removed target: ${item?.name || 'Unknown'}`, event_type: 'target_removed', created_at: new Date().toISOString() }, ...activity]
      setActivity(events); localStorage.setItem('webguard-demo-activity', JSON.stringify(events)); return
    }
    await apiRequest(`/targets/${encodeURIComponent(id)}`, { method: 'DELETE' }); await refresh()
  }, [mode, targets, activity, refresh])

  const value = useMemo(() => ({
    theme, setTheme, mode, user, loadingAuth, loadingData, targets, activity, toast,
    supabaseConfigured, notify, startDemo, leaveDemo, signOut, refresh, addTarget, removeTarget,
  }), [theme, mode, user, loadingAuth, loadingData, targets, activity, toast, notify, startDemo, leaveDemo, signOut, refresh, addTarget, removeTarget])
  return <Context.Provider value={value}>{children}</Context.Provider>
}
export const useApp = () => useContext(Context)
