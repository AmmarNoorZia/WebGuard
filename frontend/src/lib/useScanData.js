import { useCallback, useEffect, useRef, useState } from 'react'
import { useApp } from '../contexts/AppContext'
import { apiRequest } from './api'

// Demo mode never invents scans or calls the authenticated scanner API.
export function useScanData(path, key) {
  const { mode, user } = useApp()
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const revision = useRef(0)
  const userId = user?.id
  const reload = useCallback(async () => {
    const current = ++revision.current
    if (mode === 'demo' || !userId) return
    setLoading(true)
    setError('')
    try {
      const data = await apiRequest(path)
      if (revision.current === current) setItems(data[key] || [])
    } catch (err) { if (revision.current === current) setError(err.message) }
    finally { if (revision.current === current) setLoading(false) }
  }, [mode, userId, path, key])
  useEffect(() => {
    setItems([]); setError(''); setLoading(false); reload()
    return () => { revision.current += 1 }
  }, [reload])
  return { items, loading, error, reload }
}
