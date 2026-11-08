import React from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useApp } from './contexts/AppContext'
import Layout from './components/Layout'
import Auth from './pages/Auth'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import Scans from './pages/Scans'
import Findings from './pages/Findings'
import Reports from './pages/Reports'
import Activity from './pages/Activity'
import Settings from './pages/Settings'
import Brand from './components/Brand'

export default function App() {
  const { loadingAuth, mode, user } = useApp()
  if (loadingAuth) return <div className="splash-screen"><Brand/><div className="loading-spinner"/></div>
  if (mode !== 'demo' && !user) return <Auth/>
  return <Layout><Routes><Route path="/" element={<Dashboard/>}/><Route path="/targets" element={<Targets/>}/><Route path="/scans" element={<Scans/>}/><Route path="/findings" element={<Findings/>}/><Route path="/reports" element={<Reports/>}/><Route path="/activity" element={<Activity/>}/><Route path="/settings" element={<Settings/>}/><Route path="*" element={<Navigate to="/" replace/>}/></Routes></Layout>
}
