import React, { useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bell, ChevronDown, CircleHelp, Command, FileText, Fingerprint, FolderSearch, LayoutDashboard, LockKeyhole, Menu, Moon, Plus, Search, Settings2, ShieldAlert, ShieldCheck, Sun, Target, X, LogOut } from 'lucide-react'
import Brand from './Brand'
import { useApp } from '../contexts/AppContext'

const nav = [
  { title: 'Overview', links: [
    { to: '/', name: 'Dashboard', icon: LayoutDashboard },
    { to: '/targets', name: 'Targets', icon: Target },
  ]},
  { title: 'Assessment', links: [
    { to: '/scans', name: 'Scans', icon: FolderSearch },
    { to: '/findings', name: 'Findings', icon: ShieldAlert },
    { to: '/reports', name: 'Reports', icon: FileText },
  ]},
  { title: 'Workspace', links: [
    { to: '/activity', name: 'Activity log', icon: Activity },
    { to: '/settings', name: 'Settings', icon: Settings2 },
  ]},
]
const labels = { '/':'Dashboard', '/targets':'Targets', '/scans':'Scans', '/findings':'Findings', '/reports':'Reports', '/activity':'Activity log', '/settings':'Settings' }

export default function Layout({ children }) {
  const { theme, setTheme, mode, user, targets, toast, signOut, supabaseConfigured } = useApp()
  const [mobileMenu, setMobileMenu] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const activeTitle = labels[location.pathname] || 'Dashboard'
  const email = mode === 'demo' ? 'Demo workspace' : (user?.email || 'Team member')
  const initial = email.substring(0, 1).toUpperCase()
  const go = (page) => { setMobileMenu(false); navigate(page) }
  return <div className="app-shell">
    {mobileMenu && <div className="mobile-shade" onClick={() => setMobileMenu(false)}/>} 
    <aside className={`sidebar ${mobileMenu ? 'mobile-open' : ''}`}>
      <div className="sidebar-brand"><Brand/><button className="icon-btn mobile-close" onClick={() => setMobileMenu(false)} aria-label="Close menu"><X size={18}/></button></div>
      <div className="workspace-card"><div className="workspace-icon"><Command size={18}/></div><div className="workspace-copy"><strong>WebGuard Lab</strong><small>{mode === 'demo' ? 'Local demo' : 'Your workspace'}</small></div><ChevronDown size={14} className="muted-icon"/></div>
      <div className="nav-groups">{nav.map(group => <div className="nav-group" key={group.title}><div className="nav-label">{group.title}</div>{group.links.map(link => <NavLink key={link.to} to={link.to} end={link.to === '/'} onClick={() => setMobileMenu(false)} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><link.icon size={18} strokeWidth={1.85}/><span>{link.name}</span>{link.name === 'Targets' && <span className="nav-count">{targets.length}</span>}{link.name === 'Scans' && <span className="coming-dot" title="Scanner modules planned"/>}</NavLink>)}</div>)}</div>
      <div className="sidebar-bottom"><div className="side-help"><div className="side-help-icon"><ShieldCheck size={20}/></div><strong>Security first.</strong><p>Only scan websites you own or have permission to test.</p><button onClick={() => go('/settings')}>Workspace guide <span>↗</span></button></div><div className="side-footer"><div className="avatar">{initial}</div><div className="side-user"><strong>{mode === 'demo' ? 'Demo Explorer' : (email.split('@')[0] || 'Member')}</strong><small>{mode === 'demo' ? 'Preview account' : 'Authenticated'}</small></div><button className="icon-btn" onClick={signOut} aria-label="Sign out" title="Sign out"><LogOut size={17}/></button></div></div>
    </aside>
    <div className="main-column">
      <header className="topbar"><div className="topbar-left"><button className="icon-btn mobile-toggle" aria-label="Open menu" onClick={() => setMobileMenu(true)}><Menu size={22}/></button><div className="breadcrumb"><span>Workspace</span><span className="crumb-slash">/</span><strong>{activeTitle}</strong></div></div><div className="topbar-actions"><span className="topbar-env"><span/> LOCAL TESTING ONLY</span><button className="icon-btn" title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'} aria-label="Toggle theme" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <Sun size={19}/> : <Moon size={19}/>}</button><div className="topbar-divider"/><div className="profile-area"><button className="profile-button" onClick={() => setProfileOpen(!profileOpen)}><span className="avatar small">{initial}</span><ChevronDown size={14}/></button>{profileOpen && <div className="profile-menu"><div className="menu-identity"><strong>{email}</strong><span>{mode === 'demo' ? 'Demo mode — no cloud storage' : 'Supabase authentication'}</span></div><button onClick={() => { setProfileOpen(false); navigate('/settings') }}><Settings2 size={15}/> Settings</button><button onClick={() => { setProfileOpen(false); signOut() }}><LogOut size={15}/> Sign out</button></div>}</div></div></header>
      <main className="main-content">{mode === 'demo' && <div className="demo-banner"><span className="banner-icon">D</span><span><strong>Preview mode</strong> — changes are stored only in this browser. Connect Supabase for real accounts and cloud data.</span><button onClick={() => go('/settings')}>Setup details ↗</button></div>}{children}<footer className="app-footer"><span>© WebGuard · University security project</span><span>Build 0.1.0 <b>•</b> Scanner modules not yet implemented</span></footer></main>
    </div>
    {toast && <div className={`toast ${toast.type}`} role="status">{toast.type === 'error' ? <ShieldAlert size={18}/> : <ShieldCheck size={18}/>}<span>{toast.message}</span></div>}
  </div>
}
