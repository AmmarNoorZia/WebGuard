import React, { useState } from 'react'
import { ArrowRight, CheckCircle2, Eye, EyeOff, Github, LockKeyhole, ShieldCheck, Sparkles } from 'lucide-react'
import Brand from '../components/Brand'
import { useApp } from '../contexts/AppContext'
import { supabase } from '../lib/supabase'

export default function Auth() {
  const { startDemo, supabaseConfigured, notify } = useApp()
  const [tab, setTab] = useState('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (e) => {
    e.preventDefault(); setError(''); setBusy(true)
    try {
      if (!supabase) throw new Error('Supabase is not configured yet. Use Explore demo or follow README.md.')
      if (tab === 'signup') {
        const { error } = await supabase.auth.signUp({ email, password, options: { emailRedirectTo: window.location.origin } })
        if (error) throw error
        notify('Account created. Check your email if confirmation is enabled.')
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password })
        if (error) throw error
      }
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  return <div className="auth-shell"><div className="auth-panel"><div className="auth-top"><Brand/><span className="auth-top-tag">SECURITY ASSESSMENT WORKSPACE</span></div><div className="auth-inner"><div className="auth-eyebrow"><span/> BUILT FOR SECURITY TEAMS</div><h1>Find weak points.<br/><em>Build stronger defenses.</em></h1><p>Everything you need to manage targets, track assessments, and keep web security work organized — in one beautiful workspace.</p><div className="auth-benefits"><div><CheckCircle2 size={18}/> Controlled, local-first testing</div><div><CheckCircle2 size={18}/> Five planned security modules</div><div><CheckCircle2 size={18}/> Clear reporting and audit history</div></div><div className="auth-graphic"><div className="graphic-head"><span><ShieldCheck size={17}/> WebGuard overview</span><span className="graphic-online"><span/> SYSTEM READY</span></div><div className="graphic-score"><span>Assessment engine</span><strong>05 <small>modules planned</small></strong></div><div className="graphic-bars">{[48,77,56,90,67,82,40,64,75,49,85,58].map((n,i) => <div key={i} style={{height:`${n}%`}}/>)}</div><div className="graphic-footer">SQLi <i/> XSS <i/> HEADERS <i/> COOKIES <i/> FILES</div></div></div><div className="auth-bottom">WEBGUARD / LAB PLATFORM <span>VERSION 0.1.0</span></div></div>
    <div className="auth-form-panel"><div className="auth-form-top"><span className="green-spark"><Sparkles size={16}/></span> Designed for hands-on security learning</div><div className="auth-form-wrap"><div className="auth-form-icon"><LockKeyhole size={24}/></div><h2>{tab === 'signin' ? 'Welcome back' : 'Create your account'}</h2><p>{tab === 'signin' ? 'Sign in to your WebGuard workspace.' : 'Start managing your local security assessments.'}</p><div className="auth-tabs"><button className={tab === 'signin' ? 'selected' : ''} onClick={() => setTab('signin')}>Sign in</button><button className={tab === 'signup' ? 'selected' : ''} onClick={() => setTab('signup')}>Create account</button></div><form onSubmit={submit}><label>Email address<input type="email" placeholder="you@university.edu" required value={email} onChange={e => setEmail(e.target.value)}/></label><label>Password<div className="password-field"><input type={visible ? 'text' : 'password'} placeholder="At least 6 characters" minLength={6} required value={password} onChange={e => setPassword(e.target.value)}/><button type="button" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'}>{visible ? <EyeOff size={17}/> : <Eye size={17}/>}</button></div></label>{error && <div className="form-error">{error}</div>}<button className="btn btn-primary full" disabled={busy || !supabaseConfigured}>{busy ? 'Please wait…' : tab === 'signin' ? 'Sign in to workspace' : 'Create account'} <ArrowRight size={17}/></button></form>{!supabaseConfigured && <div className="auth-notice">Supabase isn't connected yet. You can explore the complete interface in demo mode below.</div>}<div className="auth-divider">OR</div><button className="btn btn-ghost full" onClick={startDemo}>Explore the live demo <ArrowRight size={17}/></button><small className="auth-disclaimer">Demo is local-only and does not perform real security scans.</small></div><div className="auth-form-bottom">WebGuard · Built for authorized security testing</div></div></div>
}
