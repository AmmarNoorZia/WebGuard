import React from 'react'
import { CheckCircle2, Circle, Clock3 } from 'lucide-react'
export function StatusPill({ children = 'Not scanned', tone = 'neutral' }) { return <span className={`status-pill ${tone}`}><span className="pill-dot"/>{children}</span> }
export function PlannedBadge() { return <span className="planned-badge"><Clock3 size={12}/> Planned</span> }
export function EmptyState({ icon: Icon, title, text, action }) { return <div className="empty-state"><div className="empty-icon"><Icon size={26} strokeWidth={1.6}/></div><h3>{title}</h3><p>{text}</p>{action}</div> }
export function SectionHeader({ eyebrow, title, text, action }) { return <div className="section-heading"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h2>{title}</h2>{text && <p>{text}</p>}</div>{action && <div className="section-action">{action}</div>}</div> }
export function ChecklistItem({ done, children }) { return <div className={`checklist-item ${done ? 'done' : ''}`}>{done ? <CheckCircle2 size={17}/> : <Circle size={17}/>} <span>{children}</span></div> }
