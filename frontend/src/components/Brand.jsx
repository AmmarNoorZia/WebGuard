import React from 'react'
import { Shield, Radar } from 'lucide-react'
export default function Brand({ small = false }) {
  return <div className={`brand ${small ? 'brand-small' : ''}`}>
    <div className="brand-mark"><Shield size={small ? 19 : 23} strokeWidth={2.1} /><Radar size={small ? 10 : 13} className="brand-mark-dot" strokeWidth={2.6}/></div>
    <span className="brand-word">Web<span>Guard</span><i>.</i></span>
  </div>
}
