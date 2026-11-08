import React, { useEffect } from 'react'
import { X } from 'lucide-react'
export default function Modal({ open, onClose, title, subtitle, children }) {
  useEffect(() => {
    if (!open) return
    const key = (event) => { if (event.key === 'Escape') onClose() }
    document.addEventListener('keydown', key)
    return () => document.removeEventListener('keydown', key)
  }, [open, onClose])
  if (!open) return null
  return <div className="modal-backdrop" onMouseDown={onClose} role="presentation"><div className="modal" role="dialog" aria-modal="true" aria-label={title} onMouseDown={e => e.stopPropagation()}><div className="modal-top"><div><h3>{title}</h3>{subtitle && <p>{subtitle}</p>}</div><button className="icon-btn" onClick={onClose} aria-label="Close dialog"><X size={19}/></button></div>{children}</div></div>
}
