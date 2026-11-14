import React, { useEffect, useRef, useState } from 'react'
import api from '../api'
import { getRole, clearSession } from '../session'
import { usePanelNavigate } from '../navigation.js'
import { useLang, LangToggle } from '../i18n/dashboardLang.jsx'
import { ThemeToggle } from '../theme/themeContext.jsx'
import { Icon } from '../components/icons.jsx'
import { useUI } from '../components/ui/UIProvider.jsx'
import ParticleBackground from '../components/ParticleBackground.jsx'
import AuthWaveBackground from '../components/AuthWaveBackground.jsx'
import { copyText, readClipboardText } from '../utils/clipboard.js'

const STATUS_KEYS = {
  expired: 'licenseStatusExpired',
  not_found: 'licenseStatusNotFound',
  not_activated: 'licenseStatusNotActivated',
  unreachable: 'licenseStatusUnreachable',
  unconfigured: 'licenseStatusUnconfigured',
}

export default function LicenseLock({ statusInfo, onActivated }) {
  const { lang, setLang, dir, t } = useLang()
  const isSuperadmin = getRole() === 'superadmin'
  const { notify } = useUI()
  const [key, setKey] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState('')
  const [manualPasteOpen, setManualPasteOpen] = useState(false)
  const navigate = usePanelNavigate()

  const submit = async (event) => {
    event.preventDefault(); setError(''); setLoading(true)
    try {
      const { data } = await api.post('/license/activate', { key: key.trim().toLowerCase() })
      setSuccess(data.message || t('licenseActivateBtn'))
      notify?.({ type: 'success', message: data.message || t('licenseActivateBtn'), dir })
      setTimeout(() => onActivated?.(data), 550)
    }
    catch (err) { setError(err.response?.data?.detail || t('licenseInvalidKeyError')) }
    finally { setLoading(false) }
  }
  const pasteLicense = async () => {
    const text = await readClipboardText()
    if (text) { setKey(text.trim()); setError(''); return }
    setManualPasteOpen(true)
  }
  const logout = () => { clearSession(); navigate('/login') }
  const headline = t(STATUS_KEYS[statusInfo?.status] || 'licenseStatusDefault')
  const copyCurrentLicense = async () => {
    const value = statusInfo?.key_full || statusInfo?.key_masked
    if (!value) return
    const ok = await copyText(value)
    notify?.({ type: ok ? 'success' : 'error', message: ok ? t('licenseCopied') : t('clipboardWriteError'), dir })
  }

  return (
    <div dir={dir} className="license-lock-page relative flex min-h-screen items-center justify-center overflow-hidden bg-bg px-4 py-20">
      <ParticleBackground density={0.00004}/>
      <div className="login-aurora" aria-hidden="true" />
      <AuthWaveBackground />
      <div className="subtle-grid absolute inset-0 z-[1] opacity-20"/><div className="absolute top-0 z-[1] h-72 w-72 rounded-full bg-danger/10 blur-3xl"/>
      <div className="absolute end-4 top-4 z-20 flex items-center gap-2"><ThemeToggle/><LangToggle lang={lang} setLang={setLang} variant="icon" /></div>
      <div className="relative z-10 w-full max-w-md">
        <div className="mb-7 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-danger/30 bg-danger/10 text-danger"><Icon name="warning" size={31}/></div>
          <div className="eyebrow text-danger">{t('licenseLockedBadge')}</div>
          <h1 className="mt-2 text-2xl font-black">{t('licenseLockedTitle')}</h1>
          <p className="mt-3 text-sm leading-6 text-muted">{headline}</p>
          {(statusInfo?.key_full || statusInfo?.key_masked) && <button type="button" onClick={copyCurrentLicense} className="mx-auto mt-3 flex max-w-full cursor-copy items-center gap-2 rounded-lg border border-border bg-surface2 px-3 py-2 text-xs text-muted hover:border-signal/40 hover:text-signal" title={t('clickToCopy')}><Icon name="copy" size={13}/><span>{t('licenseCurrentKeyLabel')}</span><span dir="ltr" className="max-w-[260px] break-all font-data text-ink">{statusInfo.key_full || statusInfo.key_masked}</span></button>}
        </div>

        {isSuperadmin ? (
          <form onSubmit={submit} className="app-card p-5 sm:p-6">
            {error && <div className="status-danger mb-4 rounded-lg px-3 py-2.5 text-sm">{error}</div>}
            {success && <div className="status-success mb-4 rounded-lg px-3 py-2.5 text-sm">{success}</div>}
            <label className="block"><span className="field-label">{t('licenseNewKeyLabel')}</span><div className="relative"><Icon name="key" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input className="field ps-9 pe-32 text-center font-data tracking-widest" placeholder="xxxxxx-xxxxxx-xxxxxx" value={key} onChange={event => setKey(event.target.value)} autoFocus required /><button type="button" onClick={pasteLicense} className="absolute end-1.5 top-1/2 -translate-y-1/2 rounded-md border border-signal/30 bg-signal/10 px-2.5 py-1.5 text-[10px] font-bold text-signal hover:bg-signal/20">{t('pasteLicenseBtn')}</button></div></label>
            <button disabled={loading} className="btn-primary mt-4 w-full">{loading ? t('licenseCheckingBtn') : t('licenseActivateBtn')}</button>
            <button type="button" onClick={logout} className="btn-ghost mt-2 w-full text-xs"><Icon name="logout" size={15}/>{t('logoutBtn')}</button>
          </form>
        ) : (
          <div className="app-card p-6 text-center"><p className="text-sm leading-6 text-ink">{t('licenseNonSuperadminMessage')}</p><button onClick={logout} className="btn-secondary mt-5 w-full"><Icon name="logout" size={16}/>{t('logoutBtn')}</button></div>
        )}
      </div>
      {manualPasteOpen && <LockPasteModal initialValue={key} t={t} dir={dir} onClose={() => setManualPasteOpen(false)} onUse={(value) => { setKey(value.trim()); setError(''); setManualPasteOpen(false) }} />}
    </div>
  )
}


function LockPasteModal({ initialValue, t, dir, onClose, onUse }) {
  const [value, setValue] = useState(initialValue || '')
  const inputRef = useRef(null)
  useEffect(() => {
    const timer = window.setTimeout(() => { inputRef.current?.focus(); inputRef.current?.select() }, 60)
    return () => window.clearTimeout(timer)
  }, [])
  const submit = (event) => { event.preventDefault(); if (value.trim()) onUse(value) }
  return <div className="modal-backdrop !z-[130]" role="dialog" aria-modal="true">
    <div dir={dir} className="modal-panel modal-scroll-shell max-w-lg">
      <header className="modal-sticky-header"><div><h2 className="font-black text-sm">{t('pasteLicenseFallbackTitle')}</h2><p className="mt-1 text-[10px] text-muted">{t('pasteLicenseFallbackHint')}</p></div><button type="button" className="modal-close-button" onClick={onClose}>✕</button></header>
      <form onSubmit={submit} className="modal-scroll-body p-4 sm:p-5">
        <textarea ref={inputRef} className="field min-h-[120px] resize-y font-data text-start" dir="ltr" value={value} onChange={(e) => setValue(e.target.value)} onPaste={(e) => { const pasted=e.clipboardData?.getData('text'); if (pasted) { e.preventDefault(); setValue(pasted) } }} placeholder={t('pasteLicenseFallbackPlaceholder')} />
        <div className="modal-actions mt-4"><button type="button" className="btn-secondary" onClick={onClose}>{t('pasteLicenseFallbackCancel')}</button><button type="submit" className="btn-primary" disabled={!value.trim()}>{t('pasteLicenseFallbackUse')}</button></div>
      </form>
    </div>
  </div>
}
