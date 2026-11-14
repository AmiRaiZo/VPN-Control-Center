import React, { useEffect, useMemo, useRef, useState } from 'react'
import api from '../api'
import { getRole } from '../permissions'
import { useLang } from '../i18n/dashboardLang.jsx'
import { useUI } from '../components/ui/UIProvider.jsx'
import LicenseReserveModal from '../components/LicenseReserveModal.jsx'
import { Icon } from '../components/icons.jsx'
import { formatRemainingText } from '../utils/formatRemaining.js'
import { copyText, readClipboardText } from '../utils/clipboard.js'

export default function License() {
  const { t, dir } = useLang()
  const { notify } = useUI()
  const [info, setInfo] = useState(null)
  const [queue, setQueue] = useState([])
  const [loading, setLoading] = useState(true)
  const [key, setKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [reserveOpen, setReserveOpen] = useState(false)
  const [ipVisible, setIpVisible] = useState(false)
  const sameAsCurrent = Boolean(key.trim() && info?.key_full && key.trim().toLowerCase() === String(info.key_full).trim().toLowerCase())
  const [manualPasteOpen, setManualPasteOpen] = useState(false)
  const superadmin = getRole() === 'superadmin'

  const load = async () => {
    setLoading(true)
    try {
      const [statusResult, queueResult] = await Promise.all([api.get('/license/status?include_queue_details=true'), api.get('/license/reserved')])
      setInfo(statusResult.data); setQueue(queueResult.data)
    } catch (error) { notify?.({ type: 'error', message: error.response?.data?.detail || String(error), dir }) }
    finally { setLoading(false) }
  }
  useEffect(() => { load() }, [])

  const pasteLicense = async () => {
    const text = await readClipboardText()
    if (text) {
      setKey(text.trim())
      return
    }
    // Browsers block clipboard reads on plain HTTP/IP pages. Open an
    // auto-focused fallback instead of showing a dead-end error.
    setManualPasteOpen(true)
  }

  const activate = async (event) => {
    event.preventDefault(); setSaving(true)
    try {
      const { data } = await api.post('/license/activate', { key: key.trim().toLowerCase() })
      setInfo(data); setKey('')
      const queueResult = await api.get('/license/reserved').catch(() => null)
      if (queueResult) setQueue(queueResult.data || [])
      notify?.({ type: 'success', message: data.message, dir })
    } catch (error) { notify?.({ type: 'error', message: error.response?.data?.detail || String(error), dir }) }
    finally { setSaving(false) }
  }

  const copyCurrentLicense = async () => {
    const value = info?.key_full || info?.key_masked
    if (!value || value === '—') return
    const ok = await copyText(value)
    notify?.({ type: ok ? 'success' : 'error', message: ok ? t('licenseCopied') : t('clipboardWriteError'), dir })
  }

  const active = !!info && !info.locked && ['active', 'expiring_soon'].includes(info.status)
  const remaining = useMemo(() => typeof info?.days_remaining === 'number' ? formatRemainingText(info.days_remaining, info.hours_remaining, info.minutes_remaining, t) : '—', [info, t])

  if (loading) return <div className="app-card p-8"><div className="h-5 w-48 rounded skeleton"/><div className="mt-5 grid grid-cols-2 gap-3">{Array.from({length:4}).map((_,i)=><div key={i} className="h-24 rounded-xl skeleton"/>)}</div></div>

  return (
    <div dir={dir} className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3"><div><h1 className="page-heading">{t('licensePageTitle')}</h1><p className="page-subtitle">{t('licensePageSubtitle')}</p></div>{superadmin && <button className="btn-primary" onClick={() => setReserveOpen(true)}><Icon name="plus" size={16}/>{t('renewBtn')}</button>}</header>

      <section className="app-card overflow-hidden">
        <div className={`border-b px-5 py-5 sm:px-6 ${active ? 'border-success/20 bg-success/[.045]' : 'border-danger/20 bg-danger/[.045]'}`}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4"><span className={`flex h-14 w-14 items-center justify-center rounded-2xl border ${active ? 'border-signal/35 bg-signal/10 text-signal' : 'border-danger/35 bg-danger/10 text-danger'}`}><Icon name="shield" size={29}/></span><div><div className="text-[10px] font-bold uppercase tracking-[.15em] text-muted">{t('licenseStatus')}</div><div className="mt-1 text-lg font-black">{info?.message || info?.status || '—'}</div></div></div>
            <span className={`status-pill ${active ? 'status-success' : 'status-danger'}`}><span className="h-1.5 w-1.5 rounded-full bg-current"/>{active ? t('stateActive') : t('stateInactive')}</span>
          </div>
        </div>
        <div className="grid gap-3 p-5 sm:grid-cols-2 sm:p-6 xl:grid-cols-3">
          <Info icon="key" label={t('licenseCurrentKey')} value={info?.key_full || info?.key_masked || '—'} mono copyable onClick={copyCurrentLicense} hint={t('clickToCopy')} />
          <Info icon="clock" label={t('timeRemaining')} value={remaining} />
          <Info icon="chart" label={t('purchasedDuration')} value={info?.total_days_purchased != null ? `${info.total_days_purchased} ${t('purchasedDurationUnit')}` : '—'} />
          <Info icon="license" label={t('expiryDate')} value={info?.expires_at_jalali_display || '—'} mono />
          <Info icon="activity" label={t('firstActivation')} value={info?.first_online_jalali_display || info?.created_at_jalali_display || '—'} mono />
          <Info icon="globe" label={t('licenseConnectivity')} value={info?.message || '—'} />
          <SecretInfo icon="server" label={t('licenseServerIp')} value={info?.activated_server_ip || '—'} visible={ipVisible} onToggle={() => setIpVisible(v => !v)} showLabel={t('showIp')} hideLabel={t('hideIp')} />
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-[.9fr_1.1fr]">
        <section className="panel-section">
          <header className="panel-section-header"><div><h2 className="section-heading">{t('licenseQueue')}</h2><p className="mt-1 text-[10px] text-muted">{t('licenseQueueSubtitle')}</p></div><span className="status-pill status-neutral">{queue.length}</span></header>
          <div className="space-y-2 p-4">
            {queue.length ? queue.map(item => <div key={item.id} className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface2 p-3.5"><div className="flex min-w-0 items-center gap-3"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-signal/10 text-signal font-data text-xs">#{item.queue_position}</span><div className="min-w-0"><div className="truncate font-data text-xs font-bold">{item.key_masked}</div><div className="mt-1 text-[10px] text-muted">{item.status || t('waitingActivation')}</div></div></div><div className="shrink-0 text-xs font-bold text-signal font-data">{item.days_remaining ?? item.duration_days ?? '—'} {t('daysShort')}</div></div>) : <div className="empty-state"><Icon name="license" size={30} className="text-muted"/><div className="mt-3 text-sm font-semibold">{t('noReservedYet')}</div></div>}
          </div>
        </section>

        <section className="panel-section">
          <header className="panel-section-header"><div><h2 className="section-heading">{t('licenseActivateTitle')}</h2><p className="mt-1 text-[10px] text-muted">{superadmin ? t('licenseActivateSubtitle') : t('licenseReadOnly')}</p></div></header>
          <div className="p-4 sm:p-5">
            {superadmin ? <form onSubmit={activate} className="space-y-4"><label className="block"><span className="field-label">{t('keyPlaceholder')}</span><div className="relative"><Icon name="key" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input className="field ps-9 pe-32 font-data tracking-wider" value={key} onChange={event => setKey(event.target.value)} required placeholder={t('keyPlaceholder')}/><button type="button" onClick={pasteLicense} className="absolute end-1.5 top-1/2 -translate-y-1/2 rounded-md border border-signal/30 bg-signal/10 px-2.5 py-1.5 text-[10px] font-bold text-signal hover:bg-signal/20">{t('pasteLicenseBtn')}</button></div></label>{sameAsCurrent && <div className="rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-xs font-bold text-amber">{t('licenseSameKeyDisabled')}</div>}<button className="btn-primary" disabled={saving || sameAsCurrent}>{saving ? <><span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white"/>{t('checkingBtn')}</> : <><Icon name="check" size={16}/>{t('licenseActivateButton')}</>}</button></form> : <div className="status-info rounded-xl px-4 py-3 text-sm">{t('licenseReadOnly')}</div>}
          </div>
        </section>
      </div>
      {reserveOpen && <LicenseReserveModal info={info} onClose={() => setReserveOpen(false)} onReserved={load}/>}
      {manualPasteOpen && <ManualPasteModal initialValue={key} t={t} dir={dir} onClose={() => setManualPasteOpen(false)} onUse={(value) => { setKey(value.trim()); setManualPasteOpen(false) }} />}
    </div>
  )
}

function Info({ icon, label, value, mono = false, copyable = false, onClick, hint }) {
  const Tag = copyable ? 'button' : 'div'
  return <Tag type={copyable ? 'button' : undefined} onClick={onClick} className={`w-full rounded-xl border border-border bg-surface2 p-4 text-start transition ${copyable ? 'cursor-copy hover:border-signal/45 hover:bg-signal/[.045] focus:outline-none focus:ring-2 focus:ring-signal/25' : ''}`} title={copyable ? hint : undefined}><div className="flex items-center justify-between gap-2 text-[10px] text-muted"><span className="flex items-center gap-2"><Icon name={icon} size={14}/>{label}</span>{copyable && <span className="flex items-center gap-1 text-signal"><Icon name="copy" size={12}/>{hint}</span>}</div><div dir={mono ? 'ltr' : undefined} className={`mt-2 break-all text-sm font-bold ${mono ? 'font-data text-start' : ''}`}>{value}</div></Tag>
}

function SecretInfo({ icon, label, value, visible, onToggle, showLabel, hideLabel }) {
  return <div className="w-full rounded-xl border border-border bg-surface2 p-4 text-start"><div className="flex items-center justify-between gap-2 text-[10px] text-muted"><span className="flex items-center gap-2"><Icon name={icon} size={14}/>{label}</span><button type="button" onClick={onToggle} className="flex h-7 w-7 items-center justify-center rounded-lg border border-border bg-surface text-muted hover:border-signal/35 hover:text-signal" title={visible ? hideLabel : showLabel} aria-label={visible ? hideLabel : showLabel}><Icon name={visible ? 'eyeOff' : 'eye'} size={13}/></button></div><div dir="ltr" className={`mt-2 break-all text-start font-data text-sm font-bold transition ${visible ? 'text-ink' : 'select-none blur-[5px] text-muted'}`}>{value}</div></div>
}


function ManualPasteModal({ initialValue, t, dir, onClose, onUse }) {
  const [value, setValue] = useState(initialValue || '')
  const inputRef = useRef(null)
  useEffect(() => {
    const timer = window.setTimeout(() => { inputRef.current?.focus(); inputRef.current?.select() }, 60)
    return () => window.clearTimeout(timer)
  }, [])
  const submit = (event) => {
    event.preventDefault()
    if (value.trim()) onUse(value)
  }
  return <div className="modal-backdrop !z-[105]" role="dialog" aria-modal="true">
    <div dir={dir} className="modal-panel modal-scroll-shell max-w-lg">
      <header className="modal-sticky-header">
        <div><h2 className="font-black text-sm">{t('pasteLicenseFallbackTitle')}</h2><p className="mt-1 text-[10px] text-muted">{t('pasteLicenseFallbackHint')}</p></div>
        <button type="button" className="modal-close-button" onClick={onClose}>✕</button>
      </header>
      <form onSubmit={submit} className="modal-scroll-body p-4 sm:p-5">
        <textarea ref={inputRef} className="field min-h-[120px] resize-y font-data text-start" dir="ltr" value={value} onChange={(e) => setValue(e.target.value)} onPaste={(e) => { const pasted = e.clipboardData?.getData('text'); if (pasted) { e.preventDefault(); setValue(pasted) } }} placeholder={t('pasteLicenseFallbackPlaceholder')} />
        <div className="modal-actions mt-4"><button type="button" className="btn-secondary" onClick={onClose}>{t('pasteLicenseFallbackCancel')}</button><button type="submit" className="btn-primary" disabled={!value.trim()}>{t('pasteLicenseFallbackUse')}</button></div>
      </form>
    </div>
  </div>
}
