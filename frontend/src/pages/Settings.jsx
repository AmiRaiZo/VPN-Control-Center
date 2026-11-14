import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import api from '../api'
import { useUI } from '../components/ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { useBranding } from '../branding.jsx'
import SectionTabs from '../components/SectionTabs.jsx'
import { getServerRole } from '../session'



function countryFlagFromCode(code) {
  if (!code || String(code).length !== 2) return '🌐'
  return String(code).toUpperCase().replace(/./g, (char) => String.fromCodePoint(127397 + char.charCodeAt(0)))
}

function ModernSelect({
  label,
  value,
  onChange,
  options,
  placeholder,
  disabled,
  searchable = true,
  searchPlaceholder,
  emptyText,
  dir = 'rtl',
  displayDir,
  renderValue,
  renderOption,
}) {
  const rootRef = useRef(null)
  const triggerRef = useRef(null)
  const panelRef = useRef(null)
  const searchRef = useRef(null)
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [panelStyle, setPanelStyle] = useState({})

  const selected = useMemo(
    () => options.find((item) => String(item.value) === String(value)) || null,
    [options, value],
  )

  const showSearch = searchable && options.length > 8
  const normalizedQuery = String(query || '').trim().toLocaleLowerCase()
  const filteredOptions = useMemo(() => {
    if (!normalizedQuery) return options
    return options.filter((item) => {
      const haystack = [item.label, item.value, item.searchText, item.meta].filter(Boolean).join(' ')
      return haystack.toLocaleLowerCase().includes(normalizedQuery)
    })
  }, [normalizedQuery, options])

  const positionPanel = () => {
    const trigger = triggerRef.current
    if (!trigger) return
    const rect = trigger.getBoundingClientRect()
    const viewportWidth = Math.max(document.documentElement.clientWidth, window.innerWidth || 0)
    const viewportHeight = Math.max(document.documentElement.clientHeight, window.innerHeight || 0)
    const edge = 8
    const gap = 7
    const below = viewportHeight - rect.bottom - edge
    const above = rect.top - edge
    const openUp = below < 235 && above > below
    const available = Math.max(150, Math.min(360, (openUp ? above : below) - gap))
    const width = Math.min(rect.width, viewportWidth - edge * 2)
    const left = Math.max(edge, Math.min(rect.left, viewportWidth - width - edge))
    setPanelStyle({
      position: 'fixed',
      left,
      right: 'auto',
      width,
      top: openUp ? 'auto' : rect.bottom + gap,
      bottom: openUp ? viewportHeight - rect.top + gap : 'auto',
      maxHeight: available,
      zIndex: 2147483000,
    })
  }

  useLayoutEffect(() => {
    if (!open) return undefined
    positionPanel()
    const reposition = () => window.requestAnimationFrame(positionPanel)
    window.addEventListener('resize', reposition, { passive: true })
    window.addEventListener('scroll', reposition, true)
    return () => {
      window.removeEventListener('resize', reposition)
      window.removeEventListener('scroll', reposition, true)
    }
  }, [open, query, options.length])

  useEffect(() => {
    if (!open) return undefined
    const closeOnOutside = (event) => {
      if (!rootRef.current?.contains(event.target) && !panelRef.current?.contains(event.target)) {
        setOpen(false)
        setQuery('')
      }
    }
    const closeOnEscape = (event) => {
      if (event.key === 'Escape') {
        setOpen(false)
        setQuery('')
      }
    }
    document.addEventListener('mousedown', closeOnOutside)
    document.addEventListener('touchstart', closeOnOutside, { passive: true })
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('mousedown', closeOnOutside)
      document.removeEventListener('touchstart', closeOnOutside)
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [open])

  useEffect(() => {
    if (!open) {
      setQuery('')
      return undefined
    }
    if (showSearch) {
      const timer = window.setTimeout(() => searchRef.current?.focus(), 20)
      return () => window.clearTimeout(timer)
    }
    return undefined
  }, [open, showSearch])

  const selectOption = (nextValue) => {
    onChange(nextValue)
    setOpen(false)
    setQuery('')
  }

  const menu = open && typeof document !== 'undefined' ? createPortal(
    <div ref={panelRef} className="modern-select-panel modern-select-panel--portal" style={panelStyle} dir={dir}>
      {showSearch && (
        <div className="modern-select-search">
          <input
            ref={searchRef}
            type="text"
            className="modern-select-search-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={searchPlaceholder}
          />
        </div>
      )}
      <div className="modern-select-options" role="listbox" dir={displayDir || dir}>
        {!filteredOptions.length && <div className="modern-select-empty">{emptyText}</div>}
        {filteredOptions.map((item) => {
          const active = String(item.value) === String(value)
          return (
            <button
              key={item.value}
              type="button"
              role="option"
              aria-selected={active}
              className={`modern-select-option ${active ? 'is-active' : ''}`}
              onClick={() => selectOption(item.value)}
              title={typeof item.label === 'string' ? item.label : item.meta || item.value}
            >
              <span className="modern-select-option-main">
                {renderOption ? renderOption(item, active) : item.label}
              </span>
              {active && <span className="modern-select-option-check">✓</span>}
            </button>
          )
        })}
      </div>
    </div>,
    document.body,
  ) : null

  return (
    <div ref={rootRef} className={`modern-select ${disabled ? 'is-disabled' : ''}`} dir={dir}>
      {label && <span className="field-label">{label}</span>}
      <button
        ref={triggerRef}
        type="button"
        className={`modern-select-trigger ${open ? 'is-open' : ''}`}
        disabled={disabled}
        onClick={() => setOpen((current) => !current)}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span className={`modern-select-value ${!selected ? 'is-placeholder' : ''}`} dir={displayDir || dir}>
          {selected ? (renderValue ? renderValue(selected) : selected.label) : placeholder}
        </span>
        <span className="modern-select-chevron" aria-hidden="true">⌄</span>
      </button>
      {menu}
    </div>
  )
}

function PanelPortCard() {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [port, setPort] = useState(80)
  const [domainActive, setDomainActive] = useState(false)
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/panel-port')
      setPort(data.port)
      setDomainActive(data.domain_active)
      setDomain(data.domain || '')
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const { data } = await withBusy(t('changingPanelPortBusy'), () => api.post('/settings/panel-port', { port: Number(port) }))
      setSuccess(data?.url ? t('panelPortChangedSuccessUrl').replace('{url}', data.url) : t('panelPortChangedSuccess').replace('{port}', port))
    } catch (err) {
      setError(err.response?.data?.detail || t('panelPortChangeError'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel-section p-5 space-y-4">
      <div className="text-sm font-bold text-ink">{t('panelPortTitle')}</div>
      {domainActive && (
        <p className="text-[11px] text-muted">
          {t('panelPortDomainNote').replace('{domain}', domain)}
        </p>
      )}
      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}
      <form onSubmit={submit} className="flex flex-col sm:flex-row gap-2">
        <input
          type="number" min="1" max="65535"
          className="flex-1 bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
        <button disabled={loading} className="bg-signal text-bg font-bold rounded-lg px-4 py-2 sm:py-0 text-sm hover:opacity-90 disabled:opacity-50 whitespace-nowrap">
          {loading ? '...' : t('btnSave')}
        </button>
      </form>
    </div>
  )
}

function LoginFooterNoteCard() {
  const { lang } = useLang()
  const { branding, refreshBranding } = useBranding()
  const fa = lang === 'fa'
  const [text, setText] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/settings/login-footer-note').then(({ data }) => setText(data.text || '')).catch(() => {})
  }, [])
  useEffect(() => { setText(branding.login_footer_note || '') }, [branding.login_footer_note])

  const submit = async (event) => {
    event.preventDefault(); setSaving(true); setMessage(''); setError('')
    try {
      const { data } = await api.post('/settings/login-footer-note', { text })
      setText(data.text || '')
      await refreshBranding()
      setMessage(fa ? 'متن زیر فرم ورود ذخیره شد.' : 'Login footer text saved.')
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'ذخیره متن ناموفق بود.' : 'Could not save the text.'))
    } finally { setSaving(false) }
  }

  return <div className="panel-section p-5 space-y-4">
    <div>
      <div className="text-sm font-bold text-ink">{fa ? 'نوشته کنار سپر صفحه ورود' : 'Login shield caption'}</div>
      <p className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'آیکن سپر همیشه باقی می‌ماند. متن دلخواه مثل «ساخته شده توسط…» را بنویس؛ با خالی‌گذاشتن فیلد فقط سپر نمایش داده می‌شود.' : 'The shield icon always remains. Enter a custom credit, or leave the field empty to show only the shield.'}</p>
    </div>
    {error && <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>}
    {message && <div className="rounded-lg border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">{message}</div>}
    <form onSubmit={submit} className="space-y-3">
      <div className="flex min-h-11 items-center justify-center gap-2 rounded-xl border border-border bg-surface2 px-3 text-xs text-muted">
        <span aria-hidden="true">🛡</span>{text && <span>{text}</span>}
      </div>
      <input className="field" value={text} onChange={e => setText(e.target.value)} maxLength={180} placeholder={fa ? 'مثلاً: ساخته شده توسط AmiRaiZo' : 'Example: Built by AmiRaiZo'} />
      <button disabled={saving} className="btn-primary w-full">{saving ? '…' : (fa ? 'ذخیره متن' : 'Save text')}</button>
    </form>
  </div>
}

function SiteTitlesCard() {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [panelTitle, setPanelTitle] = useState('')
  const [subTitle, setSubTitle] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/site-titles')
      setPanelTitle(data.panel_title || '')
      setSubTitle(data.sub_title || '')
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      await withBusy(t('savingTitlesBusy'), () =>
        api.post('/settings/site-titles', { panel_title: panelTitle, sub_title: subTitle })
      )
      setSuccess(t('titlesSavedSuccess'))
    } catch (err) {
      setError(err.response?.data?.detail || t('titlesSaveError'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel-section p-5 space-y-4">
      <div>
        <div className="text-sm font-bold text-ink">{t('siteTitlesTitle')}</div>
      </div>

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

      <form onSubmit={submit} className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('panelTitleLabel')}</label>
          <input
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal"
            value={panelTitle}
            onChange={(e) => setPanelTitle(e.target.value)}
            maxLength={100}
            required
          />
        </div>
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subTitleLabel')}</label>
          <input
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal"
            value={subTitle}
            onChange={(e) => setSubTitle(e.target.value)}
            maxLength={100}
            required
          />
        </div>
        <button disabled={loading} className="btn-primary w-full">
          {loading ? t('btnSavingTitles') : t('btnSaveTitles')}
        </button>
      </form>
    </div>
  )
}

export function DomainCard({ nodeMode = false }) {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [domain, setDomain] = useState('')
  const [status, setStatus] = useState('not_configured')
  const [currentDomain, setCurrentDomain] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/domain')
      setCurrentDomain(data.domain)
      setStatus(data.status)
      if (data.domain) setDomain(data.domain)
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const data = await withBusy(t('gettingSslBusy'), async () => {
        const res = await api.post('/settings/domain', { domain })
        return res.data
      })
      setSuccess(t('domainActivatedSuccess').replace('{url}', data.url))
      setStatus('active')
      setCurrentDomain(data.domain)
      if (nodeMode && data?.url) {
        window.setTimeout(() => window.location.assign(`${String(data.url).replace(/\/$/, '')}/admins`), 1200)
      }
    } catch (err) {
      setError(err.response?.data?.detail || t('sslActivateError'))
      setStatus('failed')
    } finally {
      setLoading(false)
    }
  }

  const statusLabel = {
    active: { text: t('statusActive'), color: 'text-signal' },
    failed: { text: t('statusFailed'), color: 'text-danger' },
    in_progress: { text: t('statusInProgress'), color: 'text-amber' },
    not_configured: { text: t('statusNotConfigured'), color: 'text-muted' },
  }[status] || { text: status, color: 'text-muted' }

  return (
    <div className="panel-section p-5 space-y-4">
      <div className="text-sm font-bold text-ink">{t('domainSslTitle')}</div>
      {nodeMode && (
        <p className="text-[11px] leading-5 text-muted">
          {t('nodeSslHint')}
        </p>
      )}

      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
        <span className="text-muted">{t('currentStatusLabel')}</span>
        <span className={`font-data ${statusLabel.color}`}>{statusLabel.text}</span>
      </div>
      {currentDomain && (
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
          <span className="text-muted">{t('configuredDomainLabel')}</span>
          <a href={`https://${currentDomain}`} target="_blank" rel="noreferrer" className="font-data text-signal break-all text-left">
            {currentDomain}
          </a>
        </div>
      )}

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

      <form onSubmit={submit} className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subDomainLabel')}</label>
          <input
            placeholder="panel.yourdomain.com"
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
          />
        </div>
        <button disabled={loading} className="btn-primary w-full">
          {loading ? t('btnGettingSsl') : t('btnActivateDomainSsl')}
        </button>
      </form>
    </div>
  )
}

function VpnDomainCard() {
  const { confirm, withBusy } = useUI()
  const { t } = useLang()
  const [domain, setDomain] = useState('')
  const [status, setStatus] = useState('not_configured')
  const [currentDomain, setCurrentDomain] = useState(null)
  const [loading, setLoading] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/vpn-domain')
      setCurrentDomain(data.domain)
      setStatus(data.status)
      if (data.domain) setDomain(data.domain)
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const data = await withBusy(t('verifyingDomainBusy'), async () => {
        const res = await api.post('/settings/vpn-domain', { domain })
        return res.data
      })
      setSuccess(t('vpnDomainVerifiedSuccess'))
      setStatus('active')
      setCurrentDomain(data.domain)
    } catch (err) {
      setError(err.response?.data?.detail || t('domainVerifyError'))
      setStatus('failed')
    } finally {
      setLoading(false)
    }
  }

  const remove = async () => {
    const ok = await confirm({
      title: t('removeDomainTitle'),
      message: t('removeDomainMessage'),
      confirmLabel: t('removeDomainConfirmBtn'),
      danger: true,
    })
    if (!ok) return
    setRemoving(true)
    setError('')
    setSuccess('')
    try {
      await withBusy(t('removingDomainBusy'), () => api.delete('/settings/vpn-domain'))
      setCurrentDomain(null)
      setDomain('')
      setStatus('not_configured')
      setSuccess(t('domainRemovedSuccess'))
    } catch (err) {
      setError(err.response?.data?.detail || t('domainRemoveError'))
    } finally {
      setRemoving(false)
    }
  }

  const statusLabel = {
    active: { text: t('statusActive'), color: 'text-signal' },
    failed: { text: t('statusFailed'), color: 'text-danger' },
    in_progress: { text: t('statusInProgress'), color: 'text-amber' },
    not_configured: { text: t('statusNotConfigured'), color: 'text-muted' },
  }[status] || { text: status, color: 'text-muted' }

  return (
    <div className="panel-section p-5 space-y-4">
      <div>
        <div className="text-sm font-bold text-ink">{t('vpnDomainTitle')}</div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
        <span className="text-muted">{t('currentStatusLabel')}</span>
        <span className={`font-data ${statusLabel.color}`}>{statusLabel.text}</span>
      </div>
      {currentDomain && (
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
          <span className="text-muted">{t('configuredDomainLabel')}</span>
          <span className="font-data text-ink break-all text-left">{currentDomain}</span>
        </div>
      )}

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

      <form onSubmit={submit} className="flex flex-col sm:flex-row gap-2">
        <input
          placeholder="vpn.yourdomain.com"
          className="flex-1 bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          required
        />
        <button disabled={loading} className="bg-signal text-bg font-bold rounded-lg px-4 py-2 sm:py-0 text-sm hover:opacity-90 disabled:opacity-50 whitespace-nowrap">
          {loading ? '...' : t('btnVerifyAndGetSsl')}
        </button>
      </form>
      {currentDomain && (
        <button onClick={remove} disabled={removing} className="text-xs text-muted hover:text-danger">
          {removing ? t('btnRemovingDomain') : t('btnRemoveDomainBackToIp')}
        </button>
      )}
    </div>
  )
}

function Ikev2SslCard() {
  const { confirm, withBusy } = useUI()
  const { t } = useLang()
  const [domain, setDomain] = useState('')
  const [status, setStatus] = useState('not_configured')
  const [currentDomain, setCurrentDomain] = useState(null)
  const [loading, setLoading] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/ikev2-ssl')
      setCurrentDomain(data.domain)
      setStatus(data.status)
      if (data.domain) setDomain(data.domain)
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      await withBusy(t('verifyingDomainBusy'), async () => {
        // بک‌اند فوراً برمی‌گردد و کار certbot/nginx را در پس‌زمینه انجام
        // می‌دهد (چون nginx خودش را ری‌استارت می‌کند و منتظر ماندن برای آن
        // همین درخواست را از پشت Cloudflare قطع می‌کرد)، پس این‌جا وضعیت را
        // poll می‌کنیم تا "active"/"failed" شود.
        await api.post('/settings/ikev2-ssl', { domain })
        setStatus('in_progress')

        for (let i = 0; i < 60; i++) {
          await sleep(3000)
          const { data } = await api.get('/settings/ikev2-ssl')
          setStatus(data.status)
          if (data.status === 'active') {
            setSuccess(t('ikev2SslVerifiedSuccess'))
            setCurrentDomain(data.domain)
            return
          }
          if (data.status === 'failed') {
            setError(data.log ? data.log.slice(-500) : t('domainVerifyError'))
            return
          }
        }
        setError(t('domainVerifyError'))
      })
    } catch (err) {
      setError(err.response?.data?.detail || t('domainVerifyError'))
      setStatus('failed')
    } finally {
      setLoading(false)
    }
  }

  const remove = async () => {
    const ok = await confirm({
      title: t('removeDomainTitle'),
      message: t('removeDomainMessage'),
      confirmLabel: t('removeDomainConfirmBtn'),
      danger: true,
    })
    if (!ok) return
    setRemoving(true)
    setError('')
    setSuccess('')
    try {
      await withBusy(t('removingDomainBusy'), () => api.delete('/settings/ikev2-ssl'))
      setCurrentDomain(null)
      setDomain('')
      setStatus('not_configured')
      setSuccess(t('domainRemovedSuccess'))
    } catch (err) {
      setError(err.response?.data?.detail || t('domainRemoveError'))
    } finally {
      setRemoving(false)
    }
  }

  const statusLabel = {
    active: { text: t('statusActive'), color: 'text-signal' },
    failed: { text: t('statusFailed'), color: 'text-danger' },
    in_progress: { text: t('statusInProgress'), color: 'text-amber' },
    not_configured: { text: t('statusNotConfigured'), color: 'text-muted' },
  }[status] || { text: status, color: 'text-muted' }

  return (
    <div className="panel-section p-5 space-y-4">
      <div>
        <div className="text-sm font-bold text-skyblue">{t('ikev2SslTitle')}</div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
        <span className="text-muted">{t('currentStatusLabel')}</span>
        <span className={`font-data ${statusLabel.color}`}>{statusLabel.text}</span>
      </div>
      {currentDomain && (
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
          <span className="text-muted">{t('configuredDomainLabel')}</span>
          <span className="font-data text-ink break-all text-left">{currentDomain}</span>
        </div>
      )}

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

      <form onSubmit={submit} className="flex flex-col sm:flex-row gap-2">
        <input
          placeholder="ikev2.yourdomain.com"
          className="flex-1 bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          required
        />
        <button disabled={loading} className="bg-signal text-bg font-bold rounded-lg px-4 py-2 sm:py-0 text-sm hover:opacity-90 disabled:opacity-50 whitespace-nowrap">
          {loading ? '...' : t('btnVerifyAndGetSsl')}
        </button>
      </form>
      {currentDomain && (
        <button onClick={remove} disabled={removing} className="text-xs text-muted hover:text-danger">
          {removing ? t('btnRemovingDomain') : t('btnRemoveDomainBackToIp')}
        </button>
      )}
    </div>
  )
}

function SubDomainCard() {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [domain, setDomain] = useState('')
  const [port, setPort] = useState(443)
  const [status, setStatus] = useState('not_configured')
  const [currentDomain, setCurrentDomain] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/sub-domain')
      setCurrentDomain(data.domain)
      setStatus(data.status)
      if (data.domain) setDomain(data.domain)
      if (data.port) setPort(data.port)
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const data = await withBusy(t('gettingSubSslBusy'), async () => {
        const res = await api.post('/settings/sub-domain', { domain, port: Number(port) })
        return res.data
      })
      setSuccess(t('subDomainActivatedSuccess').replace('{url}', data.url))
      setStatus('active')
      setCurrentDomain(data.domain)
      setPort(data.port)
    } catch (err) {
      setError(err.response?.data?.detail || t('subSslActivateError'))
      setStatus('failed')
    } finally {
      setLoading(false)
    }
  }

  const statusLabel = {
    active: { text: t('statusActive'), color: 'text-signal' },
    failed: { text: t('statusFailed'), color: 'text-danger' },
    in_progress: { text: t('statusInProgress'), color: 'text-amber' },
    not_configured: { text: t('statusNotConfigured'), color: 'text-muted' },
  }[status] || { text: status, color: 'text-muted' }

  return (
    <div className="panel-section p-5 space-y-4">
      <div>
        <div className="text-sm font-bold text-ink">{t('subDomainCardTitle')}</div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
        <span className="text-muted">{t('currentStatusLabel')}</span>
        <span className={`font-data ${statusLabel.color}`}>{statusLabel.text}</span>
      </div>
      {currentDomain && (
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
          <span className="text-muted">{t('configuredDomainLabel')}</span>
          <a href={`https://${currentDomain}/sub/`} target="_blank" rel="noreferrer" className="font-data text-signal break-all text-left">
            {currentDomain}
          </a>
        </div>
      )}

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

      <form onSubmit={submit} className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subDomainLabel')}</label>
          <input
            placeholder="sub.yourdomain.com"
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
          />
        </div>
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subDomainPortLabel')}</label>
          <input
            type="number" min="1" max="65535"
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            required
          />
        </div>
        <button disabled={loading} className="btn-primary w-full">
          {loading ? t('gettingSubSslBusy') : t('btnActivateSubDomainSsl')}
        </button>
      </form>
    </div>
  )
}


function XrayConnectionHostsCard() {
  const { lang } = useLang()
  const fa = lang === 'fa'
  const [form, setForm] = useState({ vmess_host: '', vless_host: '' })
  const [fallback, setFallback] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/settings/xray-connection-hosts').then(({ data }) => {
      setForm({ vmess_host: data.vmess_host || '', vless_host: data.vless_host || '' })
      setFallback(data.fallback || '')
    }).catch(() => {})
  }, [])

  const submit = async (event) => {
    event.preventDefault(); setSaving(true); setMessage(''); setError('')
    try {
      const { data } = await api.post('/settings/xray-connection-hosts', form)
      setForm({ vmess_host: data.vmess_host || '', vless_host: data.vless_host || '' })
      setMessage(fa ? 'آدرس‌های اتصال داخل کانفیگ‌ها ذخیره شد.' : 'Connection hosts saved.')
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'ذخیره آدرس‌ها ناموفق بود.' : 'Could not save hosts.'))
    } finally { setSaving(false) }
  }

  return <div className="panel-section p-5 space-y-4">
    <div>
      <div className="text-sm font-bold text-ink">{fa ? 'آدرس اتصال VMess و VLESS' : 'VMess / VLESS connection hosts'}</div>
      <p className="mt-1 text-[11px] leading-5 text-muted">
        {fa
          ? 'دامنه‌ای که داخل خود کانفیگ کاربر قرار می‌گیرد. DNS این دامنه باید به سرور اشاره کند. خالی = انتخاب خودکار.'
          : 'Host embedded in generated client configs. Its DNS must point to this server. Empty means automatic.'}
      </p>
      {fallback && <div className="mt-2 text-[10px] text-muted font-data" dir="ltr">Auto: {fallback}</div>}
    </div>
    {error && <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>}
    {message && <div className="rounded-lg border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">{message}</div>}
    <form onSubmit={submit} className="space-y-3">
      <label className="block"><span className="field-label">VMess host</span><input dir="ltr" className="field font-data" placeholder="vm.example.com" value={form.vmess_host} onChange={e => setForm(v => ({ ...v, vmess_host: e.target.value }))}/></label>
      <label className="block"><span className="field-label">VLESS host</span><input dir="ltr" className="field font-data" placeholder="vl.example.com" value={form.vless_host} onChange={e => setForm(v => ({ ...v, vless_host: e.target.value }))}/></label>
      <button disabled={saving} className="btn-primary w-full">{saving ? '...' : (fa ? 'ذخیره آدرس اتصال' : 'Save connection hosts')}</button>
    </form>
  </div>
}

function XraySubDomainCard() {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [domain, setDomain] = useState('')
  const [port, setPort] = useState(443)
  const [status, setStatus] = useState('not_configured')
  const [currentDomain, setCurrentDomain] = useState(null)
  const [loading, setLoading] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/xray-sub-domain')
      setCurrentDomain(data.domain || null)
      setStatus(data.status || 'not_configured')
      if (data.domain) setDomain(data.domain)
      if (data.port) setPort(data.port)
    } catch (_) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const data = await withBusy(t('xraySubDomainBusy'), async () => {
        const res = await api.post('/settings/xray-sub-domain', { domain, port: Number(port) })
        return res.data
      })
      setCurrentDomain(data.domain)
      setStatus('active')
      setPort(data.port)
      setSuccess(t('xraySubDomainSuccess').replace('{url}', data.url))
    } catch (err) {
      setStatus('failed')
      setError(err.response?.data?.detail || t('xraySubDomainError'))
    } finally {
      setLoading(false)
    }
  }

  const remove = async () => {
    if (!window.confirm(t('xraySubDomainRemove') + '؟')) return
    setRemoving(true)
    setError('')
    setSuccess('')
    try {
      await api.delete('/settings/xray-sub-domain')
      setCurrentDomain(null)
      setStatus('not_configured')
      setDomain('')
      setPort(443)
      setSuccess(t('xraySubDomainRemoved'))
    } catch (err) {
      setError(err.response?.data?.detail || t('xraySubDomainError'))
    } finally {
      setRemoving(false)
    }
  }

  const statusLabel = {
    active: { text: t('statusActive'), color: 'text-signal' },
    failed: { text: t('statusFailed'), color: 'text-danger' },
    in_progress: { text: t('statusInProgress'), color: 'text-amber' },
    not_configured: { text: t('statusNotConfigured'), color: 'text-muted' },
  }[status] || { text: status, color: 'text-muted' }

  const currentUrl = currentDomain
    ? `https://${currentDomain}${Number(port) === 443 ? '' : `:${port}`}/api/sub/USER_TOKEN/xray-sub`
    : ''

  return (
    <div className="panel-section p-5 space-y-4">
      <div className="space-y-1">
        <div className="text-sm font-bold text-ink">{t('xraySubDomainCardTitle')}</div>
        <p className="text-[11px] leading-5 text-muted">{t('xraySubDomainCardDesc')}</p>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-sm">
        <span className="text-muted">{t('currentStatusLabel')}</span>
        <span className={`font-data ${statusLabel.color}`}>{statusLabel.text}</span>
      </div>
      {currentUrl && (
        <div className="rounded-lg border border-border bg-surface2/60 p-3 text-xs">
          <div className="mb-1 text-muted">{t('configuredDomainLabel')}</div>
          <div className="break-all font-data text-signal" dir="ltr">{currentUrl}</div>
        </div>
      )}

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

      <form onSubmit={submit} className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subDomainLabel')}</label>
          <input
            placeholder="xray-sub.yourdomain.com"
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
          />
        </div>
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subDomainPortLabel')}</label>
          <input
            type="number" min="1" max="65535"
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            required
          />
        </div>
        <button disabled={loading} className="btn-primary w-full">
          {loading ? t('xraySubDomainBusy') : t('xraySubDomainButton')}
        </button>
      </form>

      {currentDomain && (
        <button type="button" onClick={remove} disabled={removing} className="text-xs text-muted hover:text-danger disabled:opacity-50">
          {removing ? t('btnRemovingDomain') : t('xraySubDomainRemove')}
        </button>
      )}
    </div>
  )
}

function SubDomainPortCard() {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [port, setPort] = useState(443)
  const [active, setActive] = useState(false)
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/sub-domain')
      setActive(data.status === 'active' && !!data.domain)
      setDomain(data.domain || '')
      if (data.port) setPort(data.port)
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  if (!active) return null

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const { data } = await withBusy(t('changingSubDomainPortBusy'), () => api.post('/settings/sub-domain-port', { port: Number(port) }))
      setSuccess(t('subDomainPortChangedSuccess').replace('{url}', data.url))
    } catch (err) {
      setError(err.response?.data?.detail || t('subDomainPortChangeError'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel-section p-5 space-y-4">
      <div className="text-sm font-bold text-ink">{t('subDomainPortTitle')}</div>
      <p className="text-[11px] text-muted">
        {t('subDomainPortNote').replace('{domain}', domain)}
      </p>
      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}
      <form onSubmit={submit} className="flex flex-col sm:flex-row gap-2">
        <input
          type="number" min="1" max="65535"
          className="flex-1 bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
        <button disabled={loading} className="bg-signal text-bg font-bold rounded-lg px-4 py-2 sm:py-0 text-sm hover:opacity-90 disabled:opacity-50 whitespace-nowrap">
          {loading ? '...' : t('btnSave')}
        </button>
      </form>
    </div>
  )
}

function SubDownloadLinkCard() {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [label, setLabel] = useState('')
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = async () => {
    try {
      const { data } = await api.get('/settings/sub-download')
      setLabel(data.label || '')
      setUrl(data.url || '')
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      await withBusy(t('savingSubDownloadBusy'), () =>
        api.post('/settings/sub-download', { label: label.trim(), url: url.trim() })
      )
      setSuccess(t('subDownloadSavedSuccess'))
    } catch (err) {
      setError(err.response?.data?.detail || t('subDownloadSaveError'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel-section p-5 space-y-4">
      <div>
        <div className="text-sm font-bold text-ink">{t('subDownloadCardTitle')}</div>
        <div className="text-xs text-muted mt-1 leading-5">{t('subDownloadCardDesc')}</div>
      </div>

      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

      <form onSubmit={submit} className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subDownloadLabelField')}</label>
          <input
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder={t('subDownloadLabelPlaceholder')}
            maxLength={60}
          />
        </div>
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('subDownloadUrlField')}</label>
          <input
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal font-data"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/app.apk"
          />
        </div>
        <button disabled={loading} className="btn-primary w-full">
          {loading ? t('savingSubDownloadBusy') : t('btnSave')}
        </button>
      </form>
    </div>
  )
}

const PLATFORM_KEYS = ['android', 'windows', 'ios', 'mac']
const PLATFORM_LABEL_KEYS = {
  android: 'platformAndroidLabel',
  windows: 'platformWindowsLabel',
  ios: 'platformIosLabel',
  mac: 'platformMacLabel',
}

function PlatformAppsCard() {
  const { withBusy } = useUI()
  const { t, lang } = useLang()
  const [groups, setGroups] = useState(null)
  const [activePlatform, setActivePlatform] = useState(() => {
    try {
      const saved = window.localStorage.getItem('vpnpanel_platform_apps_tab')
      return PLATFORM_KEYS.includes(saved) ? saved : 'android'
    } catch (_) {
      return 'android'
    }
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const platformMeta = {
    android: { icon: '◉', accent: 'from-emerald-500/15 to-transparent' },
    windows: { icon: '⊞', accent: 'from-sky-500/15 to-transparent' },
    ios: { icon: '◆', accent: 'from-violet-500/15 to-transparent' },
    mac: { icon: '⌘', accent: 'from-orange-500/15 to-transparent' },
  }

  const load = async () => {
    try {
      const { data } = await api.get('/settings/platform-apps')
      setGroups(data)
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const selectPlatform = (key) => {
    setActivePlatform(key)
    setError('')
    setSuccess('')
    try { window.localStorage.setItem('vpnpanel_platform_apps_tab', key) } catch (_) { /* ignore */ }
  }

  const updateGroupLabel = (key, label) => {
    setGroups((g) => ({ ...g, [key]: { ...g[key], label } }))
  }

  const updateApp = (key, idx, field, value) => {
    setGroups((g) => {
      const apps = g[key].apps.map((a, i) => (i === idx ? { ...a, [field]: value } : a))
      return { ...g, [key]: { ...g[key], apps } }
    })
  }

  const addApp = (key) => {
    setGroups((g) => ({ ...g, [key]: { ...g[key], apps: [...g[key].apps, { name: '', desc: '', url: '' }] } }))
  }

  const removeApp = (key, idx) => {
    setGroups((g) => ({ ...g, [key]: { ...g[key], apps: g[key].apps.filter((_, i) => i !== idx) } }))
  }

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const { data } = await withBusy(t('savingPlatformAppsBusy'), () =>
        api.post('/settings/platform-apps', groups)
      )
      setGroups(data)
      setSuccess(t('platformAppsSavedSuccess'))
    } catch (err) {
      setError(err.response?.data?.detail || t('platformAppsSaveError'))
    } finally {
      setLoading(false)
    }
  }

  const resetDefault = async () => {
    if (!window.confirm(t('platformAppsResetConfirm'))) return
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      const { data } = await withBusy(t('savingPlatformAppsBusy'), () => api.delete('/settings/platform-apps'))
      setGroups(data)
      setSuccess(t('platformAppsResetSuccess'))
    } catch (err) {
      setError(err.response?.data?.detail || t('platformAppsResetError'))
    } finally {
      setLoading(false)
    }
  }

  if (!groups) return null

  const activeGroup = groups[activePlatform]
  const activeLabel = t(PLATFORM_LABEL_KEYS[activePlatform])
  const isEnglish = lang === 'en'

  return (
    <div className="panel-section overflow-hidden">
      <div className="border-b border-border px-4 py-4 sm:px-5">
        <div className="text-sm font-bold text-ink">{t('platformAppsCardTitle')}</div>
        <div className="text-xs text-muted mt-1 leading-5">{t('platformAppsCardDesc')}</div>
      </div>

      <div className="border-b border-border bg-surface2/45 px-3 py-3 sm:px-5">
        <div
          role="tablist"
          aria-label={t('platformAppsCardTitle')}
          className="grid grid-cols-2 gap-2 lg:grid-cols-4"
        >
          {PLATFORM_KEYS.map((key) => {
            const active = key === activePlatform
            const count = groups[key]?.apps?.length || 0
            return (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => selectPlatform(key)}
                className={`group relative min-h-[62px] overflow-hidden rounded-xl border px-3 py-2.5 text-start transition-all duration-200 ${active
                  ? 'border-signal/60 bg-signal/10 shadow-[0_8px_24px_rgba(255,112,0,.10)]'
                  : 'border-border bg-surface hover:border-signal/30 hover:bg-surface2'
                }`}
              >
                <span className={`pointer-events-none absolute inset-0 bg-gradient-to-br ${platformMeta[key].accent} opacity-0 transition-opacity ${active ? 'opacity-100' : 'group-hover:opacity-70'}`} />
                <span className="relative flex items-center gap-2.5">
                  <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg border text-base font-black ${active
                    ? 'border-signal/50 bg-signal text-bg'
                    : 'border-border bg-surface2 text-muted'
                  }`}>
                    {platformMeta[key].icon}
                  </span>
                  <span className="min-w-0">
                    <span className={`block truncate text-xs font-extrabold ${active ? 'text-ink' : 'text-muted'}`}>
                      {t(PLATFORM_LABEL_KEYS[key])}
                    </span>
                    <span className="mt-1 block text-[10px] text-muted">
                      {count} {isEnglish ? (count === 1 ? 'app' : 'apps') : 'برنامه'}
                    </span>
                  </span>
                </span>
              </button>
            )
          })}
        </div>
      </div>

      <form onSubmit={submit} className="space-y-4 p-4 sm:p-5">
        {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
        {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}

        <section
          role="tabpanel"
          aria-label={activeLabel}
          className="rounded-2xl border border-border bg-surface2/55 p-3 sm:p-4"
        >
          <div className="mb-4 flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <span className="grid h-10 w-10 place-items-center rounded-xl border border-signal/35 bg-signal/10 text-lg font-black text-signal">
                {platformMeta[activePlatform].icon}
              </span>
              <div>
                <div className="text-sm font-extrabold text-ink">{activeLabel}</div>
                <div className="mt-1 text-[11px] text-muted">
                  {isEnglish ? 'Configure only this platform in the current tab.' : 'تنظیمات همین پلتفرم را در این تب ویرایش کنید.'}
                </div>
              </div>
            </div>
            <span className="w-fit rounded-full border border-border bg-surface px-3 py-1 text-[10px] font-bold text-muted">
              {activeGroup.apps.length} {isEnglish ? 'recommended apps' : 'برنامه پیشنهادی'}
            </span>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-xs text-muted mb-1.5 font-data">{t('platformAppsGroupLabelField')}</label>
              <input
                className="w-full bg-surface border border-border rounded-xl px-3 py-2.5 text-sm outline-none focus:border-signal"
                value={activeGroup.label}
                onChange={(e) => updateGroupLabel(activePlatform, e.target.value)}
                maxLength={40}
              />
            </div>

            <div className="space-y-3">
              {activeGroup.apps.map((app, idx) => (
                <div key={idx} className="rounded-xl border border-border bg-surface p-3 shadow-sm">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-border bg-surface2 text-[11px] font-extrabold text-muted">
                        {idx + 1}
                      </span>
                      <span className="truncate text-xs font-bold text-ink">
                        {app.name || (isEnglish ? 'New app' : 'برنامه جدید')}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => removeApp(activePlatform, idx)}
                      className="shrink-0 rounded-lg border border-danger/25 bg-danger/5 px-2.5 py-1.5 text-[11px] font-bold text-danger transition hover:bg-danger/10"
                    >
                      {t('platformAppsRemoveAppBtn')}
                    </button>
                  </div>

                  <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                    <input
                      className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm outline-none focus:border-signal"
                      value={app.name}
                      placeholder={t('platformAppsAppNameField')}
                      onChange={(e) => updateApp(activePlatform, idx, 'name', e.target.value)}
                      maxLength={60}
                    />
                    <input
                      className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-xs outline-none focus:border-signal"
                      value={app.desc}
                      placeholder={t('platformAppsAppDescField')}
                      onChange={(e) => updateApp(activePlatform, idx, 'desc', e.target.value)}
                      maxLength={200}
                    />
                    <input
                      className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-xs outline-none focus:border-signal font-data lg:col-span-2"
                      value={app.url || ''}
                      placeholder={t('platformAppsAppUrlField')}
                      onChange={(e) => updateApp(activePlatform, idx, 'url', e.target.value)}
                    />
                  </div>
                </div>
              ))}

              <button
                type="button"
                onClick={() => addApp(activePlatform)}
                className="w-full rounded-xl border border-dashed border-signal/35 bg-signal/5 px-4 py-3 text-xs font-extrabold text-signal transition hover:border-signal/60 hover:bg-signal/10 sm:w-auto"
              >
                {t('platformAppsAddAppBtn')}
              </button>
            </div>
          </div>
        </section>

        <div className="flex flex-col-reverse gap-2 border-t border-border pt-4 sm:flex-row sm:items-center sm:justify-end">
          <button
            type="button"
            disabled={loading}
            onClick={resetDefault}
            className="btn-secondary sm:min-w-[170px]"
          >
            {t('platformAppsResetBtn')}
          </button>
          <button disabled={loading} className="btn-primary sm:min-w-[190px]">
            {loading ? t('savingPlatformAppsBusy') : t('btnSave')}
          </button>
        </div>
      </form>
    </div>
  )
}


const BRANDING_MAX_BYTES = 10 * 1024 * 1024
const BRANDING_OPTIMIZE_AFTER_BYTES = 2.5 * 1024 * 1024

async function optimizeBrandingImage(file, kind) {
  const accepted = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp'])
  const type = String(file?.type || '').toLowerCase()
  if (!accepted.has(type)) throw new Error('TYPE')
  if (file.size <= BRANDING_OPTIMIZE_AFTER_BYTES) return file

  try {
    const bitmap = await createImageBitmap(file)
    const maxWidth = kind === 'logo' ? 1600 : 2560
    const maxHeight = kind === 'logo' ? 1600 : 1600
    const scale = Math.min(1, maxWidth / bitmap.width, maxHeight / bitmap.height)
    const width = Math.max(1, Math.round(bitmap.width * scale))
    const height = Math.max(1, Math.round(bitmap.height * scale))
    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height
    const ctx = canvas.getContext('2d', { alpha: true })
    if (!ctx) throw new Error('CANVAS')
    ctx.drawImage(bitmap, 0, 0, width, height)
    bitmap.close?.()
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/webp', kind === 'logo' ? 0.92 : 0.86))
    if (!blob) throw new Error('ENCODE')
    if (blob.size > BRANDING_MAX_BYTES) throw new Error('SIZE')
    const base = String(file.name || kind).replace(/\.[^.]+$/, '')
    return new File([blob], `${base}.webp`, { type: 'image/webp', lastModified: Date.now() })
  } catch (error) {
    if (file.size > BRANDING_MAX_BYTES) throw new Error('SIZE')
    return file
  }
}

function brandingUploadError(err, fa) {
  if (err?.message === 'TYPE') return fa ? 'فقط تصویر PNG، JPEG یا WebP قابل بارگذاری است.' : 'Only PNG, JPEG or WebP images are supported.'
  if (err?.message === 'SIZE') return fa ? 'حجم تصویر حتی پس از بهینه‌سازی بیشتر از ۱۰ مگابایت است.' : 'The image is still larger than 10 MB after optimization.'
  const status = err?.response?.status
  if (status === 413) return fa ? 'حجم درخواست از محدودیت وب‌سرور بیشتر است؛ تنظیمات Nginx این نسخه را نصب کن.' : 'The upload is larger than the web-server limit.'
  if (status === 401 || status === 403) return fa ? 'اجازه بارگذاری تصویر برای این حساب وجود ندارد.' : 'This account is not allowed to upload images.'
  const detail = err?.response?.data?.detail
  if (typeof detail === 'string' && detail.trim()) return detail
  if (!err?.response) return fa ? 'ارتباط با سرور هنگام آپلود قطع شد. اتصال و آدرس پنل را بررسی کن.' : 'The connection to the server was interrupted during upload.'
  return fa ? 'آپلود تصویر ناموفق بود.' : 'Image upload failed.'
}

function BrandingCard() {
  const { lang, t } = useLang()
  const { withBusy } = useUI()
  const { branding, refreshBranding } = useBranding()
  const fa = lang === 'fa'
  const [form, setForm] = useState({
    hero_enabled: true,
    brand_name: 'VPN PANEL',
    hero_badge: '',
    hero_title: '',
    hero_subtitle: '',
    hero_footer: '',
    login_footer_note: '',
  })
  const [assets, setAssets] = useState(branding)
  const [saving, setSaving] = useState(false)
  const [uploading, setUploading] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const applyData = (data) => {
    setAssets(data)
    setForm({
      hero_enabled: data.hero_enabled !== false,
      brand_name: data.brand_name ?? 'VPN PANEL',
      hero_badge: data.hero_badge ?? t('loginPanelBadge'),
      hero_title: data.hero_title ?? t('loginHeroTitle'),
      hero_subtitle: data.hero_subtitle ?? t('loginHeroSubtitle'),
      hero_footer: data.hero_footer ?? 'VPN Panel · Secure Administration',
      login_footer_note: data.login_footer_note ?? '',
    })
  }

  useEffect(() => {
    api.get('/settings/branding').then(({ data }) => applyData(data)).catch(() => {})
  }, [])
  useEffect(() => { applyData(branding) }, [branding])

  const set = (key, value) => setForm(prev => ({ ...prev, [key]: value }))
  const save = async (event) => {
    event.preventDefault(); setError(''); setMessage(''); setSaving(true)
    try {
      const { data } = await withBusy(fa ? 'در حال ذخیره ظاهر پنل…' : 'Saving panel branding…', () => api.post('/settings/branding', form))
      applyData(data); await refreshBranding(); setMessage(fa ? 'ظاهر و متن‌های پنل ذخیره شد.' : 'Branding settings saved.')
    } catch (err) { setError(err.response?.data?.detail || (fa ? 'ذخیره تنظیمات ناموفق بود.' : 'Could not save branding.')) }
    finally { setSaving(false) }
  }

  const upload = async (kind, file) => {
    if (!file) return
    setError(''); setMessage(''); setUploading(kind)
    try {
      const prepared = await optimizeBrandingImage(file, kind)
      const body = new FormData(); body.append('image', prepared, prepared.name)
      // Do not set Content-Type manually. The browser must add the multipart boundary.
      const { data } = await api.post(`/settings/branding/upload/${kind}`, body, { timeout: 120000 })
      applyData(data); await refreshBranding(); setMessage(fa ? 'تصویر با موفقیت بارگذاری و بهینه‌سازی شد.' : 'Image uploaded and optimized successfully.')
    } catch (err) { setError(brandingUploadError(err, fa)) }
    finally { setUploading('') }
  }

  const remove = async (kind) => {
    setError(''); setMessage(''); setUploading(kind)
    try {
      const { data } = await api.delete(`/settings/branding/asset/${kind}`)
      applyData(data); await refreshBranding(); setMessage(fa ? 'تصویر حذف شد.' : 'Image removed.')
    } catch (err) { setError(err.response?.data?.detail || (fa ? 'حذف تصویر ناموفق بود.' : 'Could not remove image.')) }
    finally { setUploading('') }
  }

  return <div className="space-y-5">
    <div className="panel-section p-5">
      <div className="mb-4"><div className="text-sm font-bold text-ink">{fa ? 'برندینگ و صفحه ورود' : 'Branding & login page'}</div><p className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'لوگو، تصویر معرفی و نوشته‌های سمت معرفی صفحه ورود را شخصی‌سازی کن. هر نوشته‌ای که خالی باشد نمایش داده نمی‌شود؛ با خاموش‌کردن بخش معرفی، فرم ورود تمام‌صفحه می‌شود.' : 'Customize the logo, login illustration and hero text. Empty text fields are hidden; disabling the hero makes the login form full width.'}</p></div>
      {error && <div className="mb-3 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>}
      {message && <div className="mb-3 rounded-lg border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">{message}</div>}
      <form onSubmit={save} className="space-y-4">
        <label className={`settings-modern-toggle ${form.hero_enabled ? 'is-active' : ''}`}><span className="min-w-0"><span className="block text-xs font-bold text-ink">{fa ? 'نمایش بخش معرفی ورود' : 'Show login hero'}</span><span className="mt-1 block text-[10px] text-muted">{fa ? 'در صورت خاموش بودن، ستون معرفی به‌طور کامل حذف می‌شود.' : 'When disabled, the entire hero column is removed.'}</span></span><input className="sr-only" type="checkbox" checked={form.hero_enabled} onChange={e => set('hero_enabled', e.target.checked)} /><span aria-hidden="true" className="settings-modern-toggle__switch"><span /></span></label>
        <div className="grid gap-3 md:grid-cols-2">
          <TextField label={fa ? 'نام برند کنار لوگو' : 'Brand name'} value={form.brand_name} onChange={v => set('brand_name', v)} placeholder="VPN PANEL" />
          <TextField label={fa ? 'نشان کوچک معرفی' : 'Hero badge'} value={form.hero_badge} onChange={v => set('hero_badge', v)} />
          <TextField label={fa ? 'عنوان اصلی معرفی' : 'Hero title'} value={form.hero_title} onChange={v => set('hero_title', v)} />
          <TextField label={fa ? 'متن پایین صفحه معرفی' : 'Hero footer'} value={form.hero_footer} onChange={v => set('hero_footer', v)} />
          <TextField label={fa ? 'متن زیر فرم ورود (کنار آیکن)' : 'Login form footer text'} value={form.login_footer_note} onChange={v => set('login_footer_note', v)} placeholder={fa ? 'مثلاً: ساخته شده توسط AmiRaiZo' : 'Example: Built by AmiRaiZo'} />
        </div>
        <label className="block"><span className="field-label">{fa ? 'توضیحات معرفی' : 'Hero description'}</span><textarea className="field min-h-[112px] resize-y" value={form.hero_subtitle} onChange={e => set('hero_subtitle', e.target.value)} maxLength={500}/></label>
        <button disabled={saving} className="btn-primary w-full">{saving ? (fa ? 'در حال ذخیره…' : 'Saving…') : (fa ? 'ذخیره ظاهر و نوشته‌ها' : 'Save branding')}</button>
      </form>
    </div>

    <div className="grid gap-5 xl:grid-cols-2">
      <ImageAssetCard title={fa ? 'لوگوی پنل و بالای فرم ورود' : 'Panel & login form logo'} hint={fa ? 'PNG، JPEG یا WebP تا ۱۰ مگابایت؛ تصاویر بزرگ پیش از ارسال خودکار بهینه می‌شوند؛ در منوی پنل، بالای فرم ورود، مرکز طرح معرفی و آیکن تب/نوار بالای مرورگر موبایل استفاده می‌شود.' : 'PNG, JPEG or WebP up to 10 MB; large images are optimized before upload; used in the sidebar, above the login form, inside the hero visual and as the browser tab/mobile header icon.'} url={assets.logo_url} busy={uploading === 'logo'} onUpload={file => upload('logo', file)} onRemove={() => remove('logo')} fa={fa}/>
      <ImageAssetCard title={fa ? 'تصویر پس‌زمینه بخش معرفی' : 'Login hero image'} hint={fa ? 'تصویر به‌صورت Cover با لایه تیره/روشن تطبیقی نمایش داده می‌شود.' : 'Displayed as a cover image with an adaptive theme overlay.'} url={assets.hero_image_url} busy={uploading === 'hero'} onUpload={file => upload('hero', file)} onRemove={() => remove('hero')} fa={fa}/>
    </div>
  </div>
}

function TextField({ label, value, onChange, placeholder = '' }) {
  return <label className="block"><span className="field-label">{label}</span><input className="field" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} maxLength={180}/></label>
}

function ImageAssetCard({ title, hint, url, busy, onUpload, onRemove, fa }) {
  return <div className="panel-section p-5 space-y-4"><div><div className="text-sm font-bold text-ink">{title}</div><p className="mt-1 text-[10px] leading-5 text-muted">{hint}</p></div><div className="flex min-h-[170px] items-center justify-center overflow-hidden rounded-xl border border-dashed border-border bg-surface2">{url ? <img src={url} alt="" className="max-h-[220px] w-full object-contain"/> : <span className="text-xs text-muted">{fa ? 'تصویری انتخاب نشده است' : 'No image selected'}</span>}</div><div className="flex flex-wrap gap-2"><label className="btn-secondary cursor-pointer"><input type="file" accept="image/png,image/jpeg,image/webp" className="hidden" disabled={busy} onChange={e => { onUpload(e.target.files?.[0]); e.target.value = '' }}/>{busy ? '…' : (fa ? 'انتخاب و آپلود تصویر' : 'Choose & upload')}</label>{url && <button type="button" className="btn-danger" disabled={busy} onClick={onRemove}>{fa ? 'حذف تصویر' : 'Remove image'}</button>}</div></div>
}

function PortFallbackCard() {
  const { lang } = useLang()
  const fa = lang === 'fa'
  const [form, setForm] = useState({ enabled: true, minimum: 20000, maximum: 55000 })
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  useEffect(() => { api.get('/settings/port-fallback').then(({ data }) => setForm(data)).catch(() => {}) }, [])
  const save = async (event) => {
    event.preventDefault(); setSaving(true); setMessage(''); setError('')
    try { await api.post('/settings/port-fallback', { enabled: !!form.enabled, minimum: Number(form.minimum), maximum: Number(form.maximum) }); setMessage(fa ? 'تنظیمات پورت جایگزین ذخیره شد.' : 'Fallback port settings saved.') }
    catch (err) { setError(err.response?.data?.detail || (fa ? 'ذخیره ناموفق بود.' : 'Save failed.')) }
    finally { setSaving(false) }
  }
  return <div className="panel-section p-5 space-y-4"><div><div className="text-sm font-bold text-ink">{fa ? 'پورت جایگزین خودکار هنگام نصب و ترمیم' : 'Automatic fallback ports'}</div><p className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'برای L2TP، OpenVPN، OpenConnect، SSTP، VMess و VLESS اگر پورت توسط برنامه دیگری اشغال باشد، یک پورت آزاد از این بازه انتخاب و نتیجه روی کارت پروتکل ثبت می‌شود. PPTP و IKEv2 به‌دلیل پورت استاندارد کلاینت، مخفیانه تغییر نمی‌کنند.' : 'For configurable protocols, an occupied port is replaced with a free one from this range and reported on the protocol card. PPTP and IKEv2 standard ports are never changed silently.'}</p></div>{error && <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>}{message && <div className="rounded-lg border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">{message}</div>}<form onSubmit={save} className="space-y-3"><label className="flex items-center justify-between rounded-xl border border-border bg-surface2 px-4 py-3"><span className="text-xs font-bold text-ink">{fa ? 'فعال باشد' : 'Enabled'}</span><input type="checkbox" checked={!!form.enabled} onChange={e => setForm(v => ({ ...v, enabled: e.target.checked }))}/></label><div className="grid grid-cols-2 gap-3"><TextField label={fa ? 'شروع بازه' : 'Range start'} value={form.minimum} onChange={v => setForm(x => ({ ...x, minimum: v }))}/><TextField label={fa ? 'پایان بازه' : 'Range end'} value={form.maximum} onChange={v => setForm(x => ({ ...x, maximum: v }))}/></div><button disabled={saving} className="btn-primary w-full">{saving ? '…' : (fa ? 'ذخیره' : 'Save')}</button></form></div>
}


function NodeControllerCard() {
  const { lang } = useLang()
  const fa = lang === 'fa'
  const [form, setForm] = useState({
    controller_url: '',
    controller_token: '',
    verify_controller_tls: true,
    verify_node_tls: true,
  })
  const [state, setState] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [showToken, setShowToken] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/settings/node-controller', { skipInstantCache: true })
      setState(data)
      setForm(current => ({
        ...current,
        controller_url: data.controller_url || '',
        controller_token: '',
        verify_controller_tls: data.verify_controller_tls !== false,
        verify_node_tls: data.verify_node_tls !== false,
      }))
      setError('')
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'دریافت اطلاعات سرور اصلی ناموفق بود.' : 'Could not load controller settings.'))
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const submit = async (event) => {
    event.preventDefault(); setError(''); setMessage('')
    const controllerUrl = String(form.controller_url || '').trim().replace(/\/+$/, '')
    const controllerToken = String(form.controller_token || '').trim()
    if (!/^https?:\/\//i.test(controllerUrl)) {
      setError(fa ? 'آدرس سرور اصلی باید با http:// یا https:// شروع شود.' : 'Controller URL must start with http:// or https://.'); return
    }
    if (controllerToken.length < 16) {
      setError(fa ? 'توکن اتصال سرور اصلی جدید را کامل وارد کن.' : 'Enter the complete connection token from the new controller.'); return
    }
    if (!confirmed) {
      setError(fa ? 'تأیید انتقال نود را فعال کن.' : 'Confirm the node migration first.'); return
    }
    setSaving(true)
    try {
      const { data } = await api.post('/settings/node-controller', {
        controller_url: controllerUrl,
        controller_token: controllerToken,
        verify_controller_tls: Boolean(form.verify_controller_tls),
        verify_node_tls: Boolean(form.verify_node_tls),
      })
      setState(current => ({
        ...(current || {}),
        controller_url: data.controller_url,
        node_name: data.node_name,
        node_public_url: data.node_public_url,
        token_configured: true,
        verify_controller_tls: Boolean(form.verify_controller_tls),
        verify_node_tls: Boolean(form.verify_node_tls),
      }))
      setForm(current => ({ ...current, controller_url: data.controller_url, controller_token: '' }))
      setConfirmed(false)
      setMessage(data.cleanup_warning
        ? (fa ? `نود منتقل شد؛ حذف رکورد از کنترلر قبلی کامل نشد: ${data.cleanup_warning}` : `Node moved, but old controller cleanup was incomplete: ${data.cleanup_warning}`)
        : (fa ? 'نود با موفقیت تست، ثبت و به سرور اصلی جدید منتقل شد.' : 'The node was tested, registered and moved to the new controller.'))
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'انتقال نود به سرور اصلی جدید ناموفق بود؛ تنظیم قبلی حفظ شد.' : 'Could not move the node; the previous controller settings were preserved.'))
    } finally { setSaving(false) }
  }

  return <div className="panel-section p-5 space-y-4 xl:col-span-2">
    <div>
      <div className="text-sm font-bold text-ink">{fa ? 'تغییر سرور اصلی نود' : 'Change node controller'}</div>
      <p className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'آدرس و توکن اتصال را از بخش نودهای سرور اصلی جدید بردار. پنل ابتدا ارتباط دوطرفه را تست می‌کند؛ فقط بعد از ثبت موفق، تنظیمات این نود تغییر می‌کند و در صورت خطا کنترلر قبلی دست‌نخورده می‌ماند.' : 'Copy the URL and connection token from the new controller Nodes page. The panel tests both directions first and changes this node only after successful registration; failures keep the previous controller intact.'}</p>
    </div>

    <div className="grid gap-2 sm:grid-cols-3">
      <div className="rounded-xl border border-border bg-surface2 px-3 py-3 sm:col-span-2"><span className="block text-[10px] text-muted">{fa ? 'سرور اصلی فعلی' : 'Current controller'}</span><b dir="ltr" className="mt-1 block truncate text-xs font-data text-ink">{state?.controller_url || '—'}</b></div>
      <div className="rounded-xl border border-border bg-surface2 px-3 py-3"><span className="block text-[10px] text-muted">{fa ? 'وضعیت توکن' : 'Token status'}</span><b className={`mt-1 block text-xs ${state?.token_configured ? 'text-success' : 'text-warning'}`}>{state?.token_configured ? (fa ? 'ثبت شده' : 'Configured') : (fa ? 'ثبت نشده' : 'Missing')}</b></div>
      <div className="rounded-xl border border-border bg-surface2 px-3 py-3"><span className="block text-[10px] text-muted">{fa ? 'نام نود' : 'Node name'}</span><b className="mt-1 block truncate text-xs text-ink">{state?.node_name || '—'}</b></div>
      <div className="rounded-xl border border-border bg-surface2 px-3 py-3 sm:col-span-2"><span className="block text-[10px] text-muted">{fa ? 'آدرس عمومی نود' : 'Node public URL'}</span><b dir="ltr" className="mt-1 block truncate text-xs font-data text-ink">{state?.node_public_url || '—'}</b></div>
    </div>

    {error && <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>}
    {message && <div className={`rounded-lg border px-3 py-2 text-xs ${message.includes('کامل نشد') || message.includes('incomplete') ? 'border-warning/30 bg-warning/10 text-warning' : 'border-success/30 bg-success/10 text-success'}`}>{message}</div>}

    <form onSubmit={submit} className="space-y-3">
      <label><span className="field-label">{fa ? 'آدرس سرور اصلی جدید' : 'New controller URL'}</span><input dir="ltr" type="url" className="field font-data" disabled={loading || saving} value={form.controller_url} onChange={e => setForm(v => ({ ...v, controller_url: e.target.value }))} placeholder="https://panel.example.com" autoComplete="off" required /></label>
      <label><span className="field-label">{fa ? 'توکن اتصال نود از سرور اصلی جدید' : 'Node connection token from new controller'}</span><div className="relative"><input dir="ltr" type={showToken ? 'text' : 'password'} className="field font-data pe-16" disabled={loading || saving} value={form.controller_token} onChange={e => setForm(v => ({ ...v, controller_token: e.target.value }))} placeholder={fa ? 'توکن جدید را وارد کن' : 'Enter the new token'} autoComplete="new-password" required /><button type="button" className="absolute inset-y-1 end-1 rounded-lg px-3 text-[10px] font-bold text-muted hover:text-ink" onClick={() => setShowToken(v => !v)}>{showToken ? (fa ? 'مخفی' : 'Hide') : (fa ? 'نمایش' : 'Show')}</button></div></label>

      <div className="grid gap-2 sm:grid-cols-2">
        <label className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface2 px-4 py-3"><span><b className="block text-xs">{fa ? 'بررسی SSL سرور اصلی' : 'Verify controller SSL'}</b><small className="mt-1 block text-[10px] text-muted">{fa ? 'برای دامنه با گواهی معتبر روشن بماند.' : 'Keep enabled for a trusted HTTPS domain.'}</small></span><button type="button" role="switch" aria-checked={Boolean(form.verify_controller_tls)} onClick={() => setForm(v => ({ ...v, verify_controller_tls: !v.verify_controller_tls }))} className={`modern-toggle ${form.verify_controller_tls ? 'is-on' : ''}`}><span /></button></label>
        <label className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface2 px-4 py-3"><span><b className="block text-xs">{fa ? 'بررسی SSL همین نود' : 'Verify this node SSL'}</b><small className="mt-1 block text-[10px] text-muted">{fa ? 'کنترلر جدید هنگام Health Check گواهی نود را بررسی می‌کند.' : 'The new controller validates this node certificate.'}</small></span><button type="button" role="switch" aria-checked={Boolean(form.verify_node_tls)} onClick={() => setForm(v => ({ ...v, verify_node_tls: !v.verify_node_tls }))} className={`modern-toggle ${form.verify_node_tls ? 'is-on' : ''}`}><span /></button></label>
      </div>

      <label className={`flex cursor-pointer items-start gap-3 rounded-xl border px-4 py-3 ${confirmed ? 'border-warning/40 bg-warning/10' : 'border-border bg-surface2'}`}><input type="checkbox" className="mt-0.5" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} disabled={loading || saving}/><span><b className="block text-xs text-ink">{fa ? 'انتقال این نود را تأیید می‌کنم' : 'I confirm moving this node'}</b><small className="mt-1 block text-[10px] leading-5 text-muted">{fa ? 'پس از موفقیت، کاربران و تنظیمات این نود از کنترلر جدید همگام می‌شوند و رکورد کنترلر قبلی به‌صورت امن پاک می‌شود.' : 'After success, users and settings sync from the new controller and the old controller row is cleaned up safely.'}</small></span></label>
      <button disabled={loading || saving || !confirmed} className="btn-primary w-full">{saving ? (fa ? 'در حال تست و انتقال…' : 'Testing and moving…') : (fa ? 'تست اتصال و تغییر سرور اصلی' : 'Test connection and change controller')}</button>
    </form>
  </div>
}


function NodeSshSettingsCard() {
  const { lang } = useLang()
  const fa = lang === 'fa'
  const [form, setForm] = useState({ host: '', port: 22, username: 'root', password: '', save_password: true, password_saved: false })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/settings/node-ssh').then(({ data }) => setForm(v => ({ ...v, ...data, password: '' })))
      .catch(err => setError(err.response?.data?.detail || (fa ? 'دریافت تنظیمات SSH ناموفق بود.' : 'Could not load SSH settings.')))
      .finally(() => setLoading(false))
  }, [])

  const save = async (event) => {
    event.preventDefault(); setSaving(true); setMessage(''); setError('')
    if (!String(form.host || '').trim() || !String(form.username || '').trim()) {
      setSaving(false); setError(fa ? 'آدرس و نام کاربری SSH الزامی است.' : 'SSH host and username are required.'); return
    }
    try {
      const payload = {
        host: String(form.host || '').trim(),
        port: Number(form.port) || 22,
        username: String(form.username || '').trim(),
        save_password: Boolean(form.save_password),
        clear_password: !form.save_password && Boolean(form.password_saved),
      }
      if (form.password) payload.password = form.password
      const { data } = await api.post('/settings/node-ssh', payload)
      setForm(v => ({ ...v, ...data, password: '' }))
      setMessage(fa ? 'تنظیمات SSH ذخیره و برای ثبت در پنل اصلی ارسال شد.' : 'SSH settings were saved and queued for controller registration.')
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'ذخیره تنظیمات SSH ناموفق بود.' : 'Could not save SSH settings.'))
    } finally { setSaving(false) }
  }

  return <div className="panel-section p-5 space-y-4">
    <div><div className="text-sm font-bold text-ink">{fa ? 'دسترسی SSH نود' : 'Node SSH access'}</div><p className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'این مشخصات برای کنترل و آپدیت اضطراری نود در پنل اصلی ثبت می‌شود. رمز به‌صورت رمزنگاری‌شده نگهداری می‌شود.' : 'These credentials are registered on the controller for emergency control and updates. The password is stored encrypted.'}</p></div>
    {error && <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>}
    {message && <div className="rounded-lg border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">{message}</div>}
    <form onSubmit={save} className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="sm:col-span-2"><span className="field-label">{fa ? 'IP یا دامنه SSH' : 'SSH IP or host'}</span><input dir="ltr" className="field" disabled={loading || saving} value={form.host || ''} onChange={e => setForm(v => ({ ...v, host: e.target.value }))} placeholder="1.2.3.4" /></label>
        <label><span className="field-label">{fa ? 'پورت SSH' : 'SSH port'}</span><input type="number" min="1" max="65535" className="field font-data" disabled={loading || saving} value={form.port || 22} onChange={e => setForm(v => ({ ...v, port: e.target.value }))} /></label>
        <label className="sm:col-span-3"><span className="field-label">{fa ? 'نام کاربری SSH' : 'SSH username'}</span><input dir="ltr" className="field" disabled={loading || saving} value={form.username || ''} onChange={e => setForm(v => ({ ...v, username: e.target.value }))} placeholder="root" /></label>
        <label className="sm:col-span-3"><span className="field-label">{fa ? `رمز SSH${form.password_saved ? ' — رمز قبلی ذخیره است' : ''}` : `SSH password${form.password_saved ? ' — saved' : ''}`}</span><input type="password" dir="ltr" autoComplete="new-password" className="field" disabled={loading || saving} value={form.password || ''} onChange={e => setForm(v => ({ ...v, password: e.target.value }))} placeholder={form.password_saved ? (fa ? 'برای تغییر، رمز جدید را وارد کن' : 'Enter a new password to replace it') : ''} /></label>
      </div>
      <label className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface2 px-4 py-3"><span><b className="block text-xs">{fa ? 'ذخیره امن رمز SSH' : 'Securely save SSH password'}</b><small className="mt-1 block text-[10px] text-muted">{fa ? 'با خاموش‌کردن، رمز قبلی از نود و پنل اصلی حذف می‌شود.' : 'Turning this off removes the saved password from the node and controller.'}</small></span><button type="button" role="switch" aria-checked={Boolean(form.save_password)} onClick={() => setForm(v => ({ ...v, save_password: !v.save_password }))} className={`modern-toggle ${form.save_password ? 'is-on' : ''}`}><span /></button></label>
      <button disabled={loading || saving} className="btn-primary w-full">{saving ? '…' : (fa ? 'ذخیره تنظیمات SSH' : 'Save SSH settings')}</button>
    </form>
  </div>
}


function SystemTimeCard() {
  const { lang } = useLang()
  const fa = lang === 'fa'
  const [data, setData] = useState(null)
  const [form, setForm] = useState({ mode: 'auto', country_code: '', timezone: 'UTC', manual_datetime: '' })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const { data: result } = await api.get('/settings/system-time')
      const countries = Array.isArray(result.countries) ? result.countries : []
      const currentZone = result.configured_timezone || result.timezone || 'UTC'
      const inferredCountry = result.country_code || countries.find(item => (item.timezones || []).includes(currentZone))?.code || ''
      setData(result)
      setForm({
        mode: result.mode === 'manual' ? 'manual' : 'auto',
        country_code: inferredCountry,
        timezone: currentZone,
        manual_datetime: String(result.local_time || '').slice(0, 16),
      })
      setError('')
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'دریافت ساعت سرور ناموفق بود.' : 'Could not load server time.'))
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const displayNames = useMemo(() => {
    try { return new Intl.DisplayNames([fa ? 'fa' : 'en'], { type: 'region' }) }
    catch { return null }
  }, [fa])

  const countries = useMemo(() => {
    const items = Array.isArray(data?.countries) ? data.countries : []
    return [...items].sort((a, b) => {
      const aName = displayNames?.of(a.code) || a.code
      const bName = displayNames?.of(b.code) || b.code
      return aName.localeCompare(bName, fa ? 'fa' : 'en')
    })
  }, [data, displayNames, fa])

  const countryZones = countries.find(item => item.code === form.country_code)?.timezones || []
  const timezoneOptions = form.mode === 'auto' ? countryZones : (data?.timezones || [])

  const selectMode = (mode) => {
    setMessage('')
    setForm(current => {
      if (mode === 'auto') {
        const country = current.country_code || countries.find(item => (item.timezones || []).includes(current.timezone))?.code || countries[0]?.code || ''
        const zones = countries.find(item => item.code === country)?.timezones || []
        return { ...current, mode, country_code: country, timezone: zones.includes(current.timezone) ? current.timezone : (zones[0] || current.timezone) }
      }
      return { ...current, mode }
    })
  }

  const changeCountry = (countryCode) => {
    const zones = countries.find(item => item.code === countryCode)?.timezones || []
    setForm(current => ({ ...current, country_code: countryCode, timezone: zones[0] || current.timezone }))
  }

  const submit = async (event) => {
    event.preventDefault(); setSaving(true); setError(''); setMessage('')
    try {
      const payload = {
        mode: form.mode,
        country_code: form.mode === 'auto' ? form.country_code : '',
        timezone: form.timezone,
        manual_datetime: form.mode === 'manual' ? form.manual_datetime : null,
      }
      const { data: result } = await api.post('/settings/system-time', payload)
      setData(result)
      setForm(current => ({ ...current, manual_datetime: String(result.local_time || '').slice(0, 16) }))
      setMessage(fa ? 'ساعت و منطقه زمانی سرور اعمال شد.' : 'Server time and timezone applied.')
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'اعمال ساعت سرور ناموفق بود.' : 'Could not apply server time.'))
    } finally { setSaving(false) }
  }

  const ntpText = data?.ntp_enabled == null
    ? (fa ? 'نامشخص' : 'Unknown')
    : data.ntp_enabled ? (fa ? 'فعال' : 'Enabled') : (fa ? 'غیرفعال' : 'Disabled')
  const syncText = data?.ntp_synchronized == null
    ? (fa ? 'نامشخص' : 'Unknown')
    : data.ntp_synchronized ? (fa ? 'همگام' : 'Synchronized') : (fa ? 'در انتظار همگام‌سازی' : 'Waiting for sync')

  return <div className="system-time-card panel-section p-4 sm:p-5 space-y-4">
    <div>
      <div className="text-sm font-bold text-ink">{fa ? 'ساعت و منطقه زمانی سرور' : 'Server time & timezone'}</div>
      <p className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'در حالت خودکار، کشور را انتخاب کن تا منطقه زمانی اعمال و همگام‌سازی اینترنتی ساعت فعال شود. در حالت دستی، منطقه زمانی و تاریخ/ساعت دقیق را خودت تعیین می‌کنی.' : 'Automatic mode applies a country timezone and enables internet time sync. Manual mode lets you set the timezone and exact date/time.'}</p>
    </div>
    {error && <div className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>}
    {message && <div className="rounded-lg border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">{message}</div>}
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
      <div className="rounded-xl border border-border bg-surface2 px-3 py-2"><span className="block text-[10px] text-muted">{fa ? 'زمان فعلی' : 'Current time'}</span><b className="mt-1 block text-xs font-data text-ink" dir="ltr">{data?.local_time ? new Date(data.local_time).toLocaleString(fa ? 'fa-IR' : 'en-US') : '—'}</b></div>
      <div className="rounded-xl border border-border bg-surface2 px-3 py-2"><span className="block text-[10px] text-muted">{fa ? 'منطقه زمانی' : 'Timezone'}</span><b className="mt-1 block truncate text-xs font-data text-ink" dir="ltr">{data?.timezone || '—'}</b></div>
      <div className="rounded-xl border border-border bg-surface2 px-3 py-2"><span className="block text-[10px] text-muted">{fa ? 'همگام‌سازی ساعت' : 'Clock sync'}</span><b className="mt-1 block text-xs text-ink">{ntpText} · {syncText}</b></div>
    </div>
    <form onSubmit={submit} className="space-y-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <button type="button" onClick={() => selectMode('auto')} className={`rounded-xl border px-3 py-3 text-xs font-extrabold transition ${form.mode === 'auto' ? 'border-signal/50 bg-signal/10 text-signal' : 'border-border bg-surface2 text-muted'}`}>{fa ? 'خودکار بر اساس کشور' : 'Automatic by country'}</button>
        <button type="button" onClick={() => selectMode('manual')} className={`rounded-xl border px-3 py-3 text-xs font-extrabold transition ${form.mode === 'manual' ? 'border-signal/50 bg-signal/10 text-signal' : 'border-border bg-surface2 text-muted'}`}>{fa ? 'تنظیم دستی' : 'Manual setup'}</button>
      </div>
      {form.mode === 'auto' && <ModernSelect
        label={fa ? 'کشور' : 'Country'}
        value={form.country_code}
        onChange={changeCountry}
        options={countries.map(item => ({
          value: item.code,
          label: displayNames?.of(item.code) || item.code,
          meta: item.code,
          flag: countryFlagFromCode(item.code),
          searchText: `${displayNames?.of(item.code) || item.code} ${item.code}`,
        }))}
        placeholder={fa ? 'انتخاب کشور' : 'Select country'}
        disabled={loading || saving}
        searchPlaceholder={fa ? 'جستجوی کشور…' : 'Search country…'}
        emptyText={fa ? 'کشوری پیدا نشد.' : 'No country found.'}
        renderValue={(item) => <span className="modern-select-country"><span className="modern-select-flag" aria-hidden="true">{item.flag}</span><span className="truncate">{item.label}</span></span>}
        renderOption={(item) => <span className="modern-select-country"><span className="modern-select-flag" aria-hidden="true">{item.flag}</span><span className="min-w-0"><span className="block truncate">{item.label}</span><span className="modern-select-meta">{item.meta}</span></span></span>}
      />}
      <ModernSelect
        label={fa ? 'منطقه زمانی' : 'Timezone'}
        value={form.timezone}
        onChange={(value) => setForm(current => ({ ...current, timezone: value }))}
        options={timezoneOptions.map(zone => ({ value: zone, label: zone, searchText: zone }))}
        placeholder={fa ? 'انتخاب منطقه زمانی' : 'Select timezone'}
        disabled={loading || saving || !timezoneOptions.length}
        dir={fa ? 'rtl' : 'ltr'}
        displayDir="ltr"
        searchPlaceholder={fa ? 'جستجوی منطقه زمانی…' : 'Search timezone…'}
        emptyText={fa ? 'منطقه زمانی پیدا نشد.' : 'No timezone found.'}
        renderValue={(item) => <span className="truncate font-data">{item.label}</span>}
        renderOption={(item) => <span className="truncate font-data">{item.label}</span>}
      />
      {form.mode === 'manual' && <label><span className="field-label">{fa ? 'تاریخ و ساعت دستی' : 'Manual date & time'}</span><input type="datetime-local" className="field font-data" dir="ltr" disabled={loading || saving} value={form.manual_datetime} onChange={e => setForm(current => ({ ...current, manual_datetime: e.target.value }))} required /></label>}
      <p className="text-[10px] leading-5 text-muted">{form.mode === 'auto' ? (fa ? 'NTP روشن می‌شود و ساعت پس از چند لحظه از اینترنت همگام خواهد شد.' : 'NTP will be enabled and the clock will synchronize shortly.') : (fa ? 'NTP خاموش می‌شود و ساعت واردشده مستقیماً روی سرور اعمال می‌شود.' : 'NTP will be disabled and the entered time will be applied directly.')}</p>
      <button disabled={loading || saving || !form.timezone || (form.mode === 'auto' && !form.country_code)} className="btn-primary w-full">{saving ? '…' : (fa ? 'اعمال تنظیمات ساعت' : 'Apply time settings')}</button>
    </form>
  </div>
}

function SettingsInner() {
  const { dir, t, lang } = useLang()
  const nodeMode = getServerRole() === 'node'

  if (nodeMode) {
    return (
      <div dir={dir} className={`space-y-6 ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
        <header><h1 className="page-heading">{lang === 'fa' ? 'تنظیمات نود' : 'Node settings'}</h1><p className="page-subtitle">{lang === 'fa' ? 'سرور اصلی، دسترسی SSH، پورت وب و ساعت همین نود را مدیریت کن.' : 'Manage this node controller, SSH access, web port and clock.'}</p></header>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
          <NodeControllerCard />
          <NodeSshSettingsCard />
          <PanelPortCard />
          <SystemTimeCard />
        </div>
      </div>
    )
  }

  const tabs = [
    {
      id: 'general',
      label: t('settingsTabGeneral'),
      icon: 'settings',
      content: (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
          <SiteTitlesCard />
          <LoginFooterNoteCard />
        </div>
      ),
    },
    {
      id: 'time-region',
      label: dir === 'rtl' ? 'زمان و منطقه' : 'Time & region',
      icon: 'clock',
      content: (
        <div className="mx-auto w-full max-w-5xl">
          <SystemTimeCard />
        </div>
      ),
    },
    {
      id: 'branding',
      label: dir === 'rtl' ? 'ظاهر و برندینگ' : 'Branding',
      icon: 'image',
      content: <BrandingCard />,
    },
    {
      id: 'panel-access',
      label: t('settingsTabPanelAccess'),
      icon: 'globe',
      content: (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
          <DomainCard />
          <PanelPortCard />
        </div>
      ),
    },
    {
      id: 'vpn-security',
      label: t('settingsTabVpnSecurity'),
      icon: 'shield',
      content: (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
          <VpnDomainCard />
          <Ikev2SslCard />
          <PortFallbackCard />
        </div>
      ),
    },
    {
      id: 'subscription',
      label: t('settingsTabSubscription'),
      icon: 'license',
      content: (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
          <SubDomainCard />
          <XraySubDomainCard />
          <XrayConnectionHostsCard />
          <SubDomainPortCard />
          <SubDownloadLinkCard />
        </div>
      ),
    },
    {
      id: 'client-apps',
      label: t('settingsTabClientApps'),
      icon: 'server',
      content: (
        <div className="max-w-5xl">
          <PlatformAppsCard />
        </div>
      ),
    },
  ]

  return (
    <div dir={dir} className={`space-y-6 ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
      <header><h1 className="page-heading">{t('settingsTitle')}</h1><p className="page-subtitle">{t('settingsPageSubtitle')}</p></header>
      <SectionTabs
        tabs={tabs}
        param="section"
        storageKey="vpnpanel_settings_section"
        ariaLabel={t('settingsTabsAria')}
        dir={dir}
      />
    </div>
  )
}

export default function Settings() {
  return <SettingsInner />
}
