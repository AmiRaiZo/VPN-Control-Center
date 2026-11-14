import React, { useEffect, useMemo, useRef, useState } from 'react'
import { usePanelNavigate } from '../navigation.js'
import api from '../api'
import { getRole, hasSection } from '../permissions.js'
import { useLang } from '../i18n/dashboardLang.jsx'
import { useTheme } from '../theme/themeContext.jsx'
import { Icon } from '../components/icons.jsx'
import ProtocolBadge from '../components/ProtocolBadge.jsx'
import { formatRemainingText } from '../utils/formatRemaining.js'
import BandwidthChart from '../components/BandwidthChart.jsx'
import { formatBytes } from '../utils/formatBytes.js'

const GB = 1073741824
const DASHBOARD_CACHE_KEY = 'vpnpanel_dashboard_cache_v2'
const EMPTY_SUMMARY = {
  total_users: 0, active_users: 0, online_users: 0, online_connections: 0, total_used_bytes: 0,
  admin_max_users: 0, admin_used_users: 0,
  system: { cpu_percent: 0, ram_percent: 0, disk_percent: 0, uptime_seconds: 0, bandwidth_rx_mbps: 0, bandwidth_tx_mbps: 0 },
}

function readDashboardCache() {
  try {
    const parsed = JSON.parse(localStorage.getItem(DASHBOARD_CACHE_KEY) || 'null')
    if (!parsed || typeof parsed !== 'object') return {}
    // Use the last successful snapshot immediately, but discard very old data.
    if (Date.now() - Number(parsed.saved_at || 0) > 24 * 60 * 60 * 1000) return {}
    return parsed
  } catch { return {} }
}

function writeDashboardCache(patch) {
  try {
    const previous = readDashboardCache()
    localStorage.setItem(DASHBOARD_CACHE_KEY, JSON.stringify({ ...previous, ...patch, saved_at: Date.now() }))
  } catch { /* private mode / quota */ }
}

function formatUptime(seconds, t) {
  const total = Math.max(0, Number(seconds || 0))
  const days = Math.floor(total / 86400)
  const hours = Math.floor((total % 86400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (days > 0) return `${days}${t('dayShort')} ${hours}${t('hourShort')} ${minutes}${t('minuteShort')}`
  return `${hours}${t('hourShort')} ${minutes}${t('minuteShort')}`
}

function formatDuration(value, t) {
  if (!value) return '—'
  const start = new Date(value).getTime()
  if (!Number.isFinite(start)) return '—'
  const seconds = Math.max(0, Math.floor((Date.now() - start) / 1000))
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return hours ? `${hours}${t('hourShort')} ${minutes}${t('minuteShort')}` : `${minutes}${t('minuteShort')}`
}

function MetricCard({ icon, label, value, detail, detailTone = 'success' }) {
  return (
    <article className="app-card animate-enter min-h-[108px] p-4 sm:p-5">
      <div className="flex items-center gap-4">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-signal/10 text-signal"><Icon name={icon} size={24} strokeWidth={1.9}/></span>
        <div className="min-w-0">
          <div className="metric-label truncate">{label}</div>
          <div className="metric-value truncate">{value}</div>
          {detail && <div className={`mt-1 flex items-center gap-1 text-[10px] font-semibold ${detailTone === 'danger' ? 'text-danger' : detailTone === 'warning' ? 'text-amber' : detailTone === 'neutral' ? 'text-muted' : 'text-success'}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{detail}</div>}
        </div>
      </div>
    </article>
  )
}

function SectionCard({ title, action, children, className = '' }) {
  return (
    <section className={`panel-section ${className}`}>
      <header className="panel-section-header"><h2 className="section-heading">{title}</h2>{action}</header>
      {children}
    </section>
  )
}

function Gauge({ label, value, sub, icon }) {
  const safe = Math.max(0, Math.min(100, Number(value || 0)))
  const danger = safe >= 90
  const warning = safe >= 75
  const color = danger ? 'rgb(var(--color-danger))' : warning ? 'rgb(var(--color-amber))' : 'rgb(var(--color-signal))'
  return (
    <div className="flex flex-col items-center justify-center px-2 py-4 text-center">
      <div className="relative h-[116px] w-[116px]">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="49" fill="none" stroke="rgb(var(--color-border) / .65)" strokeWidth="9" />
          <circle cx="60" cy="60" r="49" fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={`${safe * 3.078} 308`} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <Icon name={icon} size={16} className="mb-1 text-muted" />
          <div className="text-xl font-semibold font-data">{Math.round(safe)}%</div>
        </div>
      </div>
      <div className="mt-1 text-xs font-semibold text-ink">{label}</div>
      <div className="mt-1 text-[10px] text-muted font-data">{sub}</div>
    </div>
  )
}

function Status({ active, label, tone }) {
  const resolved = tone || (active ? 'success' : 'neutral')
  const pillClass = resolved === 'danger' ? 'status-danger' : resolved === 'warning' ? 'status-warning' : resolved === 'success' ? 'status-success' : 'status-neutral'
  const dotClass = resolved === 'danger' ? 'bg-danger' : resolved === 'warning' ? 'bg-amber' : resolved === 'success' ? 'bg-success' : 'bg-muted'
  return <span className={`status-pill ${pillClass}`}><span className={`h-1.5 w-1.5 rounded-full ${dotClass}`} />{label}</span>
}

function LicensePanel({ info, summary, t, onOpen }) {
  const [ipVisible, setIpVisible] = useState(false)
  if (!info || (info.status === 'unconfigured' && !info.configured)) return null
  const active = !info.locked && ['active', 'expiring_soon'].includes(info.status)
  const days = typeof info.days_remaining === 'number' ? info.days_remaining : null
  const total = Number(summary?.admin_max_users || 0)
  const used = Number(summary?.admin_used_users || summary?.total_users || 0)
  const userPercent = total > 0 ? Math.min(100, (used / total) * 100) : 0
  return (
    <SectionCard title={t('licenseOverviewTitle')} action={<button onClick={onOpen} className="btn-ghost !py-1.5 text-xs text-signal">{t('viewDetails')}<Icon name="arrowRight" size={14}/></button>}>
      <div className="p-4 sm:p-5">
        <div className="grid grid-cols-[auto_1fr] gap-4">
          <div className={`flex h-16 w-16 items-center justify-center rounded-2xl border ${active ? 'border-signal/35 bg-signal/10 text-signal' : 'border-danger/35 bg-danger/10 text-danger'}`}><Icon name="shield" size={32}/></div>
          <div className="grid min-w-0 grid-cols-2 gap-x-4 gap-y-3 text-xs">
            <div><div className="text-[10px] text-muted">{t('statusLabel')}</div><div className={`mt-1 font-bold ${active ? 'text-success' : 'text-danger'}`}>{active ? t('stateActive') : t('stateInactive')}</div></div>
            <div><div className="text-[10px] text-muted">{t('timeRemaining')}</div><div className="mt-1 font-data font-semibold">{days === null ? '—' : formatRemainingText(days, info.hours_remaining, info.minutes_remaining, t)}</div></div>
            <div><div className="text-[10px] text-muted">{t('expiryDate')}</div><div className="mt-1 truncate font-data font-semibold">{info.expires_at_jalali_display || '—'}</div></div>
            <div><div className="text-[10px] text-muted">{t('purchasedDuration')}</div><div className="mt-1 font-data font-semibold">{info.total_days_purchased ?? '—'} {info.total_days_purchased != null ? t('purchasedDurationUnit') : ''}</div></div>
          </div>
        </div>
        <div className="mt-4 flex items-center justify-between gap-3 rounded-xl border border-border bg-surface2 px-3.5 py-3">
          <div className="min-w-0">
            <div className="text-[10px] text-muted">{t('licenseServerIp')}</div>
            <div dir="ltr" className={`mt-1 truncate font-data text-xs font-bold text-ink transition ${ipVisible ? '' : 'select-none blur-[5px]'}`}>{info.activated_server_ip || '—'}</div>
          </div>
          <button type="button" onClick={() => setIpVisible(v => !v)} className="icon-button !h-8 !w-8 shrink-0" title={ipVisible ? t('hideIp') : t('showIp')} aria-label={ipVisible ? t('hideIp') : t('showIp')}>
            <Icon name={ipVisible ? 'eyeOff' : 'eye'} size={15}/>
          </button>
        </div>
        {total > 0 && <div className="mt-5 border-t border-border pt-4"><div className="mb-2 flex items-center justify-between text-[10px]"><span className="text-muted">{t('userCapacity')}</span><span className="font-data text-ink">{used} / {total}</span></div><div className="h-2 overflow-hidden rounded-full bg-surface2"><div className="h-full rounded-full bg-signal" style={{ width: `${userPercent}%` }} /></div></div>}
      </div>
    </SectionCard>
  )
}


function formatAdminRemaining(totalSeconds, t) {
  if (totalSeconds == null) return '—'
  const safe = Math.max(0, Math.floor(Number(totalSeconds) || 0))
  const days = Math.floor(safe / 86400)
  const hours = Math.floor((safe % 86400) / 3600)
  const minutes = Math.floor((safe % 3600) / 60)
  if (days > 0) return `${days} ${t('purchasedDurationUnit')} ${hours}${t('hourShort')} ${minutes}${t('minuteShort')}`
  if (hours > 0) return `${hours}${t('hourShort')} ${minutes}${t('minuteShort')}`
  return `${minutes}${t('minuteShort')}`
}

function SubAdminPlanPanel({ summary, t }) {
  const [remainingSeconds, setRemainingSeconds] = useState(() => summary?.admin_subscription_remaining_seconds ?? null)
  useEffect(() => {
    const initial = summary?.admin_subscription_remaining_seconds ?? null
    setRemainingSeconds(initial)
    if (initial == null) return undefined
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') setRemainingSeconds(value => value == null ? null : Math.max(0, value - 30))
    }, 30000)
    return () => window.clearInterval(timer)
  }, [summary?.admin_subscription_remaining_seconds])
  const maxUsers = summary?.admin_max_users
  const usedUsers = Number(summary?.admin_used_users || 0)
  const maxQuota = summary?.admin_max_total_quota_gb
  const usedQuota = Number(summary?.admin_used_total_quota_gb || 0)
  const locked = Boolean(summary?.admin_license_locked || summary?.admin_subscription_expired)
  const userPercent = maxUsers > 0 ? Math.min(100, (usedUsers / maxUsers) * 100) : 0
  const quotaPercent = maxQuota > 0 ? Math.min(100, (usedQuota / maxQuota) * 100) : 0
  return (
    <SectionCard title={t('adminPlanTitle') || 'مشخصات ادمین'}>
      <div className="p-4 sm:p-5">
        <div className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-border bg-surface2 px-3.5 py-3">
          <div>
            <div className="text-[10px] text-muted">{t('statusLabel')}</div>
            <div className={`mt-1 text-sm font-extrabold ${locked ? 'text-danger' : 'text-success'}`}>{locked ? t('stateInactive') : t('stateActive')}</div>
          </div>
          <span className={`flex h-10 w-10 items-center justify-center rounded-xl border ${locked ? 'border-danger/30 bg-danger/10 text-danger' : 'border-success/30 bg-success/10 text-success'}`}><Icon name={locked ? 'lock' : 'shield'} size={20}/></span>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-border bg-surface2 p-3">
            <div className="text-[10px] text-muted">{t('adminMaxUsersLabel') || 'حداکثر تعداد ساخت کاربر'}</div>
            <div className="mt-1 font-data text-base font-extrabold text-ink">{maxUsers == null ? '∞' : `${usedUsers} / ${maxUsers}`}</div>
          </div>
          <div className="rounded-xl border border-border bg-surface2 p-3">
            <div className="text-[10px] text-muted">{t('adminQuotaLabel') || 'حجم'}</div>
            <div className="mt-1 font-data text-base font-extrabold text-ink">{maxQuota == null ? '∞' : `${usedQuota.toFixed(2)} / ${Number(maxQuota).toFixed(2)} GB`}</div>
          </div>
          <div className="rounded-xl border border-border bg-surface2 p-3">
            <div className="text-[10px] text-muted">{t('timeRemaining')}</div>
            <div className={`mt-1 font-data text-base font-extrabold ${remainingSeconds === 0 ? 'text-danger' : 'text-ink'}`}>{formatAdminRemaining(remainingSeconds, t)}</div>
          </div>
        </div>
        {maxUsers > 0 && <div className="mt-4"><div className="mb-1.5 flex justify-between text-[10px] text-muted"><span>{t('userCapacity')}</span><span className="font-data">{Math.round(userPercent)}%</span></div><div className="h-2 rounded-full bg-surface2"><div className="h-full rounded-full bg-signal" style={{width:`${userPercent}%`}}/></div></div>}
        {maxQuota > 0 && <div className="mt-3"><div className="mb-1.5 flex justify-between text-[10px] text-muted"><span>{t('adminQuotaLabel') || 'حجم'}</span><span className="font-data">{Math.round(quotaPercent)}%</span></div><div className="h-2 rounded-full bg-surface2"><div className="h-full rounded-full bg-info" style={{width:`${quotaPercent}%`}}/></div></div>}
      </div>
    </SectionCard>
  )
}

export default function Dashboard() {
  const navigate = usePanelNavigate()
  const { dir, t } = useLang()
  const { resolvedTheme } = useTheme()
  const cached = useMemo(() => readDashboardCache(), [])
  const [summary, setSummary] = useState(() => cached.summary || EMPTY_SUMMARY)
  const [license, setLicense] = useState(() => cached.license || null)
  const [protocolServers, setProtocolServers] = useState(() => {
    if (Array.isArray(cached.protocolServers)) return cached.protocolServers
    if (Array.isArray(cached.protocols) && cached.protocols.length) {
      return [{ id: 'local', name: 'سرور اصلی', local: true, node: false, status: 'online', protocols: cached.protocols }]
    }
    return []
  })
  const [selectedProtocolServerId, setSelectedProtocolServerId] = useState(() => cached.selectedProtocolServerId || '')
  const [online, setOnline] = useState(() => cached.online || [])
  const [onlineLoaded, setOnlineLoaded] = useState(false)
  const [banned, setBanned] = useState(() => cached.banned || [])
  const [history, setHistory] = useState([])
  const [error, setError] = useState('')
  const summaryTimer = useRef(null)
  const secondaryTimer = useRef(null)
  const canSettings = hasSection('settings')
  const canOnline = hasSection('online')
  const isSuperadmin = getRole() === 'superadmin'

  const loadSummary = async () => {
    if (document.visibilityState === 'hidden') return
    try {
      const { data } = await api.get('/dashboard/summary')
      setSummary(data)
      writeDashboardCache({ summary: data })
      setError('')
      setHistory(prev => {
        const point = {
          time: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }),
          rx: Number(data.system?.bandwidth_rx_mbps || 0),
          tx: Number(data.system?.bandwidth_tx_mbps || 0),
        }
        if (!prev.length) {
          const prior = { ...point, time: new Date(Date.now() - 8000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) }
          return [prior, point]
        }
        return [...prev, point].slice(-24)
      })
    } catch (e) {
      setError(e.response?.data?.detail || t('loadingStatusError'))
    }
  }

  const loadSecondary = () => {
    if (document.visibilityState === 'hidden') return
    // These requests are deliberately independent. A slow license-server or
    // protocol health probe must never hold the rest of the dashboard hostage.
    if (isSuperadmin) api.get('/license/status').then(({ data }) => { setLicense(data); writeDashboardCache({ license: data }) }).catch(() => {})
    if (canSettings) api.get('/dashboard/protocol-overview').then(({ data }) => {
      const servers = Array.isArray(data?.servers) ? data.servers.map(server => ({
        ...server,
        protocols: (server.protocols || []).filter(item => item.key !== 'wireguard'),
      })) : []
      setProtocolServers(servers)
      setSelectedProtocolServerId(current => {
        const stillExists = servers.some(server => server.id === current && (server.protocols || []).length)
        const next = stillExists ? current : (data?.preferred_server_id || servers.find(server => (server.protocols || []).length)?.id || servers[0]?.id || '')
        writeDashboardCache({ protocolServers: servers, selectedProtocolServerId: next })
        return next
      })
    }).catch(() => {})
    if (canOnline) {
      api.get('/dashboard/online-users').then(({ data }) => { const value = data || []; setOnline(value); setOnlineLoaded(true); writeDashboardCache({ online: value }) }).catch(() => {})
      api.get('/ip-bans').then(({ data }) => { const value = data || []; setBanned(value); writeDashboardCache({ banned: value }) }).catch(() => {})
    }
  }

  useEffect(() => {
    loadSummary()
    loadSecondary()
  }, [])

  const allOnlineSessions = useMemo(() => online.flatMap(user => (user.sessions || []).map(session => ({ ...session, username: user.username }))), [online])
  const flattenedSessions = useMemo(() => [...allOnlineSessions].sort((a, b) => new Date(b.connect_time) - new Date(a.connect_time)).slice(0, 5), [allOnlineSessions])
  // The summary endpoint used to count only controller-local ConnectionLog rows,
  // while this exact list already included remote node snapshots.  Prefer the
  // loaded exact sessions so the metric and Recent Connections can never
  // contradict each other; fall back to the backend aggregate during startup.
  const liveConnectionCount = onlineLoaded
    ? allOnlineSessions.length
    : Number(summary.online_connections ?? summary.online_users ?? 0)
  const banStats = useMemo(() => {
    const now = Date.now()
    const countSince = days => banned.filter(item => {
      const created = new Date(item.created_at).getTime()
      return Number.isFinite(created) && now - created <= days * 86400000
    }).length
    return { total: banned.length, day: countSince(1), week: countSince(7), month: countSince(30) }
  }, [banned])

  const system = summary.system || {}
  const litePerformance = typeof document !== 'undefined' && document.documentElement.dataset.performance === 'lite'
  // Low-memory desktop browsers were incorrectly forced into the two-number
  // mobile fallback. Keep the lightweight fallback only on narrow screens; a
  // desktop dashboard always receives the actual chart.
  const narrowDashboard = typeof window !== 'undefined' && window.matchMedia('(max-width: 767px)').matches
  const liteBandwidthOnly = litePerformance && narrowDashboard
  const chartGrid = resolvedTheme === 'light' ? '#d9dce1' : '#292c31'
  const chartText = resolvedTheme === 'light' ? '#666c75' : '#9399a2'
  const tooltipBg = resolvedTheme === 'light' ? '#ffffff' : '#111315'
  const selectedProtocolServer = protocolServers.find(server => server.id === selectedProtocolServerId)
    || protocolServers.find(server => (server.protocols || []).length)
    || protocolServers[0]
  const protocols = selectedProtocolServer?.protocols || []
  const activeProtocolCount = protocols.filter(item => ['active', 'activating', 'degraded'].includes(item.state)).length

  return (
    <div dir={dir} className="space-y-4 sm:space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="page-heading">{t('dashTitle')}</h1><p className="page-subtitle">{t('dashSubtitle')}</p></div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-[10px] text-muted"><span className="h-2 w-2 rounded-full bg-success signal-dot" />{t('liveDataLabel')}</div>
      </header>
      {error && <div className="rounded-xl border border-amber/25 bg-amber/5 px-4 py-2 text-[10px] text-amber">{error}</div>}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <MetricCard icon="users" label={t('statTotalUsers')} value={summary.total_users.toLocaleString()} detail={`${summary.active_users} ${t('statActiveUsers')}`} />
        <MetricCard icon="activity" label={t('activeConnectionsLabel')} value={liveConnectionCount.toLocaleString()} detail={t('liveNowLabel')} />
        <MetricCard icon="globe" label={t('statTotalTraffic')} value={formatBytes(summary.total_used_bytes, 2)} detail={t('accountedTrafficLabel')} detailTone="neutral" />
        <MetricCard icon="server" label={t('statServerLoad')} value={`${Math.round(system.cpu_percent || 0)}%`} detail={(system.cpu_percent || 0) < 75 ? t('serverHealthyLabel') : t('serverAttentionLabel')} detailTone={(system.cpu_percent || 0) < 75 ? 'success' : 'warning'} />
        <div className="col-span-2 lg:col-span-1"><MetricCard icon="clock" label={t('uptimeLabel')} value={formatUptime(system.uptime_seconds, t)} detail={t('systemOperational')} /></div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[.93fr_1.17fr]">
        {canSettings && <SectionCard title={t('protocolsOverviewTitle')} action={<div className="flex items-center gap-2">
          {protocolServers.length > 1 && <select value={selectedProtocolServer?.id || ''} onChange={(event) => { setSelectedProtocolServerId(event.target.value); writeDashboardCache({ selectedProtocolServerId: event.target.value }) }} className="max-w-[180px] rounded-lg border border-border bg-surface2 px-2.5 py-1.5 text-[10px] font-semibold text-ink outline-none focus:border-signal" aria-label={t('protocolServerLabel')}>
            {protocolServers.map(server => <option key={server.id} value={server.id}>{server.name}{server.status === 'offline' ? ` — ${t('nodeOfflineLabel')}` : ''}</option>)}
          </select>}
          <button onClick={() => navigate('/protocols')} className="btn-ghost !py-1.5 text-xs text-signal">{t('viewAll')}<Icon name="arrowRight" size={14}/></button>
        </div>}>
          <div className="overflow-x-auto">
            <table className="w-full !min-w-[560px] text-xs">
              <thead><tr><th className="px-4 py-3 text-start">{t('protocolLabel')}</th><th className="px-4 py-3 text-start">{t('statusLabel')}</th><th className="px-4 py-3 text-center">{t('activeConnectionsLabel')}</th><th className="px-4 py-3 text-start">{t('listenerLabel')}</th><th className="px-4 py-3 text-end">{t('actionsLabel')}</th></tr></thead>
              <tbody>{protocols.slice(0, 7).map(item => {
                const serverOffline = selectedProtocolServer?.status === 'offline'
                const active = !serverOffline && ['active', 'activating', 'degraded'].includes(item.state)
                const failed = !serverOffline && item.state === 'failed'
                const statusLabel = serverOffline ? t('nodeOfflineLabel') : active ? t('stateActive') : failed ? t('stateFailed') : item.installed ? t('stateInactive') : t('notInstalledLabel')
                const tone = serverOffline ? 'neutral' : failed ? 'danger' : item.state === 'degraded' || item.state === 'activating' ? 'warning' : active ? 'success' : 'neutral'
                return <tr key={item.key}><td className="px-4 py-3.5"><div className="flex items-center gap-2.5"><span className="flex h-8 w-8 items-center justify-center rounded-lg bg-signal/10 text-signal"><Icon name={item.key === 'openvpn' || item.key === 'openconnect' ? 'globe' : item.key === 'vmess' || item.key === 'vless' ? 'activity' : 'shield'} size={16}/></span><div><div className="font-bold text-ink">{item.label}</div><div className="mt-0.5 text-[9px] text-muted">{item.backend || '—'}</div></div></div></td><td className="px-4 py-3.5"><Status active={active} tone={tone} label={statusLabel} /></td><td className="px-4 py-3.5 text-center font-data">{item.inbounds ?? 0}</td><td className="max-w-[130px] truncate px-4 py-3.5 font-data text-[10px] text-muted" title={item.listen}>{item.listen || '—'}</td><td className="px-4 py-3.5 text-end"><button onClick={() => navigate('/protocols')} className="icon-button !h-8 !w-8" aria-label={t('navProtocols')}><Icon name="settings" size={14}/></button></td></tr>
              })}</tbody>
            </table>
            {!protocols.length && <div className="p-8 text-center text-xs text-muted">{selectedProtocolServer?.node ? t('nodeProtocolStatusUnavailable') : t('loadingStatus')}</div>}
          </div>
          <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3 text-[10px] text-muted"><span><span className="font-data text-ink">{activeProtocolCount}</span> {t('activeProtocolsLabel')}</span><span className="truncate font-semibold text-ink">{selectedProtocolServer?.name || '—'}</span></div>
        </SectionCard>}

        <SectionCard title={t('trafficOverviewTitle')} action={<div className="flex items-center gap-3 text-[10px]"><span className="flex items-center gap-1.5 text-muted"><span className="h-2 w-2 rounded-full bg-signal" />RX</span><span className="flex items-center gap-1.5 text-muted"><span className="h-2 w-2 rounded-full bg-info" />TX</span></div>} className={!canSettings ? 'xl:col-span-2' : ''}>
          <div className="px-2 pb-2 pt-4 sm:px-4">
            {liteBandwidthOnly ? (
              <div className="dashboard-lite-bandwidth" aria-label={t('trafficOverviewTitle')}>
                <div><span>RX</span><b>{Number(system.bandwidth_rx_mbps || 0).toFixed(2)} Mbps</b></div>
                <div><span>TX</span><b>{Number(system.bandwidth_tx_mbps || 0).toFixed(2)} Mbps</b></div>
              </div>
            ) : (
              <BandwidthChart data={history} gridColor={chartGrid} textColor={chartText} tooltipBackground={tooltipBg} />
            )}
            <div className="px-2 pb-2 text-center text-[10px] text-muted">{t('liveBandwidthNote')}</div>
          </div>
        </SectionCard>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.05fr_.95fr_.92fr]">
        {canOnline && <SectionCard title={t('latestConnectionsTitle')} action={<button onClick={() => navigate('/online')} className="btn-secondary !px-3 !py-1.5 text-[10px]">{t('viewAll')}</button>} className="dashboard-online-card">
          {flattenedSessions.length ? <div className="overflow-x-auto"><table className="w-full !min-w-[510px] text-xs"><thead><tr><th className="px-4 py-3 text-start">{t('colUser')}</th><th className="px-4 py-3 text-start">{t('protocolLabel')}</th><th className="px-4 py-3 text-start">IP</th><th className="px-4 py-3 text-start">{t('durationLabel')}</th><th className="px-4 py-3 text-end">{t('statusLabel')}</th></tr></thead><tbody>{flattenedSessions.map(session => <tr key={session.session_key || `${session.server_id || 'local'}:${session.id}`}><td className="px-4 py-3 font-semibold">{session.username}</td><td className="px-4 py-3"><ProtocolBadge protocol={session.protocol}/></td><td className="px-4 py-3 font-data text-[10px] text-muted">{session.ip_address || '—'}</td><td className="px-4 py-3 font-data text-[10px]">{formatDuration(session.connect_time, t)}</td><td className="px-4 py-3 text-end"><Status active label={t('stateActive')}/></td></tr>)}</tbody></table></div> : <div className="m-4 rounded-xl border border-border bg-surface2 px-4 py-8 text-center"><Icon name="online" size={28} className="mx-auto text-muted"/><div className="mt-3 text-xs font-semibold">{t('noOnlineUsers')}</div></div>}
        </SectionCard>}

        <SectionCard title={t('serverResourcesHeading')} className={!canOnline ? 'xl:col-span-2' : ''}>
          <div className="grid grid-cols-3 divide-x divide-border rtl:divide-x-reverse">
            <Gauge label="CPU" value={system.cpu_percent} sub={t('currentUsageLabel')} icon="cpu" />
            <Gauge label="RAM" value={system.ram_percent} sub={`${system.ram_used_gb ?? 0}/${system.ram_total_gb ?? 0} GB`} icon="memory" />
            <Gauge label={t('diskLabel')} value={system.disk_percent} sub={`${system.disk_used_gb ?? 0}/${system.disk_total_gb ?? 0} GB`} icon="disk" />
          </div>
          {canSettings && <div className="border-t border-border p-3"><button onClick={() => navigate('/settings')} className="btn-secondary w-full !py-2 text-xs">{t('viewSystemDetails')}<Icon name="arrowRight" size={14}/></button></div>}
        </SectionCard>

        {isSuperadmin ? <LicensePanel info={license} summary={summary} t={t} onOpen={() => navigate('/license')} /> : <SubAdminPlanPanel summary={summary} t={t} />}
      </div>

      {canOnline && <SectionCard title={t('bannedOverviewTitle')} action={<button onClick={() => navigate('/banned-ips')} className="btn-secondary !px-3 !py-1.5 text-[10px]">{t('manageBannedIps')}<Icon name="arrowRight" size={13}/></button>}>
        <div className="grid grid-cols-2 divide-border md:grid-cols-4 md:divide-x rtl:md:divide-x-reverse">
          {[
            ['ban', t('totalBannedIpsLabel'), banStats.total],
            ['clock', t('last24HoursLabel'), banStats.day],
            ['chart', t('last7DaysLabel'), banStats.week],
            ['activity', t('last30DaysLabel'), banStats.month],
          ].map(([icon, label, value], index) => <div key={label} className={`flex items-center gap-3 px-5 py-4 ${index < 2 ? 'max-md:border-b max-md:border-border' : ''}`}><span className="flex h-10 w-10 items-center justify-center rounded-xl bg-signal/10 text-signal"><Icon name={icon} size={20}/></span><div><div className="text-[10px] text-muted">{label}</div><div className="mt-1 text-xl font-semibold font-data">{value}</div></div></div>)}
        </div>
      </SectionCard>}
    </div>
  )
}

function DashboardSkeleton() {
  return <div className="space-y-5"><div className="h-12 w-64 rounded-xl skeleton"/><div className="grid grid-cols-2 gap-3 lg:grid-cols-5">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-[108px] rounded-[15px] skeleton"/>)}</div><div className="grid gap-4 xl:grid-cols-2"><div className="h-[420px] rounded-[15px] skeleton"/><div className="h-[420px] rounded-[15px] skeleton"/></div></div>
}
