import React, { useCallback, useEffect, useRef, useState } from 'react'
import api from '../api'
import ProtocolBadge from '../components/ProtocolBadge.jsx'
import { useUI } from '../components/ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { Icon } from '../components/icons.jsx'
import { formatBytes as fmtBytes } from '../utils/formatBytes.js'
import { hasProtocol } from '../permissions.js'

const POLL_MS = 2000

function sessionKey(session) {
  return session.session_key || `${session.server_id || 'local'}:${session.id}`
}

function sessionActionPath(session, action) {
  const serverId = String(session.server_id || 'local')
  if (serverId.startsWith('node:')) {
    const nodeId = serverId.split(':')[1]
    return `/nodes/${nodeId}/sessions/${session.id}/${action}`
  }
  return `/users/sessions/${session.id}/${action}`
}

function ServerBadge({ session }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-data ${session.server_local ? 'border-success/30 text-success' : 'border-accent/30 text-accent'}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${session.server_local ? 'bg-success' : 'bg-accent'}`} />
      {session.server_name || (session.server_local ? 'سرور اصلی' : 'Node')}
    </span>
  )
}

function presenceMeta(state, lang) {
  const value = String(state || 'active').toLowerCase()
  if (value === 'idle') return { cls: 'presence-idle', label: lang === 'en' ? 'Connected · idle' : 'متصل · بیکار' }
  if (value === 'probing') return { cls: 'presence-probing', label: lang === 'en' ? 'Checking connection' : 'در حال بررسی اتصال' }
  return { cls: 'presence-active', label: lang === 'en' ? 'Active' : 'فعال' }
}

function PresenceBadge({ state, compact = false }) {
  const { lang } = useLang()
  const meta = presenceMeta(state, lang)
  return (
    <span className={`presence-badge ${meta.cls} ${compact ? 'is-compact' : ''}`} title={meta.label}>
      <span className="presence-badge__dot" />
      {!compact && <span>{meta.label}</span>}
    </span>
  )
}

function groupPresenceState(group) {
  const states = (group.sessions || []).map((item) => String(item.presence_state || 'active'))
  if (states.includes('active')) return 'active'
  if (states.includes('idle')) return 'idle'
  return 'probing'
}

function PlatformCell({ session }) {
  const { t } = useLang()
  const PLATFORM_LABELS = {
    win: t('platformWindows'),
    windows: t('platformWindows'),
    mac: t('platformMac'),
    macos: t('platformMac'),
    linux: t('platformLinux'),
    ios: t('platformIos'),
    android: t('platformAndroid'),
    openbsd: 'OpenBSD',
    freebsd: 'FreeBSD',
    netbsd: 'NetBSD',
    solaris: 'Solaris',
    'win-wfp': t('platformWindows'),
    mikrotik: t('platformMikrotik'),
  }
  // پلتفرم واقعی (نه حدسی): برای OpenVPN همیشه در دسترس است. برای L2TP
  // بهترین‌تلاش (مثلاً تشخیص روتر MikroTik) از روی اطلاعاتی است که خودِ
  // کلاینت هنگام برقراری تونل اعلام می‌کند - ممکن است خیلی از کلاینت‌های
  // L2TP دیگر (ویندوز/iOS/اندروید) آن را نفرستند. PPTP هیچ‌وقت این را ندارد.
  if (session.platform) {
    const label = PLATFORM_LABELS[session.platform.toLowerCase()] || session.platform
    return (
      <div className="flex flex-col">
        <span className="text-ink">{label}</span>
        {session.client_info && (
          <span className="text-[11px] text-muted font-data">{session.client_info}</span>
        )}
      </div>
    )
  }
  return <span className="text-muted text-xs">{t('stateUnknown')}</span>
}

function SessionActions({ session, onDisconnectSession, onBanSession, disconnectingSessionId, banningSessionId }) {
  const { t, lang } = useLang()
  const actionLabel = lang === 'en' ? 'Block internet' : 'قطع اینترنت'
  return (
    <div className="flex items-center justify-center gap-1">
      <button
        onClick={() => onDisconnectSession(session)}
        disabled={!session.ip_address || disconnectingSessionId === sessionKey(session) || banningSessionId === sessionKey(session)}
        className="btn-secondary !px-2.5 !py-1.5 text-[10px] disabled:opacity-50"
        title={session.ip_address ? actionLabel : t('disconnectIpUnknownTitle')}
      >
        {actionLabel}
      </button>
      <button
        onClick={() => onBanSession(session)}
        disabled={!session.ip_address || disconnectingSessionId === sessionKey(session) || banningSessionId === sessionKey(session)}
        className="btn-danger !px-2.5 !py-1.5 text-[10px] disabled:opacity-50"
        title={session.ip_address ? `${t('banIpTitlePrefix')} ${session.ip_address} ${t('banIpTitleSuffix')}` : t('disconnectIpUnknownTitle')}
      >
        {t('btnBanIp')}
      </button>
    </div>
  )
}

function UserGroupRow({ group, onDisconnectSession, onBanSession, disconnectingSessionId, banningSessionId }) {
  const { t, lang } = useLang()
  const [open, setOpen] = useState(false)
  const single = group.sessions.length === 1
  const locale = lang === 'en' ? 'en-US' : 'fa-IR'

  return (
    <>
      <tr
        className="border-t border-border hover:bg-surface2/50 cursor-pointer"
        onClick={() => !single && setOpen((o) => !o)}
      >
        <td className="px-4 py-3">
          <div className="flex items-center justify-center gap-2">
            {!single && (
              <span className={`text-muted text-xs transition-transform ${open ? 'rotate-90' : ''}`}>◀</span>
            )}
            <PresenceBadge state={groupPresenceState(group)} compact />
            <span className="font-data">{group.username}</span>
            {!single && (
              <span className="text-[11px] text-muted font-data bg-surface2 border border-border rounded-full px-2 py-0.5">
                {group.session_count} {t('concurrentConnSuffix')}
              </span>
            )}
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="flex gap-1 flex-wrap justify-center">
            {[...new Set(group.sessions.map((s) => s.protocol))].map((p) => (
              <ProtocolBadge key={p} protocol={p} />
            ))}
          </div>
        </td>
        <td className="px-4 py-3 text-center">
          {single ? <ServerBadge session={group.sessions[0]} /> : (
            <div className="flex flex-wrap justify-center gap-1">
              {[...new Map(group.sessions.map((item) => [item.server_id, item])).values()].map((item) => <ServerBadge key={item.server_id} session={item} />)}
            </div>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-center">
          {single ? <PlatformCell session={group.sessions[0]} /> : <span className="text-muted">{t('stateUnknown')}</span>}
        </td>
        <td className="px-4 py-3 font-data text-xs text-center">
          {single ? (group.sessions[0].ip_address || '—') : '—'}
        </td>
        <td className="px-4 py-3 font-data text-xs text-center">
          {single ? group.sessions[0].connect_time_display || new Date(group.sessions[0].connect_time).toLocaleString(locale) : '—'}
        </td>
        <td className="px-4 py-3 text-center">
          <div className="font-data text-xs text-ink">{fmtBytes(group.used_bytes || 0)}</div>
          <div className="mt-0.5 text-[10px] text-muted">{group.quota_bytes > 0 ? `${fmtBytes(group.quota_bytes)} سقف` : (lang === 'en' ? 'Unlimited' : 'نامحدود')}</div>
        </td>
        <td className="px-4 py-3 text-center" onClick={(e) => e.stopPropagation()}>
          {single && (
            <SessionActions
              session={group.sessions[0]}
              onDisconnectSession={(s) => onDisconnectSession(group, s)}
              onBanSession={(s) => onBanSession(group, s)}
              disconnectingSessionId={disconnectingSessionId}
              banningSessionId={banningSessionId}
            />
          )}
        </td>
      </tr>
      {!single && open && group.sessions.filter((s) => hasProtocol(s.protocol)).map((s, idx) => (
        <tr key={sessionKey(s)} className="border-t border-border bg-surface2/30">
          <td className="px-4 py-2.5 pr-10 text-xs text-muted text-center">{t('connectionLabel')} {idx + 1}</td>
          <td className="px-4 py-2.5 text-center">
            <div className="flex items-center justify-center gap-1.5">
              <ProtocolBadge protocol={s.protocol} />
              <PresenceBadge state={s.presence_state} />
              {s.internet_blocked && <span className="xray-blocked-badge">{lang === 'en' ? 'No internet' : 'بدون اینترنت'}</span>}
              {s.device_limit_blocked && <span className="xray-device-limit-badge">{lang === 'en' ? 'Device limit' : 'سقف دستگاه'}</span>}
            </div>
          </td>
          <td className="px-4 py-2.5 text-center"><ServerBadge session={s} /></td>
          <td className="px-4 py-2.5 text-xs text-center"><PlatformCell session={s} /></td>
          <td className="px-4 py-2.5 font-data text-xs text-center">{s.ip_address || '—'}</td>
          <td className="px-4 py-2.5 font-data text-xs text-center">{s.connect_time_display || new Date(s.connect_time).toLocaleString(locale)}</td>
          <td className="px-4 py-2.5 font-data text-xs text-center">{fmtBytes(s.session_bytes || 0)}</td>
          <td className="px-4 py-2.5 text-center">
            <SessionActions
              session={s}
              onDisconnectSession={(sess) => onDisconnectSession(group, sess)}
              onBanSession={(sess) => onBanSession(group, sess)}
              disconnectingSessionId={disconnectingSessionId}
              banningSessionId={banningSessionId}
            />
          </td>
        </tr>
      ))}
    </>
  )
}

function MobileUserCard({ group, onDisconnectSession, onBanSession, disconnectingSessionId, banningSessionId }) {
  const { t, lang } = useLang()
  const locale = lang === 'en' ? 'en-US' : 'fa-IR'
  const protocols = [...new Set(group.sessions.map((session) => session.protocol).filter(hasProtocol))]

  return (
    <article className="online-mobile-card">
      <div className="online-mobile-card__header">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <PresenceBadge state={groupPresenceState(group)} compact />
            <strong className="truncate font-data text-sm text-ink">{group.username}</strong>
          </div>
          <div className="mt-1 text-[10px] text-muted font-data">
            {group.session_count} {t('concurrentConnSuffix')} · {fmtBytes(group.used_bytes || 0)}
            <span className="mx-1">/</span>
            {group.quota_bytes > 0 ? fmtBytes(group.quota_bytes) : (lang === 'en' ? 'Unlimited' : 'نامحدود')}
          </div>
        </div>
        <div className="flex max-w-[48%] flex-wrap justify-end gap-1">
          {protocols.map((protocol) => <ProtocolBadge key={protocol} protocol={protocol} />)}
        </div>
      </div>

      <div className="online-mobile-card__sessions">
        {group.sessions.filter((session) => hasProtocol(session.protocol)).map((session, index) => (
          <section key={sessionKey(session)} className="online-mobile-session">
            <div className="online-mobile-session__top">
              <div className="flex min-w-0 items-center gap-1.5">
                <span className="text-[10px] text-muted">{t('connectionLabel')} {index + 1}</span>
                <ProtocolBadge protocol={session.protocol} />
                <ServerBadge session={session} />
                <PresenceBadge state={session.presence_state} />
                {session.internet_blocked && <span className="xray-blocked-badge">{lang === 'en' ? 'No internet' : 'بدون اینترنت'}</span>}
                {session.device_limit_blocked && <span className="xray-device-limit-badge">{lang === 'en' ? 'Limit' : 'سقف'}</span>}
              </div>
              <span className="shrink-0 text-[10px] text-muted font-data">{fmtBytes(session.session_bytes || 0)}</span>
            </div>

            <div className="online-mobile-session__facts">
              <div>
                <span>{t('colIp')}</span>
                <b dir="ltr" className="font-data">{session.ip_address || '—'}</b>
              </div>
              <div>
                <span>{t('colPlatform')}</span>
                <b><PlatformCell session={session} /></b>
              </div>
              <div className="col-span-2">
                <span>{t('colConnectTime')}</span>
                <b className="font-data">{session.connect_time_display || new Date(session.connect_time).toLocaleString(locale)}</b>
              </div>
            </div>

            <SessionActions
              session={session}
              onDisconnectSession={(item) => onDisconnectSession(group, item)}
              onBanSession={(item) => onBanSession(group, item)}
              disconnectingSessionId={disconnectingSessionId}
              banningSessionId={banningSessionId}
            />
          </section>
        ))}
      </div>
    </article>
  )
}

function OnlineUsersInner() {
  const { confirm, withBusy, notify } = useUI()
  const { lang, dir, t } = useLang()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [disconnectingSessionId, setDisconnectingSessionId] = useState(null)
  const [banningSessionId, setBanningSessionId] = useState(null)
  const inFlight = useRef(false)
  const mounted = useRef(true)
  const timerRef = useRef(null)
  const abortRef = useRef(null)
  const rowsSignature = useRef('')
  const locale = lang === 'en' ? 'en-US' : 'fa-IR'

  const load = useCallback(async () => {
    if (inFlight.current || document.visibilityState === 'hidden') return
    inFlight.current = true
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    try {
      const { data } = await api.get('/dashboard/online-users', { signal: controller.signal, skipInstantCache: true })
      if (!mounted.current) return
      // Avoid a full React tree update when the backend returned the exact same
      // presence/usage snapshot. This matters on older mobile browsers.
      const signature = JSON.stringify(data)
      if (signature !== rowsSignature.current) {
        rowsSignature.current = signature
        setRows(data)
      }
      setLastUpdated(new Date())
    } catch (error) {
      if (error?.code !== 'ERR_CANCELED' && error?.name !== 'CanceledError') throw error
    } finally {
      inFlight.current = false
      if (mounted.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    mounted.current = true
    const schedule = () => {
      window.clearTimeout(timerRef.current)
      if (!mounted.current || document.visibilityState === 'hidden') return
      timerRef.current = window.setTimeout(async () => {
        try { await load() } catch { /* keep the lightweight live loop alive */ }
        schedule()
      }, POLL_MS)
    }
    load().finally(schedule)

    const onVisible = () => {
      window.clearTimeout(timerRef.current)
      if (document.visibilityState === 'visible') load().finally(schedule)
    }
    document.addEventListener('visibilitychange', onVisible)

    return () => {
      mounted.current = false
      window.clearTimeout(timerRef.current)
      abortRef.current?.abort()
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [load])

  const removeSessionOptimistically = (sessionId) => {
    setRows((current) => current
      .map((group) => {
        const sessions = group.sessions.filter((item) => item.id !== sessionId)
        return { ...group, sessions, session_count: sessions.length }
      })
      .filter((group) => group.sessions.length > 0))
  }

  const disconnectSession = async (group, session) => {
    if (!session.ip_address) {
      notify({ type: 'error', message: lang === 'en' ? 'The public IP of this connection is unknown.' : 'آی‌پی پابلیک این اتصال مشخص نیست.' })
      return
    }
    const label = `${group.username} (${session.ip_address})`
    const ok = await confirm({
      title: lang === 'en' ? 'Block internet on all protocols' : 'قطع اینترنت در همه پروتکل‌ها',
      message: lang === 'en'
        ? `Block public IP ${session.ip_address} for all nine VPN protocols? Every active VPN session from this IP will be disconnected and reconnects through any protocol will be blocked until you restore it.`
        : `اینترنت آی‌پی پابلیک ${session.ip_address} در هر ۹ پروتکل قطع شود؟ همه اتصال‌های VPN این آی‌پی قطع می‌شوند و تا زمان وصل‌کردن از بخش «اینترنت قطع‌شده‌ها»، با هیچ پروتکلی دوباره وصل نمی‌شود.`,
      confirmLabel: lang === 'en' ? 'Block all protocols' : 'قطع همه پروتکل‌ها',
      danger: true,
    })
    if (!ok) return
    setDisconnectingSessionId(sessionKey(session))
    try {
      await withBusy(
        lang === 'en' ? `Blocking ${session.ip_address} on all protocols...` : `در حال قطع اینترنت ${session.ip_address} در همه پروتکل‌ها...`,
        () => api.post(sessionActionPath(session, 'internet-block')),
      )
      setRows((current) => current
        .map((row) => {
          const sessions = row.sessions.filter((item) => item.ip_address !== session.ip_address)
          return { ...row, sessions, session_count: sessions.length }
        })
        .filter((row) => row.sessions.length > 0))
      notify({
        type: 'success',
        message: lang === 'en'
          ? `${label} was blocked across all VPN protocols.`
          : `اینترنت ${label} در همه پروتکل‌ها قطع شد.`,
      })
      window.setTimeout(load, 500)
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || (lang === 'en' ? 'Internet block failed.' : 'قطع اینترنت ناموفق بود.') })
    } finally {
      setDisconnectingSessionId(null)
    }
  }

  const banSession = async (group, session) => {
    if (!session.ip_address) return
    const ok = await confirm({
      title: t('banIpSessionTitle'),
      message: `${t('banIpSessionMessagePrefix')}${session.ip_address}${t('banIpSessionMessageMiddle')} ${group.username}${t('banIpSessionMessageSuffix')}`,
      confirmLabel: t('banIpSessionConfirmBtn'),
      danger: true,
    })
    if (!ok) return
    setBanningSessionId(sessionKey(session))
    try {
      await withBusy(`${t('banningIpSessionBusyPrefix')} ${session.ip_address}...`, () => api.post(sessionActionPath(session, 'ban-ip')))
      notify({ type: 'success', message: `${t('ipBannedSessionSuccessPrefix')}${session.ip_address}${t('ipBannedSessionSuccessSuffix')}` })
      load()
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || t('banIpSessionError') })
    } finally {
      setBanningSessionId(null)
    }
  }

  return (
    <div dir={dir} className={`space-y-5 ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="page-heading">{t('onlineUsersTitle')}</h1><p className="page-subtitle">{t('onlineUsersSubtitle')}</p></div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-[10px] text-muted font-data"><span className="h-2 w-2 rounded-full bg-success signal-dot" />{t('autoRefreshLabel')}{lastUpdated && <span>· {lastUpdated.toLocaleTimeString(locale)}</span>}</div>
      </header>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="app-card p-4"><div className="text-[10px] text-muted">{t('onlineUsersTitle')}</div><div className="mt-1 text-2xl font-semibold font-data">{rows.length}</div></div>
        <div className="app-card p-4"><div className="text-[10px] text-muted">{t('activeConnectionsLabel')}</div><div className="mt-1 text-2xl font-semibold font-data">{rows.reduce((sum,row)=>sum+(row.session_count||row.sessions?.length||0),0)}</div></div>
        <div className="app-card col-span-2 p-4 sm:col-span-1"><div className="text-[10px] text-muted">{t('liveDataLabel')}</div><div className="mt-2 flex items-center gap-2 text-xs text-success"><Icon name="activity" size={16}/>{t('systemOperational')}</div></div>
      </div>

      <section className="panel-section">
        <div className="online-mobile-list md:hidden">
          {loading && <div className="py-8 text-center text-sm text-muted">{t('loadingOnline')}</div>}
          {!loading && rows.length === 0 && <div className="py-8 text-center text-sm text-muted">{t('noOnlineUsers')}</div>}
          {rows.map((group) => (
            <MobileUserCard
              key={group.username}
              group={group}
              onDisconnectSession={disconnectSession}
              onBanSession={banSession}
              disconnectingSessionId={disconnectingSessionId}
              banningSessionId={banningSessionId}
            />
          ))}
        </div>
        <div className="hidden overflow-x-auto md:block">
          <table className="w-full text-sm">
            <thead className="bg-surface2 text-muted text-xs">
              <tr>
                <th className="text-center px-4 py-3 font-data">{t('colUser')}</th>
                <th className="text-center px-4 py-3 font-data">{t('colProtocol')}</th>
                <th className="text-center px-4 py-3 font-data">{lang === 'en' ? 'Server' : 'سرور'}</th>
                <th className="text-center px-4 py-3 font-data">{t('colPlatform')}</th>
                <th className="text-center px-4 py-3 font-data">{t('colIp')}</th>
                <th className="text-center px-4 py-3 font-data">{t('colConnectTime')}</th>
                <th className="text-center px-4 py-3 font-data">{lang === 'en' ? 'Usage' : 'مصرف'}</th>
                <th className="text-center px-4 py-3 font-data">{t('colActions')}</th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={8} className="text-center py-8 text-muted">{t('loadingOnline')}</td></tr>}
              {!loading && rows.length === 0 && (
                <tr><td colSpan={8} className="text-center py-8 text-muted">{t('noOnlineUsers')}</td></tr>
              )}
              {rows.map((group) => (
                <UserGroupRow
                  key={group.username}
                  group={group}
                  onDisconnectSession={disconnectSession}
                  onBanSession={banSession}
                  disconnectingSessionId={disconnectingSessionId}
                  banningSessionId={banningSessionId}
                />
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}

export default function OnlineUsers() {
  return <OnlineUsersInner />
}
