import React, { useEffect, useMemo, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { usePanelNavigate } from '../navigation.js'
import { hasSection, hasPermission, getRole } from '../permissions.js'
import { clearSession, getRemoteNodeName, getServerRole, isRemoteControlSession, setServerRole } from '../session'
import api from '../api'
import { useUI } from './ui/UIProvider.jsx'
import { consumeUpdateSuccess, getDismissedVersion, setDismissedVersion } from '../updateNotice.js'
import { useLang, LangToggle } from '../i18n/dashboardLang.jsx'
import { ThemeToggle } from '../theme/themeContext.jsx'
import { Icon } from './icons.jsx'
import { useBranding } from '../branding.jsx'
import ParticleBackground from './ParticleBackground.jsx'

const groups = [
  { key: 'navManagement', items: [
    { to: '/dashboard', labelKey: 'navDashboard', icon: 'dashboard', section: 'dashboard' },
    { to: '/users', labelKey: 'navUsers', icon: 'users', section: 'users' },
    { to: '/online', labelKey: 'navOnline', icon: 'online', section: 'online' },
    { to: '/internet-blocks', labelKey: 'navInternetBlocks', icon: 'ban', permission: 'internet_blocks:view' },
    { to: '/banned-ips', labelKey: 'navBannedIps', icon: 'ban', section: 'bans' },
    { to: '/admins', labelKey: 'navAdmins', icon: 'admins', superadminOnly: true },
    { to: '/nodes', labelKey: 'navNodes', icon: 'server', section: 'nodes' },
  ]},
  { key: 'navConfiguration', items: [
    { to: '/license', labelKey: 'navLicense', icon: 'license', section: 'license' },
    { to: '/protocols', labelKey: 'navProtocols', icon: 'protocols', section: 'protocols' },
    { to: '/settings', labelKey: 'navSettings', icon: 'settings', section: 'settings' },
  ]},
  { key: 'navSystem', items: [
    { to: '/telegram-bot', labelKey: 'navTelegramBot', icon: 'telegram' },
    { to: '/backup', labelKey: 'navBackup', icon: 'backup', superadminOnly: true },
  ]},
]

export default function Layout() {
  const navigate = usePanelNavigate()
  const location = useLocation()
  const { notify } = useUI()
  const { lang, setLang, dir, t } = useLang()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('vpnpanel_sidebar_collapsed') === '1')
  const [newVersionNotice, setNewVersionNotice] = useState(null)
  const [adminInfo, setAdminInfo] = useState(null)
  const [profileOpen, setProfileOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef = useRef(null)
  const profileRef = useRef(null)
  const meSignatureRef = useRef('')
  const isSuperadmin = getRole() === 'superadmin'
  const remoteControl = isRemoteControlSession()
  const remoteNodeName = getRemoteNodeName()
  const [serverRole, setServerRoleState] = useState(() => getServerRole())
  const updateTarget = '/backup?view=updates'
  const litePerformance = typeof document !== 'undefined' && document.documentElement.dataset.performance === 'lite'

  const visibleGroups = useMemo(() => groups.map(group => ({
    ...group,
    items: group.items.filter(item => {
      // The dedicated node panel is intentionally minimal. User lifecycle,
      // bans, protocol control, licensing, backups and multi-node management
      // live on the controller. A node exposes only the current account and
      // its local access settings.
      if (serverRole === 'node' && !remoteControl && !['/admins', '/settings'].includes(item.to)) return false
      if (item.to === '/license' && !isSuperadmin) return false
      return item.authenticated || (item.superadminOnly ? isSuperadmin : (item.permission ? hasPermission(item.permission) : hasSection(item.section)))
    })
  })).filter(group => group.items.length), [isSuperadmin, remoteControl, serverRole])

  const allItems = useMemo(() => visibleGroups.flatMap(group => group.items), [visibleGroups])
  const currentItem = allItems.find(item => item.to === location.pathname) || allItems[0]
  const searchResults = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return allItems
    return allItems.filter(item => t(item.labelKey).toLowerCase().includes(q) || item.to.includes(q))
  }, [search, allItems, t])

  useEffect(() => { localStorage.setItem('vpnpanel_sidebar_collapsed', collapsed ? '1' : '0') }, [collapsed])

  useEffect(() => {
    const onKey = (event) => {
      if (document.body.classList.contains('vpnpanel-blocking-modal-open')) {
        // Keep layout shortcuts disabled, but allow inputs inside the portal to
        // receive typing, Backspace, Delete and arrow keys normally.
        return
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        searchRef.current?.focus()
        setSearchOpen(true)
      }
      if (event.key === 'Escape') {
        setSearchOpen(false)
        setProfileOpen(false)
        setMobileOpen(false)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])


  useEffect(() => {
    if (document.visibilityState === 'hidden') return undefined
    const allowed = new Set(allItems.map((item) => item.to))
    const routeRequests = {
      '/dashboard': ['/dashboard/summary', '/dashboard/protocol-overview', '/dashboard/online-users'],
      '/users': ['/users/server-targets', '/users'],
      '/online': ['/dashboard/online-users'],
      '/internet-blocks': ['/internet-blocks'],
      '/banned-ips': ['/ip-bans'],
      '/admins': ['/admins', '/admins/server-targets'],
      '/nodes': ['/nodes'],
      '/license': ['/license/status?include_queue_details=true', '/license/reserved'],
      '/protocols': ['/nodes/protocol-targets'],
      '/settings': ['/settings/panel-port', '/settings/site-titles', '/settings/domain', '/settings/vpn-domain'],
    }
    const orderedRoutes = [location.pathname, ...Array.from(allowed).filter((path) => path !== location.pathname)]
    const requests = Array.from(new Set(orderedRoutes.flatMap((path) => routeRequests[path] || [])))
    if (!requests.length) return undefined

    let cancelled = false
    let idleId = null
    let timerId = null
    let index = 0
    const runNext = () => {
      if (cancelled || document.visibilityState === 'hidden' || index >= requests.length) return
      const url = requests[index]
      index += 1
      api.get(url, { prefetchOnly: true }).catch(() => {}).finally(() => {
        if (!cancelled) timerId = window.setTimeout(runNext, 90)
      })
    }
    const start = () => {
      if (!cancelled) runNext()
    }
    if (typeof window.requestIdleCallback === 'function') idleId = window.requestIdleCallback(start, { timeout: 700 })
    else timerId = window.setTimeout(start, 250)

    return () => {
      cancelled = true
      if (idleId !== null && typeof window.cancelIdleCallback === 'function') window.cancelIdleCallback(idleId)
      if (timerId !== null) window.clearTimeout(timerId)
    }
  }, [allItems, location.pathname])

  useEffect(() => {
    const onOutside = (event) => {
      if (profileRef.current && !profileRef.current.contains(event.target)) setProfileOpen(false)
    }
    document.addEventListener('mousedown', onOutside)
    return () => document.removeEventListener('mousedown', onOutside)
  }, [])

  useEffect(() => {
    let dead = false
    const refreshMe = () => {
      if (document.visibilityState === 'hidden') return Promise.resolve()
      return api.get('/auth/me').then(({ data }) => {
        if (dead) return
        const reportedRole = data.server_role || 'main'
        // The controller can choose whether this server renders the dedicated
        // node panel or the full local panel. The backend-reported role is the
        // source of truth for both direct login and remote handoff.
        const nextRole = reportedRole
        const signature = JSON.stringify({ ...data, server_role: nextRole })
        if (signature !== meSignatureRef.current) {
          meSignatureRef.current = signature
          setAdminInfo({ ...data, server_role: nextRole })
          setServerRole(nextRole)
          setServerRoleState(nextRole)
        }
        if (data.internal_license_required) navigate('/admin-license', { replace: true })
        else if (nextRole === 'node' && !remoteControl && window.location.pathname === '/nodes') navigate('/admins', { replace: true })
      }).catch(() => {})
    }
    refreshMe()
    return () => { dead = true }
  }, [navigate, remoteControl])

  useEffect(() => {
    const pending = consumeUpdateSuccess()
    if (pending) {
      const parts = [t('updateCompletedMsg')]
      if (pending.version) parts.push(`${t('updateAvailablePrefix')} ${pending.version}`)
      if (pending.notes) parts.push(pending.notes)
      notify?.({ type: 'success', message: parts.join(' — '), duration: 8000, dir })
    }
  }, [])

  useEffect(() => {
    if (!isSuperadmin || (serverRole === 'node' && !remoteControl) || location.pathname === '/backup') return
    let cancelled = false
    api.get('/backup/update/check').then(({ data }) => {
      if (!cancelled && data.update_available && data.latest_version && data.latest_version !== getDismissedVersion()) {
        setNewVersionNotice({ version: data.latest_version, notes: data.notes })
      }
    }).catch(() => {})
    return () => { cancelled = true }
  }, [isSuperadmin, serverRole, location.pathname])

  useEffect(() => {
    if (serverRole === 'node' && !remoteControl) return undefined
    let cancelled = false
    api.get('/license/status').then(({ data }) => {
      if (cancelled) return
      if (data.locked) return navigate('/license-locked', { replace: true })
      if (data.switch_notice) {
        notify?.({ type: 'info', message: data.switch_notice, duration: 9000, dir })
        api.post('/license/switch-notice/ack').catch(() => {})
      }
    }).catch(() => {})
    return () => { cancelled = true }
  }, [navigate, serverRole])

  useEffect(() => {
    setMobileOpen(false)
    setSearchOpen(false)
    setSearch('')
  }, [location.pathname, location.search])

  useEffect(() => {
    if (!mobileOpen) return undefined
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const onResize = () => {
      if (window.innerWidth >= 1024) setMobileOpen(false)
    }
    window.addEventListener('resize', onResize)
    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('resize', onResize)
    }
  }, [mobileOpen])

  const logout = () => { clearSession(); navigate('/login') }
  const sidebarWidth = collapsed ? 'lg:w-[82px]' : 'lg:w-[230px]'
  const username = adminInfo?.username || (isSuperadmin ? t('adminRoleSuper') : t('adminRoleDelegated'))

  const goToSearchResult = (to) => {
    navigate(to)
    setSearch('')
    setSearchOpen(false)
  }

  return (
    <div dir={dir} className="app-shell relative flex min-h-screen overflow-x-hidden">
      {!litePerformance && <ParticleBackground density={0.000045}/>}
      <header className="fixed inset-x-0 top-0 z-30 flex h-16 items-center justify-between border-b border-border bg-bg/95 px-4 backdrop-blur lg:hidden">
        <Brand compact={false} />
        <button className="icon-button" onClick={() => setMobileOpen(true)} aria-label={t('openMenuLabel')}><Icon name="menu" /></button>
      </header>

      {mobileOpen && <button className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden" onClick={() => setMobileOpen(false)} aria-label={t('closeMenuLabel')} />}

      <aside data-mobile-open={mobileOpen ? 'true' : 'false'} className={`app-sidebar fixed inset-y-0 start-0 z-50 flex h-[100dvh] w-[286px] max-w-[88vw] flex-col border-e border-border bg-surface/95 shadow-2xl backdrop-blur-xl transition-[width,transform] duration-200 ${sidebarWidth} lg:translate-x-0`}>
        <div className={`flex h-[72px] shrink-0 items-center border-b border-border ${collapsed ? 'lg:justify-center lg:px-3' : 'justify-between px-4'}`}>
          <Brand compact={collapsed} />
          <button className="text-muted hover:text-ink lg:hidden" onClick={() => setMobileOpen(false)} aria-label={t('closeMenuLabel')}><Icon name="close" /></button>
        </div>

        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
          {visibleGroups.map(group => (
            <section key={group.key}>
              {!collapsed && <div className="mb-2 px-3 text-[9px] font-bold uppercase tracking-[.18em] text-muted">{t(group.key)}</div>}
              <div className="space-y-1">
                {group.items.map(item => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    title={collapsed ? t(item.labelKey) : undefined}
                    onClick={() => setMobileOpen(false)}
                    className={({ isActive }) => `group relative flex min-h-[42px] items-center gap-3 rounded-lg border px-3 text-[13px] font-semibold transition-colors ${collapsed ? 'lg:justify-center lg:px-2' : ''} ${isActive ? 'border-signal/45 bg-signal/12 text-ink' : 'border-transparent text-muted hover:bg-surface2 hover:text-ink'}`}
                  >
                    {({ isActive }) => <>
                      {isActive && <span className="absolute inset-y-2 start-0 w-[3px] rounded-full bg-signal" />}
                      <Icon name={item.icon} size={18} className={isActive ? 'text-signal' : 'text-muted group-hover:text-signal'} />
                      <span className={collapsed ? 'lg:hidden' : ''}>{t(item.labelKey)}</span>
                      {!collapsed && <Icon name={dir === 'rtl' ? 'arrowLeft' : 'arrowRight'} size={13} className="ms-auto opacity-0 transition-opacity group-hover:opacity-60" />}
                    </>}
                  </NavLink>
                ))}
              </div>
            </section>
          ))}
        </nav>

        <div className="shrink-0 border-t border-border p-3">
          {!collapsed && (
            <div className="mb-2 rounded-xl border border-border bg-surface2 p-3">
              <div className="flex items-center gap-3">
                <span className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-success/20 bg-success/10 text-success">
                  <Icon name="shield" size={17}/><span className="absolute -bottom-0.5 -end-0.5 h-2.5 w-2.5 rounded-full bg-success ring-2 ring-surface2" />
                </span>
                <div className="min-w-0"><div className="truncate text-xs font-bold text-ink">{username}</div><div className="mt-0.5 text-[10px] text-muted">{t('systemOperational')}</div></div>
              </div>
            </div>
          )}
          <button onClick={logout} title={collapsed ? t('logoutBtn') : undefined} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] text-muted hover:bg-danger/10 hover:text-danger ${collapsed ? 'lg:justify-center' : ''}`}><Icon name="logout" size={18}/><span className={collapsed ? 'lg:hidden' : ''}>{t('logoutBtn')}</span></button>
        </div>
      </aside>

      <div className={`app-main min-w-0 flex-1 transition-[margin] duration-200 ${collapsed ? 'lg:ms-[82px]' : 'lg:ms-[230px]'}`}>
        <header className="sticky top-0 z-20 hidden h-[72px] items-center justify-between border-b border-border bg-bg/92 px-5 backdrop-blur lg:flex xl:px-7">
          <div className="flex min-w-0 items-center gap-4">
            <button className="icon-button" onClick={() => setCollapsed(v => !v)} aria-label={t('openMenuLabel')}><Icon name="menu" /></button>
            <div className="min-w-0">
              <div className="truncate text-base font-extrabold text-ink">{currentItem ? t(currentItem.labelKey) : 'VPN Panel'}</div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <div className="relative hidden xl:block">
              <div className="relative w-[280px]">
                <Icon name="search" size={16} className="pointer-events-none absolute start-3 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  ref={searchRef}
                  value={search}
                  onChange={(event) => { setSearch(event.target.value); setSearchOpen(true) }}
                  onFocus={() => setSearchOpen(true)}
                  placeholder={t('globalSearchPlaceholder')}
                  className="h-10 w-full rounded-lg border border-border bg-surface ps-10 pe-14 text-xs text-ink placeholder:text-muted/70 focus:border-signal"
                />
                <kbd className="pointer-events-none absolute end-2.5 top-1/2 -translate-y-1/2 rounded border border-border bg-surface2 px-1.5 py-1 text-[9px] text-muted">Ctrl K</kbd>
              </div>
              {searchOpen && (
                <div className="absolute end-0 top-[46px] z-50 w-[320px] overflow-hidden rounded-xl border border-border bg-surface p-1.5 shadow-2xl">
                  {searchResults.length ? searchResults.map(item => (
                    <button key={item.to} onMouseDown={(e) => e.preventDefault()} onClick={() => goToSearchResult(item.to)} className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-start text-xs text-muted hover:bg-surface2 hover:text-ink">
                      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-signal/10 text-signal"><Icon name={item.icon} size={16}/></span>
                      <span className="font-semibold">{t(item.labelKey)}</span>
                      <Icon name={dir === 'rtl' ? 'arrowLeft' : 'arrowRight'} size={13} className="ms-auto" />
                    </button>
                  )) : <div className="px-3 py-7 text-center text-xs text-muted">{t('noSearchResults')}</div>}
                </div>
              )}
            </div>

            <button className="icon-button relative" aria-label={t('notificationLabel')} onClick={() => newVersionNotice && navigate(updateTarget)}>
              <Icon name="bell" size={17}/>{newVersionNotice && <span className="absolute end-1.5 top-1.5 h-2 w-2 rounded-full bg-signal ring-2 ring-bg" />}
            </button>
            <LangToggle lang={lang} setLang={setLang} variant="icon" />
            <ThemeToggle />

            <div ref={profileRef} className="relative ms-1">
              <button onClick={() => setProfileOpen(v => !v)} className="flex items-center gap-2.5 rounded-lg border border-transparent px-2 py-1.5 hover:border-border hover:bg-surface">
                <span className="flex h-9 w-9 items-center justify-center rounded-full border border-border bg-surface2 text-muted"><Icon name="user" size={18}/></span>
                <span className="hidden max-w-[130px] text-start 2xl:block"><span className="block truncate text-xs font-bold text-ink">{username}</span><span className="mt-0.5 block text-[9px] text-muted">{isSuperadmin ? t('adminRoleSuper') : t('adminRoleDelegated')}</span></span>
                <Icon name="chevron" size={13} className={`hidden text-muted transition-transform 2xl:block ${profileOpen ? 'rotate-180' : ''}`} />
              </button>
              {profileOpen && <div className="absolute end-0 top-[50px] z-50 w-56 overflow-hidden rounded-xl border border-border bg-surface p-2 shadow-2xl">
                <div className="border-b border-border px-3 py-2.5"><div className="truncate text-xs font-bold">{username}</div><div className="mt-1 text-[10px] text-muted">{isSuperadmin ? t('adminRoleSuper') : t('adminRoleDelegated')}</div></div>
                <button onClick={logout} className="mt-1 flex w-full items-center gap-2 rounded-lg px-3 py-2.5 text-xs text-muted hover:bg-danger/10 hover:text-danger"><Icon name="logout" size={16}/>{t('logoutBtn')}</button>
              </div>}
            </div>
          </div>
        </header>

        <main className="app-page-content relative z-10 mx-auto max-w-[1720px] px-3 pb-10 pt-20 sm:px-5 lg:px-6 lg:pt-6 xl:px-7">
          {serverRole === 'node' && (
            <div className="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-signal/35 bg-signal/10 px-4 py-3 text-xs">
              <div className="flex items-center gap-2 font-extrabold text-signal">
                <Icon name="server" size={17}/>
                <span>{lang === 'fa' ? `مدیریت مستقیم پنل نود${remoteNodeName ? ` — ${remoteNodeName}` : ''}` : `Direct node panel${remoteNodeName ? ` — ${remoteNodeName}` : ''}`}</span>
              </div>
              <span className="text-[11px] text-muted">{lang === 'fa' ? 'تمام تغییرات این صفحه فقط روی همین نود اعمال می‌شوند؛ این پنل، سرور اصلی نیست.' : 'All changes on this page apply only to this node; this is not the main controller.'}</span>
            </div>
          )}
          <Outlet />
        </main>
      </div>

      {newVersionNotice && <div className="modal-backdrop" role="dialog" aria-modal="true">
        <div className="modal-panel max-w-md p-5 space-y-4">
          <div className="flex gap-3"><span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-signal/10 text-signal"><Icon name="backup"/></span><div><div className="font-black">{t('updateAvailablePrefix')} {newVersionNotice.version} {t('updateAvailableSuffix')}</div>{newVersionNotice.notes && <p className="mt-1 text-sm leading-6 text-muted">{newVersionNotice.notes}</p>}</div></div>
          <div className="flex justify-end gap-2"><button className="btn-secondary" onClick={() => { setDismissedVersion(newVersionNotice.version); setNewVersionNotice(null) }}>{t('updateDismissBtn')}</button><button className="btn-primary" onClick={() => { setDismissedVersion(newVersionNotice.version); setNewVersionNotice(null); navigate(updateTarget) }}>{t('updateGoBtn')}</button></div>
        </div>
      </div>}
    </div>
  )
}

function Brand({ compact = false }) {
  const { branding } = useBranding()
  const brandName = branding.brand_name === null || branding.brand_name === undefined ? 'VPN PANEL' : branding.brand_name
  const parts = String(brandName || '').trim().split(/\s+/)
  const tail = parts.length > 1 ? parts.pop() : ''
  return (
    <div className="flex items-center gap-2.5 overflow-hidden">
      <div className="relative flex h-10 w-10 shrink-0 items-center justify-center text-signal">
        {branding.logo_url ? <img src={branding.logo_url} alt="" className="h-10 w-10 rounded-xl object-contain" /> : <svg viewBox="0 0 48 48" className="h-10 w-10" aria-hidden="true"><path d="M24 3 41 10v12c0 11-6.8 18.6-17 23C13.8 40.6 7 33 7 22V10L24 3Z" fill="none" stroke="currentColor" strokeWidth="3.2"/><path d="M24 13a7 7 0 0 0-4 12.7V35h8v-9.3A7 7 0 0 0 24 13Z" fill="none" stroke="currentColor" strokeWidth="3"/><circle cx="24" cy="20" r="1.8" fill="currentColor"/></svg>}
      </div>
      {!compact && brandName && <div className="whitespace-nowrap text-[17px] font-black tracking-wide text-ink">{parts.join(' ')}{parts.length && tail ? ' ' : ''}{tail && <span className="text-signal">{tail}</span>}</div>}
    </div>
  )
}
