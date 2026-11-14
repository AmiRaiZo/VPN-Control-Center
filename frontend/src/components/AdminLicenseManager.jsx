import React, { useEffect, useMemo, useState } from 'react'
import * as ReactDOM from 'react-dom'
import api from '../api'
import { useLang } from '../i18n/dashboardLang.jsx'
import { useUI } from './ui/UIProvider.jsx'
import { Icon } from './icons.jsx'

const PERMISSIONS = [
  'dashboard:view','users:view','users:create','users:edit','users:delete','users:disconnect','users:subscription',
  'online:view','online:disconnect','internet_blocks:view','bans:view','bans:manage','protocols:view','protocols:start_stop','protocols:install','protocols:logs','protocols:edit',
  'settings:view','settings:manage','nodes:view','nodes:manage','nodes:ssh','nodes:install','protocol:l2tp','protocol:ipsec','protocol:pptp','protocol:openvpn','protocol:openconnect','protocol:sstp','protocol:ikev2','protocol:vmess','protocol:vless',
]

const initial = {
  role: 'admin',
  permissions: [],
  server_targets: [],
  max_users: '',
  max_total_quota_gb: '',
  expire_mode: 'after_activation',
  days: 30,
  hours: 0,
  minutes: 0,
  fixed_expire_at: '',
  telegram_bot_enabled: false,
  note: '',
}

function PermissionPill({ active, label, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`modern-toggle-pill ${active ? 'is-active' : ''}`}
    >
      <span className={`modern-toggle-pill__icon ${active ? 'is-active' : ''}`}>{active ? '✓' : '+'}</span>
      <span>{label}</span>
    </button>
  )
}

function LicenseSection({ title, subtitle, action, children, className = '' }) {
  return (
    <section className={`user-form-section ${className}`}>
      <div className="user-form-section__title-row">
        <div>
          <h3>{title}</h3>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      <div className="mt-4">{children}</div>
    </section>
  )
}

export default function AdminLicenseManager() {
  const { lang, dir } = useLang()
  const fa = lang !== 'en'
  const { notify, confirm, withBusy } = useUI()
  const [rows, setRows] = useState([])
  const [serverTargets, setServerTargets] = useState([])
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState(initial)
  const [error, setError] = useState('')

  const permissionGroups = useMemo(() => [
    {
      title: fa ? 'صفحات' : 'Pages',
      subtitle: fa ? 'صفحه‌هایی که ادمین زیرمجموعه می‌تواند مشاهده کند' : 'Pages the sub-admin can open',
      items: [
        ['dashboard:view', fa ? 'داشبورد' : 'Dashboard'],
        ['users:view', fa ? 'مشاهده کاربران' : 'View users'],
        ['online:view', fa ? 'کاربران آنلاین' : 'Online users'],
        ['internet_blocks:view', fa ? 'نمایش لیست اینترنت قطع‌شده‌ها' : 'View internet block list'],
        ['bans:view', fa ? 'آی‌پی‌های مسدود' : 'Banned IPs'],
        ['protocols:view', fa ? 'مرکز پروتکل‌ها' : 'Protocol center'],
        ['settings:view', fa ? 'تنظیمات' : 'Settings'],
        ['nodes:view', fa ? 'نودها' : 'Nodes'],
      ],
    },
    {
      title: fa ? 'عملیات کاربران' : 'User actions',
      subtitle: fa ? 'مجوز ساخت، ویرایش و مدیریت کاربران' : 'Create, edit and manage users',
      items: [
        ['users:create', fa ? 'ساخت کاربر' : 'Create user'],
        ['users:edit', fa ? 'ویرایش کاربر' : 'Edit user'],
        ['users:delete', fa ? 'حذف کاربر' : 'Delete user'],
        ['users:disconnect', fa ? 'قطع اتصال کاربر' : 'Disconnect user'],
        ['users:subscription', fa ? 'مشاهده و کپی لینک ساب' : 'Subscription links'],
        ['online:disconnect', fa ? 'قطع از صفحه آنلاین' : 'Disconnect online session'],
        ['bans:manage', fa ? 'مسدود یا آزادکردن IP' : 'Manage IP bans'],
      ],
    },
    {
      title: fa ? 'عملیات پروتکل‌ها و تنظیمات' : 'Protocol and settings actions',
      subtitle: fa ? 'کنترل سرویس‌ها، لاگ‌ها و تنظیمات پنل' : 'Control services, logs and panel settings',
      items: [
        ['protocols:start_stop', fa ? 'روشن، خاموش و ری‌استارت' : 'Start, stop and restart'],
        ['protocols:install', fa ? 'نصب و ترمیم' : 'Install and repair'],
        ['protocols:logs', fa ? 'مشاهده لاگ' : 'View logs'],
        ['protocols:edit', fa ? 'ویرایش تنظیمات و فایل‌ها' : 'Edit settings and files'],
        ['settings:manage', fa ? 'تغییر تنظیمات پنل' : 'Manage panel settings'],
        ['nodes:manage', fa ? 'مدیریت نودها' : 'Manage nodes'],
        ['nodes:ssh', fa ? 'کنسول SSH' : 'SSH console'],
        ['nodes:install', fa ? 'نصب نود روی VPS' : 'Install node on VPS'],
      ],
    },
    {
      title: fa ? 'پروتکل‌های مجاز' : 'Allowed protocols',
      subtitle: fa ? 'پروتکل‌هایی که این ادمین اجازه ارائه به کاربران را دارد' : 'Protocols this admin may assign to users',
      items: [
        ['protocol:l2tp', 'L2TP'],
        ['protocol:ipsec', 'IPsec'],
        ['protocol:pptp', 'PPTP'],
        ['protocol:openvpn', 'OpenVPN'],
        ['protocol:openconnect', 'OpenConnect'],
        ['protocol:sstp', 'SSTP'],
        ['protocol:ikev2', 'IKEv2'],
        ['protocol:vmess', 'VMess'],
        ['protocol:vless', 'VLESS'],
      ],
    },
  ], [fa])

  const load = () => api.get('/admins/licenses').then(({ data }) => setRows(data || [])).catch(() => {})
  const loadServerTargets = () => api.get('/admins/server-targets').then(({ data }) => setServerTargets(Array.isArray(data?.targets) ? data.targets : [])).catch(() => setServerTargets([]))
  useEffect(() => { load(); loadServerTargets() }, [])

  useEffect(() => {
    if (!open) return undefined
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  const isSuperadmin = form.role === 'superadmin'
  const all = form.permissions.length === PERMISSIONS.length
  const durationMinutes = useMemo(
    () => Math.max(1, Number(form.days || 0) * 1440 + Number(form.hours || 0) * 60 + Number(form.minutes || 0)),
    [form.days, form.hours, form.minutes],
  )

  const set = (key, value) => setForm((current) => ({ ...current, [key]: value }))
  const togglePermission = (key) => setForm((current) => ({
    ...current,
    permissions: current.permissions.includes(key)
      ? current.permissions.filter((item) => item !== key)
      : [...current.permissions, key],
  }))
  const applyGroup = (keys, enabled) => setForm((current) => ({
    ...current,
    permissions: enabled
      ? Array.from(new Set([...current.permissions, ...keys]))
      : current.permissions.filter((permission) => !keys.includes(permission)),
  }))

  const concreteServerIds = serverTargets.map((item) => item.id).filter(Boolean)
  const allServersSelected = concreteServerIds.length > 0 && (form.server_targets.includes('all') || concreteServerIds.every((id) => form.server_targets.includes(id)))
  const isServerSelected = (id) => form.server_targets.includes('all') || form.server_targets.includes(id)
  const toggleServer = (id) => setForm((current) => {
    const expanded = current.server_targets.includes('all') ? [...concreteServerIds] : [...current.server_targets]
    const next = expanded.includes(id) ? expanded.filter((item) => item !== id) : [...expanded, id]
    return { ...current, server_targets: next }
  })
  const toggleAllServers = () => setForm((current) => ({ ...current, server_targets: allServersSelected ? [] : ['all'] }))
  const openNewLicense = () => {
    setError('')
    setForm({ ...initial, permissions: [], server_targets: [] })
    setOpen(true)
  }

  const create = async (event) => {
    event.preventDefault()
    setError('')
    try {
      await withBusy(fa ? 'در حال ساخت لایسنس…' : 'Creating license…', () => api.post('/admins/licenses', {
        role: form.role,
        permissions: isSuperadmin ? [] : form.permissions,
        server_targets: form.server_targets,
        max_users: isSuperadmin || form.max_users === '' ? null : Number(form.max_users),
        max_total_quota_gb: isSuperadmin || form.max_total_quota_gb === '' ? null : Number(form.max_total_quota_gb),
        expire_mode: form.expire_mode,
        duration_minutes: form.expire_mode === 'after_activation' ? durationMinutes : null,
        fixed_expire_at: form.expire_mode === 'fixed' ? form.fixed_expire_at : null,
        telegram_bot_enabled: !!form.telegram_bot_enabled,
        telegram_user_id: null,
        note: form.note || null,
      }))
      setOpen(false)
      setForm({ ...initial, permissions: [], server_targets: [] })
      load()
      notify({ type: 'success', message: fa ? 'لایسنس داخلی ساخته شد.' : 'Internal license created.' })
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(Array.isArray(detail)
        ? detail.map((item) => item.msg).join('، ')
        : (detail || (fa ? 'ساخت لایسنس ناموفق بود.' : 'Failed to create license.')))
    }
  }

  const copy = async (code) => {
    try {
      await navigator.clipboard.writeText(code)
      notify({ type: 'success', message: fa ? 'کد کپی شد.' : 'Code copied.' })
    } catch {}
  }

  const remove = async (row) => {
    if (!(await confirm({
      title: fa ? 'حذف لایسنس' : 'Delete license',
      message: fa ? 'این کد حذف یا در صورت استفاده غیرفعال شود؟' : 'Delete or disable this key?',
      danger: true,
    }))) return
    await api.delete(`/admins/licenses/${row.id}`)
    load()
  }

  const formatDuration = (minutes) => {
    if (!minutes) return '—'
    const days = Math.floor(minutes / 1440)
    const hours = Math.floor((minutes % 1440) / 60)
    const mins = minutes % 60
    return [
      days && `${days}${fa ? ' روز' : 'd'}`,
      hours && `${hours}${fa ? ' ساعت' : 'h'}`,
      mins && `${mins}${fa ? ' دقیقه' : 'm'}`,
    ].filter(Boolean).join(' ')
  }

  const modal = open ? (
    <div className="modal-backdrop admin-license-backdrop" role="dialog" aria-modal="true" aria-labelledby="admin-license-title">
      <div dir={dir} className={`modal-panel modal-scroll-shell admin-license-modal ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
        <header className="modal-sticky-header admin-license-header">
          <div className="min-w-0">
            <h2 id="admin-license-title" className="font-black text-sm sm:text-base">{fa ? 'ساخت لایسنس داخلی' : 'Create internal license'}</h2>
            <p className="mt-1 text-[10px] text-muted">{fa ? 'نوع حساب، دسترسی‌ها و اعتبار لایسنس را تعیین کنید.' : 'Choose the account role, permissions and license validity.'}</p>
          </div>
          <button type="button" className="modal-close-button" onClick={() => setOpen(false)} aria-label={fa ? 'بستن' : 'Close'}>✕</button>
        </header>

        <form onSubmit={create} className="modal-scroll-body admin-license-body p-3 sm:p-5">
          {error && <div className="mb-4 status-danger rounded-xl px-3 py-2 text-sm">{error}</div>}

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
            <LicenseSection
              title={fa ? 'نوع حساب این لایسنس' : 'Account role for this license'}
              subtitle={fa ? 'ادمین اصلی دسترسی کامل سوپرادمین دارد؛ ادمین زیرمجموعه فقط مجوزهای انتخاب‌شده را دریافت می‌کند.' : 'A main admin gets full superadmin access; a sub-admin only gets selected permissions.'}
              className="xl:col-span-12"
            >
              <div className="grid gap-2 sm:grid-cols-2">
                <button type="button" className={`modern-switch-card ${form.role === 'admin' ? 'is-active' : ''}`} onClick={() => set('role', 'admin')}>
                  <span>
                    <b className="block text-xs">{fa ? 'ادمین زیرمجموعه' : 'Sub-admin'}</b>
                    <small className="mt-1 block text-[10px] text-muted">{fa ? 'دسترسی، سرورها و سقف منابع به‌صورت دستی تعیین می‌شود.' : 'Permissions, servers and limits are selected manually.'}</small>
                  </span>
                  <span className={`modern-switch-knob ${form.role === 'admin' ? 'is-active' : ''}`}><span className="modern-switch-knob__dot" /></span>
                </button>
                <button type="button" className={`modern-switch-card ${form.role === 'superadmin' ? 'is-active' : ''}`} onClick={() => set('role', 'superadmin')}>
                  <span>
                    <b className="block text-xs">{fa ? 'ادمین اصلی (سوپر ادمین)' : 'Main admin (superadmin)'}</b>
                    <small className="mt-1 block text-[10px] text-muted">{fa ? 'دسترسی کامل به کاربران، ادمین‌ها، نودها، پروتکل‌ها، تنظیمات و لایسنس‌ها.' : 'Full access to users, admins, nodes, protocols, settings and licenses.'}</small>
                  </span>
                  <span className={`modern-switch-knob ${form.role === 'superadmin' ? 'is-active' : ''}`}><span className="modern-switch-knob__dot" /></span>
                </button>
              </div>
              {isSuperadmin && <div className="mt-3 rounded-xl border border-warning/25 bg-warning/5 px-3 py-2 text-[11px] leading-6 text-warning">{fa ? 'این کد یک حساب ادمین اصلی با دسترسی کامل می‌سازد. آن را فقط در اختیار فرد کاملاً مورد اعتماد قرار دهید.' : 'This code creates a main administrator with full access. Share it only with a fully trusted person.'}</div>}
            </LicenseSection>

            {!isSuperadmin && <LicenseSection
              title={fa ? 'دسترسی‌ها' : 'Permissions'}
              subtitle={fa ? 'مجوزها را به‌صورت گروهی یا جداگانه انتخاب کنید.' : 'Choose permissions by group or individually.'}
              action={<button type="button" className="modern-mini-action" onClick={() => set('permissions', all ? [] : [...PERMISSIONS])}>{all ? (fa ? 'پاک کردن همه' : 'Clear all') : (fa ? 'انتخاب همه' : 'Select all')}</button>}
              className="xl:col-span-12"
            >
              <div className="grid gap-3 lg:grid-cols-2">
                {permissionGroups.map((group) => {
                  const keys = group.items.map(([key]) => key)
                  const selected = keys.filter((key) => form.permissions.includes(key)).length
                  return (
                    <section key={group.title} className="modern-group-card admin-license-permission-group">
                      <div className="mb-3 flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-xs font-extrabold text-ink">{group.title}</div>
                          <div className="mt-1 text-[10px] leading-5 text-muted">{group.subtitle}</div>
                          <div className="mt-1 text-[10px] font-data text-signal">{selected} / {group.items.length} {fa ? 'انتخاب شده' : 'selected'}</div>
                        </div>
                        <div className="flex shrink-0 gap-1">
                          <button type="button" className="modern-mini-action" onClick={() => applyGroup(keys, true)}>{fa ? 'همه' : 'All'}</button>
                          <button type="button" className="modern-mini-action" onClick={() => applyGroup(keys, false)}>{fa ? 'پاک' : 'Clear'}</button>
                        </div>
                      </div>
                      <div className="grid gap-2 sm:grid-cols-2">
                        {group.items.map(([key, label]) => (
                          <PermissionPill key={key} active={form.permissions.includes(key)} label={label} onClick={() => togglePermission(key)} />
                        ))}
                      </div>
                    </section>
                  )
                })}
              </div>
            </LicenseSection>}

            {!isSuperadmin && <LicenseSection
              title={fa ? 'سرورهای قابل دسترسی این ادمین' : 'Servers available to this admin'}
              subtitle={fa ? 'انتخاب همه یعنی همه سرورهای فعلی و سرورهایی که بعداً اضافه می‌شوند. انتخاب دستی فقط همان سرورها را مجاز می‌کند.' : 'Select all includes current and future servers; manual selection grants only those servers.'}
              action={<button type="button" className="modern-mini-action" onClick={toggleAllServers}>{allServersSelected ? (fa ? 'لغو انتخاب همه' : 'Clear all') : (fa ? 'انتخاب همه' : 'Select all')}</button>}
              className="xl:col-span-12"
            >
              <div className="grid gap-2 sm:grid-cols-2">
                {serverTargets.map((target) => (
                  <button type="button" key={target.id} onClick={() => toggleServer(target.id)} className={`modern-switch-card ${isServerSelected(target.id) ? 'is-active' : ''}`}>
                    <span>
                      <b className="block text-xs">{target.name}</b>
                      <small className="mt-1 block text-[10px] text-muted">{target.local ? (fa ? 'سرور اصلی' : 'Main server') : `${target.status || 'unknown'}${target.user_assignment_enabled === false ? (fa ? ' — مخفی از ساخت کاربر' : ' — hidden from user creation') : ''}`}</small>
                    </span>
                    <span className={`modern-switch-knob ${isServerSelected(target.id) ? 'is-active' : ''}`}><span className="modern-switch-knob__dot" /></span>
                  </button>
                ))}
                {!serverTargets.length && <div className="text-xs text-warning">{fa ? 'هیچ سروری ثبت نشده است.' : 'No servers are registered.'}</div>}
              </div>
              {!form.server_targets.length && <div className="mt-3 text-[11px] text-warning">{fa ? 'این لایسنس به هیچ سروری دسترسی نمی‌دهد و ادمین نمی‌تواند کاربر بسازد.' : 'This license grants no server access, so the admin cannot create users.'}</div>}
            </LicenseSection>}

            {!isSuperadmin && <LicenseSection title={fa ? 'سقف منابع' : 'Resource limits'} subtitle={fa ? 'خالی بماند یعنی نامحدود' : 'Leave blank for unlimited'} className="xl:col-span-6">
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block min-w-0">
                  <span className="field-label">{fa ? 'حداکثر ساخت کاربر' : 'Max users'}</span>
                  <input type="number" min="1" className="field font-data" value={form.max_users} onChange={(event) => set('max_users', event.target.value)} placeholder={fa ? 'نامحدود' : 'Unlimited'} />
                </label>
                <label className="block min-w-0">
                  <span className="field-label">{fa ? 'حجم کل (GB)' : 'Total quota (GB)'}</span>
                  <input type="number" min="0" step="0.1" className="field font-data" value={form.max_total_quota_gb} onChange={(event) => set('max_total_quota_gb', event.target.value)} placeholder={fa ? 'نامحدود' : 'Unlimited'} />
                </label>
              </div>
            </LicenseSection>}

            <LicenseSection title={fa ? 'اعتبار لایسنس' : 'License validity'} subtitle={fa ? 'اعتبار از اولین فعال‌سازی یا تا یک زمان ثابت' : 'Start after activation or use a fixed expiration'} className="xl:col-span-6">
              <div className="grid grid-cols-2 gap-2">
                <button type="button" className={`user-choice-button ${form.expire_mode === 'after_activation' ? 'is-active' : ''}`} onClick={() => set('expire_mode', 'after_activation')}>{fa ? 'بعد از فعال‌سازی' : 'After activation'}</button>
                <button type="button" className={`user-choice-button ${form.expire_mode === 'fixed' ? 'is-active' : ''}`} onClick={() => set('expire_mode', 'fixed')}>{fa ? 'تاریخ ثابت' : 'Fixed date'}</button>
              </div>

              {form.expire_mode === 'after_activation' ? (
                <div className="mt-3 grid grid-cols-3 gap-2 sm:gap-3">
                  <label className="block min-w-0"><span className="field-label">{fa ? 'روز' : 'Days'}</span><input type="number" min="0" className="field font-data" value={form.days} onChange={(event) => set('days', event.target.value)} /></label>
                  <label className="block min-w-0"><span className="field-label">{fa ? 'ساعت' : 'Hours'}</span><input type="number" min="0" max="23" className="field font-data" value={form.hours} onChange={(event) => set('hours', event.target.value)} /></label>
                  <label className="block min-w-0"><span className="field-label">{fa ? 'دقیقه' : 'Minutes'}</span><input type="number" min="0" max="59" className="field font-data" value={form.minutes} onChange={(event) => set('minutes', event.target.value)} /></label>
                </div>
              ) : (
                <label className="mt-3 block"><span className="field-label">{fa ? 'تاریخ و ساعت انقضا' : 'Expiration date/time'}</span><input type="datetime-local" className="field font-data" value={form.fixed_expire_at} onChange={(event) => set('fixed_expire_at', event.target.value)} required /></label>
              )}
            </LicenseSection>

            <LicenseSection title={fa ? 'ربات خصوصی تلگرام' : 'Private Telegram bot'} subtitle={fa ? 'در صورت فعال بودن، ثبت‌نام‌کننده با همین دسترسی‌ها در پی‌وی ربات مجاز می‌شود.' : 'When enabled, the registered admin may use the bot privately with these exact permissions.'} className="xl:col-span-12">
              <button type="button" className={`modern-switch-card ${form.telegram_bot_enabled ? 'is-active' : ''}`} onClick={() => set('telegram_bot_enabled', !form.telegram_bot_enabled)}>
                <span><b className="block text-xs">{form.telegram_bot_enabled ? (fa ? 'ربات فعال است' : 'Bot enabled') : (fa ? 'ربات غیرفعال است' : 'Bot disabled')}</b><small className="mt-1 block text-[10px] text-muted">{fa ? 'ادمین پس از ثبت‌نام فقط ربات را در پی‌وی Start می‌کند؛ گروه لازم نیست.' : 'After registration the admin only starts the bot privately; no group is needed.'}</small></span>
                <span className={`modern-switch-knob ${form.telegram_bot_enabled ? 'is-active' : ''}`}><span className="modern-switch-knob__dot" /></span>
              </button>
              {form.telegram_bot_enabled && <div className="mt-3 rounded-xl border border-signal/25 bg-signal/5 px-3 py-2 text-[10px] leading-5 text-muted">{fa ? 'در زمان ثبت‌نام، صاحب لایسنس آیدی عددی تلگرام خود را وارد می‌کند یا گزینه «ربات نمی‌خواهم» را می‌زند.' : 'During registration, the license owner enters their numeric Telegram ID or opts out of bot access.'}</div>}
            </LicenseSection>

            <LicenseSection title={fa ? 'یادداشت' : 'Note'} subtitle={fa ? 'توضیح داخلی اختیاری برای شناسایی این لایسنس' : 'Optional internal note for this license'} className="xl:col-span-12">
              <textarea className="field min-h-[82px] resize-y" value={form.note} onChange={(event) => set('note', event.target.value)} />
            </LicenseSection>
          </div>

          <footer className="modal-actions admin-license-actions mt-4">
            <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>{fa ? 'انصراف' : 'Cancel'}</button>
            <button type="submit" className="btn-primary">{fa ? 'ساخت و تولید کد' : 'Create and generate code'}</button>
          </footer>
        </form>
      </div>
    </div>
  ) : null

  return (
    <section dir={dir} className="panel-section p-5 space-y-4 xl:col-span-2">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-bold text-ink">{fa ? 'لایسنس‌های داخلی ادمین' : 'Internal admin licenses'}</div>
          <p className="mt-1 text-xs text-muted">{fa ? 'کاربر با این کد خودش نام کاربری و رمز را در صفحه ورود می‌سازد.' : 'The recipient creates their own username and password on the login page.'}</p>
        </div>
        <button className="btn-primary !px-3 !py-2 text-xs" onClick={openNewLicense}><Icon name="plus" size={14} />{fa ? 'لایسنس جدید' : 'New license'}</button>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        {rows.map((row) => (
          <div key={row.id} className="rounded-xl border border-border bg-surface2 p-4">
            <div className="flex items-center justify-between gap-2">
              <button dir="ltr" onClick={() => copy(row.code)} className="font-data text-sm font-bold text-signal hover:underline">{row.code}</button>
              <div className="flex items-center gap-1.5">
                <span className={`rounded-full px-2 py-1 text-[10px] ${row.role === 'superadmin' ? 'bg-warning/10 text-warning' : 'bg-signal/10 text-signal'}`}>{row.role === 'superadmin' ? (fa ? 'سوپر ادمین' : 'Superadmin') : (fa ? 'ادمین زیرمجموعه' : 'Sub-admin')}</span>
                <span className={`rounded-full px-2 py-1 text-[10px] ${row.used_by_admin_id ? 'bg-success/10 text-success' : 'bg-signal/10 text-signal'}`}>{row.used_by_username ? `${fa ? 'استفاده شده توسط' : 'Used by'} ${row.used_by_username}` : (fa ? 'آماده' : 'Ready')}</span>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-muted">
              {row.role === 'superadmin' ? <span className="col-span-2">{fa ? 'دسترسی' : 'Access'}: <b className="text-warning">{fa ? 'کامل ادمین اصلی' : 'Full main admin'}</b></span> : <>
                <span>{fa ? 'کاربر' : 'Users'}: <b className="text-ink">{row.max_users ?? '∞'}</b></span>
                <span>{fa ? 'حجم' : 'Quota'}: <b className="text-ink">{row.max_total_quota_gb ?? '∞'} GB</b></span>
              </>}
              <span className="col-span-2">{fa ? 'اعتبار' : 'Validity'}: <b className="text-ink">{row.expire_mode === 'fixed' ? new Date(row.fixed_expire_at).toLocaleString() : formatDuration(row.duration_minutes)}</b></span>
              <span className="col-span-2">{fa ? 'ربات' : 'Bot'}: <b className={row.telegram_bot_enabled ? 'text-success' : 'text-muted'}>{row.telegram_bot_enabled ? (fa ? `فعال — ${row.telegram_user_id || 'آیدی هنگام ثبت‌نام'}` : `Enabled — ${row.telegram_user_id || 'ID at registration'}`) : (fa ? 'غیرفعال' : 'Disabled')}</b></span>
            </div>
            <div className="mt-3 flex justify-end gap-2">
              <button onClick={() => copy(row.code)} className="btn-secondary !px-2.5 !py-1.5 text-[10px]">{fa ? 'کپی' : 'Copy'}</button>
              <button onClick={() => remove(row)} className="btn-danger !px-2.5 !py-1.5 text-[10px]">{fa ? 'حذف' : 'Delete'}</button>
            </div>
          </div>
        ))}
        {!rows.length && <div className="md:col-span-2 rounded-xl border border-dashed border-border p-8 text-center text-xs text-muted">{fa ? 'هنوز لایسنسی ساخته نشده است.' : 'No licenses have been created yet.'}</div>}
      </div>

      {modal && ReactDOM.createPortal(modal, document.body)}
    </section>
  )
}
