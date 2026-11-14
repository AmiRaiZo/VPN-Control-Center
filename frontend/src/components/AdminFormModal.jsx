import React, { useState, useEffect } from 'react'
import ReactDOM from 'react-dom'
import { generateRandomUsername, generateRandomPassword } from '../randomCredentials'
import JalaliDatePicker from './JalaliDatePicker.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'

const empty = {
  username: '',
  password: '',
  role: 'admin',
  permissions: [],
  see_all_users: false,
  max_users: '',
  max_total_quota_gb: '',
  subscription_expire_date: '',
  server_targets: [],
  telegram_bot_enabled: false,
  telegram_user_id: '',
}

function SelectionPill({ active, label, onClick }) {
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

export default function AdminFormModal({ admin, serverTargets = [], onClose, onSubmit, error }) {
  const { t, lang } = useLang()
  const fa = lang !== 'en'
  const PERMISSION_GROUPS = [
    { title: fa ? 'صفحات' : 'Pages', items: [
      ['dashboard:view', fa ? 'داشبورد' : 'Dashboard'],
      ['users:view', fa ? 'مشاهده کاربران' : 'View users'],
      ['online:view', fa ? 'کاربران آنلاین' : 'Online users'],
      ['internet_blocks:view', fa ? 'نمایش لیست اینترنت قطع‌شده‌ها' : 'View internet block list'],
      ['bans:view', fa ? 'مشاهده آی‌پی‌های مسدود' : 'View banned IPs'],
      ['license:view', fa ? 'مشاهده لایسنس' : 'View license'],
      ['protocols:view', fa ? 'مرکز پروتکل‌ها' : 'Protocol center'],
      ['settings:view', fa ? 'مشاهده تنظیمات' : 'View settings'],
      ['nodes:view', fa ? 'مشاهده نودها' : 'View nodes'],
    ]},
    { title: fa ? 'عملیات کاربران' : 'User actions', items: [
      ['users:create', fa ? 'ساخت کاربر' : 'Create user'],
      ['users:edit', fa ? 'ویرایش کاربر' : 'Edit user'],
      ['users:delete', fa ? 'حذف کاربر' : 'Delete user'],
      ['users:disconnect', fa ? 'قطع اتصال کاربر' : 'Disconnect user'],
      ['users:subscription', fa ? 'مشاهده و کپی لینک ساب' : 'Subscription links'],
      ['online:disconnect', fa ? 'قطع اتصال از صفحه آنلاین' : 'Disconnect online sessions'],
      ['bans:manage', fa ? 'مسدود/آزادکردن IP' : 'Manage IP bans'],
    ]},
    { title: fa ? 'عملیات پروتکل‌ها و تنظیمات' : 'Protocol and settings actions', items: [
      ['protocols:start_stop', fa ? 'روشن/خاموش/ری‌استارت' : 'Start/stop/restart'],
      ['protocols:install', fa ? 'نصب و ترمیم' : 'Install and repair'],
      ['protocols:logs', fa ? 'مشاهده لاگ' : 'View logs'],
      ['protocols:edit', fa ? 'ویرایش تنظیمات و فایل‌ها' : 'Edit settings and files'],
      ['settings:manage', fa ? 'تغییر تنظیمات پنل' : 'Manage panel settings'],
      ['nodes:manage', fa ? 'افزودن و مدیریت نودها' : 'Manage nodes'],
      ['nodes:ssh', fa ? 'کنسول SSH نودها' : 'Node SSH console'],
      ['nodes:install', fa ? 'نصب نود روی VPS' : 'Install node on VPS'],
    ]},
    { title: fa ? 'پروتکل‌های مجاز' : 'Allowed protocols', items: [
      ['protocol:l2tp', 'L2TP'], ['protocol:ipsec', 'IPsec'], ['protocol:pptp', 'PPTP'],
      ['protocol:openvpn', 'OpenVPN'], ['protocol:openconnect', 'OpenConnect'], ['protocol:sstp', 'SSTP'],
      ['protocol:ikev2', 'IKEv2'], ['protocol:vmess', 'VMess'], ['protocol:vless', 'VLESS'],
    ]},
  ]
  const [form, setForm] = useState(empty)

  useEffect(() => {
    const body = document.body
    const previousOverflow = body.style.overflow
    body.classList.add('vpnpanel-admin-modal-open')
    body.style.overflow = 'hidden'
    const onKeyDown = (event) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      body.classList.remove('vpnpanel-admin-modal-open')
      body.style.overflow = previousOverflow
    }
  }, [onClose])

  useEffect(() => {
    if (admin) {
      setForm({
        username: admin.username,
        password: '',
        role: admin.role,
        permissions: admin.permissions || [],
        see_all_users: !!admin.see_all_users,
        max_users: admin.max_users ?? '',
        max_total_quota_gb: admin.max_total_quota_gb ?? '',
        subscription_expire_date: admin.subscription_expire_date || '',
        server_targets: Array.isArray(admin.server_targets) ? admin.server_targets : ['all'],
        telegram_bot_enabled: !!admin.telegram_bot_enabled,
        telegram_user_id: admin.telegram_user_id ? String(admin.telegram_user_id) : '',
      })
    } else {
      setForm(empty)
    }
  }, [admin, serverTargets])

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))

  const toggleSection = (key) => {
    setForm((f) => ({
      ...f,
      permissions: f.permissions.includes(key)
        ? f.permissions.filter((p) => p !== key)
        : [...f.permissions, key],
    }))
  }

  const applyGroup = (keys, enabled) => {
    setForm((f) => ({
      ...f,
      permissions: enabled
        ? Array.from(new Set([...f.permissions, ...keys]))
        : f.permissions.filter((p) => !keys.includes(p)),
    }))
  }

  const concreteServerIds = serverTargets.map((item) => item.id).filter(Boolean)
  const allServersSelected = concreteServerIds.length > 0 && (form.server_targets.includes('all') || concreteServerIds.every((id) => form.server_targets.includes(id)))
  const isServerSelected = (id) => form.server_targets.includes('all') || form.server_targets.includes(id)
  const toggleServer = (id) => setForm((current) => {
    const expanded = current.server_targets.includes('all') ? [...concreteServerIds] : [...current.server_targets]
    const next = expanded.includes(id) ? expanded.filter((item) => item !== id) : [...expanded, id]
    return { ...current, server_targets: next }
  })
  const toggleAllServers = () => setForm((current) => ({ ...current, server_targets: allServersSelected ? [] : ['all'] }))

  const submit = (e) => {
    e.preventDefault()
    const payload = { ...form }
    if (admin && !payload.password) delete payload.password
    if (payload.role === 'superadmin') {
      payload.permissions = []
      payload.see_all_users = false
      payload.server_targets = ['all']
    }

    payload.max_users = payload.max_users === '' ? null : Number(payload.max_users)
    payload.max_total_quota_gb = payload.max_total_quota_gb === '' ? null : Number(payload.max_total_quota_gb)
    payload.subscription_expire_date = payload.subscription_expire_date === '' ? null : payload.subscription_expire_date
    payload.telegram_user_id = payload.telegram_bot_enabled && payload.telegram_user_id !== '' ? Number(payload.telegram_user_id) : null

    if (admin) {
      payload.clear_max_users = payload.max_users === null
      payload.clear_max_total_quota = payload.max_total_quota_gb === null
      payload.clear_subscription_expire_date = payload.subscription_expire_date === null
      payload.clear_telegram_user_id = !payload.telegram_bot_enabled || payload.telegram_user_id === null
      if (payload.max_users === null) delete payload.max_users
      if (payload.max_total_quota_gb === null) delete payload.max_total_quota_gb
      if (payload.subscription_expire_date === null) delete payload.subscription_expire_date
      if (payload.telegram_user_id === null) delete payload.telegram_user_id
    }

    onSubmit(payload)
  }

  return ReactDOM.createPortal(
    <div
      className="modal-backdrop admin-form-modal-backdrop"
      role="dialog"
      aria-modal="true"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}
    >
      <div className="modal-panel modal-scroll-shell admin-form-modal-panel max-w-5xl" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-sticky-header">
          <h2 className="font-bold">{admin ? t('editAdminTitle') : t('newAdminTitle')}</h2>
          <button type="button" onClick={onClose} className="modal-close-button" aria-label={fa ? 'بستن' : 'Close'}>✕</button>
        </div>

        <form onSubmit={submit} className="modal-scroll-body p-4 sm:p-5 space-y-4">
          {error && (
            <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-muted mb-1.5 font-data">{t('usernameLabel')}</label>
              <div className="flex gap-1.5">
                <input
                  className="field font-data"
                  value={form.username}
                  onChange={(e) => set('username', e.target.value.replace(/[^A-Za-z0-9_.-]/g, ''))}
                  disabled={!!admin}
                  title={t('usernameTitle')}
                  required
                />
                {!admin && (
                  <button
                    type="button"
                    onClick={() => set('username', generateRandomUsername())}
                    className="modern-inline-action"
                    title={t('randomUsernameTitle')}
                  >
                    {t('btnRandom')}
                  </button>
                )}
              </div>
            </div>

            <div>
              <label className="block text-xs text-muted mb-1.5 font-data">
                {t('passwordLabel')} {admin && t('noChangeSuffix')}
              </label>
              <div className="flex gap-1.5">
                <input
                  className="field font-data"
                  value={form.password}
                  onChange={(e) => set('password', e.target.value.replace(/[^A-Za-z0-9!@#$%^&*()_+\-=[\]{}:;,.<>?/~`|]/g, ''))}
                  title={t('passwordTitle')}
                  required={!admin}
                />
                <button
                  type="button"
                  onClick={() => set('password', generateRandomPassword())}
                  className="modern-inline-action"
                  title={t('randomPasswordTitle')}
                >
                  {t('btnRandom')}
                </button>
              </div>
            </div>
          </div>

          {admin?.managed_by_license && admin?.access_license_code && <div className="modern-group-card">
            <div className="text-xs text-muted">{fa ? 'لایسنس داخلی فعال این ادمین' : 'Active internal license'}</div>
            <div dir="ltr" className="mt-2 select-all font-data text-sm font-bold text-signal">{admin.access_license_code}</div>
          </div>}

          <section className="modern-group-card border border-signal/20">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="text-xs font-extrabold text-ink">{fa ? 'دسترسی خصوصی ربات تلگرام' : 'Private Telegram bot access'}</div>
                <div className="mt-1 text-[10px] leading-5 text-muted">{fa ? 'با فعال‌سازی، این ادمین در پی‌وی ربات و دقیقاً با همین دسترسی‌های پنل کار می‌کند.' : 'When enabled, this admin may use the bot in private chat with the same panel permissions.'}</div>
              </div>
              <button type="button" onClick={() => set('telegram_bot_enabled', !form.telegram_bot_enabled)} className={`modern-toggle-pill ${form.telegram_bot_enabled ? 'is-active' : ''}`}>
                <span className={`modern-toggle-pill__icon ${form.telegram_bot_enabled ? 'is-active' : ''}`}>{form.telegram_bot_enabled ? '✓' : '+'}</span>
                <span>{form.telegram_bot_enabled ? (fa ? 'فعال' : 'Enabled') : (fa ? 'غیرفعال' : 'Disabled')}</span>
              </button>
            </div>
            {form.telegram_bot_enabled && <div className="mt-4">
              <label className="block text-xs text-muted mb-1.5 font-data">{fa ? 'آیدی عددی تلگرام ادمین' : 'Admin numeric Telegram ID'}</label>
              <input dir="ltr" inputMode="numeric" className="field font-data" value={form.telegram_user_id} onChange={(e) => set('telegram_user_id', e.target.value.replace(/\D/g, ''))} placeholder="123456789" required />
              <p className="mt-1.5 text-[10px] leading-5 text-muted">{fa ? 'ادمین فقط کافی است ربات را در پی‌وی Start کند؛ گروه لازم نیست.' : 'The admin only needs to start the bot in private chat; no group is required.'}</p>
            </div>}
          </section>

          <div>
            <label className="block text-xs text-muted mb-2 font-data">{t('roleLabel')}</label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => set('role', 'admin')}
                className={`modern-role-card ${form.role === 'admin' ? 'is-active' : ''}`}
              >
                <div className="modern-role-card__icon">◌</div>
                <div>
                  <div className="modern-role-card__title">{t('roleSubAdmin')}</div>
                  <div className="modern-role-card__desc">{fa ? 'محدودسازی دقیق صفحه‌ها، عملیات و پروتکل‌ها' : 'Granular access to pages, actions and protocols'}</div>
                </div>
              </button>
              <button
                type="button"
                onClick={() => set('role', 'superadmin')}
                className={`modern-role-card ${form.role === 'superadmin' ? 'is-active' : ''}`}
              >
                <div className="modern-role-card__icon">★</div>
                <div>
                  <div className="modern-role-card__title">{t('roleMainAdmin')}</div>
                  <div className="modern-role-card__desc">{fa ? 'دسترسی کامل بدون محدودیت به کل پنل' : 'Full unrestricted access to the entire panel'}</div>
                </div>
              </button>
            </div>
          </div>

          {form.role === 'admin' && (
            <div className="space-y-3">
              <label className="block text-xs text-muted font-data">{t('accessibleSectionsLabel')}</label>
              <div className="grid gap-3 md:grid-cols-2">
                {PERMISSION_GROUPS.map((group) => {
                  const keys = group.items.map(([key]) => key)
                  const selectedCount = keys.filter((key) => form.permissions.includes(key)).length
                  return (
                    <section key={group.title} className="modern-group-card">
                      <div className="flex items-start justify-between gap-2 mb-3">
                        <div>
                          <div className="text-xs font-extrabold text-ink">{group.title}</div>
                          <div className="text-[11px] text-muted mt-1">
                            {selectedCount} / {group.items.length} {fa ? 'انتخاب شده' : 'selected'}
                          </div>
                        </div>
                        <div className="flex gap-1">
                          <button type="button" className="modern-mini-action" onClick={() => applyGroup(keys, true)}>{fa ? 'همه' : 'All'}</button>
                          <button type="button" className="modern-mini-action" onClick={() => applyGroup(keys, false)}>{fa ? 'پاک' : 'Clear'}</button>
                        </div>
                      </div>

                      <div className="grid gap-2 sm:grid-cols-2">
                        {group.items.map(([key, label]) => (
                          <SelectionPill
                            key={key}
                            active={form.permissions.includes(key)}
                            label={label}
                            onClick={() => toggleSection(key)}
                          />
                        ))}
                      </div>
                    </section>
                  )
                })}
              </div>
            </div>
          )}

          {form.role === 'admin' && (
            <section className="modern-group-card">
              <div className="flex items-start justify-between gap-3">
                <div><div className="text-sm font-bold text-ink">{fa ? 'سرورهای قابل دسترسی این ادمین' : 'Servers available to this admin'}</div><div className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'انتخاب همه یعنی همه سرورهای فعلی و سرورهایی که بعداً اضافه می‌شوند. انتخاب دستی فقط همان سرورها را مجاز می‌کند.' : 'Select all includes current and future servers; manual selection grants only those servers.'}</div></div>
                <button type="button" className="modern-mini-action shrink-0" onClick={toggleAllServers}>{allServersSelected ? (fa ? 'لغو انتخاب همه' : 'Clear all') : (fa ? 'انتخاب همه' : 'Select all')}</button>
              </div>
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                {serverTargets.map((target) => <button type="button" key={target.id} onClick={() => toggleServer(target.id)} className={`modern-switch-card ${isServerSelected(target.id) ? 'is-active' : ''}`}>
                  <span><b className="block text-xs">{target.name}</b><small className="mt-1 block text-[10px] text-muted">{target.local ? (fa ? 'سرور اصلی' : 'Main server') : `${target.status || 'unknown'}${target.user_assignment_enabled === false ? (fa ? ' — مخفی از ساخت کاربر' : ' — hidden from user creation') : ''}`}</small></span>
                  <span className={`modern-switch-knob ${isServerSelected(target.id) ? 'is-active' : ''}`}><span className="modern-switch-knob__dot" /></span>
                </button>)}
                {!serverTargets.length && <div className="text-xs text-warning">{fa ? 'هیچ سروری ثبت نشده است.' : 'No servers are registered.'}</div>}
              </div>
              {!form.server_targets.length && <div className="mt-3 text-[11px] text-warning">{fa ? 'این ادمین به هیچ سروری دسترسی نخواهد داشت و نمی‌تواند کاربر بسازد.' : 'This admin will have no server access and cannot create users.'}</div>}
            </section>
          )}

          {form.role === 'admin' && (
            <button
              type="button"
              onClick={() => set('see_all_users', !form.see_all_users)}
              className={`modern-switch-card ${form.see_all_users ? 'is-active' : ''}`}
            >
              <div>
                <div className="text-sm font-bold text-ink">{fa ? 'مشاهده اطلاعات کل پنل' : 'View all panel data'}</div>
                <div className="text-xs text-muted mt-1">{fa ? 'در حالت عادی، هر بخش فقط اطلاعات کاربران همین ادمین را نشان می‌دهد. با فعال‌کردن این گزینه، اطلاعات همه کاربران و رکوردهای کل پنل قابل مشاهده می‌شود.' : 'By default, every section is limited to this admin’s own users. Enable this to reveal panel-wide user data and records.'}</div>
              </div>
              <div className={`modern-switch-knob ${form.see_all_users ? 'is-active' : ''}`}>
                <span className="modern-switch-knob__dot" />
              </div>
            </button>
          )}

          {form.role === 'admin' && (
            <div className="modern-group-card space-y-3">
              <div className="text-xs text-muted">
                {t('subAdminLimitsLabel')}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-muted mb-1.5 font-data">{t('maxUsersLabel')}</label>
                  <input
                    type="number"
                    min="1"
                    className="field font-data"
                    value={form.max_users}
                    onChange={(e) => set('max_users', e.target.value)}
                    placeholder={t('unlimitedPlaceholder')}
                  />
                </div>
                <div>
                  <label className="block text-xs text-muted mb-1.5 font-data">{t('totalQuotaGbLabel')}</label>
                  <input
                    type="number"
                    min="0"
                    step="0.1"
                    className="field font-data"
                    value={form.max_total_quota_gb}
                    onChange={(e) => set('max_total_quota_gb', e.target.value)}
                    placeholder={t('unlimitedPlaceholder')}
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-muted mb-1.5 font-data">{t('subscriptionExpiryLabel')}</label>
                <JalaliDatePicker
                  value={form.subscription_expire_date || null}
                  onChange={(iso) => set('subscription_expire_date', iso || '')}
                />
              </div>
            </div>
          )}

          <div className="modal-actions pt-2">
            <button type="submit" className="btn-primary">
              {admin ? t('btnSaveChanges') : t('btnCreateAdmin')}
            </button>
            <button type="button" onClick={onClose} className="btn-secondary">
              {t('btnCancel2')}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  )
}
