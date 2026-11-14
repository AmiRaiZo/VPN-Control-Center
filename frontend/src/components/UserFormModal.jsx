import React, { useState, useEffect } from 'react'
import * as ReactDOM from 'react-dom'
import { generateRandomUsername, generateRandomPassword } from '../randomCredentials'
import JalaliDatePicker from './JalaliDatePicker.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { hasProtocol } from '../permissions.js'

const todayIso = () => new Date().toISOString().slice(0, 10)

const empty = {
  username: '', password: '',
  enable_l2tp: false, enable_pptp: false, enable_openvpn: false, enable_sstp: false,
  enable_ikev2: false, enable_openconnect: false, enable_vmess: false, enable_vless: false,
  openvpn_auth_mode: 'cert_only', sstp_auth_mode: 'password_only',
  quota_gb: 0, max_devices: 1, download_limit_mbps: 0, upload_limit_mbps: 0,
  expire_mode: 'fixed', expire_date: '', expire_after_days: 30,
  is_active: true, note: '', server_targets: [],
}

function Section({ title, subtitle, badge, action, className = '', children }) {
  return <section className={`user-form-section ${className}`}>
    <div className="user-form-section__head">
      <div className="user-form-section__title-row">
        <h3>{title}</h3>
        <div className="flex items-center gap-2">{badge && <span className="user-form-section__badge">{badge}</span>}{action}</div>
      </div>
      {subtitle && <p>{subtitle}</p>}
    </div>
    <div className="user-form-section__body">{children}</div>
  </section>
}

function ChoiceButton({ active, error, onClick, children, tone = 'signal' }) {
  return <button type="button" onClick={onClick} className={`user-choice-button tone-${tone} ${active ? 'is-active' : ''} ${error ? 'has-error' : ''}`}>
    <span className="user-choice-button__dot">{active ? '✓' : ''}</span>
    <span>{children}</span>
  </button>
}

export default function UserFormModal({ user, serverTargets = [], onClose, onSubmit, error, busy = false }) {
  const { t, dir } = useLang()
  const [form, setForm] = useState(() => ({ ...empty }))
  const [protocolError, setProtocolError] = useState(false)
  const [serverError, setServerError] = useState(false)

  useEffect(() => {
    if (user) {
      setForm({
        username: user.username, password: '',
        enable_l2tp: user.enable_l2tp, enable_pptp: user.enable_pptp,
        enable_openvpn: user.enable_openvpn, enable_sstp: user.enable_sstp,
        enable_ikev2: user.enable_ikev2, enable_openconnect: user.enable_openconnect,
        enable_vmess: !!user.enable_vmess, enable_vless: !!user.enable_vless,
        openvpn_auth_mode: user.openvpn_auth_mode || 'cert_only',
        sstp_auth_mode: user.sstp_auth_mode || 'password_only',
        quota_gb: user.quota_bytes ? +(user.quota_bytes / 1073741824).toFixed(2) : 0,
        max_devices: user.max_devices ?? 1,
        download_limit_mbps: user.download_limit_mbps || 0,
        upload_limit_mbps: user.upload_limit_mbps || 0,
        expire_mode: user.expire_mode || 'fixed', expire_date: user.expire_date || '',
        expire_after_days: user.expire_after_days || 30,
        is_active: user.is_active, note: user.note || '', server_targets: (() => { const raw = Array.isArray(user.server_targets) && user.server_targets.length ? user.server_targets : ['all']; const visible = new Set(serverTargets.map((item) => item.id)); if (raw.includes('all')) return serverTargets.length ? ['all'] : []; return raw.filter((item) => visible.has(item)); })(),
      })
    } else setForm({ ...empty, server_targets: [] })
    setProtocolError(false)
    setServerError(false)
  }, [user, serverTargets])

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }))
  const hasAnyProtocol = form.enable_l2tp || form.enable_pptp || form.enable_openvpn || form.enable_sstp || form.enable_ikev2 || form.enable_openconnect || form.enable_vmess || form.enable_vless
  const expireChoice = form.expire_mode === 'after_first_connect' ? 'after' : (form.expire_date ? 'fixed' : 'unlimited')
  const concreteServerIds = serverTargets.map((target) => target.id).filter(Boolean)
  const allServersSelected = concreteServerIds.length > 0 && (form.server_targets.includes('all') || concreteServerIds.every((id) => form.server_targets.includes(id)))
  const isServerSelected = (id) => form.server_targets.includes('all') || form.server_targets.includes(id)
  const toggleServer = (id) => {
    setForm((current) => {
      const expanded = current.server_targets.includes('all') ? [...concreteServerIds] : [...current.server_targets]
      const next = expanded.includes(id) ? expanded.filter((item) => item !== id) : [...expanded, id]
      if (next.length) setServerError(false)
      return { ...current, server_targets: next }
    })
  }
  const toggleAllServers = () => {
    setForm((current) => ({ ...current, server_targets: allServersSelected ? [] : ['all'] }))
    setServerError(allServersSelected)
  }

  const submit = (e) => {
    e.preventDefault()
    if (!hasAnyProtocol) { setProtocolError(true); return }
    if (!Array.isArray(form.server_targets) || !form.server_targets.length) { setServerError(true); return }
    setProtocolError(false)
    setServerError(false)
    const payload = { ...form }
    if (allServersSelected) payload.server_targets = ['all']
    if (payload.expire_mode === 'fixed') {
      payload.expire_after_days = null
      if (!payload.expire_date) payload.expire_date = null
    } else {
      payload.expire_date = null
      payload.expire_after_days = Number(payload.expire_after_days)
    }
    if (user && !payload.password) delete payload.password
    const nonNegativeNumber = (value) => {
      const parsed = Number(value)
      return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0
    }
    payload.quota_gb = nonNegativeNumber(payload.quota_gb)
    payload.max_devices = Math.trunc(nonNegativeNumber(payload.max_devices))
    payload.download_limit_mbps = Math.trunc(nonNegativeNumber(payload.download_limit_mbps))
    payload.upload_limit_mbps = Math.trunc(nonNegativeNumber(payload.upload_limit_mbps))
    onSubmit(payload)
  }

  const protocols = [
    ['enable_l2tp', 'L2TP/IPsec', 'signal'], ['enable_pptp', 'PPTP', 'violet'],
    ['enable_openvpn', 'OpenVPN', 'amber'], ['enable_sstp', 'SSTP', 'danger'],
    ['enable_ikev2', 'IKEv2/IPsec', 'sky'], ['enable_openconnect', 'OpenConnect', 'rose'],
    ['enable_vmess', 'VMess', 'violet'], ['enable_vless', 'VLESS', 'sky'],
  ].filter(([key]) => hasProtocol(key.replace('enable_', '')))

  const modal = (
    <div className="modal-backdrop user-form-backdrop" role="dialog" aria-modal="true">
      <div dir={dir} className={`modal-panel modal-scroll-shell user-form-modal max-w-5xl ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
        <header className="modal-sticky-header">
          <div>
            <h2 className="font-black text-sm sm:text-base">{user ? t('userFormEditTitle') : t('userFormNewTitle')}</h2>
            <p className="mt-1 text-[10px] text-muted">{t('userFormModalSubtitle')}</p>
          </div>
          <button type="button" onClick={onClose} disabled={busy} className="modal-close-button disabled:opacity-40 disabled:cursor-not-allowed" aria-label={t('userFormCancelBtn')}>✕</button>
        </header>

        <form onSubmit={submit} aria-busy={busy} className="modal-scroll-body p-3 sm:p-5">
          {error && <div className="mb-4 rounded-xl border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">{error}</div>}

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
            <Section title={t('userFormAccountSection')} subtitle={t('userFormAccountSectionHint')} className="xl:col-span-5">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="block min-w-0">
                  <span className="field-label">{t('userFormUsernameLabel')}</span>
                  <div className="credential-row">
                    <input className="field font-data" value={form.username} onChange={(e) => set('username', e.target.value.replace(/[^A-Za-z0-9_.-]/g, ''))} disabled={!!user} pattern="[A-Za-z0-9_.-]+" title={t('userFormUsernamePattern')} required />
                    {!user && <button type="button" onClick={() => set('username', generateRandomUsername())} className="modern-inline-action" title={t('userFormRandomUsernameTitle')}>{t('userFormRandomBtn')}</button>}
                  </div>
                </label>
                <label className="block min-w-0">
                  <span className="field-label">{t('userFormPasswordLabel')} {user && t('userFormPasswordNoChangeSuffix')}</span>
                  <div className="credential-row">
                    <input className="field font-data" value={form.password} onChange={(e) => set('password', e.target.value.replace(/[^A-Za-z0-9!@#$%^&*()_+\-=[\]{}:;,.<>?/~`|]/g, ''))} title={t('userFormPasswordPattern')} required={!user} />
                    <button type="button" onClick={() => set('password', generateRandomPassword())} className="modern-inline-action" title={t('userFormRandomPasswordTitle')}>{t('userFormRandomBtn')}</button>
                  </div>
                </label>
              </div>
              <button type="button" onClick={() => set('is_active', !form.is_active)} className={`user-status-toggle ${form.is_active ? 'is-active' : 'is-inactive'}`}>
                <span><b>{form.is_active ? t('userFormActiveStatus') : t('userFormInactiveStatus')}</b><small>{t('userFormStatusHint')}</small></span>
                <span className="user-status-switch"><i /></span>
              </button>
            </Section>

            <Section title={t('userFormAccessSection')} subtitle={t('userFormAccessSectionHint')} action={<button type="button" className="modern-mini-action" onClick={() => { const allSelected = protocols.every(([key]) => !!form[key]); setForm((current) => ({ ...current, ...Object.fromEntries(protocols.map(([key]) => [key, !allSelected])) })); if (!allSelected) setProtocolError(false) }}>{protocols.every(([key]) => !!form[key]) ? (dir === 'rtl' ? 'لغو انتخاب همه' : 'Clear all') : (dir === 'rtl' ? 'انتخاب همه' : 'Select all')}</button>} className="xl:col-span-7">
              <div className={`grid grid-cols-2 gap-2 ${protocols.length === 6 ? 'sm:grid-cols-3' : 'sm:grid-cols-4'}`}>
                {protocols.map(([key, label, tone]) => <ChoiceButton key={key} tone={tone} active={form[key]} error={protocolError} onClick={() => { const next = !form[key]; set(key, next); if (next) setProtocolError(false) }}>{label}</ChoiceButton>)}
              </div>
              {protocolError && <p className="mt-2 text-xs text-danger">{t('userFormProtocolRequiredError')}</p>}
              {(form.enable_openvpn || form.enable_sstp) && <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                {form.enable_openvpn && <div className="user-auth-card">
                  <span className="field-label">{t('userFormOpenvpnModeLabel')}</span>
                  <div className="grid grid-cols-2 gap-2">
                    <ChoiceButton active={form.openvpn_auth_mode === 'cert_only'} onClick={() => set('openvpn_auth_mode', 'cert_only')}>{t('userFormCertOnlyOption')}</ChoiceButton>
                    <ChoiceButton active={form.openvpn_auth_mode === 'cert_password'} onClick={() => set('openvpn_auth_mode', 'cert_password')}>{t('userFormCertPasswordOption')}</ChoiceButton>
                  </div>
                </div>}
                {form.enable_sstp && <div className="user-auth-card">
                  <span className="field-label">{t('userFormSstpModeLabel')}</span>
                  <div className="grid grid-cols-2 gap-2">
                    <ChoiceButton active={form.sstp_auth_mode === 'password_only'} onClick={() => set('sstp_auth_mode', 'password_only')}>{t('userFormPasswordOnlyOption')}</ChoiceButton>
                    <ChoiceButton active={form.sstp_auth_mode === 'cert_password'} onClick={() => set('sstp_auth_mode', 'cert_password')}>{t('userFormCertPasswordOption')}</ChoiceButton>
                  </div>
                </div>}
              </div>}
            </Section>

            <Section
              title={dir === 'rtl' ? 'سرورهای قابل استفاده' : 'Available servers'}
              subtitle={dir === 'rtl' ? 'مشخص کنید کانفیگ و دسترسی این کاربر روی کدام سرورها ساخته و همگام‌سازی شود.' : 'Choose which servers provision and expose this user configuration.'}
              action={<button type="button" className="modern-mini-action" onClick={toggleAllServers}>{allServersSelected ? (dir === 'rtl' ? 'لغو انتخاب همه' : 'Clear all') : (dir === 'rtl' ? 'انتخاب همه' : 'Select all')}</button>}
              className="xl:col-span-12"
            >
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
                {serverTargets.map((target) => {
                  const online = target.local || target.status === 'online'
                  const selected = isServerSelected(target.id)
                  return <button
                    key={target.id}
                    type="button"
                    aria-pressed={selected}
                    onClick={() => toggleServer(target.id)}
                    className={`user-server-target-card ${selected ? 'is-selected' : 'is-disabled'} ${serverError ? 'has-error' : ''}`}
                  >
                    <span className="user-server-target-card__identity">
                      <span className={`user-server-target-card__presence ${online ? 'is-online' : 'is-offline'}`} />
                      <span className="min-w-0">
                        <b className="block truncate">{target.name}</b>
                        <small className={online ? 'text-muted' : 'text-danger'}>{online ? (target.local ? (dir === 'rtl' ? 'همین سرور' : 'This server') : (dir === 'rtl' ? 'آنلاین' : 'Online')) : (dir === 'rtl' ? 'آفلاین' : 'Offline')}</small>
                      </span>
                    </span>
                    <span className="user-server-target-card__control">
                      <span className="user-server-target-card__state">
                        {selected
                          ? (dir === 'rtl' ? 'در کانفیگ نمایش داده می‌شود' : 'Shown in this user config')
                          : (dir === 'rtl' ? 'از کانفیگ حذف است' : 'Hidden from this user config')}
                      </span>
                      <span role="switch" aria-checked={selected} className={`modern-toggle ${selected ? 'is-on' : ''}`}><span /></span>
                    </span>
                  </button>
                })}
              </div>
              {serverError && <p className="mt-2 text-xs text-danger">{dir === 'rtl' ? 'حداقل یک سرور را انتخاب کنید.' : 'Select at least one server.'}</p>}
            </Section>

            <Section title={t('userFormLimitsSection')} subtitle={t('userFormLimitsSectionHint')} badge={t('userFormUnlimitedHint')} className="xl:col-span-7">
              <div className="user-metrics-grid">
                <label className="user-metric-card quota">
                  <span className="field-label">{t('userFormQuotaLabel')}</span>
                  <div className="user-metric-input">
                    <input dir="ltr" inputMode="decimal" aria-label={t('userFormQuotaLabel')} type="number" step="0.1" min="0" className="field font-data user-metric-number" value={form.quota_gb ?? 0} onChange={(e) => set('quota_gb', e.target.value)} placeholder="0" />
                    <span className="user-metric-unit">GB</span>
                  </div>
                </label>
                <label className="user-metric-card devices">
                  <span className="field-label">{t('userFormMaxDevicesLabel')}</span>
                  <div className="user-metric-input">
                    <input dir="ltr" inputMode="numeric" aria-label={t('userFormMaxDevicesLabel')} type="number" min="0" step="1" className="field font-data user-metric-number" value={form.max_devices ?? 0} onChange={(e) => set('max_devices', e.target.value)} placeholder="0" />
                    <span className="user-metric-unit">#</span>
                  </div>
                </label>
                <label className="user-metric-card download">
                  <span className="field-label">{t('userFormDownloadLimitLabel')}</span>
                  <div className="user-metric-input">
                    <span className="user-limit-icon" aria-hidden="true">↓</span>
                    <input dir="ltr" inputMode="numeric" aria-label={t('userFormDownloadLimitLabel')} type="number" min="0" step="1" className="field font-data user-metric-number" value={form.download_limit_mbps ?? 0} onChange={(e) => set('download_limit_mbps', e.target.value)} placeholder="0" />
                    <span className="user-metric-unit">Mbps</span>
                  </div>
                </label>
                <label className="user-metric-card upload">
                  <span className="field-label">{t('userFormUploadLimitLabel')}</span>
                  <div className="user-metric-input">
                    <span className="user-limit-icon" aria-hidden="true">↑</span>
                    <input dir="ltr" inputMode="numeric" aria-label={t('userFormUploadLimitLabel')} type="number" min="0" step="1" className="field font-data user-metric-number" value={form.upload_limit_mbps ?? 0} onChange={(e) => set('upload_limit_mbps', e.target.value)} placeholder="0" />
                    <span className="user-metric-unit">Mbps</span>
                  </div>
                </label>
              </div>
            </Section>

            <Section title={t('userFormExpirySection')} subtitle={t('userFormExpirySectionHint')} className="xl:col-span-5">
              <div className="user-expiry-choices">
                <ChoiceButton active={expireChoice === 'unlimited'} onClick={() => setForm((f) => ({ ...f, expire_mode: 'fixed', expire_date: '' }))}>{t('unlimitedExpiry')}</ChoiceButton>
                <ChoiceButton active={expireChoice === 'fixed'} onClick={() => setForm((f) => ({ ...f, expire_mode: 'fixed', expire_date: f.expire_date || todayIso() }))}>{t('userFormExpiryFixedOption')}</ChoiceButton>
                <ChoiceButton active={form.expire_mode === 'after_first_connect'} onClick={() => set('expire_mode', 'after_first_connect')}>{t('userFormExpiryAfterConnectOption')}</ChoiceButton>
              </div>
              <div className="mt-3">
                {form.expire_mode === 'fixed' && expireChoice === 'fixed' && <JalaliDatePicker value={form.expire_date || null} onChange={(iso) => set('expire_date', iso || '')} allowEmpty={false} />}
                {form.expire_mode === 'after_first_connect' && <input type="number" min="1" max="3650" className="field font-data" value={form.expire_after_days} onChange={(e) => set('expire_after_days', e.target.value)} placeholder={t('userFormExpiryAfterDaysPlaceholder')} required />}
              </div>
              <label className="mt-3 block"><span className="field-label">{t('userFormNoteLabel')}</span><textarea className="field min-h-[76px] resize-y" rows={2} value={form.note} onChange={(e) => set('note', e.target.value)} /></label>
            </Section>
          </div>

          <footer className="modal-actions mt-4">
            <button type="button" onClick={onClose} disabled={busy} className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed">{t('userFormCancelBtn')}</button>
            <button type="submit" disabled={busy} className="btn-primary disabled:opacity-70 disabled:cursor-wait">
              {busy && <span className="inline-block h-4 w-4 rounded-full border-2 border-white/40 border-t-white animate-spin" />}
              {busy ? (user ? t('savingChangesBusy') : t('creatingUserBusy')) : (user ? t('userFormSaveBtn') : t('userFormCreateBtn'))}
            </button>
          </footer>
        </form>
      </div>
    </div>
  )

  return ReactDOM.createPortal(modal, document.body)
}
