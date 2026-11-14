import React, { useEffect, useState } from 'react'
import * as ReactDOM from 'react-dom'
import { usePanelNavigate } from '../navigation.js'
import api from '../api'
import AdminFormModal from '../components/AdminFormModal.jsx'
import { formatJalaliDate } from '../jalali'
import { clearSession, getServerRole } from '../session'
import { useUI } from '../components/ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { Icon } from '../components/icons.jsx'
import AdminLicenseManager from '../components/AdminLicenseManager.jsx'
import { DomainCard } from './Settings.jsx'
import { UpdateCard } from './Backup.jsx'

function AccountCard() {
  const { withBusy } = useUI()
  const { t } = useLang()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newUsername, setNewUsername] = useState('')
  const [originalUsername, setOriginalUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmNewPassword, setConfirmNewPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const navigate = usePanelNavigate()

  useEffect(() => {
    api.get('/auth/me').then(({ data }) => { setNewUsername(data.username); setOriginalUsername(data.username) }).catch(() => {})
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    const usernameChanged = newUsername.trim() && newUsername.trim() !== originalUsername
    if (!usernameChanged && !newPassword) { setError('نام کاربری یا رمز جدیدی وارد نشده است.'); setLoading(false); return }
    if (newPassword && newPassword.length < 6) { setError('رمز جدید باید حداقل ۶ کاراکتر باشد.'); setLoading(false); return }
    if (newPassword !== confirmNewPassword) { setError('تکرار رمز جدید یکسان نیست.'); setLoading(false); return }
    setLoading(true)
    try {
      await withBusy(t('updatingAccountBusy'), () => api.put('/auth/me', {
        current_password: currentPassword,
        new_username: usernameChanged ? newUsername.trim() : undefined,
        new_password: newPassword || undefined,
      }))
      setSuccess(t('accountUpdatedSuccess'))
      // A username change invalidates the subject carried by the current JWT.
      // Log out immediately and use a hard navigation so no background /me
      // poll can overwrite the successful result with a stale-token error.
      window.setTimeout(() => {
        clearSession()
        window.location.assign('/login')
      }, 700)
    } catch (err) {
      setError(err.response?.data?.detail || t('accountUpdateError'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="panel-section p-5 space-y-4">
      <div className="text-sm font-bold text-ink">{t('accountCardTitle')}</div>
      {error && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{error}</div>}
      {success && <div className="bg-signal/10 border border-signal/30 text-signal text-sm rounded-lg px-3 py-2">{success}</div>}
      <form onSubmit={submit} className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('newUsernameLabel')}</label>
          <input
            className="field font-data"
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value.replace(/[^A-Za-z0-9_.-]/g, ''))}
            title={t('usernameTitle')}
          />
        </div>
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('newPasswordLabel')}</label>
          <input
            type="password"
            className="field font-data"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value.replace(/[^A-Za-z0-9!@#$%^&*()_+\-=[\]{}:;,.<>?/~`|]/g, ''))}
            title={t('passwordTitle')}
            autoComplete="new-password"
          />
        </div>
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">تکرار رمز جدید</label>
          <input
            type="password"
            className="field font-data"
            value={confirmNewPassword}
            onChange={(e) => setConfirmNewPassword(e.target.value.replace(/[^A-Za-z0-9!@#$%^&*()_+\-=[\]{}:;,.<>?/~`|]/g, ''))}
            autoComplete="new-password"
          />
        </div>
        <div>
          <label className="block text-xs text-muted mb-1.5 font-data">{t('currentPasswordLabel')}</label>
          <input
            type="password"
            className="field font-data"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </div>
        <button disabled={loading} className="btn-primary w-full">
          {loading ? t('savingChangesBusy') : t('btnSaveChanges')}
        </button>
      </form>
    </section>
  )
}

function NodeAccessCard() {
  const { notify, withBusy } = useUI()
  const { lang } = useLang()
  const fa = lang === 'fa'
  const [port, setPort] = useState('')
  const [currentUrl, setCurrentUrl] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    api.get('/settings/panel-port').then(({ data }) => {
      setPort(String(data.port || 8080))
      const host = data.domain_active && data.domain ? data.domain : window.location.hostname
      const scheme = data.domain_active ? 'https' : window.location.protocol.replace(':', '')
      const defaultPort = scheme === 'https' ? 443 : 80
      setCurrentUrl(`${scheme}://${host}${Number(data.port) === defaultPort ? '' : `:${data.port}`}`)
    }).catch((err) => notify({ type: 'error', message: err.response?.data?.detail || (fa ? 'دریافت پورت پنل ناموفق بود.' : 'Could not load panel port.') }))
      .finally(() => setLoading(false))
  }, [])

  const submit = async (event) => {
    event.preventDefault()
    const value = Number(port)
    if (!Number.isInteger(value) || value < 1 || value > 65535) {
      notify({ type: 'warning', message: fa ? 'پورت معتبر بین ۱ تا ۶۵۵۳۵ وارد کن.' : 'Enter a valid port from 1 to 65535.' }); return
    }
    setSaving(true)
    try {
      const { data } = await withBusy(fa ? 'در حال انتقال پنل نود به پورت جدید…' : 'Moving the node panel…', () => api.post('/settings/panel-port', { port: value }))
      const nextUrl = String(data.url || '').replace(/\/$/, '')
      setCurrentUrl(nextUrl)
      notify({ type: 'success', duration: 7000, message: fa ? `پورت تغییر کرد؛ پنل و آدرس ثبت‌شده نود به ${nextUrl} منتقل شد.` : `Panel and registered node URL moved to ${nextUrl}.` })
      window.setTimeout(() => window.location.assign(`${nextUrl}/admins`), 1200)
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || (fa ? 'تغییر پورت ناموفق بود.' : 'Port change failed.') })
    } finally { setSaving(false) }
  }

  return <section className="panel-section p-5 space-y-4">
    <div><div className="text-sm font-bold text-ink">{fa ? 'دسترسی محلی پنل نود' : 'Local node panel access'}</div><p className="mt-1 text-[11px] leading-5 text-muted">{fa ? 'پورت وب پنل را تغییر می‌دهد و آدرس نود را خودکار در پنل اصلی دوباره ثبت می‌کند. برای دامنه پشت Cloudflare از 443 یا 8443 استفاده کن.' : 'Changes the web port and automatically re-registers the node URL on the controller. Use 443 or 8443 behind Cloudflare.'}</p></div>
    <div dir="ltr" className="break-all rounded-xl border border-border bg-surface2 px-3 py-2 font-data text-xs text-signal">{currentUrl || '…'}</div>
    <form onSubmit={submit} className="space-y-3">
      <label className="block"><span className="field-label">{fa ? 'پورت جدید پنل نود' : 'New node panel port'}</span><input type="number" min="1" max="65535" className="field font-data" value={port} disabled={loading || saving} onChange={e => setPort(e.target.value)} /></label>
      <button disabled={loading || saving} className="btn-primary w-full">{saving ? '…' : (fa ? 'تغییر پورت و ثبت دوباره نود' : 'Change port and re-register')}</button>
    </form>
  </section>
}

function AdminsCard() {
  const { notify, withBusy, confirm } = useUI()
  const { t, dir } = useLang()
  const SECTION_LABELS = {
    dashboard: t('sectionDashboard'),
    users: t('sectionUsers'),
    online: t('sectionOnline'),
    settings: t('sectionSettings'),
  }
  const [admins, setAdmins] = useState([])
  const [serverTargets, setServerTargets] = useState([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingAdmin, setEditingAdmin] = useState(null)
  const [formError, setFormError] = useState('')
  const [listError, setListError] = useState('')
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [deleteUserAction, setDeleteUserAction] = useState('transfer')
  const [credentialResult, setCredentialResult] = useState(null)
  const [passwordTarget, setPasswordTarget] = useState(null)
  const [customPassword, setCustomPassword] = useState('')
  const [showCustomPassword, setShowCustomPassword] = useState(true)

  const load = async () => {
    setLoading(true)
    setListError('')
    try {
      const [{ data }, targetsResponse] = await Promise.all([api.get('/admins'), api.get('/admins/server-targets')])
      setAdmins(data)
      setServerTargets(Array.isArray(targetsResponse.data?.targets) ? targetsResponse.data.targets : [])
    } catch (err) {
      setListError(err.response?.data?.detail || t('adminsListError'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const openCreate = () => { setFormError(''); setEditingAdmin(null); setModalOpen(true) }
  const openEdit = (a) => { setFormError(''); setEditingAdmin(a); setModalOpen(true) }

  const submit = async (payload) => {
    setFormError('')
    try {
      await withBusy(editingAdmin ? t('savingChangesBusy') : t('creatingAdminBusy'), async () => {
        if (editingAdmin) {
          await api.put(`/admins/${editingAdmin.id}`, payload)
        } else {
          await api.post('/admins', payload)
        }
      })
      setModalOpen(false)
      load()
      notify({ type: 'success', message: editingAdmin ? t('changesSavedSuccess') : t('adminCreatedSuccess') })
    } catch (err) {
      const detail = err.response?.data?.detail
      const msg = Array.isArray(detail) ? detail.map((d) => d.msg).join('، ') : (detail || t('unknownError'))
      setFormError(msg)
    }
  }

  const viewAdminCredentials = async (a) => {
    try {
      const { data } = await withBusy(
        dir === 'rtl' ? `در حال دریافت اطلاعات ورود ${a.username}…` : `Loading credentials for ${a.username}…`,
        () => api.get(`/admins/${a.id}/credentials`, { skipInstantCache: true }),
      )
      setCredentialResult({ ...data, current: true, admin_id: a.id })
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || (dir === 'rtl' ? 'دریافت اطلاعات ورود ناموفق بود.' : 'Could not load credentials.') })
    }
  }

  const openPasswordEditor = (a) => {
    setPasswordTarget(a)
    setCustomPassword('')
    setShowCustomPassword(true)
  }

  const generatePassword = () => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-'
    const bytes = new Uint32Array(16)
    crypto.getRandomValues(bytes)
    setCustomPassword(Array.from(bytes, (value) => alphabet[value % alphabet.length]).join(''))
  }

  const saveAdminPassword = async () => {
    if (!passwordTarget) return
    if (customPassword.length < 6) {
      notify({ type: 'warning', message: dir === 'rtl' ? 'رمز باید حداقل ۶ کاراکتر انگلیسی باشد.' : 'Password must contain at least 6 characters.' })
      return
    }
    try {
      const { data } = await withBusy(
        dir === 'rtl' ? `در حال تغییر رمز ${passwordTarget.username}…` : `Changing password for ${passwordTarget.username}…`,
        () => api.put(`/admins/${passwordTarget.id}/password`, { password: customPassword }),
      )
      setPasswordTarget(null)
      setCustomPassword('')
      setCredentialResult({ ...data, current: true, changed: true, admin_id: passwordTarget.id })
      await load()
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || (dir === 'rtl' ? 'تغییر رمز ناموفق بود.' : 'Password change failed.') })
    }
  }

  const openAdminPanel = async (a) => {
    const popup = window.open('about:blank', '_blank')
    try {
      const { data } = await withBusy(
        dir === 'rtl' ? `در حال ورود به پنل ${a.username}…` : `Opening ${a.username} panel…`,
        () => api.post(`/admins/${a.id}/open-panel`),
      )
      if (popup) {
        popup.opener = null
        popup.location.replace(data.url)
      } else {
        window.location.assign(data.url)
      }
    } catch (err) {
      if (popup) popup.close()
      notify({ type: 'error', message: err.response?.data?.detail || (dir === 'rtl' ? 'ورود مستقیم ناموفق بود.' : 'Direct login failed.') })
    }
  }

  const resetAdminPassword = async (a) => {
    const ok = await confirm({
      title: dir === 'rtl' ? 'ساخت رمز جدید ادمین' : 'Generate new admin password',
      message: dir === 'rtl'
        ? `رمز فعلی ${a.username} قابل مشاهده نیست و با رمز جدید جایگزین می‌شود. ادامه می‌دهی؟`
        : `The current password for ${a.username} cannot be recovered and will be replaced. Continue?`,
      confirmLabel: dir === 'rtl' ? 'ساخت و نمایش رمز جدید' : 'Generate and show',
      danger: false,
    })
    if (!ok) return
    try {
      const { data } = await withBusy(
        dir === 'rtl' ? `در حال ساخت رمز جدید برای ${a.username}…` : `Generating a new password for ${a.username}…`,
        () => api.post(`/admins/${a.id}/reset-password`),
      )
      setCredentialResult({ ...data, current: true, changed: true, admin_id: a.id })
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || (dir === 'rtl' ? 'ساخت رمز جدید ناموفق بود.' : 'Could not generate a new password.') })
    }
  }

  const copyCredentialResult = async () => {
    if (!credentialResult) return
    const text = `Username: ${credentialResult.username}\nPassword: ${credentialResult.password}`
    try {
      await navigator.clipboard.writeText(text)
      notify({ type: 'success', message: dir === 'rtl' ? 'نام کاربری و رمز کپی شد.' : 'Username and password copied.' })
    } catch {
      notify({ type: 'error', message: dir === 'rtl' ? 'کپی خودکار ناموفق بود؛ دستی کپی کن.' : 'Automatic copy failed; copy it manually.' })
    }
  }

  const remove = (a) => {
    setDeleteUserAction('transfer')
    setDeleteTarget(a)
  }

  useEffect(() => {
    if (!deleteTarget) return undefined
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setDeleteTarget(null)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [deleteTarget])

  const confirmRemove = async () => {
    if (!deleteTarget) return
    const target = deleteTarget
    try {
      const { data } = await withBusy(
        `${t('deletingAdminBusyPrefix')}${target.username}${t('deletingAdminBusySuffix')}`,
        () => api.delete(`/admins/${target.id}`, { params: { user_action: deleteUserAction } }),
      )
      setDeleteTarget(null)
      await load()
      const affected = deleteUserAction === 'delete' ? (data?.deleted_users || 0) : (data?.transferred_users || 0)
      notify({
        type: 'success',
        message: deleteUserAction === 'delete'
          ? `${t('adminDeletedWithUsersSuccessPrefix')}${affected}${t('adminDeletedWithUsersSuccessSuffix')}`
          : `${t('adminDeletedTransferSuccessPrefix')}${affected}${t('adminDeletedTransferSuccessSuffix')}`,
      })
      if (Array.isArray(data?.cleanup_warnings) && data.cleanup_warnings.length) {
        notify({ type: 'error', duration: 9000, message: `${t('adminDeleteCleanupWarning')} ${data.cleanup_warnings.join(' | ')}` })
      }
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || t('adminDeleteError') })
    }
  }

  return (
    <section className="panel-section p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-bold text-ink">{t('manageAdminsTitle')}</div>
        </div>
        <button onClick={openCreate} className="btn-primary !px-3 !py-2 text-xs"><Icon name="plus" size={14}/>{t('btnNewAdmin')}</button>
      </div>

      {listError && <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">{listError}</div>}

      <div className="space-y-1.5">
        {loading && <div className="text-center py-4 text-muted text-sm">{t('loadingAdminsList')}</div>}
        {!loading && admins.length === 0 && <div className="text-center py-4 text-muted text-sm">{t('noAdminsFound')}</div>}
        {admins.map((a) => (
          <div key={a.id} className="flex items-start justify-between flex-wrap gap-3 rounded-xl border border-border bg-surface2 px-4 py-3.5">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-sm flex-wrap">
                <span className="font-data text-ink">{a.username}</span>
                {a.role === 'superadmin' ? (
                  <span className="text-xs text-signal">{t('mainAdminLabel')}</span>
                ) : (
                  <span className="text-xs text-muted">{t('subAdminLabel')}</span>
                )}
                {!a.is_active && <span className="text-xs text-danger">{t('inactiveLabel')}</span>}
              </div>
              <div className="mt-1.5 text-xs font-data text-muted">
                {dir === 'rtl' ? 'آخرین ورود' : 'Last login'}: <span className="text-ink">{a.last_login_at_display || (dir === 'rtl' ? 'بدون ورود' : 'Never')}</span>
              </div>
              {a.role === 'admin' && <div className={`mt-1 text-[10px] ${a.credential_saved ? 'text-signal' : 'text-warning'}`}>{a.credential_saved ? (dir === 'rtl' ? 'رمز قابل مشاهده است' : 'Password is available') : (dir === 'rtl' ? 'رمز قدیمی هنوز وارد خزانه نشده' : 'Legacy password is not in the vault yet')}</div>}
              {a.role === 'admin' && (
                <div className="text-xs font-data mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
                  <span className="text-muted">
                    {t('userStatLabel')}: <span className="text-ink">{a.used_users}/{a.max_users ?? '∞'}</span>
                  </span>
                  <span className="text-muted">
                    {t('quotaStatLabel')}: <span className="text-ink">{a.used_total_quota_gb}/{a.max_total_quota_gb ?? '∞'} GB</span>
                  </span>
                  {a.subscription_expire_date && (
                    <span className={a.subscription_expired ? 'text-danger' : 'text-muted'}>
                      {t('expiryStatLabel')}: {formatJalaliDate(a.subscription_expire_date)}
                    </span>
                  )}
                  {a.managed_by_license && a.access_license_code && (
                    <span className="text-muted">{t('navLicense')}: <span dir="ltr" className="text-ink">{a.access_license_code}</span></span>
                  )}
                </div>
              )}
            </div>
            <div className="admin-row-actions">
              {a.role === 'admin' && <button onClick={() => openAdminPanel(a)} className="btn-primary !px-2.5 !py-1.5 text-[10px]"><Icon name="external" size={13}/>{dir === 'rtl' ? 'ورود به پنل' : 'Open panel'}</button>}
              {a.role === 'admin' && <button onClick={() => viewAdminCredentials(a)} className="btn-secondary !px-2.5 !py-1.5 text-[10px]"><Icon name="eye" size={13}/>{dir === 'rtl' ? 'مشاهده ورود' : 'View login'}</button>}
              {a.role === 'admin' && <button onClick={() => openPasswordEditor(a)} className="btn-secondary !px-2.5 !py-1.5 text-[10px]">{dir === 'rtl' ? 'تغییر رمز' : 'Change password'}</button>}
              <button onClick={() => openEdit(a)} className="btn-secondary !px-2.5 !py-1.5 text-[10px]">{t('btnEdit')}</button>
              {a.role === 'admin' && <button onClick={() => resetAdminPassword(a)} className="btn-secondary !px-2.5 !py-1.5 text-[10px]">{dir === 'rtl' ? 'رمز تصادفی' : 'Random password'}</button>}
              <button onClick={() => remove(a)} className="btn-danger !px-2.5 !py-1.5 text-[10px]">{t('btnDelete')}</button>
            </div>
          </div>
        ))}
      </div>

      {modalOpen && (
        <AdminFormModal admin={editingAdmin} serverTargets={serverTargets} onClose={() => setModalOpen(false)} onSubmit={submit} error={formError} />
      )}

      {credentialResult && ReactDOM.createPortal(
        <div className="modal-backdrop !z-[150] px-3 py-4" onMouseDown={(event) => { if (event.target === event.currentTarget) setCredentialResult(null) }}>
          <div dir={dir} className="modal-panel w-full max-w-md p-0 overflow-hidden" onMouseDown={(event) => event.stopPropagation()}>
            <div className="flex items-center justify-between gap-3 border-b border-border bg-surface2/70 px-5 py-4">
              <div>
                <div className="text-base font-bold text-ink">{credentialResult.changed ? (dir === 'rtl' ? 'رمز ادمین تغییر کرد' : 'Admin password changed') : (dir === 'rtl' ? 'اطلاعات ورود ادمین' : 'Admin credentials')}</div>
                <div className="mt-1 text-[11px] text-warning">{credentialResult.available ? (dir === 'rtl' ? 'این اطلاعات از خزانه رمزگذاری‌شده خوانده شده است.' : 'Loaded from the encrypted credential vault.') : (dir === 'rtl' ? 'رمز قدیمی از هش قابل بازیابی نیست.' : 'The legacy password cannot be recovered from its hash.')}</div>
              </div>
              <button type="button" onClick={() => setCredentialResult(null)} className="modal-close-button"><Icon name="close" size={18} /></button>
            </div>
            <div className="space-y-3 p-5">
              <label className="block">
                <span className="field-label">{dir === 'rtl' ? 'نام کاربری' : 'Username'}</span>
                <div dir="ltr" className="credential-reveal-value">{credentialResult.username}</div>
              </label>
              <label className="block">
                <span className="field-label">{dir === 'rtl' ? 'رمز جدید' : 'New password'}</span>
                <div dir="ltr" className="credential-reveal-value is-password">{credentialResult.available ? credentialResult.password : '—'}</div>
              </label>
              <div className="rounded-xl border border-warning/30 bg-warning/10 px-3 py-2 text-[11px] leading-5 text-warning">
                {credentialResult.available ? (dir === 'rtl' ? 'فقط سوپرادمین می‌تواند این مقدار را از خزانه رمزگذاری‌شده ببیند.' : 'Only the superadmin can reveal this encrypted-vault value.') : (dir === 'rtl' ? 'برای این حساب یک رمز جدید تعیین کن یا منتظر اولین ورودش بعد از آپدیت بمان تا رمز فعلی وارد خزانه شود.' : 'Set a new password, or wait for the first successful login after the update to populate the vault.')}
              </div>
            </div>
            <div className="flex flex-col-reverse gap-2 border-t border-border bg-surface2/60 px-5 py-4 sm:flex-row sm:justify-end">
              <button type="button" onClick={() => setCredentialResult(null)} className="btn-secondary">{dir === 'rtl' ? 'بستن' : 'Close'}</button>
              {!credentialResult.available && <button type="button" onClick={() => { const target = admins.find((item) => item.id === credentialResult.admin_id); setCredentialResult(null); if (target) openPasswordEditor(target) }} className="btn-primary">{dir === 'rtl' ? 'تعیین رمز جدید' : 'Set new password'}</button>}
              {credentialResult.available && <button type="button" onClick={copyCredentialResult} className="btn-primary"><Icon name="copy" size={15} />{dir === 'rtl' ? 'کپی نام کاربری و رمز' : 'Copy credentials'}</button>}
            </div>
          </div>
        </div>,
        document.body,
      )}

      {passwordTarget && ReactDOM.createPortal(
        <div className="modal-backdrop !z-[155] px-3 py-4" onMouseDown={(event) => { if (event.target === event.currentTarget) setPasswordTarget(null) }}>
          <div dir={dir} className="modal-panel w-full max-w-md p-0 overflow-hidden" onMouseDown={(event) => event.stopPropagation()}>
            <div className="flex items-center justify-between gap-3 border-b border-border bg-surface2/70 px-5 py-4">
              <div><div className="text-base font-bold text-ink">{dir === 'rtl' ? `تغییر رمز ${passwordTarget.username}` : `Change ${passwordTarget.username} password`}</div><div className="mt-1 text-[11px] text-muted">{dir === 'rtl' ? 'رمز جدید جای رمز قبلی را می‌گیرد و در خزانه رمزگذاری‌شده ذخیره می‌شود.' : 'The new password replaces the old one and is saved in the encrypted vault.'}</div></div>
              <button type="button" onClick={() => setPasswordTarget(null)} className="modal-close-button"><Icon name="close" size={18}/></button>
            </div>
            <div className="space-y-3 p-5">
              <label className="block"><span className="field-label">{dir === 'rtl' ? 'نام کاربری' : 'Username'}</span><div dir="ltr" className="credential-reveal-value">{passwordTarget.username}</div></label>
              <label className="block"><span className="field-label">{dir === 'rtl' ? 'رمز جدید' : 'New password'}</span><input dir="ltr" type={showCustomPassword ? 'text' : 'password'} className="field font-data" value={customPassword} onChange={(event) => setCustomPassword(event.target.value.replace(/[^A-Za-z0-9!@#$%^&*()_+\-=[\]{}:;,.<>?/~`|]/g, ''))} autoComplete="new-password" /></label>
              <div className="flex flex-wrap gap-2"><button type="button" onClick={generatePassword} className="btn-secondary text-xs">{dir === 'rtl' ? 'ساخت رمز قوی' : 'Generate strong password'}</button><button type="button" onClick={() => setShowCustomPassword((value) => !value)} className="btn-secondary text-xs">{showCustomPassword ? (dir === 'rtl' ? 'مخفی‌کردن' : 'Hide') : (dir === 'rtl' ? 'نمایش' : 'Show')}</button></div>
            </div>
            <div className="flex flex-col-reverse gap-2 border-t border-border bg-surface2/60 px-5 py-4 sm:flex-row sm:justify-end"><button type="button" onClick={() => setPasswordTarget(null)} className="btn-secondary">{dir === 'rtl' ? 'انصراف' : 'Cancel'}</button><button type="button" onClick={saveAdminPassword} className="btn-primary">{dir === 'rtl' ? 'ذخیره و نمایش رمز' : 'Save and reveal'}</button></div>
          </div>
        </div>,
        document.body,
      )}

      {deleteTarget && ReactDOM.createPortal(
        <div
          className="modal-backdrop !z-[140] px-3 py-4"
          onMouseDown={(event) => { if (event.target === event.currentTarget) setDeleteTarget(null) }}
        >
          <div
            dir={dir}
            className="modal-panel w-full max-w-xl p-0 overflow-hidden animate-[fadeIn_.15s_ease-out]"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-border bg-surface2/70">
              <div>
                <div className="text-base font-bold text-ink">{t('deleteAdminChoiceTitle')}</div>
                <div className="text-xs text-muted mt-1">
                  {t('deleteAdminChoiceSubtitlePrefix')}
                  <span className="font-data text-ink mx-1">{deleteTarget.username}</span>
                  {t('deleteAdminChoiceSubtitleSuffix')}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                className="modal-close-button shrink-0"
                aria-label={t('btnCancel')}
              >
                <Icon name="close" size={18} />
              </button>
            </div>

            <div className="p-5 space-y-3">
              <button
                type="button"
                onClick={() => setDeleteUserAction('transfer')}
                className={`w-full rounded-2xl border p-4 text-start transition-all ${
                  deleteUserAction === 'transfer'
                    ? 'border-signal bg-signal/10 shadow-[0_0_0_1px_rgba(255,107,0,.18)]'
                    : 'border-border bg-surface2 hover:border-signal/40'
                }`}
              >
                <div className="flex items-start gap-3">
                  <span className={`mt-0.5 w-5 h-5 rounded-full border flex items-center justify-center shrink-0 ${deleteUserAction === 'transfer' ? 'border-signal bg-signal' : 'border-border'}`}>
                    {deleteUserAction === 'transfer' && <span className="w-2 h-2 rounded-full bg-white" />}
                  </span>
                  <span className="min-w-0">
                    <span className="block text-sm font-bold text-ink">{t('deleteAdminTransferUsersTitle')}</span>
                    <span className="block text-xs text-muted leading-relaxed mt-1">
                      {t('deleteAdminTransferUsersDescPrefix')}
                      <span className="font-data text-ink mx-1">{deleteTarget.used_users || 0}</span>
                      {t('deleteAdminTransferUsersDescSuffix')}
                    </span>
                  </span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setDeleteUserAction('delete')}
                className={`w-full rounded-2xl border p-4 text-start transition-all ${
                  deleteUserAction === 'delete'
                    ? 'border-danger bg-danger/10 shadow-[0_0_0_1px_rgba(239,68,68,.18)]'
                    : 'border-border bg-surface2 hover:border-danger/40'
                }`}
              >
                <div className="flex items-start gap-3">
                  <span className={`mt-0.5 w-5 h-5 rounded-full border flex items-center justify-center shrink-0 ${deleteUserAction === 'delete' ? 'border-danger bg-danger' : 'border-border'}`}>
                    {deleteUserAction === 'delete' && <span className="w-2 h-2 rounded-full bg-white" />}
                  </span>
                  <span className="min-w-0">
                    <span className="block text-sm font-bold text-danger">{t('deleteAdminDeleteUsersTitle')}</span>
                    <span className="block text-xs text-muted leading-relaxed mt-1">
                      {t('deleteAdminDeleteUsersDescPrefix')}
                      <span className="font-data text-danger mx-1">{deleteTarget.used_users || 0}</span>
                      {t('deleteAdminDeleteUsersDescSuffix')}
                    </span>
                  </span>
                </div>
              </button>

              {deleteUserAction === 'delete' && (
                <div className="rounded-xl border border-danger/30 bg-danger/10 px-3.5 py-3 text-xs text-danger leading-relaxed">
                  {t('deleteAdminPermanentWarning')}
                </div>
              )}
            </div>

            <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-2 px-5 py-4 border-t border-border bg-surface2/60">
              <button type="button" onClick={() => setDeleteTarget(null)} className="btn-secondary sm:min-w-28">
                {t('btnCancel')}
              </button>
              <button
                type="button"
                onClick={confirmRemove}
                className={deleteUserAction === 'delete' ? 'btn-danger sm:min-w-44' : 'btn-primary sm:min-w-44'}
              >
                {deleteUserAction === 'delete' ? t('deleteAdminAndUsersBtn') : t('transferUsersAndDeleteBtn')}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )}
    </section>
  )
}

function AdminsInner() {
  const { dir, t, lang } = useLang()
  const nodeMode = getServerRole() === 'node'
  return (
    <div dir={dir} className={`space-y-6 ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
      <header>
        <h1 className="page-heading">{nodeMode ? (lang === 'fa' ? 'حساب ادمین نود' : 'Node admin account') : t('adminsTitle')}</h1>
        <p className="page-subtitle">{nodeMode ? (lang === 'fa' ? 'فقط نام کاربری و رمز همین ادمین را تغییر بده.' : 'Change only the current node administrator username and password.') : t('adminsPageSubtitle')}</p>
      </header>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
        <AccountCard />
        {!nodeMode && <AdminsCard />}
        {!nodeMode && <AdminLicenseManager />}
      </div>
    </div>
  )
}

export default function Admins() {
  return <AdminsInner />
}
