import React, { useEffect, useRef, useState } from 'react'
import api from '../api'
import ProtocolBadge from '../components/ProtocolBadge.jsx'
import UserFormModal from '../components/UserFormModal.jsx'
import BulkUserIncreaseModal from '../components/BulkUserIncreaseModal.jsx'
import { formatJalaliDate } from '../jalali'
import { useUI } from '../components/ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { Icon } from '../components/icons.jsx'
import { hasPermission, hasProtocol } from '../permissions.js'
import { formatBytes as fmtBytes } from '../utils/formatBytes.js'


function enabledProtocols(user) {
  const items = []
  if (user.enable_l2tp) items.push('l2tp')
  if (user.enable_pptp) items.push('pptp')
  if (user.enable_openvpn) items.push('openvpn')
  if (user.enable_sstp) items.push('sstp')
  if (user.enable_ikev2) items.push('ikev2')
  if (user.enable_openconnect) items.push('openconnect')
  if (user.enable_vmess) items.push('vmess')
  if (user.enable_vless) items.push('vless')
  return items.filter(hasProtocol)
}

function ProtocolList({ user }) {
  const items = enabledProtocols(user)
  if (!items.length) return <span className="text-muted">—</span>
  const columns = Math.min(3, Math.max(1, items.length))
  return (
    <div className="user-protocol-layout" style={{ '--protocol-columns': columns }}>
      {items.map(protocol => <ProtocolBadge key={protocol} protocol={protocol} />)}
    </div>
  )
}

function UserOnlineDot({ user }) {
  if (!user.is_online) return null
  return <span className="user-name-online-dot" aria-label="Online" title="Online" />
}

function ConnectionState({ user, dir, compact = false }) {
  const onlineLabel = dir === 'rtl' ? 'آنلاین' : 'Online'
  const offlineLabel = dir === 'rtl' ? 'آفلاین' : 'Offline'
  const neverLabel = dir === 'rtl' ? 'بدون اتصال' : 'Never connected'
  if (user.is_online) {
    return <span className="connection-state connection-state--online"><span className="connection-state__label" dir={dir}>{onlineLabel}</span></span>
  }
  return (
    <div className={`connection-state-stack ${compact ? 'is-compact' : ''}`}>
      <span className="connection-state connection-state--offline">{offlineLabel}</span>
      <span dir="ltr" className="connection-state__time" title={user.last_connection_at_display || neverLabel}>
        {user.last_connection_at_display || neverLabel}
      </span>
    </div>
  )
}

function RowActionButton({ allowed, onClick, title, lockedTitle, danger = false, icon, tone = 'default', busy = false }) {
  const disabled = !allowed || busy
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={disabled ? undefined : onClick}
      title={disabled ? lockedTitle : title}
      aria-label={disabled ? lockedTitle : title}
      className={`icon-button user-action-button user-action-button--${tone} ${danger ? 'is-danger' : ''} ${!allowed ? 'is-locked' : ''} ${busy ? 'is-refreshing' : ''}`}
    >
      <Icon name={busy ? 'refresh' : (!allowed ? 'lock' : icon)} size={14} />
    </button>
  )
}

function CompactSpeed({ user, unlimitedLabel }) {
  const download = Number(user.download_limit_mbps || 0)
  const upload = Number(user.upload_limit_mbps || 0)
  if (!download && !upload) return <span className="text-muted">{unlimitedLabel}</span>
  return (
    <div className="user-speed-compact" dir="ltr" title={`Download: ${download || '∞'} Mbps | Upload: ${upload || '∞'} Mbps`}>
      <span className="download">↓{download || '∞'}</span>
      <span className="divider">/</span>
      <span className="upload">↑{upload || '∞'}</span>
      <span className="unit">Mbps</span>
    </div>
  )
}

function UsersInner() {
  const { confirm, notify, withBusy } = useUI()
  const { dir, t } = useLang()
  const [users, setUsers] = useState([])
  const [serverTargets, setServerTargets] = useState([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const [search, setSearch] = useState('')
  const [formError, setFormError] = useState('')
  const [formBusy, setFormBusy] = useState(false)
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkBusy, setBulkBusy] = useState(false)
  const [bulkError, setBulkError] = useState('')
  const [listError, setListError] = useState('')
  const [refreshingUserIds, setRefreshingUserIds] = useState(() => new Set())
  const inFlight = useRef(false)
  const usersSignature = useRef('')

  const loadServerTargets = async () => {
    try {
      const { data } = await api.get('/users/server-targets')
      const targets = Array.isArray(data?.targets) ? data.targets : []
      setServerTargets(targets)
    } catch { /* keep local fallback; user list must still remain usable */ }
  }

  const load = async (silent = false) => {
    if (inFlight.current) return
    inFlight.current = true
    if (!silent) setLoading(true)
    setListError('')
    try {
      const { data } = await api.get('/users')
      const signature = JSON.stringify(data)
      if (signature !== usersSignature.current) {
        usersSignature.current = signature
        setUsers(data)
      }
    } catch (err) {
      if (!silent) setListError(err.response?.data?.detail || t('loadUsersError'))
    } finally {
      inFlight.current = false
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    load()
    loadServerTargets()
  }, [])

  const openCreate = () => { setFormError(''); setEditingUser(null); setModalOpen(true) }
  const openEdit = (u) => { setFormError(''); setEditingUser(u); setModalOpen(true) }

  const submit = async (payload) => {
    if (formBusy) return
    setFormError('')
    setFormBusy(true)
    try {
      // User-edit daemon synchronization is completed by the backend in the
      // background. Keep a finite client timeout as a final guard so a broken
      // proxy can never leave this modal frozen indefinitely.
      const { data: savedUser } = editingUser
        ? await api.put(`/users/${editingUser.id}`, payload, { timeout: 15000 })
        : await api.post('/users', payload, { timeout: 15000 })

      // Close immediately from the response we already have. Do not keep the
      // dialog open while waiting for the next list refresh or a slow proxy.
      setUsers((current) => {
        const exists = current.some((item) => item.id === savedUser.id)
        const next = exists
          ? current.map((item) => item.id === savedUser.id ? savedUser : item)
          : [savedUser, ...current]
        usersSignature.current = JSON.stringify(next)
        return next
      })
      setModalOpen(false)
      notify({ type: 'success', message: editingUser ? t('changesSavedSuccess') : t('userCreatedSuccess') })
      void load(true)
    } catch (err) {
      const detail = err.response?.data?.detail
      const timeoutMessage = dir === 'rtl'
        ? 'پاسخ ذخیره‌سازی بیش از حد طول کشید. تغییرات را دوباره بررسی کنید و مجدداً ذخیره بزنید.'
        : 'Saving took too long. Check the current values and try saving again.'
      const msg = err.code === 'ECONNABORTED'
        ? timeoutMessage
        : Array.isArray(detail)
          ? detail.map((d) => d.msg).join('، ')
          : (detail || t('unknownSaveUserError'))
      setFormError(msg)
    } finally {
      setFormBusy(false)
    }
  }

  const remove = async (u) => {
    const ok = await confirm({
      title: t('deleteUserTitle'),
      message: `${t('deleteUserMessagePrefix')}${u.username}${t('deleteUserMessageSuffix')}`,
      confirmLabel: t('deleteUserConfirmBtn'),
      danger: true,
    })
    if (!ok) return
    try {
      await withBusy(`${t('deletingUserBusyPrefix')}${u.username}${t('deletingUserBusySuffix')}`, () => api.delete(`/users/${u.id}`))
      load()
      notify({ type: 'success', message: `${t('userDeletedSuccessPrefix')}${u.username}${t('userDeletedSuccessSuffix')}` })
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || t('deleteUserError') })
    }
  }

  const resetUsage = async (u) => {
    try {
      await withBusy(`${t('resettingUsageBusyPrefix')}${u.username}${t('resettingUsageBusySuffix')}`, () => api.post(`/users/${u.id}/reset-usage`))
      load()
      notify({ type: 'success', message: `${t('usageResetSuccessPrefix')}${u.username}${t('usageResetSuccessSuffix')}` })
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || t('resetUsageError') })
    }
  }

  const refreshUserStatus = async (u) => {
    if (refreshingUserIds.has(u.id)) return
    setRefreshingUserIds((current) => new Set(current).add(u.id))
    try {
      const { data } = await api.get(`/users/${u.id}`, { timeout: 10000 })
      const refreshedUser = data?.user && typeof data.user === 'object' ? data.user : data
      if (!refreshedUser || typeof refreshedUser !== 'object' || refreshedUser.id == null) {
        throw new Error(dir === 'rtl' ? 'پاسخ وضعیت کاربر معتبر نیست' : 'Invalid user status response')
      }
      setUsers((current) => {
        const next = current.map((item) => item.id === refreshedUser.id ? refreshedUser : item)
        usersSignature.current = JSON.stringify(next)
        return next
      })
      notify({
        type: 'success',
        message: dir === 'rtl'
          ? `وضعیت ${u.username} به‌روزرسانی شد`
          : `${u.username} status refreshed`,
      })
    } catch (err) {
      notify({
        type: 'error',
        message: err.response?.data?.detail || (dir === 'rtl' ? 'به‌روزرسانی وضعیت کاربر ناموفق بود' : 'Could not refresh user status'),
      })
    } finally {
      setRefreshingUserIds((current) => { const next = new Set(current); next.delete(u.id); return next })
    }
  }


  const submitBulkIncrease = async (payload) => {
    setBulkError('')
    setBulkBusy(true)
    try {
      const { data } = await api.post('/users/bulk-increase', payload)
      setBulkOpen(false)
      await load()
      notify({
        type: 'success',
        message: `${t('bulkIncreaseSuccessPrefix')}${data.matched}${t('bulkIncreaseSuccessSuffix')} ${data.reactivated ? `— ${data.reactivated} ${t('bulkIncreaseReactivatedSuffix')}` : ''}`.trim(),
      })
    } catch (err) {
      const detail = err.response?.data?.detail
      setBulkError(Array.isArray(detail) ? detail.map((item) => item.msg).join('، ') : (detail || t('bulkIncreaseError')))
    } finally {
      setBulkBusy(false)
    }
  }

  const openSubLink = (u) => {
    if (!u.sub_link) {
      notify({ type: 'error', message: t('subLinkNotReadyError') })
      return
    }
    const link = document.createElement('a')
    link.href = u.sub_link
    link.target = '_blank'
    link.rel = 'noopener noreferrer'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const copySubLink = async (u) => {
    if (!u.sub_link) {
      notify({ type: 'error', message: t('subLinkNotReadyError') })
      return
    }
    try {
      await navigator.clipboard.writeText(u.sub_link)
      notify({ type: 'success', message: `${t('subLinkCopiedSuccessPrefix')}${u.username}${t('subLinkCopiedSuccessSuffix')}` })
    } catch (err) {
      // fallback برای مرورگرهایی که navigator.clipboard را (مثلاً روی HTTP غیر localhost) اجازه نمی‌دهند
      const ta = document.createElement('textarea')
      ta.value = u.sub_link
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.focus()
      ta.select()
      try {
        document.execCommand('copy')
        notify({ type: 'success', message: `${t('subLinkCopiedSuccessPrefix')}${u.username}${t('subLinkCopiedSuccessSuffix')}` })
      } catch (e2) {
        notify({ type: 'error', message: t('subLinkCopyError') })
      }
      document.body.removeChild(ta)
    }
  }



  const filtered = users.filter((u) => u.username.toLowerCase().includes(search.toLowerCase()))
  // این ستون فقط وقتی نشان داده می‌شود که یوزرهای بیش از یک ادمین توی لیست
  // باشند (یعنی ادمین اصلی یا ادمین با دسترسی «کل یوزرهای سرور» است)؛ برای
  // یک ادمین معمولی که فقط یوزرهای خودش را می‌بیند، این ستون بی‌فایده است.
  const showOwnerColumn = new Set(filtered.map((u) => u.owner_admin_username || '—')).size > 1

  return (
    <div dir={dir} className={`space-y-5 ${dir === 'ltr' ? 'text-left' : 'text-right'}`}>
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="page-heading">{t('usersPageTitle')}</h1><p className="page-subtitle">{t('usersPageSubtitle')}</p></div>
        <div className="users-page-actions">
          {hasPermission('users:edit', 'users') && <button onClick={() => { setBulkError(''); setBulkOpen(true) }} className="btn-secondary users-bulk-button"><span className="users-bulk-button__icon">＋</span>{t('bulkIncreaseButton')}</button>}
          {hasPermission('users:create', 'users') && <button onClick={openCreate} className="btn-primary"><Icon name="plus" size={16}/>{t('newUserBtn')}</button>}
        </div>
      </header>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-surface p-3">
        <div className="relative w-full max-w-sm"><Icon name="search" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input placeholder={t('searchUsernamePlaceholder')} value={search} onChange={(e) => setSearch(e.target.value)} className="field ps-9 font-data" /></div>
        <span className="status-pill status-neutral">{filtered.length} / {users.length}</span>
      </div>

      {listError && (
        <div className="bg-danger/10 border border-danger/30 text-danger text-sm rounded-lg px-3 py-2">
          {listError}
        </div>
      )}

      <section className="panel-section">
        <div className="users-table-scroll">
          <table className="users-data-table w-full text-sm" data-owner-column={showOwnerColumn ? '1' : '0'}>
            <colgroup>
              <col className="users-col-user" />
              {showOwnerColumn && <col className="users-col-admin" />}
              <col className="users-col-protocols" />
              <col className="users-col-max" />
              <col className="users-col-speed" />
              <col className="users-col-usage" />
              <col className="users-col-expiry" />
              <col className="users-col-connection" />
              <col className="users-col-account" />
              <col className="users-col-actions" />
            </colgroup>
            <thead className="bg-surface2 text-muted text-xs">
              <tr>
                <th className="text-center px-4 py-3 font-data">{t('colUser')}</th>
                {showOwnerColumn && <th className="text-center px-4 py-3 font-data">{t('colAdmin')}</th>}
                <th className="text-center px-4 py-3 font-data">{t('colProtocols')}</th>
                <th className="text-center px-4 py-3 font-data">{t('colMaxUsers')}</th>
                <th className="text-center px-4 py-3 font-data">{t('colSpeedLimit')}</th>
                <th className="text-center px-4 py-3 font-data">{t('colUsage')}</th>
                <th className="text-center px-4 py-3 font-data">{t('colExpiry')}</th>
                <th className="text-center px-4 py-3 font-data">{dir === 'rtl' ? 'وضعیت اتصال' : 'Connection'}</th>
                <th className="text-center px-4 py-3 font-data">{dir === 'rtl' ? 'وضعیت حساب' : 'Account status'}</th>
                <th className="text-center px-4 py-3 font-data">{t('colActions')}</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={showOwnerColumn ? 10 : 9} className="text-center py-8 text-muted">{t('loadingUsersRow')}</td></tr>
              )}
              {!loading && filtered.length === 0 && (
                <tr><td colSpan={showOwnerColumn ? 10 : 9} className="text-center py-8 text-muted">{t('noUsersFound')}</td></tr>
              )}
              {filtered.map((u) => (
                <tr key={u.id} className="border-t border-border hover:bg-surface2/50">
                  <td className="user-cell user-cell--username px-3 py-3">
                    <div className="user-name-with-presence">
                      <UserOnlineDot user={u} />
                      <span dir="ltr" className="user-card-username font-data" title={u.username}>{u.username}</span>
                    </div>
                  </td>
                  {showOwnerColumn && (
                    <td className="user-cell user-cell--admin px-3 py-3 font-data text-xs text-muted text-center"><span className="user-cell__truncate" title={u.owner_admin_username || '—'}>{u.owner_admin_username || '—'}</span></td>
                  )}
                  <td className="user-cell user-cell--protocols px-3 py-3 text-center">
                    <ProtocolList user={u} />
                  </td>
                  <td className="user-cell user-cell--max px-3 py-3 font-data text-xs text-center">
                    {u.max_devices > 0 ? u.max_devices : t('unlimitedDevices')}
                  </td>
                  <td className="user-cell user-cell--speed px-3 py-3 font-data text-xs text-center">
                    <CompactSpeed user={u} unlimitedLabel={t('speedLimitUnlimited')} />
                  </td>
                  <td className="user-cell user-cell--usage px-3 py-3 font-data text-xs text-center">
                    {fmtBytes(u.used_bytes)}
                    {u.quota_bytes > 0 && <span className="text-muted"> / {fmtBytes(u.quota_bytes)}</span>}
                  </td>
                  <td className="user-cell user-cell--expiry px-3 py-3 font-data text-xs text-center">
                    {u.expire_pending ? (
                      <span className="text-muted">{u.expire_after_days} {t('expirePendingSuffix')}</span>
                    ) : u.expire_date ? (
                      <span className={u.is_expired ? 'text-danger' : 'text-ink'}>{formatJalaliDate(u.expire_date)}</span>
                    ) : (
                      <span className="text-muted">{t('unlimitedExpiry')}</span>
                    )}
                  </td>
                  <td className="user-cell user-cell--connection px-3 py-3 text-center font-data text-xs">
                    <ConnectionState user={u} dir={dir} />
                  </td>
                  <td className="user-cell user-cell--account px-3 py-3 text-center">
                    {!u.is_active ? (
                      <span className="status-pill status-danger user-account-status">{t('statusInactive')}</span>
                    ) : u.is_expired ? (
                      <span className="status-pill status-warning user-account-status">{t('statusExpired')}</span>
                    ) : (
                      <span className="status-pill status-success user-account-status">{t('statusActive')}</span>
                    )}
                  </td>
                  <td className="user-cell user-cell--actions px-3 py-3">
                    <div className="user-row-actions">
                      <RowActionButton allowed={hasPermission('users:edit', 'users')} onClick={() => openEdit(u)} title={t('editUserTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی ویرایش ندارید' : 'No edit permission'} icon="edit" tone="edit" />
                      <RowActionButton allowed={hasPermission('users:subscription', 'users')} onClick={() => openSubLink(u)} title={t('openSubLinkTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی لینک اشتراک ندارید' : 'No subscription permission'} icon="external" tone="open" />
                      <RowActionButton allowed={hasPermission('users:subscription', 'users')} onClick={() => copySubLink(u)} title={t('copySubLinkTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی کپی لینک ندارید' : 'No subscription permission'} icon="copy" tone="copy" />
                      <RowActionButton allowed={hasPermission('users:view', 'users')} busy={refreshingUserIds.has(u.id)} onClick={() => refreshUserStatus(u)} title={dir === 'rtl' ? 'به‌روزرسانی وضعیت همین کاربر' : 'Refresh this user status'} lockedTitle={dir === 'rtl' ? 'در حال به‌روزرسانی وضعیت…' : 'Refreshing status…'} icon="refresh" tone="status-refresh" />
                      <RowActionButton allowed={hasPermission('users:edit', 'users')} onClick={() => resetUsage(u)} title={t('resetUsageTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی ریست مصرف ندارید' : 'No reset permission'} icon="activity" tone="usage-reset" />
                      <RowActionButton allowed={hasPermission('users:delete', 'users')} onClick={() => remove(u)} title={t('deleteUserRowTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی حذف ندارید' : 'No delete permission'} danger icon="trash" tone="danger" />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="users-card-grid p-3">
          {loading && <div className="rounded-xl border border-border bg-surface2 p-6 text-center text-sm text-muted">{t('loadingUsersRow')}</div>}
          {!loading && filtered.length === 0 && <div className="rounded-xl border border-border bg-surface2 p-6 text-center text-sm text-muted">{t('noUsersFound')}</div>}
          {filtered.map((u) => (
            <article key={`mobile-${u.id}`} className="user-mobile-card">
              <header className="user-mobile-card__header">
                <div className="user-card-identity min-w-0">
                  <div className="user-name-with-presence">
                    <UserOnlineDot user={u} />
                    <span dir="ltr" className="user-card-username font-data font-bold" title={u.username}>{u.username}</span>
                  </div>
                  {showOwnerColumn && <div className="user-card-owner mt-1 text-[10px] text-muted">{u.owner_admin_username || '—'}</div>}
                </div>
                <div className="user-mobile-card__statuses">
                  {!u.is_active ? <span className="status-pill status-danger user-account-status">{t('statusInactive')}</span> : u.is_expired ? <span className="status-pill status-warning user-account-status">{t('statusExpired')}</span> : <span className="status-pill status-success user-account-status">{t('statusActive')}</span>}
                </div>
              </header>
              <div className="user-mobile-card__protocols"><ProtocolList user={u} /></div>
              <div className="user-mobile-card__metrics">
                <div className="user-card-metric user-card-metric--max"><span>{t('colMaxUsers')}</span><b>{u.max_devices > 0 ? u.max_devices : t('unlimitedDevices')}</b></div>
                <div className="user-card-metric user-card-metric--speed"><span>{t('colSpeedLimit')}</span><b><CompactSpeed user={u} unlimitedLabel={t('speedLimitUnlimited')} /></b></div>
                <div className="user-card-metric user-card-metric--usage"><span>{t('colUsage')}</span><b>{fmtBytes(u.used_bytes)}{u.quota_bytes > 0 ? ` / ${fmtBytes(u.quota_bytes)}` : ''}</b></div>
                <div className="user-card-metric user-card-metric--expiry"><span>{t('colExpiry')}</span><b dir="ltr" className="user-card-expiry-value">{u.expire_pending ? `${u.expire_after_days} ${t('expirePendingSuffix')}` : u.expire_date ? formatJalaliDate(u.expire_date) : t('unlimitedExpiry')}</b></div>
                <div className="user-card-metric user-card-metric--connection"><span>{dir === 'rtl' ? 'وضعیت اتصال' : 'Connection status'}</span><b><ConnectionState user={u} dir={dir} compact /></b></div>
              </div>
              <footer className="user-mobile-card__actions">
                <RowActionButton allowed={hasPermission('users:edit', 'users')} onClick={() => openEdit(u)} title={t('editUserTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی ویرایش ندارید' : 'No edit permission'} icon="edit" tone="edit" />
                <RowActionButton allowed={hasPermission('users:subscription', 'users')} onClick={() => openSubLink(u)} title={t('openSubLinkTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی لینک اشتراک ندارید' : 'No subscription permission'} icon="external" tone="open" />
                <RowActionButton allowed={hasPermission('users:subscription', 'users')} onClick={() => copySubLink(u)} title={t('copySubLinkTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی کپی لینک ندارید' : 'No subscription permission'} icon="copy" tone="copy" />
                <RowActionButton allowed={hasPermission('users:view', 'users')} busy={refreshingUserIds.has(u.id)} onClick={() => refreshUserStatus(u)} title={dir === 'rtl' ? 'به‌روزرسانی وضعیت همین کاربر' : 'Refresh this user status'} lockedTitle={dir === 'rtl' ? 'در حال به‌روزرسانی وضعیت…' : 'Refreshing status…'} icon="refresh" tone="status-refresh" />
                <RowActionButton allowed={hasPermission('users:edit', 'users')} onClick={() => resetUsage(u)} title={t('resetUsageTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی ریست مصرف ندارید' : 'No reset permission'} icon="activity" tone="usage-reset" />
                <RowActionButton allowed={hasPermission('users:delete', 'users')} onClick={() => remove(u)} title={t('deleteUserRowTitle')} lockedTitle={dir === 'rtl' ? 'دسترسی حذف ندارید' : 'No delete permission'} danger icon="trash" tone="danger" />
              </footer>
            </article>
          ))}
        </div>
      </section>

      {modalOpen && (hasPermission(editingUser ? 'users:edit' : 'users:create', 'users')) && (
        <UserFormModal user={editingUser} serverTargets={serverTargets} onClose={() => !formBusy && setModalOpen(false)} onSubmit={submit} error={formError} busy={formBusy} />
      )}
      {bulkOpen && hasPermission('users:edit', 'users') && (
        <BulkUserIncreaseModal users={users} onClose={() => !bulkBusy && setBulkOpen(false)} onSubmit={submitBulkIncrease} busy={bulkBusy} error={bulkError} />
      )}
    </div>
  )
}

export default function Users() {
  return <UsersInner />
}
