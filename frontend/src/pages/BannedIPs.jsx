import React, { useEffect, useMemo, useRef, useState } from 'react'
import api from '../api'
import { useUI } from '../components/ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { Icon } from '../components/icons.jsx'

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/

export default function BannedIPs() {
  const { confirm, withBusy, notify } = useUI()
  const { dir, t, lang } = useLang()
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [newIp, setNewIp] = useState('')
  const [newReason, setNewReason] = useState('')
  const [adding, setAdding] = useState(false)
  const [unbanningId, setUnbanningId] = useState(null)
  const debounceRef = useRef(null)

  const load = async (searchValue = search) => {
    setLoading(true); setError('')
    try {
      const { data } = await api.get('/ip-bans', { params: searchValue ? { search: searchValue } : {} })
      setItems(data)
    } catch (err) {
      setError(err.response?.data?.detail || t('loadingBansError'))
    } finally { setLoading(false) }
  }

  useEffect(() => { load('') }, [])

  const onSearchChange = (value) => {
    setSearch(value)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => load(value), 300)
  }

  const addBan = async () => {
    const ip = newIp.trim()
    if (!IPV4_RE.test(ip)) return notify({ type: 'error', message: t('invalidIpError'), dir })
    setAdding(true)
    try {
      await withBusy(t('banningIpBusy'), () => api.post('/ip-bans', { ip_address: ip, reason: newReason.trim() || null }), { dir })
      notify({ type: 'success', message: `${t('ipBannedSuccessPrefix')}${ip}${t('ipBannedSuccessSuffix')}`, dir })
      setNewIp(''); setNewReason(''); load(search)
    } catch (err) { notify({ type: 'error', message: err.response?.data?.detail || t('ipBanError'), dir }) }
    finally { setAdding(false) }
  }

  const unban = async (item) => {
    const ok = await confirm({ title: t('unbanTitle'), message: `${t('unbanMessagePrefix')}${item.ip_address}${t('unbanMessageSuffix')}`, confirmLabel: t('unbanConfirmBtn'), danger: false, dir })
    if (!ok) return
    setUnbanningId(item.id)
    try {
      await withBusy(t('unbanningBusy'), () => api.delete(`/ip-bans/${encodeURIComponent(item.ip_address)}`), { dir })
      notify({ type: 'success', message: `${t('ipUnbannedSuccessPrefix')}${item.ip_address}${t('ipUnbannedSuccessSuffix')}`, dir }); load(search)
    } catch (err) { notify({ type: 'error', message: err.response?.data?.detail || t('ipUnbanError'), dir }) }
    finally { setUnbanningId(null) }
  }

  const stats = useMemo(() => {
    const now = Date.now()
    const within = days => items.filter(i => now - new Date(i.created_at).getTime() <= days * 86400000).length
    return { total: items.length, day: within(1), week: within(7) }
  }, [items])

  return (
    <div dir={dir} className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="page-heading">{t('bannedIpsTitle')}</h1><p className="page-subtitle">{t('bannedIpsSubtitle')}</p></div>
        <div className="relative w-full sm:w-64"><Icon name="search" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input value={search} onChange={e => onSearchChange(e.target.value)} placeholder={t('searchIpPlaceholder')} className="field ps-9 font-data" /></div>
      </header>

      <div className="grid grid-cols-3 gap-3">
        {[['ban', t('totalBannedIpsLabel'), stats.total], ['clock', t('last24HoursLabel'), stats.day], ['chart', t('last7DaysLabel'), stats.week]].map(([icon,label,value]) => <div key={label} className="app-card p-4"><div className="flex items-center gap-3"><span className="flex h-10 w-10 items-center justify-center rounded-xl bg-danger/10 text-danger"><Icon name={icon} size={19}/></span><div><div className="text-[10px] text-muted">{label}</div><div className="mt-1 text-xl font-semibold font-data">{value}</div></div></div></div>)}
      </div>

      <section className="panel-section">
        <header className="panel-section-header"><div><h2 className="section-heading">{t('manualBanTitle')}</h2><p className="mt-1 text-[10px] text-muted">{t('manualBanSubtitle')}</p></div></header>
        <div className="grid gap-3 p-4 md:grid-cols-[1fr_1.4fr_auto]">
          <label><span className="field-label">{t('colIp')}</span><input value={newIp} onChange={e => setNewIp(e.target.value)} placeholder={t('manualBanIpPlaceholder')} className="field font-data" /></label>
          <label><span className="field-label">{t('colReason')}</span><input value={newReason} onChange={e => setNewReason(e.target.value)} placeholder={t('reasonNotePlaceholder')} className="field" /></label>
          <button onClick={addBan} disabled={adding || !newIp.trim()} className="btn-danger self-end"><Icon name="ban" size={16}/>{t('btnBan')}</button>
        </div>
      </section>

      {error && <div className="status-danger rounded-xl px-4 py-3 text-sm">{error}</div>}

      <section className="panel-section">
        <header className="panel-section-header"><h2 className="section-heading">{t('bannedListTitle')}</h2><span className="status-pill status-neutral">{items.length}</span></header>
        <div className="hidden overflow-x-auto sm:block">
          <table className="banned-data-table w-full text-sm"><thead><tr><th className="px-4 py-3 text-center">{t('colIp')}</th><th className="px-4 py-3 text-center">{t('colReason')}</th><th className="px-4 py-3 text-center">{t('colBannedBy')}</th><th className="px-4 py-3 text-center">{t('colBanDate')}</th><th className="px-4 py-3 text-center">{t('colActions')}</th></tr></thead>
            <tbody>
              {loading && <tr><td colSpan={5} className="py-10 text-center text-muted">{t('loadingBans')}</td></tr>}
              {!loading && !items.length && <tr><td colSpan={5}><div className="empty-state m-4"><Icon name="ban" size={30} className="text-muted"/><div className="mt-3 text-sm font-semibold">{t('noBannedIps')}</div></div></td></tr>}
              {items.map(item => <tr key={item.id}><td className="px-4 py-3.5 text-center"><div className="inline-flex items-center justify-center gap-2"><span className="h-2 w-2 rounded-full bg-danger"/><span className="font-data font-semibold">{item.ip_address}</span></div></td><td className="px-4 py-3.5 text-center text-xs text-muted">{item.reason || '—'}</td><td className="px-4 py-3.5 text-center text-xs font-data">{item.banned_by || '—'}</td><td className="px-4 py-3.5 text-center text-xs font-data text-muted">{new Date(item.created_at).toLocaleString(lang === 'en' ? 'en-US' : 'fa-IR')}</td><td className="px-4 py-3.5 text-center"><button onClick={() => unban(item)} disabled={unbanningId === item.id} className="btn-secondary !px-3 !py-1.5 text-xs"><Icon name="refresh" size={13}/>{t('btnUnban')}</button></td></tr>)}
            </tbody>
          </table>
        </div>
        <div className="space-y-3 p-3 sm:hidden">
          {loading && <div className="rounded-xl border border-border bg-surface2 p-6 text-center text-sm text-muted">{t('loadingBans')}</div>}
          {!loading && !items.length && <div className="empty-state"><Icon name="ban" size={30} className="text-muted"/><div className="mt-3 text-sm font-semibold">{t('noBannedIps')}</div></div>}
          {items.map(item => <article key={`mobile-${item.id}`} className="banned-mobile-card"><div className="flex items-center justify-between gap-3"><div className="inline-flex min-w-0 items-center gap-2"><span className="h-2 w-2 shrink-0 rounded-full bg-danger"/><b className="truncate font-data">{item.ip_address}</b></div><button onClick={() => unban(item)} disabled={unbanningId === item.id} className="btn-secondary !px-3 !py-1.5 text-xs"><Icon name="refresh" size={13}/>{t('btnUnban')}</button></div><dl><div><dt>{t('colReason')}</dt><dd>{item.reason || '—'}</dd></div><div><dt>{t('colBannedBy')}</dt><dd>{item.banned_by || '—'}</dd></div><div><dt>{t('colBanDate')}</dt><dd>{new Date(item.created_at).toLocaleString(lang === 'en' ? 'en-US' : 'fa-IR')}</dd></div></dl></article>)}
        </div>
      </section>
    </div>
  )
}
