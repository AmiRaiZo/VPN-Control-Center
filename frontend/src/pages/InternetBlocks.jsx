import React, { useEffect, useMemo, useRef, useState } from 'react'
import api from '../api'
import { useUI } from '../components/ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { Icon } from '../components/icons.jsx'

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/

export default function InternetBlocks() {
  const { confirm, withBusy, notify } = useUI()
  const { dir, lang } = useLang()
  const fa = lang !== 'en'
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [newIp, setNewIp] = useState('')
  const [newUsername, setNewUsername] = useState('')
  const [newReason, setNewReason] = useState('')
  const [adding, setAdding] = useState(false)
  const [restoringId, setRestoringId] = useState(null)
  const debounceRef = useRef(null)

  const text = {
    title: fa ? 'اینترنت قطع‌شده‌ها' : 'Internet blocks',
    subtitle: fa ? 'آی‌پی‌هایی که دسترسی VPN آن‌ها در هر ۹ پروتکل موقتاً قطع شده است' : 'Public IPs temporarily blocked across all nine VPN protocols',
    search: fa ? 'جست‌وجوی آی‌پی، کاربر یا پروتکل' : 'Search IP, user or protocol',
    total: fa ? 'کل قطع‌شده‌ها' : 'Total blocked',
    day: fa ? '۲۴ ساعت اخیر' : 'Last 24 hours',
    week: fa ? '۷ روز اخیر' : 'Last 7 days',
    manualTitle: fa ? 'قطع دستی اینترنت یک آی‌پی' : 'Block an IP manually',
    manualSubtitle: fa ? 'فقط ترافیک ۹ پروتکل VPN قطع می‌شود؛ پنل وب و سرویس‌های دیگر سرور باز می‌مانند.' : 'Only the nine VPN transports are blocked; the web panel and unrelated server services stay reachable.',
    ip: fa ? 'آی‌پی پابلیک' : 'Public IP',
    username: fa ? 'نام کاربری (اختیاری)' : 'Username (optional)',
    reason: fa ? 'دلیل / یادداشت' : 'Reason / note',
    block: fa ? 'قطع اینترنت' : 'Block internet',
    list: fa ? 'فهرست اینترنت قطع‌شده‌ها' : 'Blocked internet list',
    protocol: fa ? 'پروتکل مبدا' : 'Source protocol',
    by: fa ? 'توسط' : 'Blocked by',
    date: fa ? 'زمان قطع' : 'Blocked at',
    actions: fa ? 'عملیات' : 'Actions',
    restore: fa ? 'وصل اینترنت' : 'Restore internet',
    loading: fa ? 'در حال دریافت فهرست...' : 'Loading blocks...',
    empty: fa ? 'هیچ آی‌پی‌ای در وضعیت قطع اینترنت نیست.' : 'No public IP currently has its VPN internet blocked.',
  }

  const load = async (searchValue = search) => {
    setLoading(true); setError('')
    try {
      const { data } = await api.get('/internet-blocks', { params: searchValue ? { search: searchValue } : {} })
      setItems(data)
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'دریافت فهرست ناموفق بود.' : 'Failed to load internet blocks.'))
    } finally { setLoading(false) }
  }

  useEffect(() => { load('') }, [])

  const onSearchChange = (value) => {
    setSearch(value)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => load(value), 300)
  }

  const addBlock = async () => {
    const ip = newIp.trim()
    if (!IPV4_RE.test(ip)) {
      notify({ type: 'error', message: fa ? 'آی‌پی واردشده معتبر نیست.' : 'The IP address is invalid.', dir })
      return
    }
    setAdding(true)
    try {
      await withBusy(
        fa ? `در حال قطع اینترنت ${ip} در همه پروتکل‌ها...` : `Blocking ${ip} on all protocols...`,
        () => api.post('/internet-blocks', {
          ip_address: ip,
          username: newUsername.trim() || null,
          reason: newReason.trim() || null,
        }),
        { dir },
      )
      notify({ type: 'success', message: fa ? `اینترنت ${ip} در هر ۹ پروتکل قطع شد.` : `${ip} was blocked across all nine protocols.`, dir })
      setNewIp(''); setNewUsername(''); setNewReason(''); load(search)
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || (fa ? 'قطع اینترنت ناموفق بود.' : 'Internet block failed.'), dir })
    } finally { setAdding(false) }
  }

  const restore = async (item) => {
    const ok = await confirm({
      title: text.restore,
      message: fa
        ? `دسترسی VPN آی‌پی ${item.ip_address} در همه پروتکل‌ها دوباره وصل شود؟`
        : `Restore VPN access for ${item.ip_address} across all protocols?`,
      confirmLabel: text.restore,
      danger: false,
      dir,
    })
    if (!ok) return
    setRestoringId(item.id)
    try {
      await withBusy(
        fa ? `در حال وصل‌کردن اینترنت ${item.ip_address}...` : `Restoring ${item.ip_address}...`,
        () => api.delete(`/internet-blocks/${encodeURIComponent(item.ip_address)}`),
        { dir },
      )
      notify({ type: 'success', message: fa ? `اینترنت ${item.ip_address} وصل شد.` : `${item.ip_address} was restored.`, dir })
      load(search)
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || (fa ? 'وصل‌کردن اینترنت ناموفق بود.' : 'Restore failed.'), dir })
    } finally { setRestoringId(null) }
  }

  const stats = useMemo(() => {
    const now = Date.now()
    const within = days => items.filter(i => now - new Date(i.created_at).getTime() <= days * 86400000).length
    return { total: items.length, day: within(1), week: within(7) }
  }, [items])

  const locale = fa ? 'fa-IR' : 'en-US'

  return (
    <div dir={dir} className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="page-heading">{text.title}</h1><p className="page-subtitle">{text.subtitle}</p></div>
        <div className="relative w-full sm:w-72"><Icon name="search" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input value={search} onChange={e => onSearchChange(e.target.value)} placeholder={text.search} className="field ps-9 font-data" /></div>
      </header>

      <div className="grid grid-cols-3 gap-3">
        {[['ban', text.total, stats.total], ['clock', text.day, stats.day], ['chart', text.week, stats.week]].map(([icon,label,value]) => <div key={label} className="app-card p-4"><div className="flex items-center gap-3"><span className="flex h-10 w-10 items-center justify-center rounded-xl bg-warning/10 text-warning"><Icon name={icon} size={19}/></span><div><div className="text-[10px] text-muted">{label}</div><div className="mt-1 text-xl font-semibold font-data">{value}</div></div></div></div>)}
      </div>

      <section className="panel-section">
        <header className="panel-section-header"><div><h2 className="section-heading">{text.manualTitle}</h2><p className="mt-1 text-[10px] text-muted">{text.manualSubtitle}</p></div></header>
        <div className="grid gap-3 p-4 lg:grid-cols-[1fr_1fr_1.4fr_auto]">
          <label><span className="field-label">{text.ip}</span><input value={newIp} onChange={e => setNewIp(e.target.value)} placeholder="203.0.113.10" className="field font-data" /></label>
          <label><span className="field-label">{text.username}</span><input value={newUsername} onChange={e => setNewUsername(e.target.value)} placeholder={fa ? 'مثلاً ali' : 'e.g. ali'} className="field font-data" /></label>
          <label><span className="field-label">{text.reason}</span><input value={newReason} onChange={e => setNewReason(e.target.value)} placeholder={fa ? 'اختیاری' : 'Optional'} className="field" /></label>
          <button onClick={addBlock} disabled={adding || !newIp.trim()} className="btn-danger self-end"><Icon name="ban" size={16}/>{text.block}</button>
        </div>
      </section>

      {error && <div className="status-danger rounded-xl px-4 py-3 text-sm">{error}</div>}

      <section className="panel-section">
        <header className="panel-section-header"><h2 className="section-heading">{text.list}</h2><span className="status-pill status-neutral">{items.length}</span></header>
        <div className="hidden overflow-x-auto sm:block">
          <table className="banned-data-table w-full text-sm"><thead><tr><th className="px-4 py-3 text-center">{text.ip}</th><th className="px-4 py-3 text-center">{text.username}</th><th className="px-4 py-3 text-center">{text.protocol}</th><th className="px-4 py-3 text-center">{text.reason}</th><th className="px-4 py-3 text-center">{text.by}</th><th className="px-4 py-3 text-center">{text.date}</th><th className="px-4 py-3 text-center">{text.actions}</th></tr></thead>
            <tbody>
              {loading && <tr><td colSpan={7} className="py-10 text-center text-muted">{text.loading}</td></tr>}
              {!loading && !items.length && <tr><td colSpan={7}><div className="empty-state m-4"><Icon name="ban" size={30} className="text-muted"/><div className="mt-3 text-sm font-semibold">{text.empty}</div></div></td></tr>}
              {items.map(item => <tr key={item.id}><td className="px-4 py-3.5 text-center"><div className="inline-flex items-center justify-center gap-2"><span className="h-2 w-2 rounded-full bg-warning"/><span className="font-data font-semibold">{item.ip_address}</span></div></td><td className="px-4 py-3.5 text-center text-xs font-data">{item.username || '—'}</td><td className="px-4 py-3.5 text-center text-xs font-data uppercase">{item.protocol || '—'}</td><td className="px-4 py-3.5 text-center text-xs text-muted">{item.reason || '—'}</td><td className="px-4 py-3.5 text-center text-xs font-data">{item.blocked_by || '—'}</td><td className="px-4 py-3.5 text-center text-xs font-data text-muted">{new Date(item.created_at).toLocaleString(locale)}</td><td className="px-4 py-3.5 text-center"><button onClick={() => restore(item)} disabled={restoringId === item.id} className="btn-success-soft !px-3 !py-1.5 text-xs"><Icon name="refresh" size={13}/>{text.restore}</button></td></tr>)}
            </tbody>
          </table>
        </div>
        <div className="space-y-3 p-3 sm:hidden">
          {loading && <div className="rounded-xl border border-border bg-surface2 p-6 text-center text-sm text-muted">{text.loading}</div>}
          {!loading && !items.length && <div className="empty-state"><Icon name="ban" size={30} className="text-muted"/><div className="mt-3 text-sm font-semibold">{text.empty}</div></div>}
          {items.map(item => <article key={`mobile-${item.id}`} className="banned-mobile-card"><div className="flex items-center justify-between gap-3"><div className="inline-flex min-w-0 items-center gap-2"><span className="h-2 w-2 shrink-0 rounded-full bg-warning"/><b className="truncate font-data">{item.ip_address}</b></div><button onClick={() => restore(item)} disabled={restoringId === item.id} className="btn-success-soft !px-3 !py-1.5 text-xs"><Icon name="refresh" size={13}/>{text.restore}</button></div><dl><div><dt>{text.username}</dt><dd>{item.username || '—'}</dd></div><div><dt>{text.protocol}</dt><dd className="uppercase">{item.protocol || '—'}</dd></div><div><dt>{text.reason}</dt><dd>{item.reason || '—'}</dd></div><div><dt>{text.by}</dt><dd>{item.blocked_by || '—'}</dd></div><div><dt>{text.date}</dt><dd>{new Date(item.created_at).toLocaleString(locale)}</dd></div></dl></article>)}
        </div>
      </section>
    </div>
  )
}
