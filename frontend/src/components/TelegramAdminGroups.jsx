import React, { useEffect, useMemo, useState } from 'react'
import api from '../api'
import { Icon } from './icons.jsx'
import { useUI } from './ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { getRole } from '../permissions.js'

const W = {
  fa: {
    title: 'گروه‌های متصل به حساب من',
    hint: 'هر گروه به محدوده همین ادمین متصل می‌شود. اعضای مجاز فقط در محدوده کاربران، نودها، پروتکل‌ها و دسترسی‌های همین حساب با ربات کار می‌کنند.',
    add: 'افزودن گروه جدید', codeTitle: 'اتصال گروه در تلگرام',
    codeHint: 'ربات را داخل گروه اضافه کن و این فرمان را همان‌جا بفرست. فرستنده و صاحب حساب پنل لازم نیست ادمین گروه باشند.',
    copy: 'کپی فرمان', copied: 'فرمان اتصال کپی شد', expires: 'این کد ۱۰ دقیقه اعتبار دارد و فقط یک‌بار قابل استفاده است.',
    noBot: 'توکن یا ربات کنترل هنوز توسط سوپرادمین فعال نشده است.', noBinding: 'دسترسی ربات تلگرام برای این حساب فعال نیست.',
    empty: 'هنوز هیچ گروهی به این حساب متصل نشده است.', active: 'فعال', inactive: 'غیرفعال', control: 'کنترل ربات',
    test: 'تست ارسال', remove: 'قطع اتصال', removeConfirm: 'اتصال این گروه از حساب پنل قطع شود؟',
    allTitle: 'همه گروه‌های متصل', allHint: 'سوپرادمین می‌تواند مالک، وضعیت و دسترسی اعضای تمام گروه‌ها را مدیریت کند.',
    owner: 'مالک پنل', shared: 'همه اعضا به‌جز مسدودها', restricted: 'فقط افراد تأییدشده', loading: 'در حال دریافت گروه‌ها...',
    memberAccess: 'دسترسی اعضای گروه', memberHint: 'آیدی عددی تلگرام شخص را وارد کن و او را مجاز یا مسدود کن. مسدودکردن همیشه بالاترین اولویت را دارد.',
    accessMode: 'حالت پیش‌فرض', allMembers: 'همه اعضا مجاز باشند', allowlistOnly: 'فقط افراد تأییدشده مجاز باشند',
    numericId: 'آیدی عددی تلگرام', numericPlaceholder: 'مثلاً 123456789', optionalName: 'نام یا توضیح اختیاری',
    allow: 'مجاز کن', deny: 'مسدود کن', deleteRule: 'حذف قانون', noRules: 'هنوز قانون اختصاصی برای هیچ عضوی ثبت نشده است.',
    allowed: 'مجاز', denied: 'مسدود', invalidId: 'آیدی عددی معتبر وارد کن.', close: 'بستن', refresh: 'بروزرسانی',
  },
  en: {
    title: 'Groups connected to my account',
    hint: 'Each group is scoped to this panel admin. Allowed members can only operate within this account’s users, nodes, protocols and live permissions.',
    add: 'Add group', codeTitle: 'Connect the group in Telegram', codeHint: 'Add the bot and send this command in the group. Neither sender nor panel owner must be a Telegram group admin.',
    copy: 'Copy command', copied: 'Connection command copied', expires: 'The code is valid for 10 minutes and one use.',
    noBot: 'The control bot is not configured or enabled.', noBinding: 'Telegram bot access is disabled for this panel account.',
    empty: 'No group is connected yet.', active: 'Active', inactive: 'Inactive', control: 'Bot control', test: 'Send test', remove: 'Disconnect', removeConfirm: 'Disconnect this group?',
    allTitle: 'All connected groups', allHint: 'The superadmin can manage ownership, status and member access for every group.', owner: 'Panel owner',
    shared: 'Everyone except blocked', restricted: 'Approved members only', loading: 'Loading groups...', memberAccess: 'Group member access',
    memberHint: 'Enter a Telegram numeric user ID and explicitly allow or block it. Explicit block always has priority.', accessMode: 'Default mode',
    allMembers: 'Allow all members', allowlistOnly: 'Allow approved members only', numericId: 'Telegram numeric ID', numericPlaceholder: 'Example: 123456789', optionalName: 'Optional name or note',
    allow: 'Allow', deny: 'Block', deleteRule: 'Remove rule', noRules: 'No member-specific rule has been added.', allowed: 'Allowed', denied: 'Blocked', invalidId: 'Enter a valid numeric ID.', close: 'Close', refresh: 'Refresh',
  },
}

function Switch({ checked, onClick, disabled = false }) {
  return <button type="button" role="switch" aria-checked={checked} disabled={disabled} onClick={onClick} className={`modern-toggle shrink-0 ${checked ? 'is-on' : ''} disabled:opacity-45`}><span /></button>
}

function MemberRulesPanel({ row, words, dir, notify, onPatch, onChanged }) {
  const [loading, setLoading] = useState(true)
  const [rules, setRules] = useState([])
  const [userId, setUserId] = useState('')
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get(`/telegram-groups/${row.id}/members`)
      setRules(data?.rules || [])
    } catch (err) {
      notify?.({ type: 'error', message: err.response?.data?.detail || String(err), dir })
    } finally { setLoading(false) }
  }
  useEffect(() => { load() }, [row.id])

  const save = async status => {
    const normalized = String(userId || '').replace(/[^0-9]/g, '')
    if (!normalized || Number(normalized) <= 0) {
      notify?.({ type: 'error', message: words.invalidId, dir }); return
    }
    setSaving(status)
    try {
      await api.put(`/telegram-groups/${row.id}/members`, { telegram_user_id: normalized, status, note: note || null })
      setUserId(''); setNote('')
      await load(); await onChanged?.()
    } catch (err) {
      notify?.({ type: 'error', message: err.response?.data?.detail || String(err), dir })
    } finally { setSaving('') }
  }

  const removeRule = async rule => {
    try {
      await api.delete(`/telegram-groups/${row.id}/members/${rule.telegram_user_id}`)
      await load(); await onChanged?.()
    } catch (err) { notify?.({ type: 'error', message: err.response?.data?.detail || String(err), dir }) }
  }

  return <div className="mt-4 rounded-2xl border border-border bg-bg/35 p-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><b className="text-sm text-ink">{words.memberAccess}</b><p className="mt-1 text-[10px] leading-5 text-muted">{words.memberHint}</p></div>
      <button type="button" className="btn-secondary !min-h-9 !px-3 text-[10px]" onClick={load}><Icon name="refresh" size={14}/>{words.refresh}</button>
    </div>

    <div className="mt-4">
      <span className="mb-2 block text-[11px] font-bold text-ink">{words.accessMode}</span>
      <div className="grid gap-2 sm:grid-cols-2">
        <button type="button" onClick={() => onPatch(row, { access_mode: 'all_members' })} className={`rounded-xl border px-3 py-3 text-xs font-bold ${row.access_mode !== 'allowlist_only' ? 'border-success/45 bg-success/10 text-success' : 'border-border bg-surface2 text-muted'}`}>{words.allMembers}</button>
        <button type="button" onClick={() => onPatch(row, { access_mode: 'allowlist_only' })} className={`rounded-xl border px-3 py-3 text-xs font-bold ${row.access_mode === 'allowlist_only' ? 'border-warning/45 bg-warning/10 text-warning' : 'border-border bg-surface2 text-muted'}`}>{words.allowlistOnly}</button>
      </div>
    </div>

    <div className="mt-4 grid gap-2 sm:grid-cols-[1fr_1.2fr]">
      <input dir="ltr" inputMode="numeric" className="field font-data" placeholder={words.numericPlaceholder} value={userId} onChange={e => setUserId(e.target.value.replace(/[^0-9]/g, ''))}/>
      <input className="field" placeholder={words.optionalName} value={note} onChange={e => setNote(e.target.value)}/>
    </div>
    <div className="mt-2 grid gap-2 sm:grid-cols-2">
      <button type="button" disabled={Boolean(saving)} className="btn-secondary !border-success/35 !text-success" onClick={() => save('allow')}><Icon name="check" size={15}/>{saving === 'allow' ? '…' : words.allow}</button>
      <button type="button" disabled={Boolean(saving)} className="btn-danger" onClick={() => save('deny')}><Icon name="ban" size={15}/>{saving === 'deny' ? '…' : words.deny}</button>
    </div>

    <div className="mt-4 space-y-2">
      {loading ? <div className="py-4 text-center text-xs text-muted">{words.loading}</div> : rules.length ? rules.map(rule => <div key={rule.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-surface2/75 px-3 py-2.5">
        <div className="min-w-0"><div className="flex items-center gap-2"><span className={`rounded-lg px-2 py-1 text-[9px] font-black ${rule.is_allowed ? 'bg-success/12 text-success' : 'bg-danger/12 text-danger'}`}>{rule.is_allowed ? words.allowed : words.denied}</span><code dir="ltr" className="text-[11px] text-ink">{rule.telegram_user_id}</code></div>{rule.note && <p className="mt-1 truncate text-[10px] text-muted">{rule.note}</p>}</div>
        <button type="button" className="rounded-lg border border-border px-2.5 py-2 text-[10px] text-muted hover:border-danger/40 hover:text-danger" onClick={() => removeRule(rule)}><Icon name="trash" size={13}/>{words.deleteRule}</button>
      </div>) : <div className="rounded-xl border border-dashed border-border px-4 py-5 text-center text-[11px] text-muted">{words.noRules}</div>}
    </div>
  </div>
}

function GroupCard({ row, words, dir, notify, onPatch, onTest, onDelete, onChanged, showOwner = false }) {
  const [membersOpen, setMembersOpen] = useState(false)
  const modeLabel = row.access_mode === 'allowlist_only' ? words.restricted : words.shared
  return <article className="rounded-2xl border border-border bg-surface2/70 p-4 shadow-[0_16px_45px_rgba(0,0,0,.12)]">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="flex h-9 w-9 items-center justify-center rounded-xl bg-signal/12 text-signal"><Icon name="telegram" size={18}/></span><div className="min-w-0"><b className="block truncate text-sm text-ink">{row.title || 'Telegram group'}</b><code dir="ltr" className="mt-1 block text-[10px] text-muted">{row.chat_id}</code></div></div>
        <div className="mt-3 flex flex-wrap gap-2"><span className="rounded-lg border border-signal/25 bg-signal/8 px-2.5 py-1.5 text-[10px] font-bold text-signal">{modeLabel}</span><span className="rounded-lg border border-border bg-bg/40 px-2.5 py-1.5 text-[10px] text-muted">{row.allowed_member_count || 0} {words.allowed} · {row.blocked_member_count || 0} {words.denied}</span>{showOwner && <span className="rounded-lg border border-border bg-bg/40 px-2.5 py-1.5 text-[10px] text-muted">{words.owner}: <b className="text-ink">{row.admin_username || '—'}</b></span>}</div>
      </div><span className={`rounded-full px-2.5 py-1 text-[10px] font-black ${row.is_active ? 'bg-success/12 text-success' : 'bg-danger/12 text-danger'}`}>{row.is_active ? words.active : words.inactive}</span>
    </div>
    <div className="mt-4 grid gap-2 sm:grid-cols-2"><div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-bg/35 px-3 py-2.5"><span className="text-[11px] font-bold text-ink">{words.active}</span><Switch checked={Boolean(row.is_active)} onClick={() => onPatch(row, { is_active: !row.is_active })}/></div><div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-bg/35 px-3 py-2.5"><span className="text-[11px] font-bold text-ink">{words.control}</span><Switch checked={Boolean(row.control_enabled)} disabled={!row.is_active} onClick={() => onPatch(row, { control_enabled: !row.control_enabled })}/></div></div>
    <div className="mt-3 grid gap-2 sm:grid-cols-3"><button type="button" className="btn-secondary !py-2.5 text-xs" onClick={() => setMembersOpen(v => !v)}><Icon name="users" size={15}/>{words.memberAccess}</button><button type="button" className="btn-secondary !py-2.5 text-xs" onClick={() => onTest(row)}><Icon name="check" size={15}/>{words.test}</button><button type="button" className="btn-danger !py-2.5 text-xs" onClick={() => onDelete(row)}><Icon name="trash" size={15}/>{words.remove}</button></div>
    {membersOpen && <MemberRulesPanel row={row} words={words} dir={dir} notify={notify} onPatch={onPatch} onChanged={onChanged}/>} 
  </article>
}

export default function TelegramAdminGroups() {
  const { lang, dir } = useLang(); const words = W[lang] || W.fa
  const { notify, withBusy, confirm } = useUI()
  const [data, setData] = useState(null); const [allGroups, setAllGroups] = useState([]); const [loading, setLoading] = useState(true); const [link, setLink] = useState(null)
  const superadmin = getRole() === 'superadmin'
  const load = async () => { const requests = [api.get('/telegram-groups')]; if (superadmin) requests.push(api.get('/telegram-groups/all')); const results = await Promise.all(requests); setData(results[0].data); if (superadmin) setAllGroups(results[1].data?.groups || []) }
  useEffect(() => { let alive=true; load().catch(err => alive && notify?.({type:'error',message:err.response?.data?.detail||String(err),dir})).finally(() => alive && setLoading(false)); return () => { alive=false } }, [])
  const canLink = Boolean(data?.bot?.available && data?.admin?.telegram_bot_enabled); const myIds = useMemo(() => new Set((data?.groups || []).map(item => item.id)), [data])
  const issue = async () => { try { const {data:issued}=await withBusy(words.add,()=>api.post('/telegram-groups/link-code'),{dir}); setLink(issued) } catch(err){ notify?.({type:'error',message:err.response?.data?.detail||String(err),dir}) } }
  const copy = async () => { const value=link?.command_with_username||link?.command; if(!value)return; try{await navigator.clipboard.writeText(value)}catch{const el=document.createElement('textarea');el.value=value;document.body.appendChild(el);el.select();document.execCommand('copy');el.remove()} notify?.({type:'success',message:words.copied,dir}) }
  const patch = async (row,payload) => { try{await api.patch(`/telegram-groups/${row.id}`,payload);await load()}catch(err){notify?.({type:'error',message:err.response?.data?.detail||String(err),dir})} }
  const test = async row => { try{await withBusy(words.test,()=>api.post(`/telegram-groups/${row.id}/test`),{dir});notify?.({type:'success',message:words.test,dir})}catch(err){notify?.({type:'error',message:err.response?.data?.detail||String(err),dir})} }
  const remove = async row => { let ok=confirm?await confirm({title:words.remove,message:words.removeConfirm,danger:true,confirmLabel:words.remove,cancelLabel:lang==='en'?'Cancel':'انصراف',dir}):window.confirm(words.removeConfirm); if(!ok)return; try{await api.delete(`/telegram-groups/${row.id}`);await load()}catch(err){notify?.({type:'error',message:err.response?.data?.detail||String(err),dir})} }
  if(loading)return <div className="panel-section p-6 text-sm text-muted">{words.loading}</div>
  const cardProps={words,dir,notify,onPatch:patch,onTest:test,onDelete:remove,onChanged:load}
  return <div className="space-y-5" dir={dir} data-feature="telegram-group-member-access-v23272">
    <section className="rounded-2xl border border-border bg-surface/75 p-5"><div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between"><div><h2 className="text-base font-black text-ink">{words.title}</h2><p className="mt-2 max-w-3xl text-[11px] leading-6 text-muted">{words.hint}</p></div><button type="button" className="btn-primary min-h-11 shrink-0" disabled={!canLink} onClick={issue}><Icon name="plus" size={16}/>{words.add}</button></div>
      {!data?.bot?.available&&<div className="mt-4 rounded-xl border border-warning/30 bg-warning/10 px-4 py-3 text-xs text-warning">{words.noBot}</div>}{data?.bot?.available&&!data?.admin?.telegram_bot_enabled&&<div className="mt-4 rounded-xl border border-warning/30 bg-warning/10 px-4 py-3 text-xs text-warning">{words.noBinding}</div>}
      {link&&<div className="mt-5 rounded-2xl border border-signal/35 bg-signal/8 p-4"><div className="flex items-start gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-signal/15 text-signal"><Icon name="key" size={18}/></span><div><b className="text-sm text-ink">{words.codeTitle}</b><p className="mt-1 text-[11px] leading-6 text-muted">{words.codeHint}</p></div></div><div className="mt-4 flex flex-col gap-2 sm:flex-row"><code dir="ltr" className="flex min-h-12 flex-1 items-center rounded-xl border border-border bg-bg/70 px-4 text-sm font-black text-ink">{link.command_with_username||link.command}</code><button type="button" className="btn-secondary min-h-12" onClick={copy}><Icon name="copy" size={16}/>{words.copy}</button></div><p className="mt-2 text-[10px] text-muted">{words.expires}</p></div>}
    </section>
    {(data?.groups||[]).length?<div className="grid gap-4 xl:grid-cols-2">{data.groups.map(row=><GroupCard key={row.id} row={row} {...cardProps}/>)}</div>:<div className="rounded-2xl border border-dashed border-border bg-surface/45 px-5 py-10 text-center text-sm text-muted">{words.empty}</div>}
    {superadmin&&allGroups.filter(row=>!myIds.has(row.id)).length>0&&<section className="space-y-4"><div><h2 className="text-base font-black text-ink">{words.allTitle}</h2><p className="mt-1 text-[11px] leading-6 text-muted">{words.allHint}</p></div><div className="grid gap-4 xl:grid-cols-2">{allGroups.filter(row=>!myIds.has(row.id)).map(row=><GroupCard key={row.id} row={row} showOwner {...cardProps}/>)}</div></section>}
  </div>
}
