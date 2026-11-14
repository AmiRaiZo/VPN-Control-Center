import React, { useEffect, useMemo, useState } from 'react'
import * as ReactDOM from 'react-dom'
import api from '../api'
import { Icon } from '../components/icons.jsx'
import { useUI } from '../components/ui/UIProvider.jsx'
import { copyText } from '../utils/clipboard.js'
import { hasPermission, hasProtocol } from '../permissions.js'

const MODES = [
  { value: 'local_only', title: 'فقط سرور اصلی', text: 'کانفیگ‌ها فقط از سرور اصلی ساخته می‌شوند.' },
  { value: 'nodes_only', title: 'فقط نودهای متصل', text: 'سرور اصلی از کانفیگ حذف می‌شود و فقط نودهای آنلاین استفاده می‌شوند.' },
  { value: 'all', title: 'سرور اصلی + همه نودها', text: 'همه سرورها داخل ساب و فایل OpenVPN قرار می‌گیرند.' },
]

function StatusDot({ status }) {
  const online = status === 'online'
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[10px] ${online ? 'border-success/30 bg-success/10 text-success' : 'border-danger/30 bg-danger/10 text-danger'}`}><span className={`h-2 w-2 rounded-full ${online ? 'bg-success signal-dot' : 'bg-danger'}`} />{online ? 'آنلاین' : status === 'offline' ? 'آفلاین' : 'نامشخص'}</span>
}

function ModalShell({ title, subtitle, onClose, children, footer, wide = false, dismissible = true }) {
  const requestClose = () => { if (dismissible) onClose?.() }
  return ReactDOM.createPortal(
    <div className="modal-backdrop node-modal-backdrop" role="dialog" aria-modal="true" onMouseDown={(e) => e.target === e.currentTarget && requestClose()}>
      <div className={`modal-panel node-modal-panel flex max-h-[calc(100dvh-20px)] ${wide ? 'w-[min(1040px,calc(100vw-16px))]' : 'w-[min(720px,calc(100vw-16px))]'} flex-col overflow-hidden`}>
        <div className="node-modal-header flex shrink-0 items-start justify-between gap-3 border-b border-border px-4 py-3 sm:px-5 sm:py-4">
          <div className="min-w-0"><h2 className="font-black">{title}</h2>{subtitle && <p className="mt-1 text-[11px] leading-5 text-muted">{subtitle}</p>}</div>
          <button type="button" disabled={!dismissible} title={dismissible ? 'بستن' : 'تا پایان عملیات نمی‌توان این پنجره را بست'} className={`icon-button shrink-0 ${dismissible ? '' : 'cursor-not-allowed opacity-35'}`} onClick={requestClose}><Icon name="close" /></button>
        </div>
        <div className="node-modal-body min-h-0 flex-1 overflow-y-auto overscroll-contain p-4 sm:p-5">{children}</div>
        {footer && <div className="node-modal-footer flex shrink-0 flex-col-reverse gap-2 border-t border-border px-4 py-3 sm:flex-row sm:justify-end sm:px-5 sm:py-4">{footer}</div>}
      </div>
    </div>, document.body,
  )
}

function NodeModal({ initial, onClose, onSaved }) {
  const { notify } = useUI()
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState(() => ({
    name: '', api_url: '', api_token: '', enabled: true, user_assignment_enabled: true, node_panel_enabled: true, verify_tls: true, weight: 100,
    ssh_host: '', ssh_port: 22, ssh_username: 'root', ssh_password: '',
    panel_admin_username: 'admin', panel_admin_password: '', remote_admin_enabled: false,
    ...(initial || {}),
    // The API returns *_saved flags rather than the secret itself. Restore the
    // toggles from those flags after spreading the node payload.
    save_ssh_password: Boolean(initial?.ssh_password_saved),
    save_panel_admin_credentials: Boolean(initial?.panel_admin_password_saved),
    protocol_domains: initial?.protocol_domains || {},
  }))
  const set = (key, value) => setForm(v => ({ ...v, [key]: value }))
  const setProtocolDomain = (key, value) => setForm(v => ({ ...v, protocol_domains: { ...(v.protocol_domains || {}), [key]: value } }))
  const toggleRemoteAdmin = () => setForm(v => {
    const enabled = !v.remote_admin_enabled
    return {
      ...v,
      remote_admin_enabled: enabled,
      save_panel_admin_credentials: enabled ? true : v.save_panel_admin_credentials,
    }
  })
  const togglePanelCredentialSave = () => setForm(v => {
    const save = !v.save_panel_admin_credentials
    return {
      ...v,
      save_panel_admin_credentials: save,
      remote_admin_enabled: save ? v.remote_admin_enabled : false,
    }
  })
  const save = async () => {
    if (saving) return
    if (!form.name.trim() || !form.api_url.trim() || (!initial && !form.api_token.trim())) {
      notify({ type: 'warning', message: 'نام، آدرس API و توکن نود الزامی است.' }); return
    }
    if (form.save_ssh_password && (!form.ssh_host?.trim() || !form.ssh_username?.trim())) {
      notify({ type: 'warning', message: 'برای ذخیره مشخصات SSH، آدرس و نام کاربری SSH را وارد کنید.' }); return
    }
    if (form.save_ssh_password && !form.ssh_password && !initial?.ssh_password_saved) {
      notify({ type: 'warning', message: 'برای اولین ذخیره مشخصات SSH، رمز SSH را وارد کنید.' }); return
    }
    if (form.remote_admin_enabled && !form.save_panel_admin_credentials) {
      notify({ type: 'warning', message: 'برای مدیریت مستقیم نود، گزینه ذخیره امن مشخصات ادمین را فعال کنید.' }); return
    }
    if (form.remote_admin_enabled && !form.panel_admin_username?.trim()) {
      notify({ type: 'warning', message: 'نام کاربری ادمین پنل نود را وارد کنید.' }); return
    }
    if (form.remote_admin_enabled && !form.panel_admin_password && !initial?.panel_admin_password_saved) {
      notify({ type: 'warning', message: 'برای بار اول رمز ادمین پنل نود را وارد کنید.' }); return
    }
    setSaving(true)
    try {
      const payload = {
        ...form,
        name: form.name.trim(),
        api_url: form.api_url.trim(),
        weight: Number(form.weight) || 100,
        ssh_host: form.ssh_host?.trim() || null,
        ssh_port: Number(form.ssh_port) || 22,
        ssh_username: form.ssh_username?.trim() || null,
        save_ssh_password: Boolean(form.save_ssh_password),
        clear_ssh_password: Boolean(initial?.ssh_password_saved && !form.save_ssh_password),
        panel_admin_username: form.panel_admin_username?.trim() || null,
        save_panel_admin_credentials: Boolean(form.save_panel_admin_credentials),
        clear_panel_admin_credentials: Boolean(initial?.panel_admin_password_saved && !form.save_panel_admin_credentials),
        protocol_domains: Object.fromEntries(Object.entries(form.protocol_domains || {}).map(([key, value]) => [key, String(value || '').trim().toLowerCase()]).filter(([, value]) => value)),
      }
      delete payload.snapshot; delete payload.status; delete payload.last_seen_at; delete payload.last_error
      delete payload.created_at; delete payload.ssh_password_saved; delete payload.panel_admin_password_saved; delete payload.id
      if (initial && !payload.api_token) delete payload.api_token
      if (!payload.ssh_password) delete payload.ssh_password
      if (!payload.panel_admin_password) delete payload.panel_admin_password
      const { data } = initial ? await api.put(`/nodes/${initial.id}`, payload) : await api.post('/nodes', payload)
      notify({ type: 'success', message: 'نود و مشخصات انتخاب‌شده ذخیره شدند.' })
      await onSaved(data)
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || 'ذخیره نود ناموفق بود.' })
    } finally { setSaving(false) }
  }
  return <ModalShell title={initial ? 'ویرایش نود' : 'افزودن نود جدید'} subtitle="اطلاعات API و مشخصات اختیاری SSH و ادمین نود را وارد کنید." onClose={onClose} footer={<><button className="btn-secondary" disabled={saving} onClick={onClose}>انصراف</button><button className="btn-primary" disabled={saving} onClick={save}>{saving ? 'در حال ذخیره…' : 'ذخیره تغییرات'}</button></>}>
    <div className="grid gap-4 sm:grid-cols-2">
      <label className="space-y-1.5"><span className="text-xs text-muted">نام نود</span><input autoComplete="off" className="field node-form-input" value={form.name} onChange={e=>set('name',e.target.value)} placeholder="مثلاً Germany-1" /></label>
      <label className="space-y-1.5"><span className="text-xs text-muted">وزن اولویت</span><input autoComplete="off" inputMode="numeric" type="number" min="1" max="1000" className="field node-form-input" value={form.weight} onChange={e=>set('weight',e.target.value)} /></label>
      <label className="space-y-1.5 sm:col-span-2"><span className="text-xs text-muted">آدرس API نود</span><input autoComplete="off" dir="ltr" className="field node-form-input font-data" value={form.api_url} onChange={e=>set('api_url',e.target.value)} placeholder="https://node.example.com:8000" /></label>
      <label className="space-y-1.5 sm:col-span-2"><span className="text-xs text-muted">توکن Node Agent {initial && '(برای عدم تغییر خالی بگذار)'}</span><input autoComplete="off" dir="ltr" className="field node-form-input font-data" value={form.api_token || ''} onChange={e=>set('api_token',e.target.value)} placeholder="توکن پنل مقصد" /></label>
      <div className="sm:col-span-2 rounded-2xl border border-border bg-surface2/70 p-4">
        <div className="mb-3"><b className="text-sm">اتصال SSH اختیاری</b><p className="mt-1 text-[10px] text-muted">برای کنترل، آپدیت، نصب پروتکل و مشاهده لاگ از پنل اصلی.</p></div>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="space-y-1"><span className="text-[10px] text-muted">IP یا دامنه SSH</span><input dir="ltr" className="field node-form-input" value={form.ssh_host || ''} onChange={e=>set('ssh_host',e.target.value)} placeholder="1.2.3.4" /></label>
          <label className="space-y-1"><span className="text-[10px] text-muted">پورت</span><input type="number" className="field node-form-input" value={form.ssh_port || 22} onChange={e=>set('ssh_port',e.target.value)} /></label>
          <label className="space-y-1"><span className="text-[10px] text-muted">نام کاربری</span><input dir="ltr" className="field node-form-input" value={form.ssh_username || ''} onChange={e=>set('ssh_username',e.target.value)} placeholder="root" /></label>
          <label className="space-y-1 sm:col-span-3"><span className="text-[10px] text-muted">رمز SSH {initial?.ssh_password_saved && '(رمز ذخیره شده است؛ برای تغییر دوباره وارد کن)'}</span><input type="password" dir="ltr" autoComplete="new-password" className="field node-form-input" value={form.ssh_password || ''} onChange={e=>set('ssh_password',e.target.value)} /></label>
        </div>
        <label className="mt-3 flex items-center justify-between gap-3 rounded-xl border border-border bg-bg/40 p-3"><span><b className="block text-xs">ذخیره کامل مشخصات SSH</b><small className="mt-1 block text-[10px] text-muted">IP، پورت، نام کاربری و رمز به‌صورت رمزنگاری‌شده برای دفعات بعد نگهداری شود.</small></span><button type="button" role="switch" aria-checked={Boolean(form.save_ssh_password)} aria-label="ذخیره کامل مشخصات SSH" onClick={()=>set('save_ssh_password',!form.save_ssh_password)} className={`modern-toggle ${form.save_ssh_password ? 'is-on' : ''}`}><span /></button></label>
      </div>
      <div className="sm:col-span-2 rounded-2xl border border-signal/20 bg-signal/5 p-4">
        <div className="mb-3 flex items-start justify-between gap-3"><span><b className="text-sm">مدیریت کامل پنل نود از پنل اصلی</b><p className="mt-1 text-[10px] leading-5 text-muted">دکمه مدیریت، پنل نود را با ورود یک‌بارمصرف در صفحه جدید باز می‌کند.</p></span><button type="button" role="switch" aria-checked={Boolean(form.remote_admin_enabled)} aria-label="مدیریت کامل پنل نود از پنل اصلی" onClick={toggleRemoteAdmin} className={`modern-toggle shrink-0 ${form.remote_admin_enabled ? 'is-on' : ''}`}><span /></button></div>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="space-y-1"><span className="text-[10px] text-muted">نام کاربری ادمین اصلی نود</span><input dir="ltr" autoComplete="off" className="field node-form-input" value={form.panel_admin_username || ''} onChange={e=>set('panel_admin_username',e.target.value)} placeholder="admin" /></label>
          <label className="space-y-1"><span className="text-[10px] text-muted">رمز ادمین نود {initial?.panel_admin_password_saved && '(ذخیره شده؛ برای تغییر دوباره وارد کن)'}</span><input type="password" dir="ltr" autoComplete="new-password" className="field node-form-input" value={form.panel_admin_password || ''} onChange={e=>set('panel_admin_password',e.target.value)} /></label>
        </div>
        <label className="mt-3 flex items-center justify-between gap-3 rounded-xl border border-signal/20 bg-bg/40 p-3"><span><b className="block text-xs">ذخیره امن نام کاربری و رمز ادمین نود</b><small className="mt-1 block text-[10px] text-muted">فقط با فعال‌بودن این گزینه، ورود مستقیم و دکمه «بازکردن پنل نود» فعال می‌شود.</small></span><button type="button" role="switch" aria-checked={Boolean(form.save_panel_admin_credentials)} aria-label="ذخیره امن نام کاربری و رمز ادمین نود" onClick={togglePanelCredentialSave} className={`modern-toggle shrink-0 ${form.save_panel_admin_credentials ? 'is-on' : ''}`}><span /></button></label>
        <div className="mt-3 rounded-xl border border-warning/20 bg-warning/5 px-3 py-2 text-[10px] leading-5 text-muted">رمز خام در پاسخ API، لاگ و لیست نودها نمایش داده نمی‌شود. خاموش‌کردن گزینه ذخیره، مشخصات ذخیره‌شده قبلی را حذف و مدیریت مستقیم را غیرفعال می‌کند.</div>
      </div>
      <div className="sm:col-span-2 rounded-2xl border border-border bg-surface2/70 p-4">
        <div className="mb-3"><b className="text-sm">ساب‌دامین جداگانه پروتکل‌های این نود</b><p className="mt-1 text-[10px] leading-5 text-muted">برای هر پروتکل یک دامنه مستقل وارد کن. خالی بماند، آدرس عمومی خود نود استفاده می‌شود. DNS و SSL دامنه‌ها باید از قبل روی همین نود آماده باشند.</p></div>
        <div className="grid gap-3 sm:grid-cols-2">
          {[
            ['l2tp','L2TP/IPsec'], ['pptp','PPTP'], ['openvpn','OpenVPN'], ['openconnect','OpenConnect'],
            ['sstp','SSTP'], ['ikev2','IKEv2'], ['vmess','VMess'], ['vless','VLESS'],
          ].map(([key,label]) => <label key={key} className="space-y-1"><span className="text-[10px] text-muted">{label}</span><input dir="ltr" autoComplete="off" className="field node-form-input font-data" value={form.protocol_domains?.[key] || ''} onChange={e=>setProtocolDomain(key,e.target.value)} placeholder={`${key}.node.example.com`} /></label>)}
        </div>
      </div>
      <div className="node-option-card sm:col-span-2"><span><b className="block text-xs">پنل اختصاصی نود</b><small className="mt-1 block text-[10px] text-muted">پیش‌فرض روشن است. روشن: رابط ساده و مخصوص همین نود نمایش داده می‌شود. خاموش: رابط کامل محلی روی این سرور باز می‌شود، اما اتصال و همگام‌سازی Node Agent حفظ می‌گردد.</small></span><button type="button" role="switch" aria-checked={Boolean(form.node_panel_enabled)} aria-label="فعال بودن پنل اختصاصی نود" onClick={()=>set('node_panel_enabled',!form.node_panel_enabled)} className={`modern-toggle ${form.node_panel_enabled ? 'is-on' : ''}`}><span /></button></div>
      <div className="node-option-card sm:col-span-2"><span><b className="block text-xs">نمایش در ساخت و ویرایش کاربر</b><small className="mt-1 block text-[10px] text-muted">با خاموش‌کردن، این نود از لیست انتخاب سرور کاربران، لینک اشتراک و همگام‌سازی کاربران حذف می‌شود؛ خود نود همچنان آنلاین و قابل مدیریت می‌ماند.</small></span><button type="button" role="switch" aria-checked={Boolean(form.user_assignment_enabled)} aria-label="نمایش نود در ساخت کاربر" onClick={()=>set('user_assignment_enabled',!form.user_assignment_enabled)} className={`modern-toggle ${form.user_assignment_enabled ? 'is-on' : ''}`}><span /></button></div>
      <div className="node-option-card sm:col-span-2"><span><b className="block text-xs">نود فعال باشد</b><small className="mt-1 block text-[10px] text-muted">با خاموش‌کردن، سرور مقصد از حالت نود خارج و به حالت عادی برمی‌گردد.</small></span><button type="button" role="switch" aria-checked={Boolean(form.enabled)} aria-label="فعال بودن نود" onClick={()=>set('enabled',!form.enabled)} className={`modern-toggle ${form.enabled ? 'is-on' : ''}`}><span /></button></div>
      <div className="node-option-card sm:col-span-2"><span><b className="block text-xs">بررسی گواهی HTTPS</b><small className="mt-1 block text-[10px] text-muted">برای IP یا گواهی Self-signed خاموش کن.</small></span><button type="button" role="switch" aria-checked={Boolean(form.verify_tls)} aria-label="بررسی گواهی HTTPS" onClick={()=>set('verify_tls',!form.verify_tls)} className={`modern-toggle ${form.verify_tls ? 'is-on' : ''}`}><span /></button></div>
    </div>
  </ModalShell>
}

function ConsoleModal({ jobId, onClose }) {
  const [job, setJob] = useState(null)
  useEffect(() => {
    if (!jobId) return
    let dead = false
    const load = () => api.get(`/nodes/jobs/${jobId}`).then(({data}) => !dead && setJob(data)).catch(()=>{})
    load(); const timer=setInterval(() => { if (document.visibilityState === 'visible') load() },1000)
    const onVisible=()=>{ if (document.visibilityState === 'visible') load() }
    document.addEventListener('visibilitychange',onVisible)
    return () => { dead=true; clearInterval(timer); document.removeEventListener('visibilitychange',onVisible) }
  }, [jobId])
  const done = job && ['success','failed'].includes(job.state)
  return <ModalShell wide title={job?.title || 'کنسول نود'} subtitle={job?.state === 'running' ? 'عملیات در حال اجراست…' : job?.state === 'success' ? 'عملیات با موفقیت تمام شد.' : job?.state === 'failed' ? 'عملیات با خطا متوقف شد.' : 'در حال آماده‌سازی…'} onClose={onClose} footer={<><button className="btn-secondary" onClick={()=>copyText(job?.output || '')}><Icon name="copy" size={14}/>کپی خروجی</button><button className="btn-primary" onClick={onClose}>{done ? 'بستن' : 'بستن پنجره'}</button></>}>
    <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-surface2"><div className="h-full bg-signal transition-all" style={{width:`${job?.progress || 2}%`}} /></div>
    <pre dir="ltr" className="min-h-[360px] max-h-[62dvh] overflow-auto whitespace-pre-wrap rounded-2xl border border-border bg-bg/70 p-4 text-left font-data text-[11px] leading-6 text-emerald-300">{job?.output || '$ preparing…'}</pre>
  </ModalShell>
}

function LocalShellModal({ onClose, onJob }) {
  const { notify } = useUI()
  const [busy, setBusy] = useState(false)
  const [timeout, setTimeoutValue] = useState(600)
  const [command, setCommand] = useState('')
  const presets = [
    ['دستور دلخواه', ''],
    ['تشخیص Xray', 'sudo bash /opt/vpn-panel/scripts/check_xray_user_controls.sh'],
    ['آمار خام VM/VL', `for p in vmess vless; do port=10085; [ "$p" = vless ] && port=10086; echo "===== $p ====="; /usr/local/bin/xray api statsquery --server=127.0.0.1:$port || true; done`],
    ['سوکت‌ها و سرویس‌ها', `systemctl --no-pager --full status vpn-panel-xray-vmess vpn-panel-xray-vless vpn-panel-api; echo; ss -tnp; echo; nft list table inet vpn_panel_rate 2>&1 || true`],
    ['لاگ Xray', `for p in vmess vless; do echo "===== $p access ====="; tail -n 120 /var/log/vpn-panel/xray/$p-access.log 2>/dev/null; echo "===== $p error ====="; tail -n 120 /var/log/vpn-panel/xray/$p-error.log 2>/dev/null; done`],
  ]
  const run = async () => {
    if (busy || !command.trim()) return
    setBusy(true)
    try {
      const { data } = await api.post('/nodes/local-shell', { command: command.trim(), timeout_seconds: Number(timeout) || 600 })
      onJob(data.job_id)
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || 'اجرای دستور روی سرور ناموفق بود.' })
    } finally { setBusy(false) }
  }
  return <ModalShell wide title="ترمینال سرور فعلی" subtitle="دستورها مستقیماً روی همین سروری اجرا می‌شوند که پنل روی آن نصب است. دسترسی فقط برای ادمین اصلی فعال است." onClose={onClose} footer={<><button className="btn-secondary" onClick={onClose}>انصراف</button><button className="btn-primary" disabled={busy || !command.trim()} onClick={run}><Icon name="terminal" size={15}/>{busy ? 'در حال شروع…' : 'اجرا'}</button></>}>
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {presets.map(([label, value]) => <button key={label} type="button" className="rounded-xl border border-border bg-surface2 px-3 py-2.5 text-xs font-bold transition hover:border-signal hover:text-signal" onClick={() => setCommand(value)}>{label}</button>)}
    </div>
    <label className="mt-4 block space-y-2"><span className="text-xs text-muted">دستور دلخواه</span><textarea dir="ltr" className="field min-h-44 font-data text-xs leading-6" value={command} onChange={e=>setCommand(e.target.value)} placeholder="هر دستور Linux یا اسکریپت چندخطی را اینجا بنویسید…" spellCheck="false" /></label>
    <label className="mt-4 block max-w-56 space-y-2"><span className="text-xs text-muted">مهلت اجرا (ثانیه)</span><input type="number" min="5" max="1800" className="field node-form-input" value={timeout} onChange={e=>setTimeoutValue(e.target.value)} /></label>
  </ModalShell>
}

function ControlModal({ node, onClose, onJob, onSaved, canManage }) {
  const { notify } = useUI()
  const [command, setCommand] = useState('uname -a && uptime && ss -lntup')
  const [host, setHost] = useState(node.ssh_host || '')
  const [port, setPort] = useState(node.ssh_port || 22)
  const [username, setUsername] = useState(node.ssh_username || 'root')
  const [password, setPassword] = useState('')
  const [rememberCredentials, setRememberCredentials] = useState(Boolean(node.ssh_password_saved))
  const [savingCredentials, setSavingCredentials] = useState(false)
  const startAction = async (action) => {
    try { const {data}=await api.post(`/nodes/${node.id}/action`,{action}); onJob(data.job_id) }
    catch(err){ notify({type:'error',message:err.response?.data?.detail || 'برای این عملیات ابتدا مشخصات SSH را ذخیره کنید.'}) }
  }
  const validateRememberedCredentials = () => {
    if (!rememberCredentials) return true
    if (!host.trim() || !username.trim()) {
      notify({ type: 'warning', message: 'برای ذخیره مشخصات SSH، IP/Host و نام کاربری را وارد کنید.' })
      return false
    }
    if (!password && !node.ssh_password_saved) {
      notify({ type: 'warning', message: 'برای اولین ذخیره، رمز SSH را وارد کنید.' })
      return false
    }
    return true
  }
  const saveCredentials = async () => {
    if (savingCredentials || !rememberCredentials || !validateRememberedCredentials()) return
    setSavingCredentials(true)
    try {
      const payload = {
        ssh_host: host.trim(), ssh_port: Number(port) || 22, ssh_username: username.trim(),
        save_ssh_password: true,
      }
      if (password) payload.ssh_password = password
      await api.put(`/nodes/${node.id}`, payload)
      notify({ type: 'success', message: 'IP، پورت، نام کاربری و رمز SSH به‌صورت امن ذخیره شدند.' })
      setPassword('')
      await onSaved?.()
    } catch (err) {
      notify({ type: 'error', message: err.response?.data?.detail || 'ذخیره مشخصات SSH ناموفق بود.' })
    } finally { setSavingCredentials(false) }
  }
  const run = async () => {
    if (!validateRememberedCredentials()) return
    try {
      const {data}=await api.post(`/nodes/${node.id}/ssh`,{
        command, host:host||null, port:Number(port)||22, username:username||null,
        password:password||null, save_password:rememberCredentials, timeout_seconds:600,
      })
      onJob(data.job_id)
    } catch(err){ notify({type:'error',message:err.response?.data?.detail || 'اتصال SSH ناموفق بود.'}) }
  }
  return <ModalShell wide title={`کنترل نود — ${node.name}`} subtitle="وضعیت، لاگ، نصب پروتکل‌ها، آپدیت و فرمان SSH را از همین پنل اجرا کن." onClose={onClose} footer={<button className="btn-secondary" onClick={onClose}>بستن</button>}>
    {canManage && <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      {[['status','وضعیت'],['logs','لاگ‌ها'],['restart_panel','ری‌استارت پنل'],['install_all','نصب همه پروتکل‌ها'],['update','آپدیت نود']].map(([key,label])=><button key={key} className="rounded-xl border border-border bg-surface2 p-3 text-xs font-bold hover:border-signal hover:text-signal" onClick={()=>startAction(key)}>{label}</button>)}
    </div>}
    <div className="mt-5 rounded-2xl border border-border bg-surface2/70 p-4">
      <div className="mb-3 flex items-center gap-2"><Icon name="terminal" className="text-signal"/><b>SSH</b></div>
      <div className="grid gap-3 sm:grid-cols-4"><input dir="ltr" className="field node-form-input" placeholder="IP / Host" value={host} onChange={e=>setHost(e.target.value)}/><input type="number" className="field node-form-input" value={port} onChange={e=>setPort(e.target.value)}/><input dir="ltr" className="field node-form-input" placeholder="root" value={username} onChange={e=>setUsername(e.target.value)}/><input type="password" dir="ltr" autoComplete="new-password" className="field node-form-input" placeholder={node.ssh_password_saved?'رمز ذخیره شده':'رمز SSH'} value={password} onChange={e=>setPassword(e.target.value)}/></div>
      <textarea dir="ltr" className="field mt-3 min-h-28 font-data text-xs" value={command} onChange={e=>setCommand(e.target.value)} />
      <div className="mt-3 rounded-xl border border-border bg-bg/40 p-3">
        <label className="flex items-center justify-between gap-3 text-xs"><span><b className="block">ذخیره کامل مشخصات SSH</b><small className="mt-1 block text-[10px] text-muted">IP، پورت، نام کاربری و رمز برای کنترل‌های بعدی ذخیره شود.</small></span><button type="button" role="switch" aria-checked={Boolean(rememberCredentials)} aria-label="ذخیره کامل مشخصات SSH" onClick={()=>setRememberCredentials(!rememberCredentials)} className={`modern-toggle ${rememberCredentials?'is-on':''}`}><span/></button></label>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-end gap-2"><button className="btn-secondary" disabled={!rememberCredentials || savingCredentials} onClick={saveCredentials}>{savingCredentials?'در حال ذخیره…':'ذخیره مشخصات بدون اجرا'}</button><button className="btn-primary" onClick={run}><Icon name="terminal" size={15}/>اجرای SSH</button></div>
    </div>
  </ModalShell>
}

function InstallModal({ onClose, onJob }) {
  const { notify } = useUI()
  const [busy,setBusy]=useState(false)
  const [form,setForm]=useState({host:'',ssh_port:22,ssh_username:'root',ssh_password:'',node_name:'',node_public_url:'',panel_port:8080,admin_username:'admin',admin_password:'',license_key:'',verify_controller_tls:true,verify_node_tls:true})
  const set=(k,v)=>setForm(x=>({...x,[k]:v}))
  const submit=async()=>{
    if(busy)return
    if(!form.host||!form.ssh_password||!form.node_name||!form.node_public_url||!form.admin_password){notify({type:'warning',message:'آدرس VPS، رمز SSH، نام و آدرس نود و رمز ادمین الزامی است.'});return}
    setBusy(true)
    try{const {data}=await api.post('/nodes/remote-install',{...form,ssh_port:Number(form.ssh_port),panel_port:Number(form.panel_port)});onJob(data.job_id)}catch(err){notify({type:'error',message:err.response?.data?.detail||'شروع نصب نود ناموفق بود.'})}finally{setBusy(false)}
  }
  return <ModalShell wide title="نصب خودکار پنل نود روی VPS" subtitle="پنل از طریق SSH وارد VPS می‌شود، تمام پیش‌نیازها را نصب و نود را به همین کنترلر متصل می‌کند." onClose={onClose} footer={<><button className="btn-secondary" onClick={onClose}>انصراف</button><button className="btn-primary" disabled={busy} onClick={submit}>{busy?'در حال شروع…':'شروع نصب نود'}</button></>}>
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <label className="space-y-1"><span className="text-xs text-muted">آدرس VPS</span><input dir="ltr" className="field node-form-input" value={form.host} onChange={e=>set('host',e.target.value)} placeholder="1.2.3.4"/></label>
      <label className="space-y-1"><span className="text-xs text-muted">پورت SSH</span><input type="number" className="field node-form-input" value={form.ssh_port} onChange={e=>set('ssh_port',e.target.value)}/></label>
      <label className="space-y-1"><span className="text-xs text-muted">یوزر SSH</span><input dir="ltr" className="field node-form-input" value={form.ssh_username} onChange={e=>set('ssh_username',e.target.value)}/></label>
      <label className="space-y-1 sm:col-span-2 lg:col-span-3"><span className="text-xs text-muted">رمز SSH</span><input type="password" dir="ltr" className="field node-form-input" value={form.ssh_password} onChange={e=>set('ssh_password',e.target.value)}/></label>
      <label className="space-y-1"><span className="text-xs text-muted">نام نود</span><input className="field node-form-input" value={form.node_name} onChange={e=>set('node_name',e.target.value)} placeholder="Germany-1"/></label>
      <label className="space-y-1 sm:col-span-2"><span className="text-xs text-muted">آدرس عمومی پنل نود</span><input dir="ltr" className="field node-form-input" value={form.node_public_url} onChange={e=>set('node_public_url',e.target.value)} placeholder="https://node.example.com:8080"/></label>
      <label className="space-y-1"><span className="text-xs text-muted">پورت پنل نود</span><input type="number" className="field node-form-input" value={form.panel_port} onChange={e=>set('panel_port',e.target.value)}/></label>
      <label className="space-y-1"><span className="text-xs text-muted">یوزر ادمین نود</span><input dir="ltr" className="field node-form-input" value={form.admin_username} onChange={e=>set('admin_username',e.target.value)}/></label>
      <label className="space-y-1"><span className="text-xs text-muted">رمز ادمین نود</span><input type="password" dir="ltr" className="field node-form-input" value={form.admin_password} onChange={e=>set('admin_password',e.target.value)}/></label>
      <label className="space-y-1 sm:col-span-2 lg:col-span-3"><span className="text-xs text-muted">لایسنس پنل نود (اختیاری)</span><input dir="ltr" className="field node-form-input" value={form.license_key} onChange={e=>set('license_key',e.target.value)}/></label>
    </div>
  </ModalShell>
}


function NodeUpdateCenter({ nodes, canInstall, onRefresh }) {
  const { notify, confirm } = useUI()
  const [selected, setSelected] = useState([])
  const [states, setStates] = useState({})
  const [running, setRunning] = useState(false)
  const [showConsole, setShowConsole] = useState(false)

  const eligible = useMemo(() => (nodes || []).filter(node => node.enabled !== false), [nodes])
  useEffect(() => {
    const valid = new Set(eligible.map(node => node.id))
    setSelected(current => current.filter(id => valid.has(id)))
  }, [eligible])
  useEffect(() => {
    if (running) setShowConsole(true)
  }, [running])

  const patch = (id, value) => setStates(current => ({
    ...current,
    [id]: { ...(current[id] || {}), ...value },
  }))
  const toggle = id => setSelected(current => current.includes(id) ? current.filter(value => value !== id) : [...current, id])
  const allSelected = eligible.length > 0 && eligible.every(node => selected.includes(node.id))
  const toggleAll = () => setSelected(allSelected ? [] : eligible.map(node => node.id))
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

  const checkOne = async node => {
    patch(node.id, { state: 'checking', message: 'در حال بررسی نسخه…', percent: 0, log: '' })
    try {
      const { data } = await api.get(`/nodes/${node.id}/update/check`)
      patch(node.id, {
        state: data.update_available ? 'available' : 'current',
        current_version: data.current_version || node.snapshot?.version || '—',
        latest_version: data.latest_version || '—',
        message: data.update_available ? `نسخه ${data.latest_version} آماده است.` : 'این نود روی آخرین نسخه است.',
        percent: data.update_available ? 0 : 100,
      })
      return data
    } catch (err) {
      const oldAgent = [404, 405].includes(err.response?.status)
      const message = oldAgent
        ? (node.ssh_password_saved ? 'API آپدیت این نسخه بسیار قدیمی است؛ مسیر نهایی SSH استفاده می‌شود.' : 'API آپدیت این نسخه بسیار قدیمی است و برای مسیر نهایی باید SSH ذخیره باشد.')
        : (err.response?.data?.detail || 'بررسی نسخه نود ناموفق بود.')
      patch(node.id, { state: oldAgent ? 'legacy' : 'error', message, percent: 0 })
      return { legacy: oldAgent }
    }
  }

  const checkSelected = async () => {
    const chosen = eligible.filter(node => selected.includes(node.id))
    if (!chosen.length) { notify({ type: 'warning', message: 'حداقل یک نود را انتخاب کن.' }); return }
    for (const node of chosen) await checkOne(node)
  }

  const pollAgentUpdate = async node => {
    let connectionFailures = 0
    for (let tick = 0; tick < 480; tick += 1) {
      await sleep(2000)
      try {
        const { data } = await api.get(`/nodes/${node.id}/update/status`)
        connectionFailures = 0
        patch(node.id, {
          state: data.state === 'failed' ? 'error' : data.state === 'success' ? 'success' : 'updating',
          percent: Number(data.percent || 1),
          message: data.message || 'در حال آپدیت…',
          ...(data.log_tail ? { log: data.log_tail } : {}),
        })
        if (data.state === 'success') return true
        if (data.state === 'failed') {
          try { const log = await api.get(`/nodes/${node.id}/update/log`); patch(node.id, { log: log.data?.log || '' }) } catch {}
          return false
        }
      } catch {
        connectionFailures += 1
        patch(node.id, { state: 'updating', message: connectionFailures < 8 ? 'API نود برای اعمال آپدیت موقتاً در حال ری‌استارت است…' : 'منتظر بازگشت API نود…' })
      }
    }
    patch(node.id, { state: 'error', message: 'مهلت انتظار برای بازگشت نود تمام شد.' })
    return false
  }

  const pollSshJob = async (node, jobId) => {
    for (let tick = 0; tick < 600; tick += 1) {
      await sleep(1500)
      try {
        const { data } = await api.get(`/nodes/jobs/${jobId}`)
        patch(node.id, { state: data.state === 'failed' ? 'error' : data.state === 'success' ? 'success' : 'updating', percent: Number(data.progress || 1), message: data.state === 'running' ? 'آپدیت اولیه از طریق SSH در حال اجراست…' : data.state === 'success' ? 'آپدیت نود کامل شد.' : data.state === 'failed' ? 'آپدیت SSH ناموفق بود.' : 'در صف اجرا…', log: data.output || '' })
        if (data.state === 'success') {
          try { await api.post(`/nodes/${node.id}/update/report`, { ok: true, source: 'ssh', message: 'آپدیت نود از طریق SSH با موفقیت کامل شد.' }) } catch {}
          return true
        }
        if (data.state === 'failed') {
          try { await api.post(`/nodes/${node.id}/update/report`, { ok: false, source: 'ssh', message: String(data.output || 'آپدیت SSH ناموفق بود.').slice(-1800) }) } catch {}
          return false
        }
      } catch {}
    }
    patch(node.id, { state: 'error', message: 'مهلت اجرای آپدیت SSH تمام شد.' })
    try { await api.post(`/nodes/${node.id}/update/report`, { ok: false, source: 'ssh', message: 'مهلت اجرای آپدیت SSH تمام شد.' }) } catch {}
    return false
  }

  const updateOne = async node => {
    // Always re-check immediately before starting. A card may still contain a
    // cached "current" result from before a new ZIP was published.
    const info = await checkOne(node)
    if (info?.update_available === false) return true
    patch(node.id, { state: 'updating', percent: 1, message: 'در حال شروع آپدیت نود…', log: '' })
    try {
      await api.post(`/nodes/${node.id}/update/start`)
      return await pollAgentUpdate(node)
    } catch (err) {
      if (err.response?.status === 409) {
        patch(node.id, { state: 'updating', percent: 2, message: 'آپدیت از قبل روی این نود در حال اجراست؛ کنسول به همان فرایند متصل شد.' })
        return await pollAgentUpdate(node)
      }
      const canFallback = node.ssh_password_saved && [404, 405, 502].includes(err.response?.status)
      if (!canFallback) {
        patch(node.id, { state: 'error', message: err.response?.data?.detail || 'شروع آپدیت نود ناموفق بود.' })
        return false
      }
      try {
        patch(node.id, { state: 'updating', percent: 1, message: 'Node Agent قدیمی است؛ آپدیت اولیه از طریق SSH شروع شد…' })
        const { data } = await api.post(`/nodes/${node.id}/action`, { action: 'update' })
        return await pollSshJob(node, data.job_id)
      } catch (fallbackError) {
        patch(node.id, { state: 'error', message: fallbackError.response?.data?.detail || 'آپدیت اولیه از طریق SSH ناموفق بود.' })
        return false
      }
    }
  }

  const startSelected = async () => {
    const chosen = eligible.filter(node => selected.includes(node.id))
    if (!chosen.length) { notify({ type: 'warning', message: 'حداقل یک نود را انتخاب کن.' }); return }
    if (!await confirm({ title: 'آپدیت نودها', message: `آپدیت ${chosen.length} نود به‌صورت ترتیبی شروع شود؟ هنگام آپدیت هر نود چند لحظه آفلاین می‌شود.`, confirmLabel: 'شروع آپدیت' })) return
    setRunning(true); setShowConsole(true)
    let success = 0
    try {
      for (const node of chosen) if (await updateOne(node)) success += 1
      notify({ type: success === chosen.length ? 'success' : 'warning', message: `${success} از ${chosen.length} نود با موفقیت بررسی/آپدیت شدند.` })
      await onRefresh?.()
    } finally { setRunning(false) }
  }

  if (!canInstall) return null
  const stateLabel = value => ({ checking: 'در حال بررسی', available: 'آپدیت موجود', current: 'بروز', legacy: 'نیاز به آپدیت اولیه', updating: 'در حال آپدیت', success: 'موفق', error: 'خطا' }[value] || 'بررسی نشده')
  return <section className="panel-section overflow-hidden">
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-4">
      <div><h2 className="section-title">آپدیت متمرکز پنل نودها</h2><p className="section-subtitle">نسخه نودها را از همین پنل بررسی و به‌صورت ترتیبی آپدیت کن؛ ابتدا Node Agent، سپس ورود امن ذخیره‌شده پنل نود و فقط در نسخه‌های بسیار قدیمی SSH استفاده می‌شود.</p></div>
      <div className="flex flex-wrap gap-2"><button className="btn-secondary" disabled={running || !eligible.length} onClick={toggleAll}>{allSelected ? 'لغو انتخاب همه' : 'انتخاب همه'}</button><button className="btn-secondary" disabled={running || !selected.length} onClick={checkSelected}><Icon name="activity" size={15}/>بررسی نسخه‌ها</button><button className="btn-primary" disabled={running || !selected.length} onClick={startSelected}><Icon name="refresh" size={15}/>{running ? 'در حال آپدیت…' : 'آپدیت انتخاب‌شده‌ها'}</button></div>
    </div>
    <div className="grid gap-3 p-4 lg:grid-cols-2">
      {!eligible.length ? <div className="col-span-full rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted">نود فعالی برای آپدیت وجود ندارد.</div> : eligible.map(node => {
        const info = states[node.id] || {}
        const checked = selected.includes(node.id)
        return <article key={node.id} className={`rounded-2xl border p-4 transition ${checked ? 'border-signal bg-signal/5' : 'border-border bg-surface2/60'}`}>
          <div className="flex items-start justify-between gap-3"><label className="flex min-w-0 cursor-pointer items-center gap-3"><input type="checkbox" className="h-4 w-4 accent-orange-500" checked={checked} disabled={running} onChange={()=>toggle(node.id)}/><span className="min-w-0"><b className="block truncate text-sm">{node.name}</b><small dir="ltr" className="mt-1 block truncate font-data text-[10px] text-muted">{node.api_url}</small></span></label><StatusDot status={node.status}/></div>
          <div className="mt-3 grid grid-cols-3 gap-2 text-center text-[10px]"><div className="rounded-xl border border-border bg-bg/50 p-2"><span className="text-muted">فعلی</span><b dir="ltr" className="mt-1 block font-data">{info.current_version || node.snapshot?.version || '—'}</b></div><div className="rounded-xl border border-border bg-bg/50 p-2"><span className="text-muted">آخرین</span><b dir="ltr" className="mt-1 block font-data">{info.latest_version || '—'}</b></div><div className="rounded-xl border border-border bg-bg/50 p-2"><span className="text-muted">وضعیت</span><b className={`mt-1 block ${['error'].includes(info.state) ? 'text-danger' : ['available','legacy','updating'].includes(info.state) ? 'text-signal' : ['success','current'].includes(info.state) ? 'text-success' : ''}`}>{stateLabel(info.state)}</b></div></div>
          {info.message && <p className="mt-3 text-[10px] leading-5 text-muted">{info.message}</p>}
          {info.state === 'updating' && <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-bg"><div className="h-full bg-signal transition-all" style={{width:`${Math.max(2, Math.min(100, info.percent || 2))}%`}}/></div>}
        </article>
      })}
    </div>
    {Object.keys(states).length > 0 && <div className="border-t border-border p-4"><button className="btn-secondary" onClick={()=>setShowConsole(true)}>نمایش وضعیت و لاگ آپدیت‌ها</button></div>}
    {showConsole && <ModalShell wide dismissible={!running} title="کنسول آپدیت نودها" subtitle={running ? 'آپدیت در حال اجراست؛ این پنجره تا پایان عملیات خودکار بسته نمی‌شود و لاگ زنده نمایش داده می‌شود.' : 'نتیجه آخرین بررسی و آپدیت نودها'} onClose={()=>{ if (!running) setShowConsole(false) }} footer={running ? <button className="btn-secondary" disabled>در حال اجرا؛ پنجره باز می‌ماند</button> : <button className="btn-primary" onClick={()=>setShowConsole(false)}>بستن</button>}>
      <div className="space-y-3">
        {running && <div className="rounded-xl border border-signal/25 bg-signal/5 p-3 text-[11px] leading-6 text-signal">کنسول به فرایند آپدیت متصل است. بستن با ضربدر، کلیک بیرون و کلید Escape تا پایان عملیات غیرفعال است.</div>}
        {eligible.filter(node => states[node.id]).map(node => { const info=states[node.id]||{}; return <div key={node.id} className="rounded-2xl border border-border bg-bg/50 p-3"><div className="flex items-center justify-between gap-3"><b>{node.name}</b><span className="text-[10px] text-muted">{stateLabel(info.state)} — {info.percent || 0}%</span></div><p className="mt-2 text-[10px] text-muted">{info.message}</p>{info.log && <pre dir="ltr" className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap rounded-xl border border-border bg-black/40 p-3 text-left font-data text-[10px] leading-5 text-emerald-300">{info.log}</pre>}</div>})}
      </div>
    </ModalShell>}
  </section>
}

export default function Nodes() {
  const { notify, confirm, withBusy } = useUI()
  const [mode,setMode]=useState('local_only'),[nodes,setNodes]=useState([]),[token,setToken]=useState(''),[tokenVisible,setTokenVisible]=useState(true),[localRole,setLocalRole]=useState('main'),[controllerUrl,setControllerUrl]=useState(''),[localShellAllowed,setLocalShellAllowed]=useState(false),[localAssignmentEnabled,setLocalAssignmentEnabled]=useState(true),[loading,setLoading]=useState(true)
  const [modal,setModal]=useState(null),[control,setControl]=useState(null),[installOpen,setInstallOpen]=useState(false),[localShellOpen,setLocalShellOpen]=useState(false),[jobId,setJobId]=useState(null)
  const canManage=hasPermission('nodes:manage','nodes'), canSsh=hasPermission('nodes:ssh','nodes'), canInstall=hasPermission('nodes:install','nodes')
  const load=async()=>{try{const [{data},tokenRes]=await Promise.all([api.get('/nodes'),api.get('/nodes/agent-token').catch(()=>({data:{token:''}}))]);setMode(data.mode);setNodes(data.nodes||[]);if(Object.prototype.hasOwnProperty.call(tokenRes.data||{},'token'))setToken(tokenRes.data.token||'');setLocalRole(data.local_role||'main');setControllerUrl(data.controller_url||'');setLocalShellAllowed(Boolean(data.local_shell_allowed));setLocalAssignmentEnabled(data.local_user_assignment_enabled !== false)}catch(err){notify({type:'error',message:err.response?.data?.detail||'دریافت نودها ناموفق بود.'})}finally{setLoading(false)}}
  useEffect(()=>{load()},[])
  const changeMode=async value=>{try{await api.post('/nodes/mode',{mode:value});setMode(value);notify({type:'success',message:'حالت سرورها ذخیره شد.'})}catch(err){notify({type:'error',message:err.response?.data?.detail||'ذخیره ناموفق بود.'})}}
  const toggleLocalAssignment=async()=>{const next=!localAssignmentEnabled;try{setLocalAssignmentEnabled(next);await api.put('/nodes/assignment/local',{enabled:next});notify({type:'success',message:next?'سرور اصلی در ساخت کاربر نمایش داده می‌شود.':'سرور اصلی از ساخت کاربر و کانفیگ‌ها حذف شد.'});await load()}catch(err){setLocalAssignmentEnabled(!next);notify({type:'error',message:err.response?.data?.detail||'تغییر وضعیت سرور اصلی ناموفق بود.'})}}
  const toggleNodeAssignment=async node=>{const next=node.user_assignment_enabled===false;setNodes(current=>current.map(item=>item.id===node.id?{...item,user_assignment_enabled:next}:item));try{await api.put(`/nodes/${node.id}`,{user_assignment_enabled:next});notify({type:'success',message:next?`${node.name} در ساخت کاربر نمایش داده می‌شود.`:`${node.name} از ساخت کاربر و کانفیگ‌ها حذف شد.`});await load()}catch(err){setNodes(current=>current.map(item=>item.id===node.id?{...item,user_assignment_enabled:!next}:item));notify({type:'error',message:err.response?.data?.detail||'تغییر وضعیت نود ناموفق بود.'})}}
  const test=async node=>{try{await withBusy(`تست ${node.name}`,()=>api.post(`/nodes/${node.id}/test`));notify({type:'success',message:'اتصال نود برقرار است.'})}catch(err){notify({type:'error',message:err.response?.data?.detail||'نود پاسخ نداد.'})}load()}
  const sync=async node=>{try{const {data}=await withBusy(`همگام‌سازی ${node.name}`,()=>api.post(`/nodes/${node.id}/sync`));notify({type:'success',message:`همگام‌سازی انجام شد: ${data.created||0} جدید، ${data.updated||0} بروزرسانی.`});load()}catch(err){notify({type:'error',message:err.response?.data?.detail||'همگام‌سازی ناموفق بود.'})}}
  const openAdmin=async node=>{const popup=window.open('about:blank','_blank');if(!popup){notify({type:'error',message:'مرورگر بازشدن صفحه جدید را مسدود کرده است.'});return}const escapeHtml=(value)=>String(value||'').replace(/[&<>"']/g,(char)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[char]));const render=(message,error='')=>{try{popup.document.open();popup.document.write(`<title>${escapeHtml(node.name)} — Node</title><body dir="rtl" style="font-family:system-ui;background:#0b0d10;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0"><div style="width:min(90vw,460px);padding:24px;border:1px solid #2a3038;background:#12161b;border-radius:18px;text-align:center"><div style="color:#ff7b19;font-weight:800">پنل نود — ${escapeHtml(node.name)}</div><div style="margin-top:12px;color:#b7c0cb;font-size:13px">${escapeHtml(message)}</div>${error?`<pre dir="ltr" style="white-space:pre-wrap;text-align:left;margin-top:14px;padding:12px;border:1px solid #6b2630;background:#2a1116;color:#ff9aa6;border-radius:10px;font-size:11px">${escapeHtml(error)}</pre><button onclick="window.close()" style="margin-top:14px;background:#ff6b00;color:white;border:0;border-radius:9px;padding:9px 16px;cursor:pointer">بستن</button>`:'<div style="margin:18px auto 0;width:30px;height:30px;border:3px solid #343b44;border-top-color:#ff6b00;border-radius:999px;animation:spin .8s linear infinite"></div><style>@keyframes spin{to{transform:rotate(360deg)}}</style>'}</div></body>`);popup.document.close()}catch{}};render('در حال آماده‌سازی نشست مدیریت نود…');const timeoutId=setTimeout(()=>render('ارتباط با نود بیشتر از حد انتظار طول کشید.','پاسخی از نود دریافت نشد. آدرس، پورت، SSL و دسترسی Node Agent را بررسی کنید.'),17000);try{const {data}=await api.post(`/nodes/${node.id}/open-admin`,null,{timeout:15000});clearTimeout(timeoutId);if(!data?.url)throw new Error('آدرس ورود نود از سرور دریافت نشد');render('نشست آماده شد؛ در حال ورود…');popup.location.replace(data.url)}catch(err){clearTimeout(timeoutId);const message=err.response?.data?.detail||err.message||'ورود مستقیم به پنل نود ناموفق بود.';render('ساخت نشست مدیریت نود ناموفق بود.',message);notify({type:'error',message})}}
  const remove=async node=>{if(!await confirm({title:'حذف نود',message:`نود «${node.name}» حذف شود؟`,confirmLabel:'حذف',danger:true}))return;try{await api.delete(`/nodes/${node.id}`);setNodes(v=>v.filter(n=>n.id!==node.id));notify({type:'success',message:'نود حذف شد.'})}catch(err){notify({type:'error',message:err.response?.data?.detail||'حذف ناموفق بود.'})}}
  const regenerate=async()=>{if(!await confirm({title:'توکن جدید',message:'توکن قبلی نامعتبر می‌شود.',confirmLabel:'بازسازی',danger:true}))return;const {data}=await api.post('/nodes/agent-token/regenerate');setToken(data.token)}
  const openJob=id=>{setControl(null);setInstallOpen(false);setLocalShellOpen(false);setJobId(id)}
  return <div dir="rtl" className="space-y-5 text-right">
    <header className="flex flex-wrap items-end justify-between gap-3"><div><div className="flex flex-wrap items-center gap-2"><h1 className="page-heading">نودها</h1><span className="status-pill status-neutral">این سرور: {localRole==='node'?'نود':'اصلی'}</span></div><p className="page-subtitle">مدیریت چند سرور، همگام‌سازی و کنترل کامل از راه دور{localRole==='node'&&controllerUrl?` — متصل به ${controllerUrl}`:''}</p></div><div className="flex flex-wrap gap-2">{canSsh&&localShellAllowed&&<button className="btn-secondary" onClick={()=>setLocalShellOpen(true)}><Icon name="terminal" size={15}/>ترمینال سرور فعلی</button>}{canInstall&&<button className="btn-secondary" onClick={()=>setInstallOpen(true)}><Icon name="terminal" size={15}/>نصب نود روی VPS</button>}{canManage&&<button className="btn-primary" onClick={()=>setModal({})}><Icon name="plus" size={16}/>افزودن نود</button>}</div></header>
    <section className="panel-section p-4 sm:p-5"><div className="mb-4"><h2 className="section-title">نحوه استفاده از سرورها</h2><p className="section-subtitle">OpenVPN همه Remoteها را در یک فایل با remote-random می‌گیرد؛ VMess/VLESS هم همه نودهای آنلاین را داخل ساب می‌گذارند.</p></div><div className="grid gap-3 lg:grid-cols-3">{MODES.map(item=><button disabled={!canManage} key={item.value} onClick={()=>changeMode(item.value)} className={`rounded-2xl border p-4 text-start transition ${mode===item.value?'border-signal bg-signal/10':'border-border bg-surface2 hover:border-signal/40'}`}><b className="text-sm">{item.title}</b><p className="mt-1 text-[11px] leading-5 text-muted">{item.text}</p></button>)}</div></section>
    <section className="panel-section p-4 sm:p-5"><div className="mb-4"><h2 className="section-title">نمایش سرورها در ساخت کاربر و کانفیگ</h2><p className="section-subtitle">سرور خاموش از فرم ساخت/ویرایش کاربر، Subscription و همگام‌سازی کاربران حذف می‌شود ولی برای مدیریت و آپدیت همچنان در بخش نودها باقی می‌ماند.</p></div><div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3"><button disabled={!canManage} onClick={toggleLocalAssignment} className={`modern-switch-card ${localAssignmentEnabled?'is-active':''}`}><span><b className="block text-sm">سرور اصلی</b><small className="mt-1 block text-[10px] text-muted">{localAssignmentEnabled?'در فرم کاربران و کانفیگ‌ها نمایش داده می‌شود':'کاملاً از انتخاب کاربران مخفی است'}</small></span><span className={`modern-switch-knob ${localAssignmentEnabled?'is-active':''}`}><span className="modern-switch-knob__dot" /></span></button>{nodes.map(node=><button key={node.id} disabled={!canManage||node.enabled===false} onClick={()=>toggleNodeAssignment(node)} className={`modern-switch-card ${node.user_assignment_enabled!==false?'is-active':''}`} title="برای تغییر، تنظیمات نود را باز کن"><span><b className="block text-sm">{node.name}</b><small className="mt-1 block text-[10px] text-muted">{node.user_assignment_enabled!==false?'قابل انتخاب برای کاربران':'مخفی از ساخت کاربر'}</small></span><span className={`modern-switch-knob ${node.user_assignment_enabled!==false?'is-active':''}`}><span className="modern-switch-knob__dot" /></span></button>)}</div></section>
    <section className="panel-section p-4 sm:p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="section-title">API Secret / توکن Node Agent</h2><p className="section-subtitle">برای اتصال این سرور به یک کنترلر دیگر.</p></div><div className="flex gap-2"><button className="btn-secondary" onClick={()=>copyText(token).then(()=>notify({type:'success',message:'توکن کپی شد.'}))}><Icon name="copy" size={15}/>کپی</button>{canManage&&<button className="btn-danger" onClick={regenerate}><Icon name="refresh" size={15}/>بازسازی</button>}</div></div><div className="mt-4 flex gap-2"><div dir="ltr" className="min-w-0 flex-1 break-all rounded-xl border border-border bg-bg/60 p-3 font-data text-xs text-signal">{token ? (tokenVisible ? token : '••••••••••••••••••••••••••••••••') : 'API Secret دریافت نشد؛ صفحه را تازه‌سازی یا بازسازی کن'}</div><button className="btn-secondary" onClick={()=>setTokenVisible(v=>!v)}>{tokenVisible?'مخفی':'نمایش'}</button></div></section>
    <NodeUpdateCenter nodes={nodes} canInstall={canInstall} onRefresh={load}/>
    <section className="panel-section overflow-hidden"><div className="flex items-center justify-between border-b border-border p-4"><div><h2 className="section-title">سرورهای متصل</h2><p className="section-subtitle">سلامت و همگام‌سازی خودکار؛ کنترل دستی با SSH.</p></div><span className="status-pill status-neutral">{nodes.length} نود</span></div><div className="grid gap-3 p-4 xl:grid-cols-2">{loading?<div className="col-span-full py-10 text-center text-muted">در حال بارگذاری…</div>:!nodes.length?<div className="col-span-full rounded-2xl border border-dashed border-border py-12 text-center text-muted">سروری برای نمایش در محدوده دسترسی این حساب وجود ندارد.</div>:nodes.map(node=>{const snap=node.snapshot||{};const enabled=Object.entries(snap.protocols||{}).filter(([k,v])=>v?.enabled&&hasProtocol(k)).map(([k])=>k.toUpperCase());const adminReady=Boolean(node.remote_admin_enabled&&node.panel_admin_password_saved&&node.panel_admin_username);return <article key={node.id} className="rounded-2xl border border-border bg-surface2/70 p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="flex items-center gap-2"><h3 className="font-black">{node.name}</h3><StatusDot status={node.status}/></div><div dir="ltr" className="mt-1 max-w-[360px] truncate font-data text-[10px] text-muted">{node.api_url}</div></div><div className="flex flex-wrap gap-1.5"><button className="icon-button" title="تست" onClick={()=>test(node)}><Icon name="activity" size={16}/></button>{canManage&&<button className="icon-button" title="همگام‌سازی" onClick={()=>sync(node)}><Icon name="refresh" size={16}/></button>}{canManage&&<button className={`icon-button ${adminReady?'text-signal':'text-muted'}`} title={adminReady?'مدیریت کامل پنل نود':'فعال‌سازی مدیریت مستقیم'} onClick={()=>adminReady?openAdmin(node):(notify({type:'info',message:'ابتدا در ویرایش نود، ذخیره امن مشخصات ادمین و مدیریت مستقیم را فعال کنید.'}),setModal(node))}><Icon name="external" size={16}/></button>}{canSsh&&<button className="icon-button" title="کنترل و SSH" onClick={()=>setControl(node)}><Icon name="terminal" size={16}/></button>}{canManage&&<button className="icon-button" title="ویرایش" onClick={()=>setModal(node)}><Icon name="edit" size={16}/></button>}{canManage&&<button className="icon-button text-danger" title="حذف" onClick={()=>remove(node)}><Icon name="trash" size={16}/></button>}</div></div><div className="mt-4 grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-4">{[['آدرس عمومی',snap.public_address||'—'],['نسخه',snap.version||'—'],['آنلاین',snap.online_sessions??'—'],['وزن',node.weight]].map(([a,b])=><div key={a} className="rounded-xl border border-border bg-bg/50 p-3 text-center"><span className="text-muted">{a}</span><b dir="ltr" className="mt-1 block truncate font-data">{b}</b></div>)}</div>{canManage&&<button className={`btn-secondary mt-3 w-full justify-center ${adminReady?'':'opacity-80'}`} onClick={()=>adminReady?openAdmin(node):(notify({type:'info',message:'مشخصات ادمین نود هنوز ذخیره و فعال نشده است.'}),setModal(node))}><Icon name="external" size={15}/>{adminReady?'بازکردن و مدیریت کامل پنل نود':'فعال‌سازی مدیریت کامل پنل نود'}</button>}{canSsh&&<button className="btn-secondary mt-2 w-full justify-center" onClick={()=>setControl(node)}><Icon name="terminal" size={15}/>ترمینال این نود</button>}<div className="mt-3 flex flex-wrap gap-1.5">{adminReady?<span className="rounded-lg border border-success/25 bg-success/5 px-2 py-1 text-[9px] text-success">مدیریت مستقیم فعال</span>:<span className="rounded-lg border border-border bg-bg/40 px-2 py-1 text-[9px] text-muted">مدیریت مستقیم تنظیم نشده</span>}<span className={`rounded-lg border px-2 py-1 text-[9px] ${node.node_panel_enabled!==false?'border-signal/25 bg-signal/5 text-signal':'border-border bg-bg/40 text-muted'}`}>{node.node_panel_enabled!==false?'پنل اختصاصی نود':'رابط کامل محلی'}</span><span className={`rounded-lg border px-2 py-1 text-[9px] ${node.user_assignment_enabled!==false?'border-success/25 bg-success/5 text-success':'border-warning/25 bg-warning/5 text-warning'}`}>{node.user_assignment_enabled!==false?'نمایش در ساخت کاربر':'مخفی از ساخت کاربر'}</span>{enabled.map(p=><span key={p} className="rounded-lg border border-signal/20 bg-signal/5 px-2 py-1 text-[9px] text-signal">{p}</span>)}</div>{node.status!=='online'&&node.last_error&&<div className="mt-3 rounded-xl border border-danger/20 bg-danger/5 p-2 text-[10px] text-danger">{node.last_error}</div>}</article>})}</div></section>
    {modal&&<NodeModal initial={modal.id?modal:null} onClose={()=>setModal(null)} onSaved={async()=>{setModal(null);await load()}}/>}
    {control&&<ControlModal node={control} canManage={canManage} onClose={()=>setControl(null)} onJob={openJob} onSaved={async()=>{await load()}}/>} {installOpen&&<InstallModal onClose={()=>setInstallOpen(false)} onJob={openJob}/>} {localShellOpen&&<LocalShellModal onClose={()=>setLocalShellOpen(false)} onJob={openJob}/>} {jobId&&<ConsoleModal jobId={jobId} onClose={()=>{setJobId(null);load()}}/>}
  </div>
}
