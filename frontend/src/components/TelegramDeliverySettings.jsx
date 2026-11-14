import React, { useEffect, useState } from 'react'
import api from '../api'
import { Icon } from './icons.jsx'
import { useUI } from './ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'

const TEXT = {
  fa: {
    heading: 'لاگ‌ها و بکاپ تلگرام',
    subtitle: 'ارسال رویدادهای پنل، اتصال کاربران و بکاپ‌های زمان‌بندی‌شده به چت‌ها یا کانال‌های جداگانه',
    loading: 'در حال بارگذاری تنظیمات تلگرام...', enabled: 'فعال', disabled: 'غیرفعال',
    tokenTitle: 'اتصال ربات اعلان‌ها', tokenLabel: 'توکن ربات تلگرام', tokenPlaceholder: '123456789:AAExample-BotToken',
    tokenHint: 'این توکن فقط برای ارسال اعلان‌های پنل و بکاپ استفاده می‌شود؛ polling و کنترل تعاملی قدیمی غیرفعال شده است.',
    show: 'نمایش', hide: 'مخفی‌کردن',
    logTitle: 'کانال لاگ رویدادهای پنل', logHint: 'ورود مدیر، ساخت و ویرایش کاربر، تغییر تنظیمات، بن آی‌پی و سایر رویدادهای مدیریتی.',
    logPlaceholder: '-1001234567890 یا @my_log_channel', testLog: 'ارسال پیام تست لاگ',
    connTitle: 'کانال اتصال و قطع اتصال کاربران', connHint: 'ورود و خروج کاربران همراه با یوزرنیم و IP. اگر خالی باشد از کانال لاگ اصلی استفاده می‌شود.',
    connPlaceholder: 'خالی = همان کانال لاگ اصلی', testConn: 'ارسال پیام تست اتصال',
    backupTitle: 'کانال بکاپ خودکار', backupHint: 'فایل بکاپ کامل پنل و نودها هر روز در ساعت انتخاب‌شده و بر اساس منطقه زمانی خود پنل ارسال می‌شود.',
    backupPlaceholder: '-1001234567890 یا @my_backup_channel', interval: 'ساعت ارسال روزانه (۰ تا ۲۳)', timezone: 'منطقه زمانی پنل:',
    password: 'رمز root سرور در پیام بکاپ', passwordPlaceholder: 'رمز root را دستی وارد کنید',
    passwordHint: 'لینوکس رمز فعلی را به‌صورت واضح قابل خواندن نمی‌کند؛ آن را یک‌بار دستی وارد کنید. مقدار رمزگذاری‌شده ذخیره و در توضیح هر بکاپ تلگرام نوشته می‌شود.',
    passwordWarning: 'هشدار: هر عضو کانال بکاپ این رمز را می‌بیند؛ کانال حتماً خصوصی باشد.',
    passwordSet: 'رمز root ذخیره شده و در پیام بکاپ درج می‌شود.', clearPassword: 'پاک‌کردن رمز ذخیره‌شده', lastSent: 'آخرین ارسال:',
    sendNow: 'ارسال بکاپ همین الان', save: 'ذخیره تنظیمات لاگ و بکاپ', saving: 'در حال ذخیره تنظیمات تلگرام...',
    saved: 'تنظیمات لاگ و بکاپ تلگرام ذخیره شد', saveError: 'ذخیره تنظیمات تلگرام ناموفق بود',
    testing: 'در حال ارسال پیام تست...', testLogSent: 'پیام تست به کانال لاگ ارسال شد', testConnSent: 'پیام تست به کانال اتصالات ارسال شد',
    testError: 'ارسال پیام تست ناموفق بود', sending: 'در حال ساخت و ارسال بکاپ کامل...', sent: 'فایل بکاپ به تلگرام ارسال شد', sentDegraded: 'بکاپ ارسال شد اما کامل نیست؛ علت دقیق پایین نمایش داده شده است.', healthWarningTitle: 'هشدار سلامت آخرین بکاپ', sendError: 'ارسال بکاپ ناموفق بود',
  },
  en: {
    heading: 'Telegram Logs & Backups', subtitle: 'Send panel events, connection activity, and scheduled backups to separate chats or channels',
    loading: 'Loading Telegram settings...', enabled: 'Enabled', disabled: 'Disabled',
    tokenTitle: 'Notification bot connection', tokenLabel: 'Telegram bot token', tokenPlaceholder: '123456789:AAExample-BotToken',
    tokenHint: 'This token is used only for panel notifications and backups. The legacy interactive polling controller is disabled.', show: 'Show', hide: 'Hide',
    logTitle: 'Panel event log channel', logHint: 'Admin logins, user changes, settings changes, IP bans, and other management events.',
    logPlaceholder: '-1001234567890 or @my_log_channel', testLog: 'Send log test',
    connTitle: 'User connection channel', connHint: 'VPN connection events with username and IP. Leave empty to use the main log channel.',
    connPlaceholder: 'Empty = main log channel', testConn: 'Send connection test',
    backupTitle: 'Automatic backup channel', backupHint: 'A full panel and node backup is sent every day at the selected hour in the panel timezone.',
    backupPlaceholder: '-1001234567890 or @my_backup_channel', interval: 'Daily send hour (0–23)', timezone: 'Panel timezone:',
    password: 'Root password in backup message', passwordPlaceholder: 'Enter the root password manually',
    passwordHint: 'Linux cannot reveal the current plaintext password. Enter it once; it is stored encrypted and added to each Telegram backup caption.',
    passwordWarning: 'Warning: every backup-channel member can see this password. Keep the channel private.',
    passwordSet: 'The root password is stored and will be included in backup messages.',
    clearPassword: 'Clear stored password', lastSent: 'Last sent:', sendNow: 'Send backup now', save: 'Save log and backup settings',
    saving: 'Saving Telegram settings...', saved: 'Telegram log and backup settings saved', saveError: 'Could not save Telegram settings',
    testing: 'Sending test message...', testLogSent: 'Test sent to log channel', testConnSent: 'Test sent to connection channel',
    testError: 'Could not send test message', sending: 'Building and sending full backup...', sent: 'Backup sent to Telegram', sentDegraded: 'Backup was sent, but it is incomplete. The exact cause is shown below.', healthWarningTitle: 'Last backup health warning', sendError: 'Could not send backup',
  },
}

function Toggle({ checked, onChange, w }) {
  return <button type="button" onClick={() => onChange(!checked)} aria-pressed={checked}
    className={`flex min-w-[112px] items-center justify-between gap-3 rounded-xl border px-3 py-2 text-xs font-extrabold ${checked ? 'border-success/35 bg-success/10 text-success' : 'border-border bg-surface2 text-muted'}`}>
    <span>{checked ? w.enabled : w.disabled}</span>
    <span className={`relative h-5 w-10 rounded-full ${checked ? 'bg-success' : 'border border-border bg-bg'}`}>
      <span className="absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all" style={{ insetInlineStart: checked ? '1.375rem' : '0.125rem' }} />
    </span>
  </button>
}

function Block({ icon, title, hint, enabled, onToggle, w, children }) {
  return <section className="overflow-hidden rounded-2xl border border-border bg-surface/75">
    <div className="flex flex-col gap-3 border-b border-border/75 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-start gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-signal/10 text-signal"><Icon name={icon} size={19}/></span>
        <div><div className="text-sm font-black text-ink">{title}</div><p className="mt-1 max-w-3xl text-[11px] leading-5 text-muted">{hint}</p></div>
      </div>
      {typeof enabled === 'boolean' && <Toggle checked={enabled} onChange={onToggle} w={w}/>} 
    </div>
    <div className="space-y-3 p-4">{children}</div>
  </section>
}

export default function TelegramDeliverySettings() {
  const { lang, dir } = useLang(); const w = TEXT[lang] || TEXT.fa; const { withBusy, notify } = useUI()
  const [cfg, setCfg] = useState({bot_token:'',log_chat_id:'',log_enabled:false,conn_log_chat_id:'',conn_log_enabled:true,backup_chat_id:'',backup_enabled:false,backup_daily_hour:6,backup_timezone:'UTC',backup_last_sent_at:null,backup_last_health_complete:true,backup_last_health_warnings:[],backup_server_password:'',backup_server_password_configured:false,clear_backup_server_password:false})
  const [loading,setLoading]=useState(true), [saving,setSaving]=useState(false), [working,setWorking]=useState(''), [error,setError]=useState(''), [showToken,setShowToken]=useState(false), [showPassword,setShowPassword]=useState(false)

  useEffect(() => { let cancelled=false; api.get('/backup/telegram-settings').then(({data})=>{if(!cancelled)setCfg(prev=>({...prev,...data,backup_server_password:data.backup_server_password||'',clear_backup_server_password:false}))}).catch(e=>{if(!cancelled)setError(e.response?.data?.detail||w.saveError)}).finally(()=>{if(!cancelled)setLoading(false)}); return()=>{cancelled=true} }, [w.saveError])

  const save=async()=>{setError('');setSaving(true);try{const {data}=await withBusy(w.saving,()=>api.post('/backup/telegram-settings',{bot_token:cfg.bot_token,log_chat_id:cfg.log_chat_id,log_enabled:!!cfg.log_enabled,conn_log_chat_id:cfg.conn_log_chat_id,conn_log_enabled:!!cfg.conn_log_enabled,backup_chat_id:cfg.backup_chat_id,backup_enabled:!!cfg.backup_enabled,backup_daily_hour:Math.max(0,Math.min(23,Number(cfg.backup_daily_hour)||0)),backup_server_password:cfg.backup_server_password||null,clear_backup_server_password:!!cfg.clear_backup_server_password}),{dir});setCfg(prev=>({...prev,...data,backup_server_password:data.backup_server_password||'',clear_backup_server_password:false}));notify?.({type:'success',message:w.saved,dir})}catch(e){setError(e.response?.data?.detail||w.saveError)}finally{setSaving(false)}}
  const test=async kind=>{setError('');setWorking(kind);try{await withBusy(w.testing,()=>api.post(kind==='log'?'/backup/telegram-settings/test-log':'/backup/telegram-settings/test-conn-log'),{dir});notify?.({type:'success',message:kind==='log'?w.testLogSent:w.testConnSent,dir})}catch(e){setError(e.response?.data?.detail||w.testError)}finally{setWorking('')}}
  const send=async()=>{setError('');setWorking('backup');try{const {data}=await withBusy(w.sending,()=>api.post('/backup/telegram-settings/send-backup-now'),{dir});setCfg(prev=>({...prev,backup_last_sent_at:data.sent_at,backup_last_health_complete:data.backup_complete!==false,backup_last_health_warnings:Array.isArray(data.warnings)?data.warnings:[]}));notify?.({type:data.backup_complete===false?'warning':'success',message:data.backup_complete===false?w.sentDegraded:w.sent,dir})}catch(e){setError(e.response?.data?.detail||w.sendError)}finally{setWorking('')}}

  if(loading)return <div className="panel-section p-6 text-sm text-muted">{w.loading}</div>
  return <div className="space-y-5" dir={dir}>
    <div><h2 className="text-lg font-black text-ink">{w.heading}</h2><p className="mt-1 text-xs leading-6 text-muted">{w.subtitle}</p></div>
    {error&&<div className="rounded-xl border border-danger/35 bg-danger/10 px-4 py-3 text-sm text-danger">{error}</div>}
    <Block icon="telegram" title={w.tokenTitle} hint={w.tokenHint} w={w}>
      <label className="text-xs font-bold text-ink">{w.tokenLabel}</label><div className="relative" dir="ltr"><input type={showToken?'text':'password'} autoComplete="off" className="field pe-11 font-data" placeholder={w.tokenPlaceholder} value={cfg.bot_token||''} onChange={e=>setCfg(p=>({...p,bot_token:e.target.value.trim()}))}/><button type="button" onClick={()=>setShowToken(v=>!v)} className="absolute end-2 top-1/2 flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-lg text-muted hover:bg-surface2 hover:text-ink"><Icon name={showToken?'eyeOff':'eye'} size={17}/></button></div>
    </Block>
    <Block icon="log" title={w.logTitle} hint={w.logHint} enabled={cfg.log_enabled} onToggle={v=>setCfg(p=>({...p,log_enabled:v}))} w={w}><input className="field font-data" dir="ltr" placeholder={w.logPlaceholder} value={cfg.log_chat_id||''} onChange={e=>setCfg(p=>({...p,log_chat_id:e.target.value}))}/><button type="button" onClick={()=>test('log')} disabled={working==='log'} className="btn-secondary min-h-10 text-xs disabled:opacity-50">{working==='log'?'…':w.testLog}</button></Block>
    <Block icon="activity" title={w.connTitle} hint={w.connHint} enabled={cfg.conn_log_enabled} onToggle={v=>setCfg(p=>({...p,conn_log_enabled:v}))} w={w}><input className="field font-data" dir="ltr" placeholder={w.connPlaceholder} value={cfg.conn_log_chat_id||''} onChange={e=>setCfg(p=>({...p,conn_log_chat_id:e.target.value}))}/><button type="button" onClick={()=>test('conn')} disabled={working==='conn'} className="btn-secondary min-h-10 text-xs disabled:opacity-50">{working==='conn'?'…':w.testConn}</button></Block>
    <Block icon="backup" title={w.backupTitle} hint={w.backupHint} enabled={cfg.backup_enabled} onToggle={v=>setCfg(p=>({...p,backup_enabled:v}))} w={w}>
      <input className="field font-data" dir="ltr" placeholder={w.backupPlaceholder} value={cfg.backup_chat_id||''} onChange={e=>setCfg(p=>({...p,backup_chat_id:e.target.value}))}/>
      <div className="grid gap-3 lg:grid-cols-2"><div><label className="mb-1.5 block text-xs font-bold text-ink">{w.interval}</label><input type="number" min="0" max="23" className="field font-data text-center" value={cfg.backup_daily_hour} onChange={e=>setCfg(p=>({...p,backup_daily_hour:e.target.value}))}/><p className="mt-1 text-[10px] leading-5 text-muted">{w.timezone} <span className="font-data text-ink">{cfg.backup_timezone||'UTC'}</span></p></div><div><label className="mb-1.5 block text-xs font-bold text-ink">{w.password}</label><div className="relative" dir="ltr"><input type={showPassword?'text':'password'} autoComplete="new-password" className="field pe-11 font-data" placeholder={w.passwordPlaceholder} value={cfg.backup_server_password||''} onChange={e=>setCfg(p=>({...p,backup_server_password:e.target.value,clear_backup_server_password:false}))}/><button type="button" onClick={()=>setShowPassword(v=>!v)} className="absolute end-2 top-1/2 flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-lg text-muted hover:bg-surface2 hover:text-ink"><Icon name={showPassword?'eyeOff':'eye'} size={17}/></button></div><p className="mt-1 text-[10px] leading-5 text-muted">{w.passwordHint}</p><p className="mt-1 text-[10px] font-bold leading-5 text-amber">⚠ {w.passwordWarning}</p></div></div>
      {cfg.backup_server_password_configured&&<div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-success/20 bg-success/5 px-3 py-2 text-[10px] text-success"><span>{w.passwordSet}</span><button type="button" className="font-bold text-danger" onClick={()=>setCfg(p=>({...p,clear_backup_server_password:true,backup_server_password:''}))}>{w.clearPassword}</button></div>}
      {cfg.clear_backup_server_password&&<p className="text-[10px] font-bold text-danger">{w.clearPassword}</p>}
      {cfg.backup_last_sent_at&&<div className="text-xs text-muted">{w.lastSent} <span className="font-data text-ink">{new Date(`${cfg.backup_last_sent_at}Z`).toLocaleString(dir==='ltr'?'en-US':'fa-IR')}</span></div>}
      {cfg.backup_last_health_complete===false&&Array.isArray(cfg.backup_last_health_warnings)&&cfg.backup_last_health_warnings.length>0&&<div className="rounded-xl border border-amber/35 bg-amber/10 px-3 py-3 text-xs text-amber"><div className="mb-2 font-black">⚠ {w.healthWarningTitle}</div><div className="space-y-1 leading-5">{cfg.backup_last_health_warnings.slice(0,4).map((item,index)=><div key={index}>• {item}</div>)}</div></div>}
      <button type="button" onClick={send} disabled={working==='backup'} className="btn-secondary min-h-10 text-xs disabled:opacity-50">{working==='backup'?'…':w.sendNow}</button>
    </Block>
    <button type="button" onClick={save} disabled={saving} className="btn-primary min-h-12 w-full text-sm disabled:opacity-50">{saving?'…':w.save}</button>
  </div>
}
