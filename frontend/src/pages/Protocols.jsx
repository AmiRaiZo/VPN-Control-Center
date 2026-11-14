import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import * as ReactDOM from 'react-dom'
import api from '../api'
import { useUI } from '../components/ui/UIProvider.jsx'
import { useLang } from '../i18n/dashboardLang.jsx'
import { hasPermission, hasProtocol } from '../permissions.js'
import { getRemoteNodeName, getServerRole } from '../session.js'
import { copyText } from '../utils/clipboard.js'

const COLORS = {
  l2tp: 'text-signal', ipsec: 'text-signal', pptp: 'text-violet', openvpn: 'text-amber',
  openconnect: 'text-rose', sstp: 'text-danger', ikev2: 'text-skyblue', vmess: 'text-violet', vless: 'text-skyblue',
}

function protocolErrorMessage(error, fallback, lang = 'fa') {
  const data = error?.response?.data || {}
  if (data.message) return data.message
  if (data.detail === 'node_managed_by_controller') {
    return lang === 'fa'
      ? 'این نود فقط از پنل اصلی مدیریت می‌شود؛ نود را به نسخه جدید بروزرسانی کنید و دوباره تلاش کنید.'
      : 'This node is controller-managed. Update the node and try again.'
  }
  return data.detail || error?.message || fallback
}

const I18N = {
  fa: {
    title: 'مدیریت پروتکل‌ها', subtitle: 'وضعیت، نصب، لاگ و تمام تنظیمات سرویس‌های VPN', refresh: 'بروزرسانی', serverSelector: 'انتخاب سرور', mainServer: 'سرور اصلی', selectedServer: 'سرور انتخاب‌شده', nodeOffline: 'آفلاین', checkingServer: 'در حال دریافت وضعیت واقعی سرور…',
    restartAll: 'ری‌استارت همه', restartOnAllNodes: 'ری‌استارت روی همه نودها', bulkRestartTitle: 'ری‌استارت همزمان سرویس روی همه نودها', bulkRestartDesc: 'هر سرویس را جداگانه و به‌صورت همزمان روی تمام نودهای فعال ری‌استارت کنید؛ سرور اصلی با این بخش تغییر نمی‌کند.', bulkRestartPartial: 'بعضی نودها ری‌استارت نشدند', version: 'نسخه', backend: 'هسته', listen: 'پورت‌ها', inbounds: 'اتصال فعال',
    installed: 'نصب شده', notInstalled: 'نصب نشده', install: 'نصب', reinstall: 'ترمیم / نصب مجدد',
    start: 'روشن', stop: 'خاموش', restart: 'ری‌استارت', logs: 'لاگ', edit: 'ویرایش',
    active: 'فعال و آماده', activating: 'در حال راه‌اندازی', inactive: 'خاموش', failed: 'خطا', degraded: 'فعال با هشدار', unknown: 'نامشخص',
    working: 'در حال انجام...', close: 'بستن', download: 'دانلود', copy: 'کپی', copied: 'کپی شد', save: 'ذخیره و اعمال', saving: 'در حال اعمال...',
    basic: 'تنظیمات اصلی', advanced: 'ویرایش پیشرفته فایل‌ها', enabled: 'فعال', port: 'پورت',
    udpPort: 'پورت UDP', tcpPort: 'پورت TCP', dns1: 'DNS اصلی', dns2: 'DNS دوم', mtu: 'MTU', mru: 'MRU',
    rawWarning: 'ویرایش مستقیم فایل‌های سرویس برای تنظیمات ریز است. قبل از ذخیره نسخه پشتیبان ساخته می‌شود و اگر سرویس بالا نیاید، فایل قبلی خودکار برمی‌گردد.',
    restartAfterSave: 'بعد از ذخیره سرویس ری‌استارت شود', selectFile: 'فایل تنظیمات', loadError: 'دریافت اطلاعات ناموفق بود',
    actionDone: 'عملیات با موفقیت انجام شد', confirmStop: 'با خاموش‌کردن سرویس، اتصال کاربران همان پروتکل قطع می‌شود.',
    installTitle: 'کنسول نصب و ترمیم', logTitle: 'لاگ سرویس', infrastructure: 'System / Provisioning',
    infrastructureDesc: 'وضعیت پیش‌نیازهای شبکه و ماژول‌های کرنل', rerunSetup: 'اجرای مجدد راه‌اندازی', installAll: 'نصب همه پروتکل‌ها',
    localServicesTitle: 'سرویس‌های محلی این پنل', localServicesFull: 'این سرور هم پنل مدیریتی است و هم سرویس‌های VPN را اجرا می‌کند.',
    localServicesManagement: 'این سرور فقط پنل اصلی مدیریتی است و هیچ سرویس VPN محلی روی آن نصب نشده.',
    localServicesPartial: 'بعضی سرویس‌های VPN روی این سرور نصب شده‌اند؛ بقیه را می‌توانید جداگانه یا یکجا نصب کنید.',
    localServicesAction: 'نصب و فعال‌سازی همه سرویس‌های محلی',
    ipForward: 'IP forwarding', firewall: 'Firewall', nftables: 'nftables', iproute2: 'iproute2', modules: 'Kernel modules', present: 'موجود', missing: 'نیاز به نصب',
    psk: 'کلید مشترک IPsec (PSK)', show: 'نمایش', hide: 'مخفی', fixedPort: 'پورت استاندارد ثابت',
    openvpnPorts: 'پورت‌های اضافه OpenVPN', add: 'افزودن', remove: 'حذف', on: 'فعال', off: 'غیرفعال', both: 'TCP + UDP',
    free443: 'آزادکردن 443 برای OpenConnect', free443Desc: 'پنل را به پورت دیگری منتقل می‌کند و OpenConnect را به‌صورت یکجا روی 443 می‌برد.',
    newPanelPort: 'پورت جدید پنل', moveAndApply: 'انتقال پنل و فعال‌سازی OpenConnect روی 443',
    redirecting: 'تنظیم انجام شد؛ پنل با آدرس جدید باز می‌شود.', configEmpty: 'برای این سرویس فایل قابل ویرایشی تعریف نشده است.',
    noLogs: 'لاگی ثبت نشده است.', clearLogs: 'پاک‌کردن لاگ', clearLogsConfirm: 'همه لاگ‌های فعلی این سرویس از این صفحه پاک شود؟', logsCleared: 'لاگ پاک شد', status: 'وضعیت', serverAddress: 'آدرس اتصال داخل کانفیگ', refreshLogs: 'بروزرسانی لاگ',
    transport: 'انتقال', bindAddress: 'آدرس Bind', wsPath: 'مسیر WebSocket', tls: 'TLS', tlsDomain: 'دامنه TLS', flow: 'Flow', tcp: 'TCP', websocket: 'WebSocket',
    terminalHint: 'این پنجره خروجی واقعی نصب روی سرور را نمایش می‌دهد.', runCompleted: 'عملیات کامل شد.', runFailed: 'عملیات با خطا پایان یافت.',
    process: 'پردازش', portsHealth: 'پورت', configHealth: 'کانفیگ', permissionHealth: 'دسترسی', healthy: 'سالم', unhealthy: 'مشکل', restartCount: 'تعداد ری‌استارت', lastError: 'آخرین خطا', portFallback: 'پورت جایگزین', portWasBusy: 'اشغال بود و خودکار تغییر کرد', dontShowAgain: 'دیگه نشان نده',
    localIp: 'IP محلی سرور', ipRange: 'محدوده IP کاربران', clientToClient: 'ارتباط مستقیم کلاینت‌ها', redirectGateway: 'ارسال تمام ترافیک از تونل', cipher: 'رمزنگاری داده', network: 'شبکه IPv4 کاربران', tunnelAllDns: 'عبور تمام DNS از تونل', remark: 'نام نمایشی', sniffing: 'تشخیص مقصد (Sniffing)', routeOnly: 'Sniffing فقط برای مسیریابی', proxyProtocol: 'پذیرش Proxy Protocol', tcpFastOpen: 'TCP Fast Open', externalProxy: 'پروکسی خروجی SOCKS', externalProxyAddress: 'آدرس پروکسی خروجی', externalProxyPort: 'پورت پروکسی خروجی',
  },
  en: {
    title: 'Protocol Management', subtitle: 'Service status, installation, logs, and detailed VPN configuration', refresh: 'Refresh', serverSelector: 'Select server', mainServer: 'Main server', selectedServer: 'Selected server', nodeOffline: 'Offline', checkingServer: 'Loading the server’s real status…',
    restartAll: 'Restart all', restartOnAllNodes: 'Restart on all nodes', bulkRestartTitle: 'Restart one service across all nodes', bulkRestartDesc: 'Restart each service concurrently on every enabled node. This bulk action does not change the main server.', bulkRestartPartial: 'Some nodes could not be restarted', version: 'Version', backend: 'Backend', listen: 'Listen', inbounds: 'Inbounds',
    installed: 'Installed', notInstalled: 'Not installed', install: 'Install', reinstall: 'Repair / reinstall',
    start: 'Start', stop: 'Stop', restart: 'Restart', logs: 'Logs', edit: 'Edit',
    active: 'Ready', activating: 'Starting', inactive: 'Stopped', failed: 'Failed', degraded: 'Running with warning', unknown: 'Unknown',
    working: 'Working...', close: 'Close', download: 'Download', copy: 'Copy', copied: 'Copied', save: 'Save & apply', saving: 'Applying...',
    basic: 'Basic settings', advanced: 'Advanced file editor', enabled: 'Enabled', port: 'Port',
    udpPort: 'UDP port', tcpPort: 'TCP port', dns1: 'Primary DNS', dns2: 'Secondary DNS', mtu: 'MTU', mru: 'MRU',
    rawWarning: 'Use direct file editing for low-level settings. A backup is created before saving and automatically restored if the service does not start.',
    restartAfterSave: 'Restart service after saving', selectFile: 'Configuration file', loadError: 'Failed to load information',
    actionDone: 'Operation completed successfully', confirmStop: 'Stopping this service immediately disconnects users on that protocol.',
    installTitle: 'Install / repair console', logTitle: 'Service logs', infrastructure: 'System / Provisioning',
    infrastructureDesc: 'Network prerequisites and kernel module status', rerunSetup: 'Re-run setup', installAll: 'Install all protocols',
    localServicesTitle: 'Local services on this panel', localServicesFull: 'This host runs both the management panel and local VPN services.',
    localServicesManagement: 'This is a management-only controller; no local VPN service is installed.',
    localServicesPartial: 'Some local VPN services are installed; install the rest individually or all at once.',
    localServicesAction: 'Install and enable all local services',
    ipForward: 'IP forwarding', firewall: 'Firewall', nftables: 'nftables', iproute2: 'iproute2', modules: 'Kernel modules', present: 'Present', missing: 'Missing',
    psk: 'IPsec pre-shared key (PSK)', show: 'Show', hide: 'Hide', fixedPort: 'Fixed standard port',
    openvpnPorts: 'OpenVPN extra ports', add: 'Add', remove: 'Remove', on: 'Active', off: 'Inactive', both: 'TCP + UDP',
    free443: 'Free port 443 for OpenConnect', free443Desc: 'Moves the panel to another port and assigns 443 to OpenConnect in one safe operation.',
    newPanelPort: 'New panel port', moveAndApply: 'Move panel and use 443 for OpenConnect',
    redirecting: 'Applied successfully; opening the panel at its new address.', configEmpty: 'No editable file is defined for this service.',
    noLogs: 'No log output.', clearLogs: 'Clear logs', clearLogsConfirm: 'Clear all currently displayed logs for this service?', logsCleared: 'Logs cleared', status: 'Status', serverAddress: 'Connection host in config', refreshLogs: 'Refresh logs',
    transport: 'Transport', bindAddress: 'Bind address', wsPath: 'WebSocket path', tls: 'TLS', tlsDomain: 'TLS domain', flow: 'Flow', tcp: 'TCP', websocket: 'WebSocket',
    terminalHint: 'This window shows the real installation output from the server.', runCompleted: 'Operation completed.', runFailed: 'Operation failed.',
    process: 'Process', portsHealth: 'Ports', configHealth: 'Config', permissionHealth: 'Permissions', healthy: 'Healthy', unhealthy: 'Problem', restartCount: 'Restarts', lastError: 'Last error', portFallback: 'Fallback port', portWasBusy: 'was occupied and changed automatically', dontShowAgain: "Don't show again",
    localIp: 'Server local IP', ipRange: 'Client IP range', clientToClient: 'Client-to-client traffic', redirectGateway: 'Route all traffic through tunnel', cipher: 'Data cipher', network: 'Client IPv4 network', tunnelAllDns: 'Tunnel all DNS', remark: 'Display name', sniffing: 'Destination sniffing', routeOnly: 'Sniffing for routing only', proxyProtocol: 'Accept Proxy Protocol', tcpFastOpen: 'TCP Fast Open', externalProxy: 'SOCKS outbound proxy', externalProxyAddress: 'Outbound proxy address', externalProxyPort: 'Outbound proxy port',
  },
}

function Icon({ name, size = 14 }) {
  const paths = {
    refresh: <><path d="M20.5 12a8.5 8.5 0 1 0-2.49 6.01"/><path d="M20.5 5v7h-7"/></>,
    power: <><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/></>,
    log: <><path d="M4 4h16v16H4z"/><path d="m8 9 2 2-2 2M13 13h3"/></>,
    edit: <><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4z"/></>,
    install: <><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></>,
    download: <><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></>,
    close: <><path d="m6 6 12 12M18 6 6 18"/></>,
    trash: <><path d="M4 7h16"/><path d="M10 11v6M14 11v6"/><path d="m6 7 1 14h10l1-14"/><path d="M9 7V4h6v3"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1z"/></>,
    eye: <><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></>,
    eyeOff: <><path d="M3 3l18 18"/><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 4.3A11.8 11.8 0 0 1 12 4c6.5 0 10 8 10 8a17.8 17.8 0 0 1-2.1 3.2"/><path d="M6.6 6.6C3.7 8.4 2 12 2 12s3.5 8 10 8a10.7 10.7 0 0 0 4.2-.9"/></>,
  }
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>
}

function Spinner() { return <span className="inline-block w-3.5 h-3.5 rounded-full border-2 border-current/30 border-t-current animate-spin" /> }

function Modal({ open, title, children, onClose, width = 'max-w-5xl', glass = true }) {
  useEffect(() => {
    if (!open) return undefined
    const esc = (e) => { if (e.key === 'Escape') onClose() }
    const root = document.getElementById('root')
    const previousOverflow = document.body.style.overflow
    root?.setAttribute('inert', '')
    root?.setAttribute('aria-hidden', 'true')
    document.body.classList.add('vpnpanel-blocking-modal-open')
    document.body.style.overflow = 'hidden'
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('keydown', esc)
      root?.removeAttribute('inert')
      root?.removeAttribute('aria-hidden')
      document.body.classList.remove('vpnpanel-blocking-modal-open')
      document.body.style.overflow = previousOverflow
    }
  }, [open, onClose])
  if (!open) return null
  return ReactDOM.createPortal(
    <div className={`${glass ? 'glass-terminal-overlay' : 'bg-black/70'} modal-viewport fixed inset-0 z-[9999] flex items-center justify-center overflow-hidden p-3 sm:p-6`} onMouseDown={onClose}>
      <div className={`w-full ${width} modal-dialog-shell protocol-console-dialog ${glass ? 'glass-terminal-modal' : 'bg-surface border border-border shadow-2xl'} rounded-2xl flex flex-col overflow-hidden`} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-sticky-header shrink-0">
          <h2 className="text-sm sm:text-base font-bold text-ink">{title}</h2>
          <button type="button" onClick={onClose} className="modal-close-button"><Icon name="close" size={18}/></button>
        </div>
        {children}
      </div>
    </div>,
    document.body,
  )
}

function SmallButton({ children, onClick, disabled, tone = 'default', icon }) {
  const cls = tone === 'danger' ? 'text-danger border-danger/30 hover:bg-danger/10'
    : tone === 'signal' ? 'text-signal border-signal/30 hover:bg-signal/10'
    : 'text-muted border-border hover:text-ink hover:bg-surface2'
  return <button type="button" onClick={onClick} disabled={disabled} className={`protocol-glass-button inline-flex items-center justify-center gap-1.5 px-3 py-2 text-[11px] font-bold disabled:opacity-40 ${cls}`}>{icon && <Icon name={icon} size={12}/>} {children}</button>
}

function Toggle({ value, onChange, label }) {
  return <label className="flex items-center justify-between gap-4 bg-surface2 border border-border rounded-lg px-3 py-2.5 cursor-pointer">
    <span className="text-xs text-ink">{label}</span>
    <button type="button" aria-pressed={value} onClick={() => onChange(!value)} className={`relative w-10 h-5 rounded-full transition-colors ${value ? 'bg-signal' : 'bg-border'}`}>
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${value ? 'end-0.5' : 'start-0.5'}`} />
    </button>
  </label>
}

function Field({ label, value, onChange, type = 'text', min, max, placeholder, disabled }) {
  return <label className="block min-w-0">
    <span className="block text-[11px] text-muted mb-1.5 font-data">{label}</span>
    <input type={type} min={min} max={max} value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} disabled={disabled}
      className="w-full bg-surface2 border border-border rounded-lg px-3 py-2.5 text-xs sm:text-sm text-ink outline-none focus:border-signal font-data disabled:opacity-50" />
  </label>
}

function SecretField({ label, value, onChange, revealed, onToggle }) {
  return <label className="block min-w-0">
    <span className="block text-[11px] text-muted mb-1.5 font-data">{label}</span>
    <span className="relative block">
      <input type={revealed ? 'text' : 'password'} value={value ?? ''} onChange={(event) => onChange(event.target.value)}
        autoComplete="new-password" dir="ltr"
        className="w-full bg-surface2 border border-border rounded-lg ps-11 pe-3 py-2.5 text-xs sm:text-sm text-ink outline-none focus:border-signal font-data" />
      <button type="button" onClick={onToggle} className="absolute inset-y-0 start-1.5 my-auto grid h-8 w-8 place-items-center rounded-md text-muted hover:bg-surface hover:text-ink"
        aria-label={revealed ? 'Hide secret' : 'Show secret'} title={revealed ? 'Hide secret' : 'Show secret'}>
        <Icon name={revealed ? 'eyeOff' : 'eye'} size={16} />
      </button>
    </span>
  </label>
}

function HealthChip({ label, ok }) {
  return <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-1 text-[9px] ${ok ? 'border-success/25 bg-success/5 text-success' : 'border-danger/25 bg-danger/5 text-danger'}`}>
    <span className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-success' : 'bg-danger'}`}/>{label}
  </span>
}

const DISMISSED_PROTOCOL_NOTICES_KEY = 'vpnpanel_dismissed_protocol_notices_v1'

function protocolNoticeSignature(item, kind, value) {
  return `${item.key}:${kind}:${JSON.stringify(value || [])}`
}

function isProtocolNoticeDismissed(signature) {
  try { return JSON.parse(localStorage.getItem(DISMISSED_PROTOCOL_NOTICES_KEY) || '[]').includes(signature) } catch { return false }
}

function rememberProtocolNotice(signature) {
  try {
    const values = JSON.parse(localStorage.getItem(DISMISSED_PROTOCOL_NOTICES_KEY) || '[]')
    const next = Array.from(new Set([...values, signature])).slice(-120)
    localStorage.setItem(DISMISSED_PROTOCOL_NOTICES_KEY, JSON.stringify(next))
  } catch { /* localStorage unavailable */ }
}

function ProtocolCard({ item, words, dir, busy, onAction, onLogs, onEdit, onInstall }) {
  const state = item.state || 'unknown'
  const stateMap = {
    active: ['bg-success', 'text-success', words.active], activating: ['bg-amber', 'text-amber', words.activating],
    degraded: ['bg-amber', 'text-amber', words.degraded], inactive: ['bg-muted', 'text-muted', words.inactive],
    failed: ['bg-danger', 'text-danger', words.failed], not_installed: ['bg-muted', 'text-muted', words.notInstalled],
    unknown: ['bg-muted', 'text-muted', words.unknown],
  }
  const [dot, textColor, stateText] = stateMap[state] || stateMap.unknown
  const running = ['active', 'degraded'].includes(state)
  const stoppingAllowed = ['active', 'activating', 'degraded'].includes(state)
  const health = item.health || {}
  const changedSignature = protocolNoticeSignature(item, 'changed', item.port_notice?.changed)
  const blockedSignature = protocolNoticeSignature(item, 'blocked', item.port_notice?.blocked)
  const [dismissedChanged, setDismissedChanged] = useState(() => isProtocolNoticeDismissed(changedSignature))
  const [dismissedBlocked, setDismissedBlocked] = useState(() => isProtocolNoticeDismissed(blockedSignature))
  useEffect(() => setDismissedChanged(isProtocolNoticeDismissed(changedSignature)), [changedSignature])
  useEffect(() => setDismissedBlocked(isProtocolNoticeDismissed(blockedSignature)), [blockedSignature])
  const dismissNotice = (signature, setter) => { rememberProtocolNotice(signature); setter(true) }
  return (
    <article className="app-card overflow-hidden min-h-[210px] flex flex-col">
      <header className="px-4 py-3 flex items-center justify-between border-b border-border/70">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-muted"><Icon name="settings" size={13}/></span>
          <h3 className={`text-xs font-bold truncate ${COLORS[item.key] || 'text-ink'}`}>{item.label}</h3>
          <span className={`text-[9px] rounded-full px-2 py-0.5 border ${item.installed ? 'text-success border-success/25 bg-success/10' : 'text-muted border-border'}`}>
            {item.installed ? words.installed : words.notInstalled}
          </span>
        </div>
        <div className={`flex items-center gap-1.5 text-[10px] ${textColor}`}><span className={`w-1.5 h-1.5 rounded-full ${dot}`}/>{stateText}</div>
      </header>
      <div className="p-4 flex-1 space-y-2 text-[10px] font-data">
        <div className="flex justify-between gap-3 border-b border-dashed border-border pb-1.5"><span className="text-muted">{words.version}</span><span className="text-ink truncate text-end" title={item.version}>{item.version || '—'}</span></div>
        <div className="flex justify-between gap-3 border-b border-dashed border-border pb-1.5"><span className="text-muted">{words.backend}</span><span className="text-ink truncate text-end" title={item.backend}>{item.backend || '—'}</span></div>
        <div className="flex justify-between gap-3 border-b border-dashed border-border pb-1.5"><span className="text-muted">{words.listen}</span><span className="text-ink truncate text-end" title={item.listen}>{item.listen || '—'}</span></div>
        <div className="flex justify-between gap-3"><span className="text-muted">{words.inbounds}</span><span className="text-ink">{item.inbounds ?? 0}</span></div>
        {item.installed && <div className="pt-2 flex flex-wrap gap-1.5">
          <HealthChip label={words.process} ok={!!health.process}/><HealthChip label={words.portsHealth} ok={!!health.ports_ok}/><HealthChip label={words.configHealth} ok={!!health.config}/>
          {(item.key === 'vmess' || item.key === 'vless') && <HealthChip label={words.permissionHealth} ok={!!health.permissions}/>}
        </div>}
        {!!item.restart_count && state !== 'active' && <div className="text-[9px] text-amber">{words.restartCount}: {item.restart_count}</div>}
        {!!item.port_notice?.changed?.length && !dismissedChanged && <div className="space-y-1 rounded-md border border-amber/25 bg-amber/5 px-2 py-1.5 text-[9px] text-amber">
          <div className="flex items-center justify-between gap-2"><div className="font-bold">{words.portFallback}</div><button type="button" onClick={() => dismissNotice(changedSignature, setDismissedChanged)} className="rounded border border-amber/25 px-1.5 py-0.5 text-[8px] font-bold hover:bg-amber/10">{words.dontShowAgain}</button></div>
          {item.port_notice.changed.map((change, index) => <div key={`${change.setting}-${index}`} dir="ltr" className="font-data">{change.old_port}/{String(change.transport).toUpperCase()} → {change.new_port} · {words.portWasBusy}{change.owner ? ` (${change.owner})` : ''}</div>)}
        </div>}
        {!!item.port_notice?.blocked?.length && !dismissedBlocked && <div className="space-y-1 rounded-md border border-danger/30 bg-danger/5 px-2 py-1.5 text-[9px] text-danger">
          <div className="flex items-center justify-between gap-2"><div className="font-bold">{dir === 'rtl' ? 'پورت استاندارد قابل تغییر نیست' : 'Required standard port is blocked'}</div><button type="button" onClick={() => dismissNotice(blockedSignature, setDismissedBlocked)} className="rounded border border-danger/25 px-1.5 py-0.5 text-[8px] font-bold hover:bg-danger/10">{words.dontShowAgain}</button></div>
          {item.port_notice.blocked.map((conflict, index) => <div key={`${conflict.transport}-${conflict.port}-${index}`} dir="ltr" className="font-data">{String(conflict.transport).toUpperCase()}/{conflict.port} · {conflict.owner || 'unknown process'}{conflict.owner_pids?.length ? ` (PID ${conflict.owner_pids.join(',')})` : ''}</div>)}
        </div>}
        {item.last_error && <div title={item.last_error} className="rounded-md border border-danger/20 bg-danger/5 px-2 py-1.5 text-[9px] text-danger line-clamp-2">{words.lastError}: {item.last_error}</div>}
      </div>
      <footer className="px-3 pb-3 flex flex-wrap gap-1.5">
        {hasPermission('protocols:start_stop', 'settings') && item.installed && (running
          ? <><SmallButton disabled={busy} tone="signal" icon="refresh" onClick={() => onAction(item, 'restart')}>{busy ? <Spinner/> : words.restart}</SmallButton><SmallButton disabled={busy} tone="danger" icon="power" onClick={() => onAction(item, 'stop')}>{words.stop}</SmallButton></>
          : <><SmallButton disabled={busy} tone="signal" icon="power" onClick={() => onAction(item, 'start')}>{busy ? <Spinner/> : words.start}</SmallButton>{stoppingAllowed && <SmallButton disabled={busy} tone="danger" icon="power" onClick={() => onAction(item, 'stop')}>{words.stop}</SmallButton>}</>)}
        {hasPermission('protocols:logs', 'settings') && <SmallButton onClick={() => onLogs(item)} icon="log">{words.logs}</SmallButton>}
        {hasPermission('protocols:edit', 'settings') && <SmallButton onClick={() => onEdit(item)} icon="edit">{words.edit}</SmallButton>}
        {hasPermission('protocols:install', 'settings') && <SmallButton onClick={() => onInstall(item)} icon="install">{item.installed ? words.reinstall : words.install}</SmallButton>}
      </footer>
    </article>
  )
}

const PROTOCOL_LOG_CACHE_PREFIX = 'vpnpanel_protocol_log_cache_v1:'

function readProtocolLogCache(key, targetKey = 'local') {
  try { return sessionStorage.getItem(`${PROTOCOL_LOG_CACHE_PREFIX}${targetKey}:${key}`) || '' }
  catch { return '' }
}

function writeProtocolLogCache(key, output, targetKey = 'local') {
  try { sessionStorage.setItem(`${PROTOCOL_LOG_CACHE_PREFIX}${targetKey}:${key}`, String(output || '')) }
  catch { /* private browsing / disabled storage */ }
}

function LogsModal({ item, words, onClose, request, targetKey = 'local', targetName = '' }) {
  const initialCache = readProtocolLogCache(item.key, targetKey)
  const [output, setOutput] = useState(initialCache)
  const [loading, setLoading] = useState(!initialCache)
  const [copied, setCopied] = useState(false)
  const [clearing, setClearing] = useState(false)
  const terminalRef = useRef(null)

  const scrollToNewest = () => {
    const node = terminalRef.current
    if (!node) return
    node.scrollTop = node.scrollHeight
  }

  const load = async ({ background = false } = {}) => {
    if (!background && !output) setLoading(true)
    try {
      const { data } = await request('GET', `/settings/protocol-center/${item.key}/logs`, { params: { lines: 700 } })
      const nextOutput = data.output || ''
      setOutput(nextOutput)
      writeProtocolLogCache(item.key, nextOutput, targetKey)
    } catch (e) {
      const message = protocolErrorMessage(e, words.loadError)
      if (!output) setOutput(message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    const cached = readProtocolLogCache(item.key, targetKey)
    setOutput(cached)
    setLoading(!cached)
    load({ background: !!cached })
  }, [item.key, targetKey, request])

  // Scroll before the browser paints whenever cached or freshly-fetched log text
  // changes. The modal therefore opens at the latest line instead of the top.
  useLayoutEffect(() => {
    scrollToNewest()
    const frame = requestAnimationFrame(scrollToNewest)
    return () => cancelAnimationFrame(frame)
  }, [output, loading])

  const download = () => {
    const blob = new Blob([output || ''], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `${item.key}-logs.txt`; a.click(); URL.revokeObjectURL(url)
  }
  const copy = async () => {
    if (await copyText(output || '')) { setCopied(true); window.setTimeout(() => setCopied(false), 1500) }
  }
  const clearLogs = async () => {
    if (!window.confirm(words.clearLogsConfirm)) return
    setClearing(true)
    try {
      await request('DELETE', `/settings/protocol-center/${item.key}/logs`)
      setOutput('')
      writeProtocolLogCache(item.key, '', targetKey)
      await load({ background: true })
    } catch (e) {
      setOutput(protocolErrorMessage(e, words.loadError))
    } finally {
      setClearing(false)
    }
  }
  return <Modal open glass title={`${item.label} — ${words.logTitle}${targetName ? ` — ${targetName}` : ''}`} onClose={onClose} width="max-w-6xl">
    <div className="px-5 py-3 border-b border-border flex items-center gap-2 shrink-0">
      <SmallButton onClick={download} icon="download">{words.download}</SmallButton>
      <SmallButton onClick={copy} icon="log" disabled={!output}>{copied ? words.copied : words.copy}</SmallButton>
      <SmallButton onClick={() => load()} icon="refresh" disabled={loading}>{words.refreshLogs}</SmallButton>
      <SmallButton onClick={clearLogs} icon="trash" disabled={loading || clearing}>{clearing ? words.working : words.clearLogs}</SmallButton>
    </div>
    <pre ref={terminalRef} dir="ltr" className="glass-terminal-screen m-4 mt-3 min-h-[420px] max-h-[70vh] overflow-auto rounded-xl p-4 font-mono whitespace-pre-wrap selection:bg-signal/30">{output || (loading ? words.working : words.noLogs)}</pre>
  </Modal>
}

function TerminalModal({ item, words, onClose, onFinished, request, targetKey = 'local', targetName = '' }) {
  const [job, setJob] = useState(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const started = useRef(false)
  const terminalRef = useRef(null)
  useEffect(() => {
    let timer
    const begin = async () => {
      if (started.current) return
      started.current = true
      try {
        const { data } = await request('POST', `/settings/protocol-center/${item.key}/install`, { data: { force: true } })
        const poll = async () => {
          try {
            const r = await request('GET', `/settings/protocol-center/install-jobs/${data.job_id}`)
            setJob(r.data)
            if (['success', 'failed'].includes(r.data.state)) { onFinished?.(); return }
            timer = setTimeout(poll, 900)
          } catch (e) { setError(protocolErrorMessage(e, words.loadError)) }
        }
        poll()
      } catch (e) { setError(protocolErrorMessage(e, words.loadError)) }
    }
    begin()
    return () => clearTimeout(timer)
  }, [item.key, targetKey, request])
  useEffect(() => {
    const node = terminalRef.current
    if (node) node.scrollTop = node.scrollHeight
  }, [job?.output, error])
  const done = job && ['success', 'failed'].includes(job.state)
  const outputText = String(job?.output || '')
  const outerProgressMatches = [...outputText.matchAll(/^\[(\d{1,3})%\]\s+(?:=====|Full VPN provisioning started|Running combined protocol-center verification|FULL_PROVISION_OK)/gm)]
  const parsedProgress = outerProgressMatches.length
    ? Math.max(...outerProgressMatches.map((match) => Number(match[1]) || 0))
    : null
  const reportedProgress = typeof job?.progress === 'number' ? job.progress : parsedProgress
  // Never show 100 while the subprocess is still running. Some older nested
  // installers printed an internal 100% and then continued with the next
  // protocol, which made the bar appear to jump backward to 80/91%.
  const progress = job?.state === 'success'
    ? 100
    : reportedProgress == null
      ? null
      : Math.max(0, Math.min(99, reportedProgress))
  const copy = async () => {
    if (await copyText(error || job?.output || '')) { setCopied(true); window.setTimeout(() => setCopied(false), 1500) }
  }
  return <Modal open glass title={`${words.installTitle} — ${item.label}${targetName ? ` — ${targetName}` : ''}`} onClose={onClose} width="max-w-5xl">
    <div className="px-5 py-3 text-[11px] text-muted border-b border-border flex items-center justify-between gap-3">
      <span>{words.terminalHint}</span>
      <div className="flex items-center gap-2"><SmallButton onClick={copy} icon="log" disabled={!error && !job?.output}>{copied ? words.copied : words.copy}</SmallButton>{progress !== null && <span className="font-data font-bold text-signal">{progress}%</span>}</div>
    </div>
    <div className="h-1 bg-surface2 overflow-hidden">{progress !== null ? <div className={`h-full transition-[width] duration-500 ${job?.state === 'failed' ? 'bg-danger' : 'bg-signal'}`} style={{ width: `${progress}%` }}/> : (!done && !error ? <div className="h-full w-1/3 bg-signal animate-pulse"/> : <div className={`h-full w-full ${job?.state === 'success' ? 'bg-signal' : job?.state === 'failed' ? 'bg-danger' : ''}`}/>)}</div>
    <pre ref={terminalRef} dir="ltr" className={`glass-terminal-screen m-4 min-h-[440px] max-h-[68vh] overflow-auto rounded-xl p-4 font-mono whitespace-pre-wrap ${error || job?.state === 'failed' ? 'glass-terminal-screen--error' : ''}`}>{error || job?.output || '$ preparing installer...\n'}</pre>
    <div className="px-5 pb-4 flex items-center justify-between text-xs"><span className={job?.state === 'failed' ? 'text-danger' : job?.state === 'success' ? 'text-signal' : 'text-muted'}>{job?.state === 'failed' ? words.runFailed : job?.state === 'success' ? words.runCompleted : words.working}</span><SmallButton onClick={onClose}>{words.close}</SmallButton></div>
  </Modal>
}

function OpenvpnExtraPorts({ words, request, targetKey = 'local' }) {
  const { confirm, notify } = useUI()
  const [ports, setPorts] = useState([]); const [port, setPort] = useState(''); const [proto, setProto] = useState('tcp'); const [busy, setBusy] = useState(false)
  const load = async () => { try { const { data } = await request('GET', '/settings/openvpn-ports'); setPorts(data || []) } catch {} }
  useEffect(() => { load() }, [targetKey, request])
  const add = async () => {
    const portNumber = Number(port)
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      notify({ type: 'error', message: words.loadError })
      return
    }
    setBusy(true)
    try { const { data } = await request('POST', '/settings/openvpn-ports', { data: { port: portNumber, protocol: proto } }); setPorts(data); setPort(''); notify({ type: 'success', message: words.actionDone }) }
    catch (e) { notify({ type: 'error', message: protocolErrorMessage(e, words.loadError) }) } finally { setBusy(false) }
  }
  const toggle = async (row) => { try { const { data } = await request('POST', `/settings/openvpn-ports/${row.id}/toggle`); setPorts(data) } catch (e) { notify({ type: 'error', message: protocolErrorMessage(e, words.loadError) }) } }
  const remove = async (row) => {
    if (!await confirm({ title: words.remove, message: `${row.port}/${row.protocol.toUpperCase()}`, danger: true })) return
    try { const { data } = await request('DELETE', `/settings/openvpn-ports/${row.id}`); setPorts(data) } catch (e) { notify({ type: 'error', message: protocolErrorMessage(e, words.loadError) }) }
  }
  return <section className="rounded-xl border border-border bg-surface2 p-4 space-y-3">
    <h4 className="text-xs font-bold text-ink">{words.openvpnPorts}</h4>
    <div className="space-y-1.5 max-h-40 overflow-auto">{ports.map((row) => <div key={row.id} className="flex items-center justify-between gap-3 rounded-lg bg-surface border border-border px-3 py-2 text-xs">
      <span className="font-data"><span className={`inline-block w-1.5 h-1.5 rounded-full me-2 ${row.is_active ? 'bg-signal' : 'bg-muted'}`}/>{row.port}/{row.protocol.toUpperCase()}</span>
      <span className="flex gap-2"><button type="button" onClick={() => toggle(row)} className="text-muted hover:text-ink">{row.is_active ? words.off : words.on}</button><button type="button" onClick={() => remove(row)} className="text-danger">{words.remove}</button></span>
    </div>)}</div>
    <div className="grid grid-cols-[1fr_auto_auto] gap-2"><input type="text" dir="ltr" inputMode="numeric" pattern="[0-9]*" maxLength={5} value={port} onChange={(e) => setPort(e.target.value.replace(/[۰-۹]/g, (d) => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d))).replace(/[٠-٩]/g, (d) => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d))).replace(/\D/g, '').slice(0, 5))} className="min-w-0 bg-surface border border-border rounded-lg px-3 py-2 text-xs text-left outline-none focus:border-signal font-data" placeholder={words.port}/><select value={proto} onChange={(e) => setProto(e.target.value)} className="bg-surface border border-border rounded-lg px-2 text-xs"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">{words.both}</option></select><SmallButton disabled={busy || !port || Number(port) < 1 || Number(port) > 65535} onClick={add} tone="signal">{busy ? <Spinner/> : words.add}</SmallButton></div>
  </section>
}

function EditModal({ item, settings, center, words, onClose, onSaved, request, targetKey = 'local', targetName = '' }) {
  const { notify, confirm } = useUI()
  const [draft, setDraft] = useState({ ...settings })
  const [tab, setTab] = useState('basic')
  const [saving, setSaving] = useState(false)
  const [psk, setPsk] = useState(''); const [showPsk, setShowPsk] = useState(false)
  const [cfg, setCfg] = useState(null); const [cfgLoading, setCfgLoading] = useState(false); const [restartCfg, setRestartCfg] = useState(true)
  const [newPanelPort, setNewPanelPort] = useState(center?.panel?.port === 443 ? 8444 : (center?.panel?.port || 8444))
  const set = (key, value) => setDraft((d) => ({ ...d, [key]: value }))

  useEffect(() => {
    if (item.key === 'ipsec' || item.key === 'l2tp') request('GET', '/settings/ipsec-psk').then(({ data }) => setPsk(data.psk || '')).catch(() => {})
    if (item.key === 'vmess' || item.key === 'vless') request('GET', `/settings/xray/${item.key}`).then(({ data }) => setDraft(data)).catch(() => {})
  }, [item.key, targetKey, request])

  const loadConfig = async (fileId) => {
    if (!item.config_files?.length) return
    setCfgLoading(true)
    try { const { data } = await request('GET', `/settings/protocol-center/${item.key}/config`, { params: fileId ? { file_id: fileId } : {} }); setCfg(data) }
    catch (e) { notify({ type: 'error', message: protocolErrorMessage(e, words.loadError) }) } finally { setCfgLoading(false) }
  }
  useEffect(() => { if (tab === 'advanced' && !cfg) loadConfig() }, [tab])

  const normalized = () => ({ ...draft,
    ...(draft.l2tp_port !== undefined ? { l2tp_port: Number(draft.l2tp_port) } : {}),
    ...(draft.l2tp_mtu !== undefined ? { l2tp_mtu: Number(draft.l2tp_mtu) } : {}),
    ...(draft.l2tp_mru !== undefined ? { l2tp_mru: Number(draft.l2tp_mru) } : {}),
    ...(draft.pptp_mtu !== undefined ? { pptp_mtu: Number(draft.pptp_mtu) } : {}),
    ...(draft.pptp_mru !== undefined ? { pptp_mru: Number(draft.pptp_mru) } : {}),
    ...(draft.openvpn_udp_port !== undefined ? { openvpn_udp_port: Number(draft.openvpn_udp_port) } : {}),
    ...(draft.openvpn_tcp_port !== undefined ? { openvpn_tcp_port: Number(draft.openvpn_tcp_port) } : {}),
    ...(draft.openvpn_mtu !== undefined ? { openvpn_mtu: Number(draft.openvpn_mtu) } : {}),
    ...(draft.sstp_port !== undefined ? { sstp_port: Number(draft.sstp_port) } : {}),
    ...(draft.sstp_mtu !== undefined ? { sstp_mtu: Number(draft.sstp_mtu) } : {}),
    ...(draft.sstp_mru !== undefined ? { sstp_mru: Number(draft.sstp_mru) } : {}),
    ...(draft.openconnect_port !== undefined ? { openconnect_port: Number(draft.openconnect_port) } : {}),
    ...(draft.openconnect_mtu !== undefined ? { openconnect_mtu: Number(draft.openconnect_mtu) } : {}),
    ...(draft.external_proxy_port !== undefined ? { external_proxy_port: Number(draft.external_proxy_port) } : {}),
    ...(draft.port !== undefined ? { port: Number(draft.port) } : {}),
  })
  const saveBasic = async () => {
    setSaving(true)
    try {
      if (item.key === 'vmess' || item.key === 'vless') await request('PUT', `/settings/xray/${item.key}`, { data: normalized() })
      else if (item.key !== 'ipsec') await request('POST', `/settings/protocol-center/${item.key}/settings`, { data: normalized() })
      if ((item.key === 'ipsec' || item.key === 'l2tp') && psk) await request('POST', '/settings/ipsec-psk', { data: { psk } })
      notify({ type: 'success', message: words.actionDone }); onSaved(); onClose()
    } catch (e) { notify({ type: 'error', message: protocolErrorMessage(e, words.loadError) }) } finally { setSaving(false) }
  }
  const saveConfig = async () => {
    if (!cfg) return
    setSaving(true)
    try { await request('POST', `/settings/protocol-center/${item.key}/config`, { data: { file_id: cfg.selected, content: cfg.content, restart: restartCfg } }); notify({ type: 'success', message: words.actionDone }); onSaved() }
    catch (e) { notify({ type: 'error', message: protocolErrorMessage(e, words.loadError) }) } finally { setSaving(false) }
  }
  const use443 = async () => {
    const ok = await confirm({ title: words.free443, message: `${words.newPanelPort}: ${newPanelPort}`, confirmLabel: words.moveAndApply })
    if (!ok) return
    setSaving(true)
    try {
      const { data } = await request('POST', '/settings/openconnect/use-443', { data: { panel_port: Number(newPanelPort), dns1: draft.openconnect_dns1, dns2: draft.openconnect_dns2 } })
      notify({ type: 'success', message: words.redirecting, duration: 8000 }); setTimeout(() => { window.location.href = data.url }, 1800)
    } catch (e) { notify({ type: 'error', message: protocolErrorMessage(e, words.loadError) }) } finally { setSaving(false) }
  }

  const basicFields = () => {
    switch (item.key) {
      case 'l2tp': return <div className="space-y-4">
        <Toggle label={words.enabled} value={!!draft.l2tp_enabled} onChange={(v) => set('l2tp_enabled', v)}/>
        <div className="grid sm:grid-cols-3 gap-3"><Field label={`${words.port} UDP`} type="number" min="1" max="65535" value={draft.l2tp_port} onChange={(v) => set('l2tp_port', v)}/><Field label={words.mtu} type="number" min="576" max="1460" value={draft.l2tp_mtu} onChange={(v) => set('l2tp_mtu', v)}/><Field label={words.mru} type="number" min="576" max="1460" value={draft.l2tp_mru} onChange={(v) => set('l2tp_mru', v)}/></div>
        <div className="grid sm:grid-cols-2 gap-3"><Field label={words.dns1} value={draft.l2tp_dns1 ?? ''} onChange={(v) => set('l2tp_dns1', v)}/><Field label={words.dns2} value={draft.l2tp_dns2 ?? ''} onChange={(v) => set('l2tp_dns2', v)}/><Field label={words.localIp} value={draft.l2tp_local_ip ?? ''} onChange={(v) => set('l2tp_local_ip', v)}/><Field label={words.ipRange} value={draft.l2tp_ip_range ?? ''} onChange={(v) => set('l2tp_ip_range', v)}/></div>
        <Toggle label={words.clientToClient} value={!!draft.l2tp_client_to_client} onChange={(v) => set('l2tp_client_to_client', v)}/>
        <SecretField label={words.psk} value={psk} onChange={setPsk} revealed={showPsk} onToggle={() => setShowPsk((value) => !value)} />
      </div>
      case 'ipsec': return <div className="space-y-4"><div className="rounded-lg border border-border bg-surface2 px-3 py-2 text-xs text-muted">UDP 500 / 4500 — {words.fixedPort}</div><SecretField label={words.psk} value={psk} onChange={setPsk} revealed={showPsk} onToggle={() => setShowPsk((value) => !value)} /></div>
      case 'pptp': return <div className="space-y-4">
        <Toggle label={words.enabled} value={!!draft.pptp_enabled} onChange={(v) => set('pptp_enabled', v)}/><div className="rounded-lg border border-border bg-surface2 px-3 py-2 text-xs text-muted">TCP 1723 / GRE — {words.fixedPort}</div>
        <div className="grid sm:grid-cols-2 gap-3"><Field label={words.dns1} value={draft.pptp_dns1 ?? ''} onChange={(v) => set('pptp_dns1', v)}/><Field label={words.dns2} value={draft.pptp_dns2 ?? ''} onChange={(v) => set('pptp_dns2', v)}/><Field label={words.localIp} value={draft.pptp_local_ip ?? ''} onChange={(v) => set('pptp_local_ip', v)}/><Field label={words.ipRange} value={draft.pptp_ip_range ?? ''} onChange={(v) => set('pptp_ip_range', v)}/><Field label={words.mtu} type="number" min="576" max="1500" value={draft.pptp_mtu} onChange={(v) => set('pptp_mtu', v)}/><Field label={words.mru} type="number" min="576" max="1500" value={draft.pptp_mru} onChange={(v) => set('pptp_mru', v)}/></div>
        <Toggle label={words.clientToClient} value={!!draft.pptp_client_to_client} onChange={(v) => set('pptp_client_to_client', v)}/>
      </div>
      case 'openvpn': return <div className="space-y-4">
        <Toggle label={words.enabled} value={!!draft.openvpn_enabled} onChange={(v) => set('openvpn_enabled', v)}/>
        <div className="grid sm:grid-cols-2 gap-3"><Field label={words.udpPort} type="number" min="1" max="65535" value={draft.openvpn_udp_port} onChange={(v) => set('openvpn_udp_port', v)}/><Field label={words.tcpPort} type="number" min="1" max="65535" value={draft.openvpn_tcp_port} onChange={(v) => set('openvpn_tcp_port', v)}/><Field label={words.dns1} value={draft.openvpn_dns1} onChange={(v) => set('openvpn_dns1', v)} placeholder="1.1.1.1"/><Field label={words.dns2} value={draft.openvpn_dns2} onChange={(v) => set('openvpn_dns2', v)} placeholder="8.8.8.8"/><Field label={words.mtu} type="number" min="576" max="1500" value={draft.openvpn_mtu} onChange={(v) => set('openvpn_mtu', v)}/><Field label={words.cipher} value={draft.openvpn_cipher ?? 'AES-256-GCM'} onChange={(v) => set('openvpn_cipher', v)}/></div>
        <div className="grid sm:grid-cols-2 gap-3"><Toggle label={words.clientToClient} value={!!draft.openvpn_client_to_client} onChange={(v) => set('openvpn_client_to_client', v)}/><Toggle label={words.redirectGateway} value={!!draft.openvpn_redirect_gateway} onChange={(v) => set('openvpn_redirect_gateway', v)}/></div><OpenvpnExtraPorts words={words} request={request} targetKey={targetKey}/>
      </div>
      case 'sstp': return <div className="space-y-4"><Toggle label={words.enabled} value={!!draft.sstp_enabled} onChange={(v) => set('sstp_enabled', v)}/><div className="grid sm:grid-cols-2 gap-3"><Field label={words.tcpPort} type="number" min="1" max="65535" value={draft.sstp_port} onChange={(v) => set('sstp_port', v)}/><Field label={words.dns1} value={draft.sstp_dns1 ?? ''} onChange={(v) => set('sstp_dns1', v)}/><Field label={words.dns2} value={draft.sstp_dns2 ?? ''} onChange={(v) => set('sstp_dns2', v)}/><Field label={words.mtu} type="number" min="576" max="1500" value={draft.sstp_mtu} onChange={(v) => set('sstp_mtu', v)}/><Field label={words.mru} type="number" min="576" max="1500" value={draft.sstp_mru} onChange={(v) => set('sstp_mru', v)}/></div></div>
      case 'ikev2': return <div className="space-y-4"><Toggle label={words.enabled} value={!!draft.ikev2_enabled} onChange={(v) => set('ikev2_enabled', v)}/><div className="rounded-lg border border-border bg-surface2 px-3 py-2 text-xs text-muted">UDP 500 / 4500 — {words.fixedPort}</div><div className="grid sm:grid-cols-2 gap-3"><Field label={words.dns1} value={draft.ikev2_dns1 ?? ''} onChange={(v) => set('ikev2_dns1', v)}/><Field label={words.dns2} value={draft.ikev2_dns2 ?? ''} onChange={(v) => set('ikev2_dns2', v)}/><Field label={words.ipRange} value={draft.ikev2_ip_pool ?? ''} onChange={(v) => set('ikev2_ip_pool', v)}/></div></div>
      case 'openconnect': return <div className="space-y-4"><div className="grid sm:grid-cols-2 gap-3"><Field label={words.tcpPort} type="number" min="1" max="65535" value={draft.openconnect_port} onChange={(v) => set('openconnect_port', v)}/><Field label={words.mtu} type="number" min="576" max="1500" value={draft.openconnect_mtu} onChange={(v) => set('openconnect_mtu', v)}/><Field label={words.dns1} value={draft.openconnect_dns1} onChange={(v) => set('openconnect_dns1', v)} placeholder="1.1.1.1"/><Field label={words.dns2} value={draft.openconnect_dns2} onChange={(v) => set('openconnect_dns2', v)} placeholder="8.8.8.8"/><Field label={words.network} value={draft.openconnect_ipv4_network ?? ''} onChange={(v) => set('openconnect_ipv4_network', v)}/></div><Toggle label={words.tunnelAllDns} value={!!draft.openconnect_tunnel_all_dns} onChange={(v) => set('openconnect_tunnel_all_dns', v)}/><section className="rounded-xl border border-signal/25 bg-signal/5 p-4 space-y-3"><h4 className="text-xs font-bold text-signal">{words.free443}</h4><p className="text-[11px] text-muted leading-5">{words.free443Desc}</p><div className="grid sm:grid-cols-[1fr_auto] gap-2 items-end"><Field label={`${words.newPanelPort} (${words.status}: ${center?.panel?.port || '—'})`} type="number" min="1" max="65535" value={newPanelPort} onChange={setNewPanelPort}/><button type="button" disabled={saving} onClick={use443} className="rounded-lg bg-signal text-bg px-4 py-2.5 text-xs font-bold disabled:opacity-50">{words.moveAndApply}</button></div></section></div>
      case 'vmess':
      case 'vless': return <div className="space-y-4">
        <Toggle label={words.enabled} value={!!draft.enabled} onChange={(v)=>set('enabled',v)}/>
        <div className="grid sm:grid-cols-2 gap-3"><Field label={words.remark} value={draft.remark ?? item.key.toUpperCase()} onChange={(v)=>set('remark',v)}/><Field label={words.tcpPort} type="number" min="1" max="65535" value={draft.port ?? ''} onChange={(v)=>set('port',v)}/><Field label={words.bindAddress} value={draft.bind_address ?? '0.0.0.0'} onChange={(v)=>set('bind_address',v)}/><label className="block"><span className="block text-[11px] text-muted mb-1.5">{words.transport}</span><select className="field" value={draft.transport ?? 'tcp'} onChange={(e)=>set('transport',e.target.value)}><option value="tcp">{words.tcp}</option><option value="ws">{words.websocket}</option></select></label><Field label={words.serverAddress} value={draft.server_address ?? ''} onChange={(v)=>set('server_address',v)}/></div>
        {draft.transport==='ws'&&<Field label={words.wsPath} value={draft.ws_path ?? `/${item.key}`} onChange={(v)=>set('ws_path',v)}/>}<div className="grid sm:grid-cols-2 gap-3"><Toggle label={words.proxyProtocol} value={!!draft.accept_proxy_protocol} onChange={(v)=>set('accept_proxy_protocol',v)}/><Toggle label={words.tcpFastOpen} value={!!draft.tcp_fast_open} onChange={(v)=>set('tcp_fast_open',v)}/><Toggle label={words.sniffing} value={!!draft.sniffing_enabled} onChange={(v)=>set('sniffing_enabled',v)}/><Toggle label={words.routeOnly} value={!!draft.sniffing_route_only} onChange={(v)=>set('sniffing_route_only',v)}/></div>
        <Toggle label={words.tls} value={!!draft.tls_enabled} onChange={(v)=>set('tls_enabled',v)}/>{draft.tls_enabled&&<Field label={words.tlsDomain} value={draft.tls_domain ?? ''} onChange={(v)=>set('tls_domain',v)}/>} {item.key==='vless'&&<label className="block"><span className="block text-[11px] text-muted mb-1.5">{words.flow}</span><select className="field" value={draft.flow ?? ''} onChange={(e)=>set('flow',e.target.value)}><option value="">None</option><option value="xtls-rprx-vision">xtls-rprx-vision</option></select></label>}
        <section className="rounded-xl border border-border bg-surface2 p-4 space-y-3"><Toggle label={words.externalProxy} value={!!draft.external_proxy_enabled} onChange={(v)=>set('external_proxy_enabled',v)}/>{draft.external_proxy_enabled&&<div className="grid sm:grid-cols-2 gap-3"><Field label={words.externalProxyAddress} value={draft.external_proxy_address ?? '127.0.0.1'} onChange={(v)=>set('external_proxy_address',v)}/><Field label={words.externalProxyPort} type="number" min="1" max="65535" value={draft.external_proxy_port ?? 1080} onChange={(v)=>set('external_proxy_port',v)}/></div>}</section>
      </div>
      default: return null
    }
  }

  return <Modal open title={`${words.edit} — ${item.label}${targetName ? ` — ${targetName}` : ''}`} onClose={onClose} width="max-w-4xl">
    <div className="px-5 pt-4 flex gap-2 border-b border-border"><button type="button" onClick={() => setTab('basic')} className={`px-3 py-2 text-xs border-b-2 ${tab === 'basic' ? 'border-signal text-signal' : 'border-transparent text-muted'}`}>{words.basic}</button><button type="button" onClick={() => setTab('advanced')} className={`px-3 py-2 text-xs border-b-2 ${tab === 'advanced' ? 'border-signal text-signal' : 'border-transparent text-muted'}`}>{words.advanced}</button></div>
    <div className="p-5 overflow-auto min-h-[360px] max-h-[72vh]">
      {tab === 'basic' ? <>{settings.server_address && <div className="text-[11px] text-muted mb-4 font-data">{words.serverAddress}: {settings.server_address}</div>}{basicFields()}</> :
        <div className="space-y-4"><div className="rounded-lg border border-amber/30 bg-amber/5 px-3 py-2 text-[11px] text-amber leading-5">{words.rawWarning}</div>{!item.config_files?.length ? <div className="text-sm text-muted">{words.configEmpty}</div> : <>{cfgLoading || !cfg ? <div className="text-sm text-muted">{words.working}</div> : <><label className="block"><span className="block text-[11px] text-muted mb-1.5">{words.selectFile}</span><select value={cfg.selected} onChange={(e) => loadConfig(e.target.value)} className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-xs outline-none focus:border-signal">{cfg.files.map((f) => <option key={f.id} value={f.id}>{f.label} — {f.path}{f.exists ? '' : ' (new)'}</option>)}</select></label><textarea dir="ltr" spellCheck={false} value={cfg.content} onChange={(e) => setCfg((c) => ({ ...c, content: e.target.value }))} className="w-full min-h-[360px] bg-surface2 border border-border rounded-xl p-4 text-[11px] leading-5 text-ink font-mono outline-none focus:border-signal"/><Toggle label={words.restartAfterSave} value={restartCfg} onChange={setRestartCfg}/></>}</>}</div>}
    </div>
    <div className="px-5 py-4 border-t border-border flex justify-end gap-2 shrink-0"><SmallButton onClick={onClose}>{words.close}</SmallButton><button type="button" disabled={saving || (tab === 'advanced' && !cfg)} onClick={tab === 'basic' ? saveBasic : saveConfig} className="rounded-lg bg-signal text-bg px-5 py-2.5 text-xs font-bold disabled:opacity-50">{saving ? words.saving : words.save}</button></div>
  </Modal>
}

function ProtocolPageSkeleton({ dir, words }) {
  return <div dir={dir} className="space-y-5">
    <header><h1 className="page-heading">{words.title}</h1><p className="page-subtitle">{words.subtitle}</p></header>
    <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
      {Array.from({ length: 9 }).map((_, index) => <article key={index} className="panel-section min-h-[238px] p-4"><div className="h-5 w-28 rounded skeleton"/><div className="mt-5 space-y-3"><div className="h-4 rounded skeleton"/><div className="h-4 rounded skeleton"/><div className="h-4 rounded skeleton"/></div><div className="mt-7 flex gap-2"><div className="h-9 flex-1 rounded-lg skeleton"/><div className="h-9 flex-1 rounded-lg skeleton"/></div></article>)}
    </section>
  </div>
}

function InfrastructureCard({ data, refreshing, words, onInstall, onInstallAll, canInstall }) {
  const checks = [{ label: words.ipForward, ok: data?.ip_forwarding }, { label: words.firewall, ok: data?.firewall && data.firewall !== 'none', value: data?.firewall }, { label: words.nftables, ok: data?.nftables }, { label: words.iproute2, ok: data?.iproute2 }]
  if (refreshing) return <section className="panel-section p-5"><div className="flex items-center gap-3 text-xs text-muted"><Spinner/>{words.checkingServer}</div></section>
  return <section className="panel-section">
    <header className="px-4 py-3 border-b border-border flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-xs font-bold text-ink">{words.infrastructure}</h2><p className="text-[10px] text-muted mt-1">{words.infrastructureDesc}</p></div>{canInstall && <div className="flex flex-wrap items-center gap-2"><SmallButton tone="signal" icon="install" onClick={onInstallAll}>{words.installAll}</SmallButton><SmallButton icon="install" onClick={onInstall}>{words.rerunSetup}</SmallButton></div>}</header>
    <div className="p-4 space-y-3"><div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2">{checks.map((c) => <div key={c.label} className={`infra-check-card ${c.ok ? 'is-ok' : 'is-missing'}`}><div className="infra-check-card__title"><span aria-hidden="true" className={`infra-check-icon ${c.ok ? 'is-ok online-presence-dot' : 'is-missing'}`}>{c.ok ? '' : '×'}</span><span>{c.label}</span></div><div className="text-[9px] text-muted mt-1">{c.value || (c.ok ? words.present : words.missing)}</div></div>)}</div>
      <div><div className="text-[10px] text-muted mb-2">{words.modules}</div><div className="flex flex-wrap gap-1.5">{Object.entries(data?.modules || {}).map(([name, ok]) => <span key={name} className={`infra-module-chip ${ok ? 'is-ok' : 'is-missing'}`}><span aria-hidden="true" className={`infra-module-chip__icon ${ok ? 'is-ok online-presence-dot' : 'is-missing'}`}>{ok ? '' : '×'}</span><span>{name}</span></span>)}</div></div>
    </div>
  </section>
}

function LocalServicesModeCard({ mode, refreshing, words, canInstall, onInstallAll }) {
  if (refreshing) return <section className="panel-section border border-border"><div className="p-4 flex items-center gap-3 text-xs text-muted"><Spinner/>{words.checkingServer}</div></section>
  const full = mode === 'full'
  const partial = mode === 'partial'
  const description = full ? words.localServicesFull : partial ? words.localServicesPartial : words.localServicesManagement
  return <section className={`panel-section border ${full ? 'border-success/20' : 'border-amber/30'}`}>
    <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div>
        <h2 className="text-xs font-bold text-ink">{words.localServicesTitle}</h2>
        <p className={`text-[10px] mt-1 ${full ? 'text-success' : 'text-amber'}`}>{description}</p>
      </div>
      {!full && canInstall && <SmallButton tone="signal" icon="install" onClick={onInstallAll}>{words.localServicesAction}</SmallButton>}
    </div>
  </section>
}

const PROTOCOL_CACHE_KEY = 'vpnpanel_protocol_center_cache_v6'
const PROTOCOL_TARGET_KEY = 'vpnpanel_protocol_selected_server_v1'
const protocolMemoryCache = new Map()
const protocolCacheWriteTimers = new Map()

function protocolCacheStorageKey(targetKey = 'local') {
  return `${PROTOCOL_CACHE_KEY}:${targetKey}`
}

function isUsableProtocolCenter(value) {
  if (!value || !Array.isArray(value.protocols) || !value.protocols.length) return false
  if (Number(value.generated_at || 0) > 0) return true
  return value.protocols.some((item) => item && item.state && item.state !== 'checking')
}

function readProtocolCache(targetKey = 'local') {
  if (protocolMemoryCache.has(targetKey)) return protocolMemoryCache.get(targetKey) || {}
  try {
    const value = JSON.parse(localStorage.getItem(protocolCacheStorageKey(targetKey)) || 'null')
    const normalized = value && typeof value === 'object' ? value : {}
    protocolMemoryCache.set(targetKey, normalized)
    return normalized
  } catch { return {} }
}

function writeProtocolCache(targetKey, patch) {
  const previous = readProtocolCache(targetKey)
  const next = { ...previous, ...patch, saved_at: Date.now() }
  protocolMemoryCache.set(targetKey, next)
  const oldTimer = protocolCacheWriteTimers.get(targetKey)
  if (oldTimer) clearTimeout(oldTimer)
  // localStorage is synchronous.  Deferring this write keeps route changes and
  // protocol-card interactions responsive even on slower phones.
  const timer = setTimeout(() => {
    protocolCacheWriteTimers.delete(targetKey)
    try { localStorage.setItem(protocolCacheStorageKey(targetKey), JSON.stringify(next)) }
    catch { /* storage may be unavailable */ }
  }, 80)
  protocolCacheWriteTimers.set(targetKey, timer)
}

export default function Protocols() {
  const { lang, dir } = useLang()
  const words = I18N[lang] || I18N.fa
  const { confirm, notify } = useUI()
  const nodePanel = getServerRole() === 'node'
  const nodePanelName = getRemoteNodeName() || (lang === 'fa' ? 'این نود' : 'This node')
  const initialTarget = (() => {
    if (nodePanel) return 'local'
    try { return localStorage.getItem(PROTOCOL_TARGET_KEY) || 'local' } catch { return 'local' }
  })()
  const initialCache = useMemo(() => readProtocolCache(initialTarget), [])
  const [targets, setTargets] = useState([])
  const [selectedTarget, setSelectedTarget] = useState(initialTarget)
  const [center, setCenter] = useState(() => initialCache.center || null)
  const [settings, setSettings] = useState(() => initialCache.settings || null)
  const [loading, setLoading] = useState(!isUsableProtocolCenter(initialCache.center))
  const [refreshing, setRefreshing] = useState(false)
  const [busyKey, setBusyKey] = useState('')
  const [logsItem, setLogsItem] = useState(null)
  const [editItem, setEditItem] = useState(null)
  const [installItem, setInstallItem] = useState(null)
  const centerRef = useRef(center)
  const selectedTargetRef = useRef(selectedTarget)
  const inFlightRef = useRef(null)
  const lastRefreshRef = useRef(0)

  useEffect(() => { centerRef.current = center }, [center])
  useEffect(() => { selectedTargetRef.current = selectedTarget }, [selectedTarget])

  const selectedTargetInfo = useMemo(
    () => targets.find((target) => target.id === selectedTarget) || { id: selectedTarget, name: selectedTarget === 'local' ? (nodePanel ? nodePanelName : words.mainServer) : selectedTarget },
    [targets, selectedTarget, words.mainServer, nodePanel, nodePanelName],
  )

  const requestTarget = useCallback((method, path, options = {}) => {
    const upperMethod = String(method || 'GET').toUpperCase()
    if (selectedTarget === 'local') {
      return api.request({ method: upperMethod, url: path, params: options.params, data: options.data })
    }
    const nodeId = String(selectedTarget).startsWith('node:') ? String(selectedTarget).slice(5) : ''
    if (!nodeId) return Promise.reject(new Error('invalid_protocol_target'))
    return api.post(`/nodes/${nodeId}/protocol-proxy`, {
      method: upperMethod,
      path: `/api${path}`,
      params: options.params || {},
      body: options.data ?? null,
    })
  }, [selectedTarget])

  const loadTargets = useCallback(async () => {
    if (nodePanel) {
      setTargets([{ id: 'local', name: nodePanelName, local: true, status: 'online' }])
      if (selectedTarget !== 'local') setSelectedTarget('local')
      return
    }
    try {
      const { data } = await api.get('/nodes/protocol-targets')
      const next = Array.isArray(data?.targets) ? data.targets : []
      setTargets(next)
      if (next.length && !next.some((target) => target.id === selectedTarget)) {
        setSelectedTarget('local')
      }
    } catch (e) {
      notify({ type: 'error', message: protocolErrorMessage(e, words.loadError, lang), dir })
    }
  }, [nodePanel, nodePanelName, selectedTarget, notify, words.loadError, dir])

  const load = useCallback((options = {}) => {
    const normalized = typeof options === 'boolean' ? { quiet: options } : (options || {})
    const quiet = normalized.quiet !== false
    const force = Boolean(normalized.force)
    const settingsToo = normalized.settingsToo !== false
    const notifyError = Boolean(normalized.notifyError)
    const targetKey = selectedTarget

    if (inFlightRef.current?.targetKey === targetKey) return inFlightRef.current.promise

    const hasCurrentSnapshot = isUsableProtocolCenter(centerRef.current)
    if (!quiet && !hasCurrentSnapshot) setLoading(true)
    setRefreshing(true)

    const settingsPromise = settingsToo
      ? requestTarget('GET', '/settings/vpn-protocols')
          .then(({ data }) => {
            if (selectedTargetRef.current === targetKey) setSettings(data)
            writeProtocolCache(targetKey, { settings: data })
            return data
          })
      : Promise.resolve(null)

    const centerPromise = requestTarget('GET', '/settings/protocol-center', { params: force ? { fresh: 1 } : {} })
      .then(({ data }) => {
        const current = centerRef.current
        const currentUsable = isUsableProtocolCenter(current)
        const nextUsable = isUsableProtocolCenter(data)

        // Never replace real cards with the temporary all-"checking"
        // placeholder.  Keep the last snapshot on screen while the server
        // refreshes in the background, then swap values in place.
        if (selectedTargetRef.current === targetKey) {
          if (nextUsable) {
            centerRef.current = data
            setCenter(data)
          } else if (!currentUsable) {
            centerRef.current = data
            setCenter(data)
          }
        }
        if (nextUsable) writeProtocolCache(targetKey, { center: data })
        return nextUsable ? data : current
      })

    const promise = Promise.all([settingsPromise, centerPromise])
      .then(([, data]) => {
        lastRefreshRef.current = Date.now()
        return data
      })
      .catch((e) => {
        // A transient node/network error must not clear a previously rendered
        // protocol page.  The old page remains usable and the next refresh can
        // recover silently.
        const noSnapshot = !isUsableProtocolCenter(centerRef.current)
        if (notifyError || (!quiet && noSnapshot)) {
          notify({ type: 'error', message: protocolErrorMessage(e, words.loadError, lang), dir })
        }
        throw e
      })
      .finally(() => {
        if (inFlightRef.current?.promise === promise) inFlightRef.current = null
        if (selectedTargetRef.current === targetKey) {
          setLoading(false)
          setRefreshing(false)
        }
      })

    inFlightRef.current = { targetKey, promise }
    return promise
  }, [requestTarget, selectedTarget, notify, words.loadError, dir])

  useEffect(() => { loadTargets() }, [loadTargets])

  useEffect(() => {
    try { localStorage.setItem(PROTOCOL_TARGET_KEY, selectedTarget) } catch { /* storage unavailable */ }
    const cached = readProtocolCache(selectedTarget)
    const cachedUsable = isUsableProtocolCenter(cached.center)
    centerRef.current = cached.center || null
    setCenter(cached.center || null)
    setSettings(cached.settings || null)
    setLoading(!cachedUsable)
    setRefreshing(false)
    setLogsItem(null)
    setEditItem(null)
    setInstallItem(null)

    // Other pages stay stable until the operator explicitly refreshes them.
    // Only the dedicated Online Users page has a live polling loop.
    if (!cachedUsable) load({ quiet: false, force: false, settingsToo: !cached.settings, notifyError: true }).catch(() => {})
  }, [selectedTarget, load])


  const items = useMemo(() => (center?.protocols || []).filter((item) => item.key !== 'wireguard' && hasProtocol(item.key)), [center])
  const action = async (item, type) => {
    if (type === 'stop' && !await confirm({ title: `${words.stop} ${item.label}`, message: words.confirmStop, danger: true, dir })) return
    setBusyKey(item.key)
    try {
      await requestTarget('POST', `/settings/protocol-center/${item.key}/service/${type}`)
      await load({ quiet: true, force: true, settingsToo: false })
      notify({ type: 'success', message: words.actionDone, dir })
    } catch (e) {
      notify({ type: 'error', message: protocolErrorMessage(e, words.loadError, lang), dir })
    } finally { setBusyKey('') }
  }
  const restartAll = async () => {
    setBusyKey('__all__')
    try {
      const seenUnits = new Set()
      for (const item of items.filter((x) => x.installed)) {
        const signature = (item.units || [item.unit]).join('|')
        if (seenUnits.has(signature)) continue
        seenUnits.add(signature)
        await requestTarget('POST', `/settings/protocol-center/${item.key}/service/restart`)
      }
      await load({ quiet: true, force: true, settingsToo: false })
      notify({ type: 'success', message: words.actionDone, dir })
    } catch (e) {
      notify({ type: 'error', message: protocolErrorMessage(e, words.loadError, lang), dir })
    } finally { setBusyKey('') }
  }

  const restartAcrossNodes = async (item) => {
    const busy = `__nodes__:${item.key}`
    setBusyKey(busy)
    try {
      const { data } = await api.post(`/nodes/protocols/${item.key}/restart-all`)
      const failed = Array.isArray(data?.results) ? data.results.filter((row) => !row.ok) : []
      if (failed.length) {
        const names = failed.map((row) => row.name).filter(Boolean).join('، ')
        notify({ type: 'error', message: `${words.bulkRestartPartial}${names ? `: ${names}` : ''}`, dir })
      } else {
        notify({ type: 'success', message: `${words.actionDone} (${data?.succeeded ?? data?.total ?? 0}/${data?.total ?? 0})`, dir })
      }
      await load({ quiet: true, force: true, settingsToo: false })
    } catch (e) {
      notify({ type: 'error', message: protocolErrorMessage(e, words.loadError, lang), dir })
    } finally { setBusyKey('') }
  }

  const hasSnapshot = isUsableProtocolCenter(center)
  if (loading && !hasSnapshot) return <ProtocolPageSkeleton dir={dir} words={words}/>
  return <div dir={dir} className="space-y-5">
    <header className="flex flex-wrap items-end justify-between gap-3">
      <div><h1 className="page-heading">{words.title}</h1><p className="page-subtitle">{words.subtitle}</p></div>
      <div className="flex gap-2">{hasPermission('protocols:start_stop', 'settings') && <SmallButton disabled={busyKey === '__all__'} tone="signal" icon="refresh" onClick={restartAll}>{busyKey === '__all__' ? <Spinner/> : words.restartAll}</SmallButton>}<SmallButton icon="refresh" disabled={refreshing} onClick={() => { loadTargets(); load({ quiet: true, force: true, settingsToo: false, notifyError: true }).catch(() => {}) }}>{refreshing ? <Spinner/> : words.refresh}</SmallButton></div>
    </header>

    {nodePanel ? <section className="panel-section border-signal/35 bg-signal/5 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><h2 className="text-xs font-black text-signal">{lang === 'fa' ? `پروتکل‌های ${nodePanelName}` : `${nodePanelName} protocols`}</h2><p className="mt-1 text-[10px] text-muted">{lang === 'fa' ? 'تمام عملیات این صفحه فقط روی همین پنل نود اجرا می‌شود و هیچ سرور دیگری انتخاب نمی‌شود.' : 'Every action on this page applies only to this node panel.'}</p></div>
        <span className="rounded-lg border border-success/25 bg-success/10 px-3 py-1.5 text-[10px] font-bold text-success">{lang === 'fa' ? 'حالت پنل نود' : 'Node panel mode'}</span>
      </div>
    </section> : <section className="panel-section p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div><h2 className="text-xs font-bold text-ink">{words.serverSelector}</h2><p className="mt-1 text-[10px] text-muted">{words.selectedServer}: <b className="text-ink">{selectedTargetInfo.name}</b></p></div>
        {selectedTargetInfo.version && <span className="rounded-lg border border-border bg-surface2 px-2 py-1 text-[10px] font-data text-muted">v{selectedTargetInfo.version}</span>}
      </div>
      <div className="flex flex-wrap gap-2">
        {(targets.length ? targets : [{ id: 'local', name: words.mainServer, local: true, status: 'online' }]).map((target) => {
          const active = target.id === selectedTarget
          const online = target.local || target.status === 'online'
          return <button key={target.id} type="button" onClick={() => setSelectedTarget(target.id)} className={`rounded-xl border px-3 py-2 text-xs transition ${active ? 'border-signal bg-signal/10 text-signal' : 'border-border bg-surface2 text-muted hover:border-signal/40 hover:text-ink'}`}>
            <span className={`me-2 inline-block h-2 w-2 rounded-full ${online ? 'bg-success online-presence-dot' : 'bg-danger'}`}/>
            <b>{target.name}</b>
            {!online && <span className="ms-2 text-[9px] text-danger">{words.nodeOffline}</span>}
          </button>
        })}
      </div>
    </section>}

    <LocalServicesModeCard mode={center?.local_services_mode} refreshing={!hasSnapshot} words={words} canInstall={hasPermission('protocols:install', 'settings')} onInstallAll={() => setInstallItem({ key: 'all', label: words.localServicesAction })}/>
    {!nodePanel && hasPermission('protocols:start_stop', 'settings') && <section className="panel-section p-4">
      <div className="mb-3"><h2 className="text-xs font-bold text-ink">{words.bulkRestartTitle}</h2><p className="mt-1 text-[10px] leading-5 text-muted">{words.bulkRestartDesc}</p></div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">{items.map((item) => {
        const busy = busyKey === `__nodes__:${item.key}`
        return <button key={`bulk-${item.key}`} type="button" disabled={!!busyKey} onClick={() => restartAcrossNodes(item)} className="inline-flex min-h-[48px] w-full items-center justify-center gap-2 rounded-xl border border-border bg-surface2 px-3 py-2 text-center text-[10px] font-bold text-ink transition hover:border-signal/40 hover:text-signal disabled:opacity-50">
          {busy ? <Spinner/> : <Icon name="refresh" size={13}/>}<span className="truncate">{item.label}</span><span className="whitespace-nowrap text-[8px] text-muted">{words.restartOnAllNodes}</span>
        </button>
      })}</div>
    </section>}

    {!hasSnapshot ? <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">{Array.from({ length: 9 }).map((_, index) => <article key={index} className="panel-section min-h-[238px] p-4"><div className="h-5 w-28 rounded skeleton"/><div className="mt-5 space-y-3"><div className="h-4 rounded skeleton"/><div className="h-4 rounded skeleton"/><div className="h-4 rounded skeleton"/></div></article>)}</section> : <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">{items.map((item) => <ProtocolCard key={`${selectedTarget}:${item.key}`} item={item} words={words} dir={dir} busy={busyKey === item.key || busyKey === '__all__'} onAction={action} onLogs={setLogsItem} onEdit={setEditItem} onInstall={setInstallItem}/>)}</section>}
    <InfrastructureCard data={center?.infrastructure} refreshing={!hasSnapshot} words={words} canInstall={hasPermission('protocols:install', 'settings')} onInstall={() => setInstallItem({ key: 'infrastructure', label: words.infrastructure })} onInstallAll={() => setInstallItem({ key: 'all', label: words.installAll })}/>
    {logsItem && <LogsModal key={`logs:${selectedTarget}:${logsItem.key}`} item={logsItem} words={words} onClose={() => setLogsItem(null)} request={requestTarget} targetKey={selectedTarget} targetName={selectedTargetInfo.name}/>} 
    {installItem && <TerminalModal key={`install:${selectedTarget}:${installItem.key}`} item={installItem} words={words} onClose={() => setInstallItem(null)} onFinished={() => load({ quiet: true, force: true, settingsToo: false }).catch(() => {})} request={requestTarget} targetKey={selectedTarget} targetName={selectedTargetInfo.name}/>} 
    {editItem && settings && <EditModal key={`edit:${selectedTarget}:${editItem.key}`} item={editItem} settings={settings} center={center} words={words} onClose={() => setEditItem(null)} onSaved={() => load({ quiet: true, force: true, settingsToo: true }).catch(() => {})} request={requestTarget} targetKey={selectedTarget} targetName={selectedTargetInfo.name}/>} 
  </div>
}
