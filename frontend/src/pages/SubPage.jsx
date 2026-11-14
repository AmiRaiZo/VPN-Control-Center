import React, { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import axios from 'axios'
import { formatJalaliDate } from '../jalali'
import { ThemeToggle } from '../theme/themeContext.jsx'
import { LangToggle, useLang } from '../i18n/dashboardLang.jsx'
import { Icon } from '../components/icons.jsx'

const pub = axios.create({ baseURL: '/api', timeout: 20000 })

const STATUS_LABEL_KEY = {
  active: 'subPageStatusActive',
  quota: 'subPageStatusQuotaExceeded',
  time: 'subPageStatusTimeExpired',
  quota_and_time: 'subPageStatusQuotaAndTime',
  disabled_admin: 'subPageStatusDisabledAdmin',
}

const STATUS_STYLE = {
  active: { tone: 'success', icon: 'check' },
  quota: { tone: 'danger', icon: 'warning' },
  time: { tone: 'danger', icon: 'clock' },
  quota_and_time: { tone: 'danger', icon: 'warning' },
  disabled_admin: { tone: 'danger', icon: 'ban' },
}

const PLATFORM_META = {
  android: { mark: 'A', className: 'platform-android' },
  windows: { mark: 'W', className: 'platform-windows' },
  ios: { mark: 'i', className: 'platform-ios' },
  mac: { mark: 'M', className: 'platform-mac' },
}

function fmtBytes(bytes, t) {
  const value = Math.max(0, Number(bytes || 0))
  if (value === 0) return `0 ${t('subPageUnitGB')}`
  const gb = value / 1073741824
  return gb >= 1
    ? `${gb.toFixed(gb >= 100 ? 0 : 2)} ${t('subPageUnitGB')}`
    : `${(value / 1048576).toFixed(0)} ${t('subPageUnitMB')}`
}

async function responseErrorDetail(error, fallback) {
  const payload = error?.response?.data
  if (payload instanceof Blob) {
    try {
      const text = await payload.text()
      const parsed = JSON.parse(text)
      return parsed?.detail || parsed?.message || fallback
    } catch (_) {
      return fallback
    }
  }
  return payload?.detail || payload?.message || fallback
}

async function copyText(value) {
  if (!value) return false
  try {
    await navigator.clipboard.writeText(String(value))
    return true
  } catch (_) {
    const ta = document.createElement('textarea')
    ta.value = String(value)
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  }
}

function CopyField({ label, value, t, secret = false }) {
  const [copied, setCopied] = useState(false)
  const [revealed, setRevealed] = useState(!secret)
  const shown = secret && !revealed ? '••••••••••••' : (value || '—')

  const handleCopy = async () => {
    if (!value) return
    await copyText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1400)
  }

  return (
    <div className="sub-field-row">
      <div className="min-w-0">
        <div className="sub-field-label">{label}</div>
        <div className="sub-field-value font-data" title={String(value || '')}>{shown}</div>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {secret && (
          <button type="button" className="sub-icon-action" onClick={() => setRevealed((v) => !v)} title={revealed ? 'Hide' : 'Show'}>
            <Icon name={revealed ? 'eyeOff' : 'eye'} size={15} />
          </button>
        )}
        <button type="button" className={`sub-copy-action ${copied ? 'is-copied' : ''}`} onClick={handleCopy} disabled={!value}>
          <Icon name={copied ? 'check' : 'copy'} size={15} />
          <span>{copied ? t('subPageCopiedBtn') : t('subPageCopyBtn')}</span>
        </button>
      </div>
    </div>
  )
}

function Metric({ icon, label, value, accent = false }) {
  return (
    <div className={`sub-metric ${accent ? 'is-accent' : ''}`}>
      <span className="sub-metric-icon"><Icon name={icon} size={17} /></span>
      <span className="min-w-0">
        <span className="sub-metric-label">{label}</span>
        <strong className="sub-metric-value">{value}</strong>
      </span>
    </div>
  )
}

function ProtocolSection({ title, eyebrow, icon = 'server', children, footer }) {
  return (
    <section className="sub-detail-card">
      <div className="sub-detail-head">
        <span className="sub-detail-icon"><Icon name={icon} size={20} /></span>
        <div>
          {eyebrow && <div className="sub-section-eyebrow">{eyebrow}</div>}
          <h2 className="sub-detail-title">{title}</h2>
        </div>
      </div>
      <div className="sub-detail-body">{children}</div>
      {footer && <div className="sub-detail-footer">{footer}</div>}
    </section>
  )
}

function DownloadActionButton({ title, subtitle = '', label, busy = false, onClick, disabled = false }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="sub-download-action"
    >
      <span className="sub-download-action-copy">
        <strong>{title}</strong>
        {subtitle && <small dir="ltr">{subtitle}</small>}
      </span>
      <span className="sub-download-action-cta">
        <Icon name="backup" size={16} />
        <span>{busy ? '…' : label}</span>
      </span>
    </button>
  )
}

function XrayProfileCard({ profile, lang }) {
  const [copied, setCopied] = useState(false)
  const protocol = String(profile?.protocol || '').toLowerCase()
  const copy = async () => {
    await copyText(profile?.uri)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1500)
  }

  return (
    <article className={`sub-profile-card sub-profile-${protocol}`}>
      <div className="sub-profile-head">
        <div>
          <div className="sub-section-eyebrow">XRAY PROFILE</div>
          <h3>{profile?.label || protocol.toUpperCase()}</h3>
        </div>
        <span className="sub-protocol-orb">{protocol === 'vless' ? 'VL' : 'VM'}</span>
      </div>
      <button type="button" className="sub-qr-button" onClick={copy}>
        <span className="sub-qr-frame"><img src={profile?.qr_data_url || profile?.qr_url} alt={`${protocol} QR`} /></span>
        <span className="sub-qr-caption">
          <Icon name={copied ? 'check' : 'copy'} size={15} />
          {copied ? (lang === 'en' ? 'Configuration copied' : 'کانفیگ کپی شد') : (lang === 'en' ? 'Tap QR to copy config' : 'برای کپی کانفیگ روی QR بزنید')}
        </span>
      </button>
      <div className="sub-uri-preview">{profile?.uri}</div>
    </article>
  )
}

function SubscriptionCard({ url, qrData, health, lang }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    await copyText(url)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1500)
  }

  const healthText = health === 'ready'
    ? (lang === 'en' ? 'Link checked and ready' : 'لینک بررسی شد و آماده است')
    : health === 'failed'
      ? (lang === 'en' ? 'Link check failed' : 'بررسی لینک ناموفق بود')
      : (lang === 'en' ? 'Checking subscription link…' : 'در حال بررسی لینک ساب…')

  return (
    <article className="sub-subscription-card">
      <div className="sub-subscription-copy">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="sub-section-eyebrow">ONE TAP SUBSCRIPTION</div>
            <h3>{lang === 'en' ? 'Universal subscription link' : 'لینک ساب یکپارچه'}</h3>
            <p>{lang === 'en' ? 'Use this link in v2rayN, v2rayNG, Streisand and compatible clients.' : 'این لینک را داخل v2rayN، v2rayNG، Streisand و کلاینت‌های سازگار وارد کنید.'}</p>
          </div>
          <span className={`sub-link-health is-${health}`}><span />{healthText}</span>
        </div>
        <div className="sub-link-box font-data">{url || '—'}</div>
        <div className="sub-action-grid">
          <button type="button" className="sub-primary-action" onClick={copy} disabled={!url}>
            <Icon name={copied ? 'check' : 'copy'} size={17} />
            {copied ? (lang === 'en' ? 'Copied' : 'کپی شد') : (lang === 'en' ? 'Copy subscription' : 'کپی لینک ساب')}
          </button>
          <a className="sub-secondary-action" href={url || '#'} target="_blank" rel="noreferrer" aria-disabled={!url}>
            <Icon name="external" size={17} />
            {lang === 'en' ? 'Open raw link' : 'بازکردن لینک خام'}
          </a>
        </div>
      </div>
      <button type="button" className="sub-subscription-qr" onClick={copy}>
        <span className="sub-qr-frame"><img src={qrData} alt="Subscription QR" /></span>
        <span>{lang === 'en' ? 'Scan or tap to copy' : 'اسکن کنید یا برای کپی بزنید'}</span>
      </button>
    </article>
  )
}

function getDefaultPlatformApps(t) {
  return [
    { key: 'android', label: t('platformAndroidLabel'), apps: [{ name: 'V2rayNG', desc: t('appV2rayNgDesc') }, { name: 'OpenVPN Connect', desc: t('appOpenvpnConnectAndroidDesc') }, { name: t('appAndroidBuiltinName'), desc: t('appAndroidBuiltinDesc') }] },
    { key: 'windows', label: t('platformWindowsLabel'), apps: [{ name: 'v2rayN', desc: 'VMess / VLESS' }, { name: 'OpenVPN Connect', desc: t('appOpenvpnConnectWinDesc') }, { name: t('appWindowsBuiltinName'), desc: t('appWindowsBuiltinDesc') }] },
    { key: 'ios', label: t('platformIosLabel'), apps: [{ name: 'Streisand', desc: 'VMess / VLESS' }, { name: 'OpenVPN Connect', desc: t('appOpenvpnConnectIosDesc') }, { name: t('appIosBuiltinName'), desc: t('appIosBuiltinDesc') }] },
    { key: 'mac', label: t('platformMacLabel'), apps: [{ name: 'V2Box', desc: 'VMess / VLESS' }, { name: 'OpenVPN Connect', desc: t('appOpenvpnConnectMacDesc') }, { name: t('appMacBuiltinName'), desc: t('appMacBuiltinDesc') }] },
  ]
}

function PlatformAppsGrid({ t, customApps, lang }) {
  const [openKey, setOpenKey] = useState(null)
  const apps = useMemo(() => {
    if (!customApps) return getDefaultPlatformApps(t)
    return ['android', 'windows', 'ios', 'mac'].filter((key) => customApps[key]).map((key) => ({ key, label: customApps[key].label, apps: customApps[key].apps || [] }))
  }, [customApps, t])

  return (
    <section className="sub-apps-shell">
      <div className="sub-apps-heading">
        <div>
          <div className="sub-section-eyebrow">CLIENT APPS</div>
          <h2>{t('subPageAppsHeading')}</h2>
          <p>{lang === 'en' ? 'Choose your device to see compatible applications and direct download links.' : 'دستگاه خود را انتخاب کنید تا برنامه‌های سازگار و لینک دانلودشان نمایش داده شود.'}</p>
        </div>
        <span className="sub-apps-count">{apps.length} OS</span>
      </div>
      <div className="sub-platform-grid">
        {apps.map((platform) => {
          const meta = PLATFORM_META[platform.key] || PLATFORM_META.android
          const open = openKey === platform.key
          return (
            <article key={platform.key} className={`sub-platform-card ${meta.className} ${open ? 'is-open' : ''}`}>
              <button type="button" className="sub-platform-trigger" onClick={() => setOpenKey(open ? null : platform.key)}>
                <span className="sub-platform-mark">{meta.mark}</span>
                <span className="min-w-0 flex-1 text-start">
                  <strong>{platform.label}</strong>
                  <small>{platform.apps.length} {lang === 'en' ? 'recommended apps' : 'برنامه پیشنهادی'}</small>
                </span>
                <span className="sub-platform-chevron"><Icon name="chevron" size={17} /></span>
              </button>
              <div className="sub-platform-content">
                {platform.apps.map((app, index) => {
                  const content = (
                    <>
                      <span className="sub-app-index">{String(index + 1).padStart(2, '0')}</span>
                      <span className="min-w-0 flex-1">
                        <strong>{app.name}</strong>
                        <small>{app.desc}</small>
                      </span>
                      {app.url && <Icon name="external" size={16} />}
                    </>
                  )
                  return app.url ? (
                    <a key={`${app.name}-${index}`} href={app.url} target="_blank" rel="noopener noreferrer" className="sub-app-row">{content}</a>
                  ) : (
                    <div key={`${app.name}-${index}`} className="sub-app-row is-static">{content}</div>
                  )
                })}
              </div>
            </article>
          )
        })}
      </div>
    </section>
  )
}

export default function SubPage() {
  const { token } = useParams()
  const { lang, setLang, dir, t } = useLang()
  const cacheKey = `vpnpanel:sub:v23173:${token}`
  const initialCache = useMemo(() => {
    try {
      const parsed = JSON.parse(sessionStorage.getItem(cacheKey) || 'null')
      return parsed?.data || null
    } catch (_) { return null }
  }, [cacheKey])
  const [data, setData] = useState(initialCache)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(!initialCache)
  const [dlBusyKey, setDlBusyKey] = useState('')
  const [dlError, setDlError] = useState('')
  const [sstpDlBusy, setSstpDlBusy] = useState(false)
  const [sstpDlError, setSstpDlError] = useState('')
  const [subHealth, setSubHealth] = useState('checking')
  const [selectedServerId, setSelectedServerId] = useState('')

  useEffect(() => {
    let alive = true
    let inFlight = false
    const load = async (silent = false) => {
      if (inFlight) return
      inFlight = true
      if (!silent) { setLoading(true); setError('') }
      try {
        const response = await pub.get(`/sub/${token}`, { params: { _: Date.now() } })
        if (alive) {
          setData(response.data)
          try { sessionStorage.setItem(cacheKey, JSON.stringify({ data: response.data, savedAt: Date.now() })) } catch (_) {}
        }
      } catch (err) {
        if (alive && !silent) setError(err.response?.data?.detail || t('subPageLinkNotFoundError'))
      } finally {
        inFlight = false
        if (alive && !silent) setLoading(false)
      }
    }
    if (!initialCache) load(false)
    return () => { alive = false }
  }, [token, t, cacheKey, initialCache])

  useEffect(() => {
    const nodes = Array.isArray(data?.nodes) ? data.nodes : []
    if (!nodes.length) {
      setSelectedServerId('')
      return
    }
    setSelectedServerId((current) => (
      nodes.some((node) => String(node.id) === String(current))
        ? current
        : String(nodes[0].id)
    ))
  }, [data?.nodes])

  const subscriptionUrl = useMemo(() => {
    if (!data) return ''
    if (data.xray_subscription_path && typeof window !== 'undefined') return `${window.location.origin}${data.xray_subscription_path}`
    return data.xray_subscription_url || ''
  }, [data])

  useEffect(() => {
    if (!subscriptionUrl) { setSubHealth('failed'); return undefined }
    let alive = true
    const check = async () => {
      setSubHealth('checking')
      try {
        const response = await fetch(`${subscriptionUrl}${subscriptionUrl.includes('?') ? '&' : '?'}_=${Date.now()}`, { cache: 'no-store' })
        const text = (await response.text()).trim()
        let decoded = ''
        try { decoded = window.atob(text.replace(/\s+/g, '')) } catch (_) { decoded = '' }
        if (!response.ok || !(decoded.includes('vmess://') || decoded.includes('vless://'))) throw new Error('invalid subscription payload')
        if (alive) setSubHealth('ready')
      } catch (_) {
        if (alive) setSubHealth('failed')
      }
    }
    check()
    return () => { alive = false }
  }, [subscriptionUrl])

  const quotaPercent = useMemo(() => {
    if (!data?.quota_bytes || data.quota_bytes <= 0) return 0
    return Math.min(100, Math.max(0, (Number(data.used_bytes || 0) / Number(data.quota_bytes)) * 100))
  }, [data])

  const downloadOpenVpn = async (targetKey = '', nodeName = '') => {
    const busyKey = targetKey || 'combined'
    setDlError(''); setDlBusyKey(busyKey)
    try {
      const suffix = targetKey ? `/openvpn-config/${encodeURIComponent(targetKey)}` : '/openvpn-config'
      const res = await pub.get(`/sub/${token}${suffix}`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(res.data)
      const a = document.createElement('a')
      const safeNode = String(nodeName || '').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '')
      a.href = url
      a.download = `${data?.username || 'config'}${safeNode ? `-${safeNode}` : '-all-servers'}-${Date.now()}.ovpn`
      document.body.appendChild(a); a.click(); a.remove(); window.URL.revokeObjectURL(url)
    } catch (err) { setDlError(await responseErrorDetail(err, t('subPageOpenvpnDownloadError'))) }
    finally { setDlBusyKey('') }
  }

  const downloadSstpCert = async (targetKey = '') => {
    setSstpDlError(''); setSstpDlBusy(true)
    try {
      const res = await pub.get(`/sub/${token}/sstp-cert`, {
        responseType: 'blob',
        params: targetKey ? { target_key: targetKey } : undefined,
      })
      const url = window.URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url; a.download = `${data?.username || 'sstp'}-sstp-cert.cer`
      document.body.appendChild(a); a.click(); a.remove(); window.URL.revokeObjectURL(url)
    } catch (err) { setSstpDlError(await responseErrorDetail(err, t('subPageSstpDownloadError'))) }
    finally { setSstpDlBusy(false) }
  }

  const status = data ? (STATUS_STYLE[data.status_key] || STATUS_STYLE.active) : STATUS_STYLE.active
  const statusLabel = data ? t(STATUS_LABEL_KEY[data.status_key] || 'subPageStatusActive') : ''
  const profiles = data?.xray_profiles || [
    data?.enable_vmess && { protocol: 'vmess', label: 'VMESS', uri: data.vmess_uri },
    data?.enable_vless && { protocol: 'vless', label: 'VLESS', uri: data.vless_uri },
  ].filter(Boolean)
  const openvpnProfiles = Array.isArray(data?.openvpn_profiles) ? data.openvpn_profiles : []
  const openvpnSyncing = Boolean(data?.openvpn_syncing)
  const serverOptions = Array.isArray(data?.nodes) ? data.nodes : []
  const selectedServer = serverOptions.find((node) => String(node.id) === String(selectedServerId)) || serverOptions[0] || null
  const selectedProtocols = selectedServer?.protocols || {}
  const selectedServerAddress = selectedServer?.display_address || selectedServer?.address || data?.server_address || ''
  const selectedTargetKey = selectedServer ? (selectedServer.local ? 'local' : `node-${selectedServer.id}`) : ''
  const selectedProtocol = (key) => selectedProtocols?.[key] || {}
  const selectedProtocolEnabled = (key, legacyFlag) => (
    selectedServer ? Boolean(selectedProtocol(key)?.enabled) : Boolean(legacyFlag)
  )
  const selectedXrayProfiles = selectedServer && profiles.some((profile) => profile?.node_id !== undefined && profile?.node_id !== null)
    ? profiles.filter((profile) => String(profile?.node_id) === String(selectedServer.id))
    : profiles

  return (
    <div dir={dir} className="sub-page-bg min-h-screen px-3 py-5 sm:px-5 sm:py-8">
      <div className="sub-page-aurora" aria-hidden="true" />
      <div className="sub-page-mesh" aria-hidden="true" />
      <div className="sub-floating-orb sub-orb-one" aria-hidden="true" />
      <div className="sub-floating-orb sub-orb-two" aria-hidden="true" />

      <main className="relative z-10 mx-auto w-full max-w-5xl">
        <header className="sub-topbar">
          <div className="sub-brand-lockup">
            <span className="sub-brand-icon"><Icon name="shield" size={22} /></span>
            <span><strong>VPN PANEL</strong><small>SECURE SUBSCRIPTION</small></span>
          </div>
          <div className="flex items-center gap-2"><ThemeToggle /><LangToggle lang={lang} setLang={setLang} variant="icon" /></div>
        </header>

        {loading && <div className="sub-state-card"><span className="sub-loader" />{t('subPageLoading')}</div>}
        {!loading && error && <div className="sub-state-card is-error"><Icon name="warning" size={25} /><strong>{t('subPageInvalidLinkTitle')}</strong><p>{error}</p></div>}

        {!loading && !error && data && (
          <div className="space-y-5">
            <section className={`sub-hero sub-status-${status.tone}`}>
              <div className="sub-hero-grid" />
              <div className="sub-hero-glow" />
              <div className="sub-hero-copy">
                <div className="sub-live-line">
                  <span className={`sub-status-pill is-${status.tone}`}><Icon name={status.icon} size={15} />{statusLabel}</span>
                  <span className="sub-refresh-note"><span className="signal-dot" />{lang === 'en' ? 'Live update every 4 seconds' : 'به‌روزرسانی زنده هر ۴ ثانیه'}</span>
                </div>
                <div className="sub-hero-title-wrap">
                  <div>
                    <div className="sub-section-eyebrow">PRIVATE ACCESS PROFILE</div>
                    <h1>{lang === 'en' ? 'Your secure connection hub' : 'مرکز اتصال امن شما'}</h1>
                    <p>{lang === 'en' ? 'All credentials, live usage and client-ready configurations in one protected page.' : 'اطلاعات حساب، مصرف زنده و کانفیگ‌های آماده اتصال، همه در یک صفحه امن.'}</p>
                  </div>
                  <div className={`sub-online-badge ${data.online_count > 0 ? 'is-online' : ''}`}>
                    <span className="sub-online-radar"><Icon name="wifi" size={22} /></span>
                    <strong>{data.online_count}</strong>
                    <small>{data.online_count > 0 ? (lang === 'en' ? 'connected now' : 'اتصال فعال') : (lang === 'en' ? 'no live connection' : 'بدون اتصال زنده')}</small>
                  </div>
                </div>

                <div className="sub-usage-panel">
                  <div className="sub-usage-head">
                    <span>{lang === 'en' ? 'Traffic usage' : 'مصرف ترافیک'}</span>
                    <strong>{data.quota_bytes > 0 ? `${fmtBytes(data.used_bytes, t)} / ${fmtBytes(data.quota_bytes, t)}` : `${fmtBytes(data.used_bytes, t)} / ${t('subPageUnlimited')}`}</strong>
                  </div>
                  <div className="sub-progress-track"><span style={{ width: data.quota_bytes > 0 ? `${quotaPercent}%` : '18%' }} /></div>
                  <div className="sub-usage-meta"><span>{data.quota_bytes > 0 ? `${quotaPercent.toFixed(1)}%` : t('subPageUnlimited')}</span><span>{data.usage_summary}</span></div>
                </div>
              </div>
            </section>

            <section className="sub-metrics-grid">
              <Metric icon="user" label={t('subPageUsernameLabel')} value={data.username} accent />
              <Metric icon="clock" label={t('subPageExpiryLabel')} value={data.expire_date ? formatJalaliDate(data.expire_date) : t('subPageUnlimited')} />
              <Metric icon="users" label={t('subPagePurchasedDevicesLabel')} value={data.max_devices} />
              <Metric icon="chart" label={t('subPageUsedQuotaLabel')} value={fmtBytes(data.used_bytes, t)} />
            </section>

            {!!serverOptions.length && (
              <section className="sub-account-card">
                <div className="sub-card-heading">
                  <div><div className="sub-section-eyebrow">SERVER SELECTOR</div><h2>{lang === 'en' ? 'Choose a server' : 'انتخاب سرور'}</h2><p className="mt-1 text-[10px] leading-5 text-muted">{lang === 'en' ? 'Connection details below change to the selected server. OpenVPN downloads remain in their current all-server/separate-file layout.' : 'مشخصات اتصال پایین صفحه مربوط به سرور انتخاب‌شده است؛ بخش OpenVPN بدون تغییر و به‌صورت فایل ترکیبی و فایل‌های جدا باقی می‌ماند.'}</p></div>
                  <span className="sub-safe-badge"><Icon name="server" size={15} />{serverOptions.length}</span>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  {serverOptions.map((node) => {
                    const active = String(node.id) === String(selectedServer?.id)
                    const protocols = Object.entries(node.protocols || {}).filter(([, value]) => value?.enabled).map(([key]) => key.toUpperCase())
                    return <button type="button" key={String(node.id)} onClick={() => setSelectedServerId(String(node.id))} aria-pressed={active} className={`sub-server-choice ${active ? 'is-active' : ''}`}>
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0"><strong className="sub-server-choice-name">{node.name}</strong><span dir="ltr" className="mt-1 block truncate font-data text-[10px] text-muted">{node.display_address || node.address || '—'}</span></div>
                        <span className="sub-server-choice-status"><Icon name={active ? 'check' : 'server'} size={14} /></span>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-1.5">{protocols.map((item) => <span key={item} className="sub-server-choice-protocol">{item}</span>)}</div>
                    </button>
                  })}
                </div>
              </section>
            )}

            <section className="sub-account-card">
              <div className="sub-card-heading"><div><div className="sub-section-eyebrow">ACCOUNT CREDENTIALS</div><h2>{t('subPageAccountInfoTitle')}</h2></div><span className="sub-safe-badge"><Icon name="shield" size={15} />{lang === 'en' ? 'Protected' : 'محافظت‌شده'}</span></div>
              <div className="sub-account-grid">
                <CopyField label={t('subPageUsernameLabel')} value={data.username} t={t} />
                <CopyField label={t('subPagePasswordLabel')} value={data.password} t={t} secret />
              </div>
            </section>

            {(data.enable_vmess || data.enable_vless) && (
              <section className="sub-xray-shell">
                <div className="sub-card-heading">
                  <div><div className="sub-section-eyebrow">SMART XRAY ACCESS</div><h2>{t('subPageXrayHeading')}</h2>{selectedServer && <p className="mt-1 text-[10px] text-muted">{lang === 'en' ? `Profiles shown for ${selectedServer.name}` : `کانفیگ‌های نمایش‌داده‌شده برای ${selectedServer.name}`}</p>}</div>
                </div>
                {subscriptionUrl && data.xray_subscription_qr_data_url && <SubscriptionCard url={subscriptionUrl} qrData={data.xray_subscription_qr_data_url} health={subHealth} lang={lang} />}
                {!!selectedXrayProfiles.length && <div className="sub-profile-grid">{selectedXrayProfiles.map((profile) => <XrayProfileCard key={`${profile.protocol}-${profile.node_id ?? 'legacy'}`} profile={profile} lang={lang} />)}</div>}
                {!selectedXrayProfiles.length && selectedServer && <div className="sub-state-card">{lang === 'en' ? 'VMess/VLESS is not enabled on this server.' : 'VMess/VLESS روی این سرور فعال نیست.'}</div>}
              </section>
            )}

            <div className="sub-protocol-grid">
              {selectedProtocolEnabled('l2tp', data.enable_l2tp) && <ProtocolSection title={t('subPageL2tpTitle')} eyebrow="L2TP / IPSEC" icon="key"><CopyField label={t('subPageServerAddressLabel')} value={selectedProtocol('l2tp').server_address || selectedServerAddress || data.l2tp_server_address} t={t} /><CopyField label={t('subPageL2tpPortLabel')} value={selectedProtocol('l2tp').port || data.l2tp_port} t={t} /><CopyField label={t('subPageIpsecPskLabel')} value={selectedProtocol('l2tp').ipsec_psk || selectedServer?.ipsec_psk || data.ipsec_psk || ''} t={t} secret /></ProtocolSection>}
              {selectedProtocolEnabled('ikev2', data.enable_ikev2) && <ProtocolSection title={t('subPageIkev2Title')} eyebrow="IKEV2" icon="shield" footer={t('subPageIkev2Note')}><CopyField label={t('subPageServerAddressLabel')} value={selectedProtocol('ikev2').server_address || selectedServerAddress || data.ikev2_address} t={t} /><CopyField label={t('subPageUsernameLabel')} value={data.username} t={t} /><CopyField label={t('subPagePasswordLabel')} value={data.password} t={t} secret /></ProtocolSection>}
              {selectedProtocolEnabled('pptp', data.enable_pptp) && <ProtocolSection title={t('subPagePptpTitle')} eyebrow="PPTP" icon="server"><CopyField label={t('subPageServerAddressLabel')} value={selectedProtocol('pptp').server_address || selectedServerAddress || data.pptp_server_address} t={t} /><CopyField label={t('subPageUsernameLabel')} value={data.username} t={t} /><CopyField label={t('subPagePasswordLabel')} value={data.password} t={t} secret /></ProtocolSection>}
              {selectedProtocolEnabled('sstp', data.enable_sstp) && <ProtocolSection title={t('subPageSstpTitle')} eyebrow="SSTP" icon="shield" footer={data.sstp_auth_mode === 'cert_password' ? t('subPageSstpNoteCertPassword') : t('subPageSstpNoteDefault')}><CopyField label={t('subPageServerAddressLabel')} value={selectedProtocol('sstp').server_address || selectedServerAddress || data.sstp_server_address} t={t} /><CopyField label={t('subPageSstpPortLabel')} value={selectedProtocol('sstp').port || data.sstp_port} t={t} /><DownloadActionButton title={t('subPageSstpDownloadBtn')} label={lang === 'en' ? 'Download' : 'دانلود'} busy={sstpDlBusy} onClick={() => downloadSstpCert(selectedTargetKey)} disabled={sstpDlBusy} />{sstpDlError && <div className="sub-inline-error">{sstpDlError}</div>}</ProtocolSection>}
              {data.enable_openvpn && <ProtocolSection title={t('subPageOpenvpnTitle')} eyebrow="OPENVPN" icon="globe">
                {!!openvpnProfiles.length ? <>
                  <DownloadActionButton
                    title={lang === 'en' ? 'Download combined file (all servers)' : 'دانلود فایل ترکیبی همه سرورها'}
                    subtitle={lang === 'en' ? 'All selected OpenVPN servers in one profile' : 'تمام سرورهای انتخاب‌شده در یک فایل'}
                    label={lang === 'en' ? 'Download' : 'دانلود'}
                    busy={dlBusyKey === 'combined'}
                    onClick={() => downloadOpenVpn()}
                    disabled={!!dlBusyKey}
                  />
                  <div className="mt-3 space-y-2">
                    <div className="text-[10px] font-bold text-muted">{lang === 'en' ? 'Separate file for each server' : 'فایل جداگانه هر سرور'}</div>
                    {openvpnProfiles.map((profile) => <DownloadActionButton
                      key={profile.target_key}
                      title={profile.node_name}
                      subtitle={profile.server_address}
                      label={lang === 'en' ? 'Download' : 'دانلود'}
                      busy={dlBusyKey === profile.target_key}
                      onClick={() => downloadOpenVpn(profile.target_key, profile.node_name)}
                      disabled={!!dlBusyKey}
                    />)}
                  </div>
                </> : <div className="sub-state-card">
                  <span className={openvpnSyncing ? 'sub-loader' : ''} />
                  {openvpnSyncing
                    ? (lang === 'en' ? 'OpenVPN files are being synchronized with the nodes. This list will appear automatically.' : 'فایل‌های OpenVPN در حال همگام‌سازی با نودها هستند؛ لیست دانلود خودکار نمایش داده می‌شود.')
                    : (lang === 'en' ? 'No OpenVPN server is ready for this account.' : 'هیچ سرور OpenVPN آماده‌ای برای این حساب پیدا نشد.')}
                </div>}
                {dlError && <div className="sub-inline-error">{dlError}</div>}
              </ProtocolSection>}
              {selectedProtocolEnabled('openconnect', data.enable_openconnect) && <ProtocolSection title={t('subPageOpenconnectTitle')} eyebrow="ANYCONNECT" icon="wifi" footer={t('subPageOpenconnectNote')}><CopyField label={t('subPageServerAddressLabel')} value={selectedProtocol('openconnect').server_address || selectedServerAddress || data.openconnect_server_address} t={t} /><CopyField label={t('subPageOpenconnectPortLabel')} value={selectedProtocol('openconnect').port || data.openconnect_port} t={t} /><CopyField label={t('subPageUsernameLabel')} value={data.username} t={t} /><CopyField label={t('subPagePasswordLabel')} value={data.password} t={t} secret /></ProtocolSection>}
            </div>

            {!data.enable_l2tp && !data.enable_pptp && !data.enable_sstp && !data.enable_openvpn && !data.enable_ikev2 && !data.enable_openconnect && !data.enable_vmess && !data.enable_vless && <div className="sub-state-card">{t('subPageNoProtocolsMessage')}</div>}

            {data.custom_download_url && <a href={data.custom_download_url} target="_blank" rel="noreferrer" className="sub-custom-download"><Icon name="external" size={19} /><span><strong>{data.custom_download_label || t('subPageCustomDownloadDefaultLabel')}</strong><small>{lang === 'en' ? 'Open custom download page' : 'بازکردن صفحه دانلود اختصاصی'}</small></span></a>}

            <PlatformAppsGrid t={t} customApps={data.platform_apps} lang={lang} />
            <footer className="sub-footer"><span>VPN PANEL</span><span>{lang === 'en' ? 'Encrypted access • Live usage • Multi protocol' : 'دسترسی رمزگذاری‌شده • مصرف زنده • چندپروتکلی'}</span></footer>
          </div>
        )}
      </main>
    </div>
  )
}
