import React, { lazy, Suspense, useEffect, useState } from 'react'
import { usePanelNavigate } from '../navigation.js'
import api from '../api'
import { setSession } from '../session'
import { useLang, LangToggle } from '../i18n/dashboardLang.jsx'
import { ThemeToggle } from '../theme/themeContext.jsx'
import { Icon } from '../components/icons.jsx'
import { useBranding } from '../branding.jsx'
const ParticleBackground = lazy(() => import('../components/ParticleBackground.jsx'))
const AuthWaveBackground = lazy(() => import('../components/AuthWaveBackground.jsx'))
const configured = (value, fallback) => value === null || value === undefined ? fallback : value

export default function Login() {
  const { lang, setLang, dir, t } = useLang()
  const { branding } = useBranding()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [registerMode, setRegisterMode] = useState(false)
  const [registerStep, setRegisterStep] = useState('license')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [licenseCode, setLicenseCode] = useState('')
  const [licenseInfo, setLicenseInfo] = useState(null)
  const [telegramUserId, setTelegramUserId] = useState('')
  const [telegramOptOut, setTelegramOptOut] = useState(false)
  const [registeredSession, setRegisteredSession] = useState(null)
  const [loading, setLoading] = useState(false)
  const navigate = usePanelNavigate()
  const [liteMobile, setLiteMobile] = useState(() => typeof window !== 'undefined' && window.matchMedia?.('(max-width: 767px), (pointer: coarse)').matches === true)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    if (params.get('reason') === 'ip_banned') {
      setError(lang === 'en' ? 'This IP address is blocked and cannot access the panel.' : 'این آی‌پی مسدود شده و اجازه ورود به پنل را ندارد.')
    }
  }, [lang])

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return undefined
    const query = window.matchMedia('(max-width: 767px), (pointer: coarse)')
    const sync = () => setLiteMobile(query.matches)
    sync(); query.addEventListener?.('change', sync)
    return () => query.removeEventListener?.('change', sync)
  }, [])

  const brandName = configured(branding.brand_name, 'VPN PANEL')
  const heroBadge = configured(branding.hero_badge, t('loginPanelBadge'))
  const heroTitle = configured(branding.hero_title, t('loginHeroTitle'))
  const heroSubtitle = configured(branding.hero_subtitle, t('loginHeroSubtitle'))
  const heroFooter = configured(branding.hero_footer, 'VPN Panel · Secure Administration')
  const loginFooterNote = configured(branding.login_footer_note, '')
  const showHero = branding.hero_enabled && Boolean(branding.hero_image_url || brandName || heroBadge || heroTitle || heroSubtitle || heroFooter)
  const showDesktopHero = showHero && !liteMobile

  const errorText = (err) => {
    if (err?.code === 'ECONNABORTED') {
      return lang === 'en'
        ? 'The panel API did not answer in time. The login was cancelled safely; retry after the service recovers.'
        : 'پاسخ API پنل بیش از حد طول کشید. ورود بدون گیرکردن لغو شد؛ چند لحظه بعد دوباره تلاش کنید.'
    }
    const detail = err.response?.data?.detail
    if (detail === 'ip_banned') {
      return lang === 'en' ? 'This IP address is blocked and cannot access the panel.' : 'این آی‌پی مسدود شده و اجازه ورود به پنل را ندارد.'
    }
    return Array.isArray(detail) ? detail.map(item => item.msg).join('، ') : (detail || t('loginError'))
  }

  const inspectLicense = async (event) => {
    event.preventDefault(); setError(''); setLoading(true)
    try {
      const { data } = await api.post('/auth/register/license-info', { license_code: licenseCode })
      setLicenseInfo(data)
      setTelegramUserId('')
      setTelegramOptOut(false)
      setRegisterStep('account')
    } catch (err) { setError(errorText(err)) } finally { setLoading(false) }
  }

  const continueToPanel = () => {
    if (!registeredSession) return
    setSession(registeredSession.access_token, registeredSession.role, registeredSession.permissions || [], !!registeredSession.internal_license_required, registeredSession.server_role || 'main')
    navigate(registeredSession.internal_license_required ? '/admin-license' : '/dashboard')
  }

  const submit = async (event) => {
    event.preventDefault(); setError(''); setLoading(true)
    try {
      if (!registerMode) {
        const { data } = await api.post('/auth/login', { username, password }, { timeout: 15000 })
        setSession(data.access_token, data.role, data.permissions || [], !!data.internal_license_required, data.server_role || 'main')
        navigate(data.internal_license_required ? '/admin-license' : '/dashboard')
        return
      }
      const { data } = await api.post('/auth/register', {
        username, password, confirm_password: confirmPassword, license_code: licenseCode,
        telegram_user_id: licenseInfo?.telegram_bot_enabled && !telegramOptOut ? Number(telegramUserId) : null,
        telegram_bot_opt_out: !!telegramOptOut,
      })
      if (licenseInfo?.telegram_bot_enabled && !telegramOptOut) {
        setRegisteredSession(data); setRegisterStep('done')
      } else {
        setSession(data.access_token, data.role, data.permissions || [], !!data.internal_license_required, data.server_role || 'main')
        navigate(data.internal_license_required ? '/admin-license' : '/dashboard')
      }
    } catch (err) { setError(errorText(err)) } finally { setLoading(false) }
  }

  const toggleMode = () => {
    setRegisterMode(value => !value); setRegisterStep('license'); setLicenseInfo(null); setRegisteredSession(null)
    setTelegramUserId(''); setTelegramOptOut(false); setError(''); setPassword(''); setConfirmPassword('')
  }

  const passwordField = (confirm = false) => {
    if (confirm) {
      return <div className="login-password-shell"><Icon name="key" size={16} className="absolute start-3 top-1/2 z-[2] -translate-y-1/2 text-muted"/><input dir={dir} type={showConfirmPassword ? 'text' : 'password'} className="field login-password-input ps-9 font-data text-start" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} autoComplete="new-password" required /><button type="button" onClick={() => setShowConfirmPassword(v => !v)} className="login-password-toggle" aria-label={showConfirmPassword ? (lang === 'en' ? 'Hide password' : 'مخفی‌کردن رمز') : (lang === 'en' ? 'Show password' : 'نمایش رمز')}><Icon name={showConfirmPassword ? 'eyeOff' : 'eye'} size={17}/></button></div>
    }
    return <div className="login-password-shell"><Icon name="key" size={16} className="absolute start-3 top-1/2 z-[2] -translate-y-1/2 text-muted"/><input dir={dir} type={showPassword ? 'text' : 'password'} className="field login-password-input ps-9 font-data text-start" value={password} onChange={e => setPassword(e.target.value)} autoComplete={registerMode ? 'new-password' : 'current-password'} required /><button type="button" onClick={() => setShowPassword(v => !v)} className="login-password-toggle" aria-label={showPassword ? (lang === 'en' ? 'Hide password' : 'مخفی‌کردن رمز') : (lang === 'en' ? 'Show password' : 'نمایش رمز')}><Icon name={showPassword ? 'eyeOff' : 'eye'} size={17}/></button></div>
  }

  const formContent = () => {
    if (registerMode && registerStep === 'done') return <div className="space-y-4 text-center">
      <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-success/15 text-success"><Icon name="check" size={28}/></div>
      <div><h3 className="font-black">{lang === 'en' ? 'Account created successfully' : 'حساب با موفقیت ساخته شد'}</h3><p className="mt-2 text-xs leading-6 text-muted">{lang === 'en' ? 'Your Telegram access is active. Start the bot once, then continue to the panel.' : 'دسترسی ربات تلگرام برای آیدی شما فعال شد. یک‌بار ربات را Start کن و سپس وارد پنل شو.'}</p></div>
      {licenseInfo?.bot_link && <a href={licenseInfo.bot_link} target="_blank" rel="noreferrer" className="btn-primary flex w-full items-center justify-center gap-2 py-3"><Icon name="telegram" size={17}/>{licenseInfo.bot_username ? `@${licenseInfo.bot_username}` : (lang === 'en' ? 'Open Telegram bot' : 'بازکردن ربات تلگرام')}</a>}
      <button type="button" onClick={continueToPanel} className="btn-secondary w-full">{lang === 'en' ? 'Continue to panel' : 'ادامه و ورود به پنل'}</button>
    </div>

    if (registerMode && registerStep === 'license') return <form onSubmit={inspectLicense} className="app-card login-form-card p-5 sm:p-6">
      {error && <ErrorBox text={error}/>}<div className="space-y-4">
        <label className="block"><span className="field-label">{lang === 'en' ? 'Internal license' : 'لایسنس داخلی'}</span><div className="relative"><Icon name="license" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input dir="ltr" autoFocus className="field ps-9 font-data" value={licenseCode} onChange={e => setLicenseCode(e.target.value.replace(/[^A-Za-z0-9-]/g, ''))} placeholder="XXXXX-XXXXX-XXXXX-XXXXX" required /></div></label>
        <button disabled={loading} className="btn-primary w-full py-3">{loading ? (lang === 'en' ? 'Checking…' : 'در حال بررسی…') : (lang === 'en' ? 'Verify license' : 'بررسی لایسنس')}</button>
        <button type="button" onClick={toggleMode} className="btn-secondary w-full">{lang === 'en' ? 'Back to login' : 'بازگشت به ورود'}</button>
      </div>
    </form>

    return <form onSubmit={submit} className="app-card login-form-card p-5 sm:p-6">
      {error && <ErrorBox text={error}/>}<div className="space-y-4">
        <label className="block"><span className="field-label">{t('usernameFieldLabel')}</span><div className="relative"><Icon name="user" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input dir={dir} className="field ps-9 font-data text-start" value={username} onChange={e => setUsername(e.target.value)} autoFocus autoComplete="username" required /></div></label>
        <label className="block"><span className="field-label">{t('passwordFieldLabel')}</span>{passwordField(false)}</label>
        {registerMode && <><label className="block"><span className="field-label">{lang === 'en' ? 'Confirm password' : 'تکرار رمز عبور'}</span>{passwordField(true)}</label>
          {licenseInfo?.telegram_bot_enabled && <div className="space-y-3">
            <button
              type="button"
              role="switch"
              aria-checked={telegramOptOut}
              onClick={() => { setTelegramOptOut(v => !v); setTelegramUserId('') }}
              className={`telegram-optout-card ${telegramOptOut ? 'is-active' : ''}`}
            >
              <span className="telegram-optout-card__icon"><Icon name="telegram" size={20}/></span>
              <span className="telegram-optout-card__copy">
                <b>{lang === 'en' ? "I don't want Telegram bot access" : 'فعلاً ربات تلگرام نمی‌خواهم'}</b>
                <small>{lang === 'en' ? 'Create the panel account now and connect this license to Telegram later.' : 'حساب پنل الان ساخته می‌شود و بعداً می‌توانی همین لایسنس را به آیدی تلگرام خودت وصل کنی.'}</small>
              </span>
              <span className="telegram-optout-switch" aria-hidden="true">
                <span className="telegram-optout-switch__thumb">{telegramOptOut ? '✓' : ''}</span>
              </span>
            </button>
            {!telegramOptOut && <label className="block"><span className="field-label">{lang === 'en' ? 'Numeric Telegram user ID' : 'آیدی عددی تلگرام'}</span><div className="relative"><Icon name="telegram" size={16} className="absolute start-3 top-1/2 -translate-y-1/2 text-muted"/><input dir="ltr" inputMode="numeric" className="field ps-9 font-data" value={telegramUserId} onChange={e => setTelegramUserId(e.target.value.replace(/\D/g, ''))} placeholder="123456789" required /></div><p className="mt-1.5 text-[10px] leading-5 text-muted">{lang === 'en' ? 'This ID links your account to the private Telegram bot and applies the same panel permissions.' : 'این آیدی، حساب شما را به ربات خصوصی متصل می‌کند و همان دسترسی‌های لایسنس را اعمال می‌کند.'}</p></label>}
          </div>}
          <div className="rounded-xl border border-signal/25 bg-signal/5 px-3 py-2 text-[10px] text-muted"><span className="font-bold text-signal">{lang === 'en' ? 'Verified license' : 'لایسنس تأییدشده'}:</span> <span dir="ltr" className="font-data">{licenseCode}</span></div></>}
        <button disabled={loading} className="btn-primary mt-2 w-full py-3">{loading ? (registerMode ? (lang === 'en' ? 'Creating…' : 'در حال ثبت‌نام…') : t('loggingInBtn')) : (registerMode ? (lang === 'en' ? 'Create account' : 'ثبت‌نام') : t('loginBtn'))}</button>
        {registerMode && <button type="button" onClick={() => { setRegisterStep('license'); setLicenseInfo(null); setTelegramUserId(''); setTelegramOptOut(false); setError('') }} className="btn-secondary w-full">{lang === 'en' ? 'Change license' : 'تغییر لایسنس'}</button>}
        <button type="button" onClick={toggleMode} className="btn-secondary w-full">{registerMode ? (lang === 'en' ? 'Back to login' : 'بازگشت به ورود') : (lang === 'en' ? 'Register' : 'ثبت‌نام')}</button>
      </div>
    </form>
  }

  return <div dir={dir} className={`login-page relative min-h-screen overflow-hidden bg-bg text-ink ${showDesktopHero ? 'lg:grid lg:grid-cols-[1.05fr_.95fr]' : ''}`}>
    {!liteMobile && <Suspense fallback={null}><ParticleBackground density={0.000045}/><AuthWaveBackground /></Suspense>}{!liteMobile && <div className="login-aurora" aria-hidden="true" />}
    {showDesktopHero && <section className="login-hero relative z-10 hidden overflow-hidden border-e border-border lg:flex lg:flex-col lg:justify-between lg:p-12 xl:p-16">{branding.hero_image_url && <img src={branding.hero_image_url} alt="" className="login-hero-image" loading="lazy" decoding="async" />}<div className="login-hero-image-shade"/><div className="absolute -start-40 top-1/3 h-80 w-80 rounded-full bg-signal/10 blur-3xl"/>{(branding.logo_url || brandName) && <div className="relative z-10 flex items-center gap-3"><BrandMark logoUrl={branding.logo_url}/>{brandName && <BrandName value={brandName} className="login-hero-brand text-xl"/>}</div>}<div className="relative z-10 max-w-xl"><HeroShowcase logoUrl={branding.logo_url} brandName={brandName}/><div className="login-hero-badges mb-5 flex flex-wrap items-center gap-2">{heroBadge && <div className="inline-flex items-center gap-2 rounded-full border border-signal/25 bg-signal/10 px-3 py-1.5 text-[10px] font-bold uppercase tracking-[.18em] text-signal"><span className="h-1.5 w-1.5 rounded-full bg-signal orange-dot"/>{heroBadge}</div>}<div className="login-active-badge"><span className="login-active-badge__check">✓</span><span>{lang === 'en' ? 'Active' : 'فعال'}</span></div></div>{heroTitle && <h1 className="login-hero-title max-w-lg text-4xl font-black leading-[1.25] xl:text-5xl">{heroTitle}</h1>}{heroSubtitle && <p className="login-hero-subtitle mt-5 max-w-lg whitespace-pre-line text-sm leading-7">{heroSubtitle}</p>}</div>{heroFooter && <div className="login-hero-footer relative z-10 text-[10px]">{heroFooter}</div>}</section>}
    <section className={`relative z-10 flex min-h-screen items-center justify-center px-4 py-20 sm:px-8 ${showDesktopHero ? '' : 'mx-auto w-full max-w-3xl'}`}><div className="absolute end-4 top-4 flex items-center gap-2"><ThemeToggle/><LangToggle lang={lang} setLang={setLang} variant="icon" /></div><div className="w-full max-w-[420px]">{(branding.logo_url || brandName) && <div className="login-form-brand mb-7 flex items-center justify-center gap-3"><BrandMark logoUrl={branding.logo_url} size="large"/>{brandName && <BrandName value={brandName} className="text-xl"/>}</div>}<div className="mb-7"><div className="eyebrow">{t('loginPanelBadge')}</div><h2 className="mt-2 text-2xl font-black tracking-tight">{registerMode ? (lang === 'en' ? 'Create admin account' : 'ثبت‌نام ادمین') : t('loginTitle')}</h2><p className="mt-2 text-sm text-muted">{registerMode ? (lang === 'en' ? 'First verify your internal license, then create the account.' : 'ابتدا لایسنس داخلی را تأیید کن، سپس حساب را بساز.') : t('loginSubtitle')}</p></div>{formContent()}<div className="mt-5 flex min-h-5 items-center justify-center gap-2 text-[10px] text-muted"><Icon name="shield" size={13}/>{loginFooterNote && <span>{loginFooterNote}</span>}</div></div></section>
  </div>
}

function ErrorBox({ text }) { return <div className="status-danger mb-4 flex items-start gap-2 rounded-lg px-3 py-2.5 text-sm"><Icon name="warning" size={17} className="mt-0.5 shrink-0"/><span>{text}</span></div> }
function BrandName({ value, className = '' }) { const parts = String(value || '').trim().split(/\s+/); const tail = parts.length > 1 ? parts.pop() : ''; return <div className={`${className} whitespace-nowrap font-black tracking-wide`}>{parts.join(' ')}{parts.length && tail ? ' ' : ''}{tail ? <span className="text-signal">{tail}</span> : <span className="text-signal">{parts[0] || value}</span>}</div> }
function HeroShowcase({ logoUrl, brandName }) { return <div className="login-hero-showcase" aria-hidden="true"><div className="login-hero-showcase__glow"/><div className="login-hero-showcase__orbit login-hero-showcase__orbit--one"/><div className="login-hero-showcase__orbit login-hero-showcase__orbit--two"/><span className="login-hero-showcase__node node-a"/><span className="login-hero-showcase__node node-b"/><span className="login-hero-showcase__node node-c"/><div className="login-hero-showcase__core"><BrandMark logoUrl={logoUrl} size="hero"/></div><div className="login-hero-showcase__caption">{brandName || 'VPN PANEL'}</div></div> }
function BrandMark({ logoUrl, size = 'normal' }) { const sizeClass = size === 'hero' ? 'brand-mark--hero' : size === 'large' ? 'brand-mark--large' : ''; if (logoUrl) return <div className={`brand-mark ${sizeClass}`}><img src={logoUrl} alt="" className="brand-mark__image"/></div>; return <div className={`brand-mark ${sizeClass} text-signal`}><svg viewBox="0 0 48 48" className="brand-mark__svg" aria-hidden="true"><path d="M24 3 41 10v12c0 11-6.8 18.6-17 23C13.8 40.6 7 33 7 22V10L24 3Z" fill="none" stroke="currentColor" strokeWidth="3.2"/><path d="M24 13a7 7 0 0 0-4 12.7V35h8v-9.3A7 7 0 0 0 24 13Z" fill="none" stroke="currentColor" strokeWidth="3"/><circle cx="24" cy="20" r="1.8" fill="currentColor"/></svg></div> }
