import React, { createContext, useContext, useEffect, useRef, useState } from 'react'
import { useLang } from '../i18n/dashboardLang.jsx'

// -----------------------------------------------------------------------
// تم پنل (روشن/تیره/سیستم). مثل زبان، انتخاب کاربر در localStorage نگه
// داشته می‌شود. یک اسکریپت کوچک هم در index.html همین کلید را قبل از رندر
// اول می‌خواند تا کلاس درست (light/dark) زودتر از رنگی‌شدن صفحه روی
// <html> نشسته باشد و پرش رنگ (FOUC) نداشته باشیم؛ این هوک فقط از همان‌جا
// به بعد state ری‌اکت را با همان وضعیت هماهنگ نگه می‌دارد.
// -----------------------------------------------------------------------
export const THEME_KEY = 'vpnpanel_theme'

const THEME_STRINGS = {
  fa: { light: 'روشن', dark: 'تیره', system: 'سیستم', label: 'تغییر تم' },
  en: { light: 'Light', dark: 'Dark', system: 'System', label: 'Change theme' },
}

export const ThemeContext = createContext({ theme: 'dark', resolvedTheme: 'dark', setTheme: () => {} })

export function useTheme() {
  return useContext(ThemeContext)
}

function systemPrefersLight() {
  try { return window.matchMedia('(prefers-color-scheme: light)').matches } catch { return false }
}

function applyThemeClass(resolved) {
  try {
    document.documentElement.classList.remove('light', 'dark')
    document.documentElement.classList.add(resolved)
  } catch { /* ignore */ }
}

export function useThemeState() {
  const [theme, setThemeState] = useState(() => {
    try {
      const v = localStorage.getItem(THEME_KEY)
      return v === 'light' || v === 'dark' || v === 'system' ? v : 'dark'
    } catch { return 'dark' }
  })
  const [resolvedTheme, setResolvedTheme] = useState(() => (theme === 'system' ? (systemPrefersLight() ? 'light' : 'dark') : theme))

  const setTheme = (t) => {
    setThemeState(t)
    try { localStorage.setItem(THEME_KEY, t) } catch { /* ignore */ }
  }

  // هر بار انتخاب تم عوض شد، کلاس روی <html> و state حل‌شده به‌روز شود.
  useEffect(() => {
    const resolved = theme === 'system' ? (systemPrefersLight() ? 'light' : 'dark') : theme
    setResolvedTheme(resolved)
    applyThemeClass(resolved)
  }, [theme])

  // اگر روی «سیستم» باشیم، با تغییر تم سیستم‌عامل هم زنده به‌روز شود.
  useEffect(() => {
    if (theme !== 'system') return undefined
    let mql
    try { mql = window.matchMedia('(prefers-color-scheme: light)') } catch { return undefined }
    const onChange = () => {
      const resolved = mql.matches ? 'light' : 'dark'
      setResolvedTheme(resolved)
      applyThemeClass(resolved)
    }
    if (mql.addEventListener) mql.addEventListener('change', onChange)
    else mql.addListener(onChange)
    return () => {
      if (mql.removeEventListener) mql.removeEventListener('change', onChange)
      else mql.removeListener(onChange)
    }
  }, [theme])

  return { theme, resolvedTheme, setTheme }
}

// ---- آیکن‌ها ----
function SunIcon(props) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </svg>
  )
}
function MoonIcon(props) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z" />
    </svg>
  )
}
function MonitorIcon(props) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <rect x="2" y="4" width="20" height="13" rx="2" />
      <path d="M8 21h8M12 17v4" />
    </svg>
  )
}

const THEME_OPTIONS = [
  { code: 'light', Icon: SunIcon },
  { code: 'dark', Icon: MoonIcon },
  { code: 'system', Icon: MonitorIcon },
]

// دکمه‌ی دایره‌ای کوچک (مثل انتخاب زبان) که با کلیک یک دراپ‌داون با سه
// گزینه‌ی روشن/تیره/سیستم باز می‌کند - آیکن روی دکمه همیشه تم واقعی که
// الان اعمال شده را نشان می‌دهد (اگر «سیستم» انتخاب شده، خورشید یا ماه
// بسته به نتیجه‌ی حل‌شده نمایش داده می‌شود).
export function ThemeToggle() {
  const { theme, resolvedTheme, setTheme } = useTheme()
  const { lang } = useLang()
  const strings = THEME_STRINGS[lang] || THEME_STRINGS.fa
  const [open, setOpen] = useState(false)
  const wrapRef = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    const onClickOutside = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false)
    }
    const onEsc = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onClickOutside)
    document.addEventListener('keydown', onEsc)
    return () => {
      document.removeEventListener('mousedown', onClickOutside)
      document.removeEventListener('keydown', onEsc)
    }
  }, [open])

  const CurrentIcon = resolvedTheme === 'light' ? SunIcon : MoonIcon

  return (
    <div ref={wrapRef} className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={strings.label}
        title={strings.label}
        className="w-8 h-8 flex items-center justify-center bg-surface2 border border-border rounded-full text-muted hover:text-ink hover:border-signal/50 transition-colors"
      >
        <CurrentIcon />
      </button>

      {open && (
        <div
          role="listbox"
          className="absolute z-50 mt-1.5 min-w-[8.5rem] end-0 bg-surface border border-border rounded-lg shadow-lg overflow-hidden py-1"
        >
          {THEME_OPTIONS.map(({ code, Icon }) => (
            <button
              key={code}
              type="button"
              role="option"
              aria-selected={code === theme}
              onClick={() => { setTheme(code); setOpen(false) }}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-bold text-start transition-colors ${
                code === theme ? 'text-signal bg-signal/10' : 'text-ink hover:bg-surface2'
              }`}
            >
              <Icon className="shrink-0" />
              <span>{strings[code]}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
