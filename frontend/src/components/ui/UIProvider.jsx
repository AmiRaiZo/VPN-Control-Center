import React, { createContext, useCallback, useContext, useRef, useState } from 'react'
import * as ReactDOM from 'react-dom'

/*
 * جایگزین بومی (با تمِ خودِ پنل) برای window.confirm / window.alert مرورگر، به‌علاوه
 * یک لودینگ‌اورلی مشترک برای وقتی پنل دارد یک عملیات (حذف، قطع اتصال، ذخیره‌ی
 * تنظیمات و ...) را روی سرور انجام می‌دهد. قبلاً هرکدام از این‌ها با پنجره‌ی
 * پیش‌فرض مرورگر (confirm/alert) نشان داده می‌شدند که نه با تمِ تیره‌ی پنل
 * هم‌خوان بودند و نه در موبایل تجربه‌ی خوبی داشتند.
 *
 * استفاده:
 *   const { confirm, notify, withBusy } = useUI()
 *   const ok = await confirm({ title: '...', message: '...', danger: true })
 *   notify({ type: 'error', message: '...' })
 *   await withBusy('در حال حذف...', async () => { await api.delete(...) })
 */

const UIContext = createContext(null)

export function useUI() {
  const ctx = useContext(UIContext)
  if (!ctx) throw new Error('useUI باید داخل UIProvider استفاده شود')
  return ctx
}

let toastId = 0

export function UIProvider({ children }) {
  const [confirmState, setConfirmState] = useState(null)
  const [toasts, setToasts] = useState([])
  const [busyLabel, setBusyLabel] = useState(null)
  const [busyDir, setBusyDir] = useState('rtl')
  const resolveRef = useRef(null)

  const confirm = useCallback((opts) => {
    return new Promise((resolve) => {
      resolveRef.current = resolve
      setConfirmState({
        title: opts.title || 'تایید عملیات',
        message: opts.message || '',
        confirmLabel: opts.confirmLabel || 'تایید',
        cancelLabel: opts.cancelLabel || 'انصراف',
        danger: !!opts.danger,
        dir: opts.dir || 'rtl',
      })
    })
  }, [])

  const closeConfirm = useCallback((result) => {
    setConfirmState(null)
    if (resolveRef.current) {
      resolveRef.current(result)
      resolveRef.current = null
    }
  }, [])

  const notify = useCallback(({ type = 'info', message, duration = 4500, dir = 'rtl' }) => {
    const id = ++toastId
    setToasts((t) => [...t, { id, type, message, dir }])
    setTimeout(() => {
      setToasts((t) => t.filter((x) => x.id !== id))
    }, duration)
  }, [])

  const dismissToast = useCallback((id) => {
    setToasts((t) => t.filter((x) => x.id !== id))
  }, [])

  const withBusy = useCallback(async (label, fn, opts = {}) => {
    setBusyLabel(label || 'در حال انجام عملیات...')
    setBusyDir(opts.dir || 'rtl')
    try {
      return await fn()
    } finally {
      setBusyLabel(null)
    }
  }, [])

  return (
    <UIContext.Provider value={{ confirm, notify, withBusy }}>
      {children}

      {ReactDOM.createPortal(
        <>
          {confirmState && (
            <div
              className="modal-backdrop global-ui-overlay"
              style={{ zIndex: 2147483645 }}
              onClick={() => closeConfirm(false)}
            >
              <div
                dir={confirmState.dir}
                className="modal-panel max-w-sm p-5 space-y-4 animate-[fadeIn_.15s_ease-out]"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`shrink-0 w-9 h-9 rounded-full flex items-center justify-center ${
                      confirmState.danger ? 'bg-danger/10 text-danger' : 'bg-signal/10 text-signal'
                    }`}
                  >
                    {confirmState.danger ? (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 9v4m0 4h.01M10.29 3.86l-8.18 14.18A2 2 0 0 0 3.82 21h16.36a2 2 0 0 0 1.71-3.96L13.71 3.86a2 2 0 0 0-3.42 0z" />
                      </svg>
                    ) : (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 16v-4m0-4h.01" />
                      </svg>
                    )}
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-bold text-ink">{confirmState.title}</div>
                    {confirmState.message && (
                      <div className="text-xs text-muted mt-1.5 leading-relaxed">{confirmState.message}</div>
                    )}
                  </div>
                </div>
                <div className="flex items-center justify-end gap-2 pt-1">
                  <button type="button" onClick={() => closeConfirm(false)} className="btn-secondary !px-3 !py-2 text-xs">
                    {confirmState.cancelLabel}
                  </button>
                  <button
                    type="button"
                    onClick={() => closeConfirm(true)}
                    className={confirmState.danger ? 'btn-danger !px-4 !py-2 text-xs' : 'btn-primary !px-4 !py-2 text-xs'}
                  >
                    {confirmState.confirmLabel}
                  </button>
                </div>
              </div>
            </div>
          )}

          {busyLabel && (
            <div className="modal-backdrop global-ui-overlay" style={{ zIndex: 2147483646 }}>
              <div dir={busyDir} className="modal-panel max-w-sm px-6 py-5 flex items-center gap-3">
                <span className="w-5 h-5 rounded-full border-2 border-border border-t-signal animate-spin" />
                <span className="text-sm text-ink font-data">{busyLabel}</span>
              </div>
            </div>
          )}
        </>,
        document.body,
      )}

      {ReactDOM.createPortal(
        <div
          className="global-toast-layer fixed bottom-4 end-4 z-[10000] flex flex-col gap-2 w-full max-w-sm px-4 pointer-events-none"
          style={{ zIndex: 2147483647 }}
          aria-live="polite"
          aria-atomic="false"
        >
          {toasts.map((t) => (
            <div
              key={t.id}
              dir={t.dir || 'rtl'}
              onClick={() => dismissToast(t.id)}
              className={`pointer-events-auto cursor-pointer rounded-xl border px-4 py-3 text-xs shadow-2xl backdrop-blur flex items-start gap-2 animate-[fadeIn_.15s_ease-out] ${
                t.type === 'error'
                  ? 'bg-danger/15 border-danger/40 text-danger'
                  : t.type === 'success'
                  ? 'bg-success/15 border-success/40 text-success'
                  : 'bg-surface2 border-border text-ink'
              }`}
            >
              <span className="flex-1 leading-relaxed">{t.message}</span>
            </div>
          ))}
        </div>,
        document.body,
      )}
    </UIContext.Provider>
  )
}
