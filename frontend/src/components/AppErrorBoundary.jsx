import React from 'react'

const RELEASE_VERSION = '2.4.0'

async function clearFrontendCachesAndReload() {
  try {
    if ('caches' in window) {
      const keys = await window.caches.keys()
      await Promise.all(keys.map(key => window.caches.delete(key)))
    }
  } catch (_) {
    // Versioned assets are the primary cache guard; CacheStorage cleanup is best-effort.
  }
  const url = new URL(window.location.href)
  url.searchParams.set('__ui_retry', `${RELEASE_VERSION.replace(/\./g, '')}-${Date.now()}`)
  window.location.replace(url.toString())
}

export default class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    window.__VP_PANEL_BOOT_OK__ = false
    console.error('VPN Panel frontend error', error, info)
  }

  render() {
    if (!this.state.error) return this.props.children
    const message = this.state.error?.message || String(this.state.error || '')
    return (
      <main dir="rtl" role="alert" style={{ position: 'fixed', inset: 0, zIndex: 2147483647, overflow: 'auto', display: 'grid', placeItems: 'center', boxSizing: 'border-box', background: '#050608', color: '#f5f7fa', padding: 24, fontFamily: 'Noto Sans Arabic, Segoe UI, sans-serif' }}>
        <section style={{ width: 'min(560px, 100%)', border: '1px solid #2a2f38', borderRadius: 18, background: '#0d1015', padding: 24, boxShadow: '0 24px 80px rgba(0,0,0,.45)' }}>
          <h1 style={{ margin: 0, fontSize: 20 }}>رابط پنل کامل اجرا نشد</h1>
          <p style={{ margin: '12px 0 0', color: '#aeb6c2', lineHeight: 1.9, fontSize: 14 }}>
            به‌جای صفحه سیاه، خطای واقعی نمایش داده شده است. با دکمه زیر فایل یکپارچه نسخه {RELEASE_VERSION} بدون کش دوباره بارگذاری می‌شود.
          </p>
          <button
            type="button"
            onClick={clearFrontendCachesAndReload}
            style={{ width: '100%', marginTop: 18, border: 0, borderRadius: 12, background: '#ff6a00', color: '#fff', padding: '12px 16px', fontWeight: 800, cursor: 'pointer' }}
          >
            بارگذاری امن رابط
          </button>
          <pre style={{ marginTop: 14, color: '#7f8996', fontSize: 11, direction: 'ltr', textAlign: 'left', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{message}</pre>
        </section>
      </main>
    )
  }
}

export { RELEASE_VERSION, clearFrontendCachesAndReload }
