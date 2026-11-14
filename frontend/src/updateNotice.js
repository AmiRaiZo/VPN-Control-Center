// هماهنگی نمایش پیام‌های مربوط به آپدیت پنل بین صفحات مختلف، از طریق
// sessionStorage - چون بعد از آپدیت موفق کل صفحه رفرش می‌شود (تا فایل‌های
// جدید frontend واقعاً بارگذاری شوند)، هر state‌ای که فقط داخل کامپوننت
// React نگه داشته شود با رفرش از بین می‌رود.

const SUCCESS_KEY = 'vpn_panel_update_success'
const DISMISSED_KEY = 'vpn_panel_update_dismissed_version'

// قبل از رفرش صفحه بعد از یک آپدیت موفق صدا زده می‌شود.
export function markUpdateSuccess({ version, notes } = {}) {
  try {
    sessionStorage.setItem(SUCCESS_KEY, JSON.stringify({ version: version || null, notes: notes || null }))
  } catch {
    // sessionStorage در دسترس نیست (مثلاً حالت خصوصی مرورگر) - مشکلی نیست، فقط پیام بعد از رفرش نمایش داده نمی‌شود
  }
}

// یک‌بار، در بارگذاری اولیه‌ی برنامه (بعد از رفرش) صدا زده می‌شود؛ اگر پیامی
// در انتظار بود، آن را برمی‌گرداند و فوراً پاک می‌کند (فقط یک‌بار نمایش داده شود).
export function consumeUpdateSuccess() {
  try {
    const raw = sessionStorage.getItem(SUCCESS_KEY)
    if (!raw) return null
    sessionStorage.removeItem(SUCCESS_KEY)
    return JSON.parse(raw)
  } catch {
    return null
  }
}

export function getDismissedVersion() {
  try {
    return sessionStorage.getItem(DISMISSED_KEY)
  } catch {
    return null
  }
}

export function setDismissedVersion(version) {
  try {
    sessionStorage.setItem(DISMISSED_KEY, version || '')
  } catch {
    // نادیده گرفته می‌شود
  }
}
