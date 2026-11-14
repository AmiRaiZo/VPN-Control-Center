import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import axios from 'axios'

// عمداً از نمونه‌ی اصلی api.js استفاده نمی‌شود: آن یکی روی 401 کاربر را به
// /login می‌فرستد و توکن ادمین هم می‌فرستد، در حالی که این اندپوینت کاملاً
// عمومی است و باید حتی در صفحه‌ی ورود (قبل از هر لاگینی) هم کار کند.
const pub = axios.create({ baseURL: '/api' })

// این کامپوننت چیزی رندر نمی‌کند - فقط عنوان تب مرورگر را بر اساس صفحه‌ی
// فعلی (پنل ادمین/ورود در برابر صفحه‌ی عمومی «ساب») و عنوان‌های تنظیم‌شده در
// Settings > عنوان‌های سایت (یا مقدار پیش‌فرض قبلی، اگر هنوز چیزی ذخیره نشده)
// تنظیم می‌کند.
export default function TitleManager() {
  const location = useLocation()
  const titles = useRef(null)

  useEffect(() => {
    let alive = true
    pub.get('/meta/site-titles')
      .then(({ data }) => {
        if (!alive) return
        titles.current = data
        applyTitle()
      })
      .catch(() => { /* اگر گرفتنش شکست بخورد، همان عنوان استاتیک index.html می‌ماند */ })
    return () => { alive = false }
  }, [])

  const applyTitle = () => {
    if (!titles.current) return
    const isSub = location.pathname.startsWith('/sub/')
    document.title = isSub ? titles.current.sub_title : titles.current.panel_title
  }

  useEffect(() => { applyTitle() }, [location.pathname])

  return null
}
