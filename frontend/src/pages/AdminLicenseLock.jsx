import React, { useEffect, useState } from 'react'
import { usePanelNavigate } from '../navigation.js'
import api from '../api'
import { clearSession, setInternalLicenseRequired, updateSessionPermissions } from '../session'
import { useLang } from '../i18n/dashboardLang.jsx'
import { Icon } from '../components/icons.jsx'
import ParticleBackground from '../components/ParticleBackground.jsx'

export default function AdminLicenseLock() {
  const { dir, lang } = useLang()
  const fa = lang !== 'en'
  const navigate = usePanelNavigate()
  const [code, setCode] = useState('')
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.get('/admins/my-license').then(({ data }) => {
      setStatus(data)
      if (!data.locked) {
        setInternalLicenseRequired(false)
        navigate('/dashboard', { replace: true })
      }
    }).catch(() => {})
  }, [])

  const submit = async (event) => {
    event.preventDefault(); setError(''); setLoading(true)
    try {
      const { data } = await api.post('/admins/my-license/activate', { license_code: code })
      updateSessionPermissions(data.permissions || [])
      setInternalLicenseRequired(false)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(err.response?.data?.detail || (fa ? 'فعال‌سازی لایسنس ناموفق بود.' : 'License activation failed.'))
    } finally { setLoading(false) }
  }

  const logout = () => { clearSession(); navigate('/login', { replace: true }) }

  return <div dir={dir} className="relative flex min-h-screen items-center justify-center overflow-hidden bg-bg px-4 py-12 text-ink">
    <ParticleBackground density={0.000045}/>
    <div className="login-aurora" aria-hidden="true" />
    <div className="app-card relative z-10 w-full max-w-lg p-6 sm:p-8">
      <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-signal/30 bg-signal/10 text-signal"><Icon name="license" size={25}/></div>
      <h1 className="mt-5 text-center text-2xl font-black">{fa ? 'تمدید دسترسی ادمین' : 'Renew admin access'}</h1>
      <p className="mt-2 text-center text-sm leading-7 text-muted">{fa ? 'اشتراک این حساب پایان یافته است. یک لایسنس داخلی جدید وارد کنید؛ کاربران و تنظیمات باقی می‌مانند و محدودیت‌های طرح جدید جایگزین طرح قبلی می‌شوند.' : 'This account subscription has expired. Enter a new internal license; users and settings remain while the new plan replaces the old one.'}</p>
      {status?.max_users != null && <div className="mt-4 rounded-xl border border-border bg-surface2 p-3 text-xs text-muted">{fa ? 'سقف قبلی کاربران' : 'Previous user limit'}: <b className="text-ink">{status.max_users}</b></div>}
      {error && <div className="status-danger mt-4 rounded-lg px-3 py-2.5 text-sm">{error}</div>}
      <form onSubmit={submit} className="mt-5 space-y-4">
        <label className="block"><span className="field-label">{fa ? 'کد لایسنس جدید' : 'New license code'}</span><input dir="ltr" className="field font-data" value={code} onChange={(e) => setCode(e.target.value.replace(/[^A-Za-z0-9-]/g, ''))} placeholder="XXXXX-XXXXX-XXXXX-XXXXX" required /></label>
        <button disabled={loading} className="btn-primary w-full py-3">{loading ? (fa ? 'در حال فعال‌سازی…' : 'Activating…') : (fa ? 'فعال‌سازی لایسنس' : 'Activate license')}</button>
      </form>
      <button onClick={logout} className="btn-secondary mt-3 w-full">{fa ? 'خروج از حساب' : 'Sign out'}</button>
    </div>
  </div>
}
