import React, { lazy, Suspense, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import TitleManager from './components/TitleManager.jsx'
import { hasSection, hasPermission, getRole, firstAllowedPath, nodeRoleAllowsPath } from './permissions.js'
import { getToken, isInternalLicenseRequired } from './session'
import { LangContext, useLangState } from './i18n/dashboardLang.jsx'
import { ThemeContext, useThemeState } from './theme/themeContext.jsx'
import { BrandingProvider } from './branding.jsx'

const Layout = lazy(() => import('./components/Layout.jsx'))
const Login = lazy(() => import('./pages/Login.jsx'))
const SubPage = lazy(() => import('./pages/SubPage.jsx'))
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'))
const Users = lazy(() => import('./pages/Users.jsx'))
const OnlineUsers = lazy(() => import('./pages/OnlineUsers.jsx'))
const BannedIPs = lazy(() => import('./pages/BannedIPs.jsx'))
const InternetBlocks = lazy(() => import('./pages/InternetBlocks.jsx'))
const Settings = lazy(() => import('./pages/Settings.jsx'))
const Admins = lazy(() => import('./pages/Admins.jsx'))
const TelegramBot = lazy(() => import('./pages/TelegramBot.jsx'))
const LicenseLockPage = lazy(() => import('./pages/LicenseLockPage.jsx'))
const License = lazy(() => import('./pages/License.jsx'))
const Nodes = lazy(() => import('./pages/Nodes.jsx'))
const AdminLicenseLock = lazy(() => import('./pages/AdminLicenseLock.jsx'))
const Protocols = lazy(() => import('./pages/Protocols.jsx'))
const Backup = lazy(() => import('./pages/Backup.jsx'))

const routeChunkWarmers = [
  () => import('./pages/Dashboard.jsx'),
  () => import('./pages/Users.jsx'),
  () => import('./pages/OnlineUsers.jsx'),
  () => import('./pages/InternetBlocks.jsx'),
  () => import('./pages/BannedIPs.jsx'),
  () => import('./pages/Admins.jsx'),
  () => import('./pages/Nodes.jsx'),
  () => import('./pages/Protocols.jsx'),
  () => import('./pages/Settings.jsx'),
  () => import('./pages/License.jsx'),
  () => import('./pages/Backup.jsx'),
  () => import('./pages/TelegramBot.jsx'),
]

function useIdleRouteChunkWarmup() {
  useEffect(() => {
    if (!getToken() || document.visibilityState === 'hidden') return undefined
    let cancelled = false
    let timer = null
    let idle = null
    let index = 0
    const next = () => {
      if (cancelled || document.visibilityState === 'hidden' || index >= routeChunkWarmers.length) return
      const load = routeChunkWarmers[index++]
      Promise.resolve(load()).catch(() => {}).finally(() => {
        if (!cancelled) timer = window.setTimeout(next, 70)
      })
    }
    const start = () => { if (!cancelled) timer = window.setTimeout(next, 350) }
    if (typeof window.requestIdleCallback === 'function') idle = window.requestIdleCallback(start, { timeout: 1200 })
    else timer = window.setTimeout(start, 700)
    return () => {
      cancelled = true
      if (timer !== null) window.clearTimeout(timer)
      if (idle !== null && typeof window.cancelIdleCallback === 'function') window.cancelIdleCallback(idle)
    }
  }, [])
}

function RouteFallback() {
  const english = typeof document !== 'undefined' && document.documentElement.lang === 'en'
  return (
    <div className="route-fallback" role="status" aria-live="polite">
      <span className="route-fallback__dot" aria-hidden="true" />
      <span>{english ? 'Loading panel interface…' : 'در حال بارگذاری رابط پنل…'}</span>
    </div>
  )
}

function RequireAuth({ children }) {
  const token = getToken()
  if (!token) return <Navigate to="/login" replace />
  return children
}

function RequireUnlocked({ children }) {
  if (isInternalLicenseRequired()) return <Navigate to="/admin-license" replace />
  return children
}

function RequireSection({ section, children }) {
  if (!hasSection(section)) return <Navigate to={firstAllowedPath()} replace />
  return children
}

function RequirePermission({ permission, children }) {
  if (!hasPermission(permission)) return <Navigate to={firstAllowedPath()} replace />
  return children
}

function RequireServerPath({ path, children }) {
  if (!nodeRoleAllowsPath(path)) return <Navigate to={firstAllowedPath()} replace />
  return children
}

function RequireSuperadmin({ children }) {
  if (getRole() !== 'superadmin') return <Navigate to={firstAllowedPath()} replace />
  return children
}

export default function App() {
  useIdleRouteChunkWarmup()
  const { lang, setLang, dir, t } = useLangState()
  const { theme, resolvedTheme, setTheme } = useThemeState()

  return (
    <ThemeContext.Provider value={{ theme, resolvedTheme, setTheme }}>
    <LangContext.Provider value={{ lang, setLang, dir, t }}>
    <BrandingProvider>
      <TitleManager />
      <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/sub/:token" element={<SubPage />} />
        <Route path="/license-locked" element={<LicenseLockPage />} />
        <Route path="/admin-license" element={<RequireAuth><AdminLicenseLock /></RequireAuth>} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <RequireUnlocked><Layout /></RequireUnlocked>
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to={firstAllowedPath()} replace />} />
          <Route path="dashboard" element={<RequireServerPath path="/dashboard"><RequireSection section="dashboard"><Dashboard /></RequireSection></RequireServerPath>} />
          <Route path="users" element={<RequireServerPath path="/users"><RequireSection section="users"><Users /></RequireSection></RequireServerPath>} />
          <Route path="online" element={<RequireServerPath path="/online"><RequireSection section="online"><OnlineUsers /></RequireSection></RequireServerPath>} />
          <Route path="internet-blocks" element={<RequireServerPath path="/internet-blocks"><RequirePermission permission="internet_blocks:view"><InternetBlocks /></RequirePermission></RequireServerPath>} />
          <Route path="banned-ips" element={<RequireServerPath path="/banned-ips"><RequireSection section="bans"><BannedIPs /></RequireSection></RequireServerPath>} />
          <Route path="admins" element={<RequireServerPath path="/admins"><RequireSuperadmin><Admins /></RequireSuperadmin></RequireServerPath>} />
          <Route path="license" element={<RequireServerPath path="/license"><RequireSuperadmin><License /></RequireSuperadmin></RequireServerPath>} />
          <Route path="backup" element={<RequireServerPath path="/backup"><RequireSuperadmin><Backup /></RequireSuperadmin></RequireServerPath>} />
          <Route path="telegram-bot" element={<RequireServerPath path="/telegram-bot"><TelegramBot /></RequireServerPath>} />
          <Route path="nodes" element={<RequireServerPath path="/nodes"><RequireSection section="nodes"><Nodes /></RequireSection></RequireServerPath>} />
          <Route path="protocols" element={<RequireServerPath path="/protocols"><RequireSection section="protocols"><Protocols /></RequireSection></RequireServerPath>} />
          <Route path="settings" element={<RequireServerPath path="/settings"><RequireSection section="settings"><Settings /></RequireSection></RequireServerPath>} />
        </Route>
        <Route path="*" element={<Navigate to={firstAllowedPath()} replace />} />
      </Routes>
      </Suspense>
    </BrandingProvider>
    </LangContext.Provider>
    </ThemeContext.Provider>
  )
}
