import axios from 'axios'
import { getToken, clearSession, setInternalLicenseRequired } from './session'

const api = axios.create({ baseURL: '/api' })

const INSTANT_CACHE_PREFIX = 'vpnpanel:instant:v23245:'
const CACHE_REFRESH_DELAY_MS = 1200
const CACHE_FRESH_WINDOW_MS = 15000
const CACHE_RECORD_LIMIT = 80
const instantRefreshTimers = new Map()
const memoryCache = new Map()
const inFlightGets = new Map()
let licenseRedirectCheck = null

async function confirmLicenseLockBeforeRedirect() {
  if (licenseRedirectCheck) return licenseRedirectCheck
  licenseRedirectCheck = (async () => {
    try {
      const token = getToken()
      const response = await axios.get('/api/license/status', {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        params: { _: Date.now() },
        timeout: 12000,
      })
      if (response?.data?.locked === true && window.location.pathname !== '/license-locked') {
        window.location.replace('/license-locked')
      }
    } catch (_) {
      // A failed confirmation is not proof that the license is invalid. The
      // backend grace window will enforce a real lock on the next reachable
      // response, while transient API/proxy failures no longer cause a loop.
    } finally {
      window.setTimeout(() => { licenseRedirectCheck = null }, 1500)
    }
  })()
  return licenseRedirectCheck
}

function sessionCacheNamespace() {
  const token = String(getToken() || 'anonymous')
  return token.slice(-32).replace(/[^a-zA-Z0-9_-]/g, '_')
}

function stableParams(params = {}) {
  return Object.entries(params || {})
    .filter(([key, value]) => !['_', 'fresh'].includes(key) && value !== undefined && value !== null)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join('&')
}

function instantCacheKey(url, config = {}) {
  const query = stableParams(config.params)
  return `${INSTANT_CACHE_PREFIX}${sessionCacheNamespace()}:${String(url)}${query ? `?${query}` : ''}`
}

function shouldInstantCache(url, config = {}) {
  const path = String(url || '')
  if (!getToken() || config.skipInstantCache || config.responseType || config.params?._ || config.params?.fresh) return false
  if (/^\/auth\/(?!me(?:\?|$))/.test(path)) return false
  if (/\/(?:update|jobs)(?:\/|$)/.test(path)) return false
  if (/\/(?:log|logs|check|health)(?:\/|$|\?)/.test(path)) return false
  if (/\/(?:agent-token|telegram-settings|node-ssh|node-controller)(?:\/|$|\?)/.test(path)) return false
  if (path.includes('/backup/export')) return false
  return true
}

function readInstantCache(key) {
  if (memoryCache.has(key)) return memoryCache.get(key)
  try {
    const parsed = JSON.parse(sessionStorage.getItem(key) || 'null')
    if (!parsed || typeof parsed !== 'object' || !Object.prototype.hasOwnProperty.call(parsed, 'data')) return null
    memoryCache.set(key, parsed)
    return parsed
  } catch (_) { return null }
}

function trimInstantCache() {
  try {
    const prefix = `${INSTANT_CACHE_PREFIX}${sessionCacheNamespace()}:`
    const records = []
    for (let index = 0; index < sessionStorage.length; index += 1) {
      const key = sessionStorage.key(index)
      if (!key?.startsWith(prefix)) continue
      const parsed = JSON.parse(sessionStorage.getItem(key) || 'null')
      records.push({ key, savedAt: Number(parsed?.savedAt || 0) })
    }
    records.sort((a, b) => b.savedAt - a.savedAt)
    records.slice(CACHE_RECORD_LIMIT).forEach(({ key }) => {
      sessionStorage.removeItem(key)
      memoryCache.delete(key)
    })
  } catch (_) {}
}

function writeInstantCache(key, response, freshForMs = 0) {
  const record = {
    data: response.data,
    status: response.status || 200,
    statusText: response.statusText || 'OK',
    headers: response.headers || {},
    savedAt: Date.now(),
    freshUntil: Date.now() + freshForMs,
  }
  memoryCache.set(key, record)
  try {
    sessionStorage.setItem(key, JSON.stringify(record))
    trimInstantCache()
  } catch (_) {}
  return record
}

function removeCacheKey(key) {
  const timer = instantRefreshTimers.get(key)
  if (timer) window.clearTimeout(timer)
  instantRefreshTimers.delete(key)
  memoryCache.delete(key)
  try { sessionStorage.removeItem(key) } catch (_) {}
}

function matchingMutationPrefixes(url) {
  const path = String(url || '').split('?')[0]
  const groups = [
    ['/users', ['/users', '/dashboard', '/ip-bans', '/internet-blocks']],
    ['/admins', ['/admins', '/auth/me', '/dashboard']],
    ['/nodes', ['/nodes', '/dashboard', '/users/server-targets', '/admins/server-targets', '/nodes/protocol-targets']],
    ['/settings', ['/settings', '/dashboard', '/auth/me']],
    ['/protocols', ['/protocols', '/settings/protocol', '/dashboard']],
    ['/license', ['/license', '/admins/licenses', '/auth/me', '/dashboard']],
    ['/ip-bans', ['/ip-bans', '/dashboard']],
    ['/internet-blocks', ['/internet-blocks', '/dashboard']],
    ['/backup', ['/backup', '/license/status']],
  ]
  const match = groups.find(([prefix]) => path.startsWith(prefix))
  if (match) return match[1]
  const firstSegment = path.match(/^\/[^/]+/)?.[0]
  return firstSegment ? [firstSegment, '/dashboard'] : ['/dashboard']
}

function invalidateInstantCache(url = '') {
  const prefixes = matchingMutationPrefixes(url)
  const namespace = `${INSTANT_CACHE_PREFIX}${sessionCacheNamespace()}:`
  const shouldRemove = (key) => prefixes.some((prefix) => key.includes(`:${prefix}`))
  try {
    for (let index = sessionStorage.length - 1; index >= 0; index -= 1) {
      const key = sessionStorage.key(index)
      if (key?.startsWith(namespace) && shouldRemove(key)) removeCacheKey(key)
    }
  } catch (_) {}
  Array.from(memoryCache.keys()).forEach((key) => {
    if (key.startsWith(namespace) && shouldRemove(key)) removeCacheKey(key)
  })
}

function clearInstantCache() {
  const namespace = `${INSTANT_CACHE_PREFIX}${sessionCacheNamespace()}:`
  try {
    for (let index = sessionStorage.length - 1; index >= 0; index -= 1) {
      const key = sessionStorage.key(index)
      if (key?.startsWith(namespace)) removeCacheKey(key)
    }
  } catch (_) {}
  Array.from(memoryCache.keys()).forEach((key) => {
    if (key.startsWith(namespace)) removeCacheKey(key)
  })
}

api.interceptors.request.use((config) => {
  const token = getToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => {
    const method = String(res.config?.method || 'get').toLowerCase()
    if (method !== 'get') invalidateInstantCache(res.config?.url || '')
    return res
  },
  (err) => {
    if (err.response?.status === 401) {
      const requestUrl = String(err.config?.url || '')
      const isCredentialAttempt = requestUrl.includes('/auth/login') || requestUrl.includes('/auth/register')
      if (!isCredentialAttempt) {
        clearInstantCache()
        clearSession()
        window.location.href = '/login'
      }
    }
    if (err.response?.status === 403 && err.response?.data?.detail === 'ip_banned') {
      clearInstantCache()
      clearSession()
      if (window.location.pathname !== '/login' || !window.location.search.includes('reason=ip_banned')) {
        window.location.replace('/login?reason=ip_banned')
      }
    }
    if (err.response?.status === 402 && err.response?.data?.detail === 'license_locked') {
      // Do not redirect on one stale/transient 402. Confirm through the exempt
      // license-status endpoint first; this prevents dashboard/lock-page loops.
      void confirmLicenseLockBeforeRedirect()
    }
    if (err.response?.status === 423 && err.response?.data?.detail === 'subadmin_license_required') {
      setInternalLicenseRequired(true)
      if (window.location.pathname !== '/admin-license') window.location.href = '/admin-license'
    }
    return Promise.reject(err)
  },
)

const networkGet = api.get.bind(api)

function cachedResponse(cached, config) {
  return {
    data: cached.data,
    status: cached.status || 200,
    statusText: cached.statusText || 'OK',
    headers: cached.headers || {},
    config,
    request: null,
    fromInstantCache: true,
  }
}

function performNetworkGet(url, config, key, freshForMs = 0) {
  if (inFlightGets.has(key)) return inFlightGets.get(key)
  const request = networkGet(url, config)
    .then((response) => {
      writeInstantCache(key, response, freshForMs)
      return response
    })
    .finally(() => inFlightGets.delete(key))
  inFlightGets.set(key, request)
  return request
}

api.get = (url, config = {}) => {
  if (!shouldInstantCache(url, config)) return networkGet(url, config)

  const key = instantCacheKey(url, config)
  const cached = readInstantCache(key)
  if (cached) {
    if (!config.prefetchOnly && !instantRefreshTimers.has(key) && Date.now() >= Number(cached.freshUntil || 0)) {
      const refreshConfig = { ...config, skipInstantCache: true }
      const routePath = window.location.pathname
      delete refreshConfig.signal
      delete refreshConfig.prefetchOnly
      const delay = Number.isFinite(Number(config.instantRefreshDelayMs)) ? Math.max(0, Number(config.instantRefreshDelayMs)) : CACHE_REFRESH_DELAY_MS
      const timer = window.setTimeout(async () => {
        instantRefreshTimers.delete(key)
        try {
          const previousJson = JSON.stringify(cached.data)
          const response = await networkGet(url, refreshConfig)
          const next = writeInstantCache(key, response, CACHE_FRESH_WINDOW_MS)
          // Cache is refreshed silently. The active route is never remounted;
          // this preserves scroll position, open rows, filters, and form state.
          void previousJson
          void next
        } catch (_) {}
      }, delay)
      instantRefreshTimers.set(key, timer)
    }
    return Promise.resolve(cachedResponse(cached, config))
  }

  return performNetworkGet(url, config, key, Number(config.instantFreshForMs || 0))
}

api.prefetch = (requests = []) => {
  const items = Array.isArray(requests) ? requests : [requests]
  return Promise.allSettled(items.map((item) => {
    if (typeof item === 'string') return api.get(item, { prefetchOnly: true })
    return api.get(item.url, { ...(item.config || {}), prefetchOnly: true })
  }))
}

api.clearInstantCache = clearInstantCache
api.invalidateInstantCache = invalidateInstantCache

export default api
