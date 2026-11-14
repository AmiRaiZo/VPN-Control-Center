import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import axios from 'axios'

const CACHE_KEY = 'vpnpanel_public_branding_v2'
const DEFAULTS = {
  hero_enabled: true,
  brand_name: null,
  hero_badge: null,
  hero_title: null,
  hero_subtitle: null,
  hero_footer: null,
  login_footer_note: '',
  logo_url: null,
  hero_image_url: null,
  has_logo: false,
  has_hero_image: false,
}

function cachedBranding() {
  try {
    const value = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null')
    return value && typeof value === 'object' ? { ...DEFAULTS, ...value } : DEFAULTS
  } catch {
    return DEFAULTS
  }
}

const BrandingContext = createContext({ branding: DEFAULTS, refreshBranding: async () => {} })
const pub = axios.create({ baseURL: '/api', timeout: 7000 })


const DEFAULT_FAVICON = '/favicon.svg'

function ensureDocumentLink(id, rel) {
  let link = document.getElementById(id)
  if (!link) {
    link = document.createElement('link')
    link.id = id
    link.rel = rel
    document.head.appendChild(link)
  }
  return link
}

function ensureDocumentMeta(name) {
  let meta = document.head.querySelector(`meta[name="${name}"]`)
  if (!meta) {
    meta = document.createElement('meta')
    meta.name = name
    document.head.appendChild(meta)
  }
  return meta
}

function applyDocumentBranding(branding) {
  // The uploaded panel logo used to be rendered only inside React. Mobile
  // browsers therefore kept showing the generic globe in the tab/header.
  // Replacing the actual document icon links makes the same uploaded logo the
  // favicon immediately, while the versioned URL from the API busts cache.
  const iconUrl = branding?.logo_url || DEFAULT_FAVICON
  const links = [
    ensureDocumentLink('vpnpanel-favicon', 'icon'),
    ensureDocumentLink('vpnpanel-shortcut-icon', 'shortcut icon'),
    ensureDocumentLink('vpnpanel-apple-touch-icon', 'apple-touch-icon'),
  ]
  links.forEach(link => {
    if (link.getAttribute('href') !== iconUrl) link.setAttribute('href', iconUrl)
  })

  const appName = String(branding?.brand_name || 'VPN Panel').trim() || 'VPN Panel'
  ensureDocumentMeta('application-name').content = appName
  ensureDocumentMeta('apple-mobile-web-app-title').content = appName
}

export function BrandingProvider({ children }) {
  const [branding, setBranding] = useState(cachedBranding)

  const refreshBranding = async () => {
    const { data } = await pub.get('/meta/branding')
    const next = { ...DEFAULTS, ...data }
    setBranding(next)
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(next)) } catch { /* storage may be disabled */ }
    return next
  }

  useEffect(() => { refreshBranding().catch(() => {}) }, [])
  useEffect(() => { applyDocumentBranding(branding) }, [branding.logo_url, branding.brand_name])
  const value = useMemo(() => ({ branding, refreshBranding }), [branding])
  return <BrandingContext.Provider value={value}>{children}</BrandingContext.Provider>
}

export function useBranding() {
  return useContext(BrandingContext)
}
