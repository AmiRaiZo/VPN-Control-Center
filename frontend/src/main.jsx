import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import AppErrorBoundary from './components/AppErrorBoundary.jsx'
import { UIProvider } from './components/ui/UIProvider.jsx'
import './index.css'


// Use the strict compositor budget only on mobile/coarse or low-resource
// devices. Capable desktop browsers keep the full visual treatment.
const LOW_POWER_DEVICE = (() => {
  try {
    return window.matchMedia('(max-width: 767px), (pointer: coarse), (prefers-reduced-motion: reduce)').matches
      || navigator.connection?.saveData === true
      || Number(navigator.deviceMemory || 8) <= 4
      || Number(navigator.hardwareConcurrency || 8) <= 4
  } catch (_) { return false }
})()
document.documentElement.dataset.performance = LOW_POWER_DEVICE ? 'lite' : 'full'

const PERSIAN_DIGITS = '۰۱۲۳۴۵۶۷۸۹'
const ARABIC_DIGITS = '٠١٢٣٤٥٦٧٨٩'
function normalizeNumericText(value) {
  return String(value ?? '')
    .replace(/[۰-۹]/g, (char) => String(PERSIAN_DIGITS.indexOf(char)))
    .replace(/[٠-٩]/g, (char) => String(ARABIC_DIGITS.indexOf(char)))
    .replace(/٫/g, '.')
    .replace(/٬/g, '')
    .replace(/−/g, '-')
}

function installNumericInputCompatibility() {
  const nativeValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
  const prepare = (input) => {
    if (!(input instanceof HTMLInputElement) || input.type !== 'number') return false
    input.dir = 'ltr'
    input.inputMode = input.step && String(input.step).includes('.') ? 'decimal' : 'numeric'
    return true
  }
  document.addEventListener('focusin', (event) => prepare(event.target), true)
  document.addEventListener('beforeinput', (event) => {
    const input = event.target
    if (!prepare(input) || !event.data) return
    const normalized = normalizeNumericText(event.data)
    if (normalized === event.data) return
    event.preventDefault()
    const next = `${input.value || ''}${normalized}`
    if (nativeValueSetter) nativeValueSetter.call(input, next)
    else input.value = next
    input.dispatchEvent(new Event('input', { bubbles: true }))
  }, true)
  document.addEventListener('change', (event) => {
    const input = event.target
    if (!prepare(input)) return
    const normalized = normalizeNumericText(input.value)
    if (normalized !== input.value) {
      if (nativeValueSetter) nativeValueSetter.call(input, normalized)
      else input.value = normalized
      input.dispatchEvent(new Event('input', { bubbles: true }))
    }
  }, true)
}
installNumericInputCompatibility()
window.__VP_PANEL_ENTRY_LOADED__ = true
window.__VP_PANEL_ENTRY_RELEASE__ = '24000'

function markPanelBooted() {
  window.__VP_PANEL_BOOT_OK__ = true
  try {
    const url = new URL(window.location.href)
    if (url.searchParams.has('__ui_retry')) {
      url.searchParams.delete('__ui_retry')
      window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`)
    }
  } catch (_) {}
  const overlay = document.getElementById('vpnpanel-recovery-overlay')
  if (overlay) overlay.remove()
}

try {
  const rootElement = document.getElementById('root')
  if (!rootElement) throw new Error('VPN Panel root element is missing')

  // Production intentionally avoids StrictMode's development-only double mount.
  // A single deterministic mount is safer for polling pages and browser refreshes.
  // Keep exactly one React root even if a browser extension retries the entry script.
  if (window.__VP_PANEL_REACT_ROOT__ && window.__VP_PANEL_REACT_ROOT_RELEASE__ !== '24000') {
    try { window.__VP_PANEL_REACT_ROOT__.unmount() } catch (_) {}
    rootElement.replaceChildren()
    window.__VP_PANEL_REACT_ROOT__ = null
  }
  const root = window.__VP_PANEL_REACT_ROOT__ || ReactDOM.createRoot(rootElement)
  window.__VP_PANEL_REACT_ROOT__ = root
  window.__VP_PANEL_REACT_ROOT_RELEASE__ = '24000'
  root.render(
    <BrowserRouter>
      <AppErrorBoundary>
        <UIProvider>
          <App />
        </UIProvider>
      </AppErrorBoundary>
    </BrowserRouter>,
  )

  window.requestAnimationFrame(() => window.setTimeout(markPanelBooted, 0))
} catch (error) {
  if (typeof window.__vpnpanelFrontendFailed === 'function') {
    window.__vpnpanelFrontendFailed(error)
  }
  throw error
}
