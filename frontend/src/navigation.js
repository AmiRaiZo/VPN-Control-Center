export function navigateBrowser(to, options = {}) {
  if (typeof window === 'undefined') return
  if (typeof to === 'number') {
    window.history.go(to)
    return
  }
  const target = typeof to === 'string'
    ? to
    : `${to?.pathname || '/'}${to?.search || ''}${to?.hash || ''}`
  if (options?.replace) window.location.replace(target)
  else window.location.assign(target)
}

// Kept as a hook-shaped helper so component call sites stay simple, while
// deliberately avoiding React Router context for critical login/logout paths.
export function usePanelNavigate() {
  return navigateBrowser
}
