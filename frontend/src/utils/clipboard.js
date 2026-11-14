export async function copyText(text) {
  const value = String(text || '')
  if (!value) return false
  try {
    if (navigator.clipboard?.writeText && window.isSecureContext) {
      await navigator.clipboard.writeText(value)
      return true
    }
  } catch {}

  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.inset = '-9999px auto auto -9999px'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  textarea.setSelectionRange(0, textarea.value.length)
  let ok = false
  try { ok = document.execCommand('copy') } catch {}
  textarea.remove()
  return ok
}

// Clipboard reads are intentionally stricter than writes in browsers. HTTPS
// can read directly; HTTP/IP panels fall back to the manual-paste dialog.
export async function readClipboardText() {
  try {
    if (navigator.clipboard?.readText && window.isSecureContext) {
      const value = await navigator.clipboard.readText()
      if (value) return String(value)
    }
  } catch {}

  try {
    const legacy = window.clipboardData?.getData?.('Text')
    if (legacy) return String(legacy)
  } catch {}

  // A few embedded/enterprise browsers still allow execCommand('paste').
  const textarea = document.createElement('textarea')
  textarea.style.position = 'fixed'
  textarea.style.inset = '-9999px auto auto -9999px'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.focus()
  try {
    const ok = document.execCommand?.('paste')
    if (ok && textarea.value) return textarea.value
  } catch {}
  textarea.remove()
  return null
}
