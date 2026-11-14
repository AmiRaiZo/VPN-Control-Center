const UNITS = [
  ['TB', 1099511627776],
  ['GB', 1073741824],
  ['MB', 1048576],
  ['KB', 1024],
]

function formatNumber(value, maximumFractionDigits = 2) {
  return new Intl.NumberFormat('en-US', {
    useGrouping: false,
    minimumFractionDigits: 0,
    maximumFractionDigits,
  }).format(value)
}

/**
 * Format the exact integer byte counter returned by the backend.
 * Binary units are used consistently with quota accounting (1 GB = 1024^3).
 * Values below 1 GB keep two decimals instead of being rounded to a whole MB.
 */
export function formatBytes(bytes, maximumFractionDigits = 2) {
  const raw = Number(bytes)
  const safe = Number.isFinite(raw) ? Math.max(0, Math.trunc(raw)) : 0
  for (const [unit, size] of UNITS) {
    if (safe >= size) return `${formatNumber(safe / size, maximumFractionDigits)} ${unit}`
  }
  return `${safe} B`
}

export function exactBytesTitle(bytes) {
  const raw = Number(bytes)
  const safe = Number.isFinite(raw) ? Math.max(0, Math.trunc(raw)) : 0
  return `${new Intl.NumberFormat('en-US').format(safe)} bytes`
}
