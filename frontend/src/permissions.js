import { getRole as getSessionRole, getPermissionsRaw, getServerRole, isRemoteControlSession } from './session'

export function getRole() { return getSessionRole() }
export function getPermissions() { return getPermissionsRaw() }
export { getServerRole }

export function hasPermission(token, legacySection = null) {
  if (getRole() === 'superadmin') return true
  const permissions = getPermissions()
  if (permissions.includes(token)) return true
  const section = legacySection || token.split(':')[0]
  if (permissions.includes(section)) return true
  if (!token.includes(':') && permissions.some((p) => p.startsWith(`${token}:`))) return true
  return false
}

export function hasSection(section) { return hasPermission(section) }
export function hasProtocol(protocol) {
  if (getRole() === 'superadmin') return true
  const permissions = getPermissions()
  if (permissions.includes('settings')) return true
  const scoped = permissions.filter((p) => p.startsWith('protocol:'))
  return !scoped.length || scoped.includes(`protocol:${protocol}`)
}

export function nodeRoleAllowsPath(path) {
  if (getServerRole() !== 'node' || isRemoteControlSession()) return true
  return ['/admins', '/settings'].includes(path)
}

export function firstAllowedPath() {
  if (getServerRole() === 'node') return isRemoteControlSession() ? '/dashboard' : '/admins'
  const order = ['dashboard', 'users', 'online', 'bans', 'license', 'protocols', 'settings', 'nodes']
  const section = order.find((s) => hasSection(s))
  const map = { bans: '/banned-ips', license: '/license', protocols: '/protocols', nodes: '/nodes' }
  return section ? (map[section] || `/${section}`) : '/login'
}
