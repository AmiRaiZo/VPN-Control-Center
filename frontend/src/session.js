// Session-only authentication: closing the browser/tab requires login again.
const TOKEN_KEY = 'vpn_panel_token'
const ROLE_KEY = 'vpn_panel_role'
const PERMISSIONS_KEY = 'vpn_panel_permissions'
const INTERNAL_LICENSE_REQUIRED_KEY = 'vpn_panel_internal_license_required'
const SERVER_ROLE_KEY = 'vpn_panel_server_role'
const REMOTE_CONTROL_KEY = 'vpn_panel_remote_control'
const REMOTE_NODE_NAME_KEY = 'vpn_panel_remote_node_name'

export function setSession(token, role, permissions, internalLicenseRequired = false, serverRole = 'main', remoteControl = false, remoteNodeName = '') {
  sessionStorage.setItem(TOKEN_KEY, token)
  sessionStorage.setItem(ROLE_KEY, role || '')
  sessionStorage.setItem(PERMISSIONS_KEY, JSON.stringify(permissions || []))
  sessionStorage.setItem(INTERNAL_LICENSE_REQUIRED_KEY, internalLicenseRequired ? '1' : '0')
  sessionStorage.setItem(SERVER_ROLE_KEY, serverRole === 'node' ? 'node' : 'main')
  if (remoteControl) {
    sessionStorage.setItem(REMOTE_CONTROL_KEY, '1')
    if (remoteNodeName) sessionStorage.setItem(REMOTE_NODE_NAME_KEY, remoteNodeName)
  } else {
    sessionStorage.removeItem(REMOTE_CONTROL_KEY)
    sessionStorage.removeItem(REMOTE_NODE_NAME_KEY)
  }
}

export function updateSessionPermissions(permissions) {
  sessionStorage.setItem(PERMISSIONS_KEY, JSON.stringify(permissions || []))
}
export function setServerRole(value) { sessionStorage.setItem(SERVER_ROLE_KEY, value === 'node' ? 'node' : 'main') }
export function getServerRole() { return sessionStorage.getItem(SERVER_ROLE_KEY) || 'main' }
export function isRemoteControlSession() { return sessionStorage.getItem(REMOTE_CONTROL_KEY) === '1' }
export function getRemoteNodeName() { return sessionStorage.getItem(REMOTE_NODE_NAME_KEY) || '' }
export function setInternalLicenseRequired(value) { sessionStorage.setItem(INTERNAL_LICENSE_REQUIRED_KEY, value ? '1' : '0') }
export function isInternalLicenseRequired() { return sessionStorage.getItem(INTERNAL_LICENSE_REQUIRED_KEY) === '1' }
export function getToken() { return sessionStorage.getItem(TOKEN_KEY) }
export function getRole() { return sessionStorage.getItem(ROLE_KEY) || '' }
export function getPermissionsRaw() {
  try { return JSON.parse(sessionStorage.getItem(PERMISSIONS_KEY) || '[]') }
  catch { return [] }
}
export function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY)
  sessionStorage.removeItem(ROLE_KEY)
  sessionStorage.removeItem(PERMISSIONS_KEY)
  sessionStorage.removeItem(INTERNAL_LICENSE_REQUIRED_KEY)
  sessionStorage.removeItem(SERVER_ROLE_KEY)
  sessionStorage.removeItem(REMOTE_CONTROL_KEY)
  sessionStorage.removeItem(REMOTE_NODE_NAME_KEY)
}
