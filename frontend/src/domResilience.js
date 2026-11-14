// React owns the DOM below #root. Browser translation engines and a few
// accessibility/password-manager extensions may move or wrap those nodes.
// React then receives a stale parent/reference and the native DOM API throws
// NotFoundError (removeChild/insertBefore). This guard preserves the operation's
// intent instead of crashing the entire application.
export function installDomMutationResilience(targetWindow = typeof window !== 'undefined' ? window : null) {
  const NodeCtor = targetWindow?.Node
  const proto = NodeCtor?.prototype
  if (!proto || proto.__vpnpanelDomMutationResilience) return false

  const nativeRemoveChild = proto.removeChild
  const nativeInsertBefore = proto.insertBefore
  const nativeReplaceChild = proto.replaceChild
  const nativeAppendChild = proto.appendChild

  Object.defineProperty(proto, '__vpnpanelDomMutationResilience', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: true,
  })

  proto.removeChild = function vpnPanelSafeRemoveChild(child) {
    if (!child) return child
    if (child.parentNode === this) return nativeRemoveChild.call(this, child)

    // A translator/extension may have moved the exact node into a wrapper.
    // Remove it from its real parent so React's requested end state is kept.
    const actualParent = child.parentNode
    if (actualParent) {
      try { return nativeRemoveChild.call(actualParent, child) } catch (_) {}
    }

    // Already detached is equivalent to a completed removal.
    return child
  }

  proto.insertBefore = function vpnPanelSafeInsertBefore(newNode, referenceNode) {
    if (!referenceNode || referenceNode.parentNode !== this) {
      // A stale/moved reference cannot define a valid position. Appending keeps
      // the new React node in the correct parent and avoids a fatal NotFoundError.
      return nativeAppendChild.call(this, newNode)
    }
    return nativeInsertBefore.call(this, newNode, referenceNode)
  }

  proto.replaceChild = function vpnPanelSafeReplaceChild(newChild, oldChild) {
    if (oldChild?.parentNode === this) {
      return nativeReplaceChild.call(this, newChild, oldChild)
    }

    const actualParent = oldChild?.parentNode
    if (actualParent) {
      try { nativeRemoveChild.call(actualParent, oldChild) } catch (_) {}
    }
    return nativeAppendChild.call(this, newChild)
  }

  return true
}
