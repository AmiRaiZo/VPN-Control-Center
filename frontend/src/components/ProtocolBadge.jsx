import React from 'react'

const STYLES = {
  l2tp: { label: 'L2TP/IPsec', dot: 'bg-signal' },
  pptp: { label: 'PPTP', dot: 'bg-violet' },
  openvpn: { label: 'OpenVPN', dot: 'bg-amber' },
  sstp: { label: 'SSTP', dot: 'bg-danger' },
  ikev2: { label: 'IKEv2/IPsec', dot: 'bg-skyblue' },
  openconnect: { label: 'OpenConnect', dot: 'bg-success' },
  vmess: { label: 'VMess', dot: 'bg-violet' },
  vless: { label: 'VLESS', dot: 'bg-skyblue' },
}

export default function ProtocolBadge({ protocol }) {
  const s = STYLES[protocol] || { label: protocol, dot: 'bg-muted' }
  return (
    <span className="protocol-badge">
      <span aria-hidden="true" className={`protocol-badge__dot ${s.dot}`} />
      <span className="protocol-badge__label">{s.label}</span>
    </span>
  )
}
