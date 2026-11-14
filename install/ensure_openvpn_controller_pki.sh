#!/bin/bash
# Ensure one canonical OpenVPN EasyRSA PKI exists on the main controller.
# This installs only the OpenVPN/EasyRSA tooling when missing; it does not
# enable listeners, open firewall ports, or start OpenVPN on management-only
# controllers. Existing complete PKI material is preserved byte-for-byte.
set -Eeuo pipefail

MODE="${1:---generate-if-missing}"
EASYRSA_DIR="${EASYRSA_DIR:-/etc/openvpn/easy-rsa}"
SERVER_DIR="${OPENVPN_SERVER_DIR:-/etc/openvpn/server}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${EUID}" -ne 0 ]; then
  echo "This helper must run as root" >&2
  exit 1
fi

required_pki() {
  [ -s "$EASYRSA_DIR/pki/ca.crt" ] \
    && [ -s "$EASYRSA_DIR/pki/private/ca.key" ] \
    && [ -s "$EASYRSA_DIR/pki/issued/server.crt" ] \
    && [ -s "$EASYRSA_DIR/pki/private/server.key" ] \
    && [ -s "$EASYRSA_DIR/pki/dh.pem" ] \
    && [ -s "$EASYRSA_DIR/ta.key" ] \
    && [ -s "$EASYRSA_DIR/pki/crl.pem" ]
}

ensure_tools() {
  if command -v openvpn >/dev/null 2>&1 \
     && { command -v make-cadir >/dev/null 2>&1 || [ -x /usr/share/easy-rsa/easyrsa ]; }; then
    return 0
  fi
  [ -f "$SCRIPT_DIR/apt_preflight.sh" ] || {
    echo "OpenVPN/EasyRSA tools are missing and apt_preflight.sh was not found" >&2
    return 1
  }
  # shellcheck source=apt_preflight.sh
  source "$SCRIPT_DIR/apt_preflight.sh"
  vpn_panel_pause_apt_automation
  vpn_panel_wait_for_apt_lock 900 || {
    vpn_panel_restore_apt_automation || true
    return 1
  }
  vpn_panel_policy_rcd_enable
  if ! vpn_panel_apt_get update || ! vpn_panel_apt_get install openvpn easy-rsa; then
    vpn_panel_policy_rcd_disable || true
    vpn_panel_restore_apt_automation || true
    return 1
  fi
  vpn_panel_policy_rcd_disable
  vpn_panel_restore_apt_automation
}

ensure_pki_layout() {
  # Imported controller PKI snapshots contain files but cannot carry empty
  # directories. EasyRSA validates both the request directory and the CA
  # serial-certificate directory before issuing a client certificate. Restore
  # the complete standard skeleton, but never run init-pki over an existing CA.
  mkdir -p \
    "$EASYRSA_DIR/pki/issued" \
    "$EASYRSA_DIR/pki/reqs" \
    "$EASYRSA_DIR/pki/certs_by_serial" \
    "$EASYRSA_DIR/pki/inline" \
    "$EASYRSA_DIR/pki/expired" \
    "$EASYRSA_DIR/pki/revoked/certs_by_serial" \
    "$EASYRSA_DIR/pki/revoked/reqs_by_serial" \
    "$EASYRSA_DIR/pki/renewed/issued" \
    "$EASYRSA_DIR/pki/renewed/certs_by_serial" \
    "$EASYRSA_DIR/pki/private" \
    "$EASYRSA_DIR/pki/revoked/private_by_serial"
  chmod 0700 "$EASYRSA_DIR/pki/private" "$EASYRSA_DIR/pki/revoked/private_by_serial" 2>/dev/null || true
}

prepare_workspace() {
  if [ -x "$EASYRSA_DIR/easyrsa" ]; then
    ensure_pki_layout
    return 0
  fi
  mkdir -p "$(dirname "$EASYRSA_DIR")"
  rm -rf "$EASYRSA_DIR"
  if command -v make-cadir >/dev/null 2>&1; then
    make-cadir "$EASYRSA_DIR"
  elif [ -d /usr/share/easy-rsa ]; then
    cp -a /usr/share/easy-rsa "$EASYRSA_DIR"
  else
    echo "EasyRSA installation was not found" >&2
    return 1
  fi
  [ -x "$EASYRSA_DIR/easyrsa" ] || chmod +x "$EASYRSA_DIR/easyrsa" 2>/dev/null || true
  ensure_pki_layout
}

deploy_runtime_files() {
  mkdir -p "$SERVER_DIR" "$SERVER_DIR/ccd"
  install -m 0644 "$EASYRSA_DIR/pki/ca.crt" "$SERVER_DIR/ca.crt"
  install -m 0600 "$EASYRSA_DIR/pki/private/server.key" "$SERVER_DIR/server.key"
  install -m 0644 "$EASYRSA_DIR/pki/issued/server.crt" "$SERVER_DIR/server.crt"
  install -m 0644 "$EASYRSA_DIR/pki/dh.pem" "$SERVER_DIR/dh.pem"
  install -m 0644 "$EASYRSA_DIR/ta.key" "$SERVER_DIR/ta.key"
  install -m 0644 "$EASYRSA_DIR/pki/crl.pem" "$SERVER_DIR/crl.pem"
}

ensure_tools
if required_pki; then
  prepare_workspace
  deploy_runtime_files
  echo "[*] Canonical OpenVPN PKI already exists and its EasyRSA layout is healthy."
  exit 0
fi

if [ "$MODE" = "--prepare-only" ]; then
  prepare_workspace
  exit 0
fi

# Never silently destroy a partial PKI. Preserve it for forensic/manual recovery
# before generating the first canonical controller bundle.
if [ -e "$EASYRSA_DIR" ]; then
  backup="/var/backups/vpn-panel-openvpn-pki-incomplete-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$(dirname "$backup")"
  mv "$EASYRSA_DIR" "$backup"
  echo "[*] Incomplete OpenVPN PKI moved to $backup"
fi
prepare_workspace
cd "$EASYRSA_DIR"
cat > vars <<'VARS'
set_var EASYRSA_ALGO ec
set_var EASYRSA_DIGEST "sha512"
VARS
export EASYRSA_BATCH=1
./easyrsa init-pki
EASYRSA_REQ_CN="VPN-Panel-Shared-CA" ./easyrsa build-ca nopass
./easyrsa gen-req server nopass
./easyrsa --batch sign-req server server
./easyrsa gen-dh
openvpn --genkey secret ta.key 2>/dev/null || openvpn --genkey --secret ta.key
./easyrsa gen-crl

deploy_runtime_files
chmod 0600 "$EASYRSA_DIR/pki/private/ca.key" "$EASYRSA_DIR/pki/private/server.key" "$EASYRSA_DIR/ta.key"
echo "[*] Canonical OpenVPN PKI generated without starting any VPN listener."
