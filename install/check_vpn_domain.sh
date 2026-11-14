#!/bin/bash
###############################################################################
# Called by the panel backend when the admin sets a "VPN protocols domain"
# under Settings (separate from the panel's own Domain & SSL). Unlike
# setup_domain_ssl.sh, this does NOT touch Nginx or request a certificate —
# L2TP/PPTP/OpenVPN are not HTTP(S) protocols, so no SSL cert is needed here.
# It only confirms the domain's A record resolves to this server's real IP,
# to catch the common mistake of pointing it at a proxied/CDN record (e.g. a
# Cloudflare "proxied" orange-cloud record only forwards HTTP(S) — L2TP/PPTP/
# OpenVPN traffic aimed at it will just time out).
#
# Usage: check_vpn_domain.sh <domain>
###############################################################################
set -e

DOMAIN="$1"
ENV_FILE="/opt/vpn-panel/backend/.env"

if [ -z "$DOMAIN" ]; then
  echo "Usage: check_vpn_domain.sh <domain>" >&2
  exit 1
fi

SERVER_IP=""
if [ -f "$ENV_FILE" ]; then
  SERVER_IP=$(grep -E '^PUBLIC_SERVER_IP=' "$ENV_FILE" | cut -d= -f2-)
fi
if ! [[ "$SERVER_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  SERVER_IP=""
fi
if [ -z "$SERVER_IP" ]; then
  for _url in "https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org"; do
    _try=$(curl -s -f -4 --max-time 5 "$_url" 2>/dev/null | tr -d '[:space:]')
    if [[ "$_try" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      SERVER_IP="$_try"
      break
    fi
  done
fi

RESOLVED_IP=$(getent hosts "$DOMAIN" | awk '{print $1}' | head -n1)
if [ -z "$RESOLVED_IP" ]; then
  RESOLVED_IP=$(dig +short A "$DOMAIN" 2>/dev/null | tail -n1)
fi

if [ -z "$RESOLVED_IP" ]; then
  echo "DNS_ERROR: could not resolve any A record for ${DOMAIN} yet. Point an A record at ${SERVER_IP} and wait for DNS to propagate, then try again." >&2
  exit 1
fi

if [ -n "$SERVER_IP" ] && [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
  echo "DNS_ERROR: ${DOMAIN} currently resolves to ${RESOLVED_IP}, but this server's IP is ${SERVER_IP}. If you're using Cloudflare or another CDN, make sure the record is DNS-only (grey cloud), not proxied — proxied records forward web traffic only and VPN protocols will silently fail to connect. Fix the record and try again." >&2
  exit 1
fi

echo "VPN_DOMAIN_OK ${DOMAIN}"
