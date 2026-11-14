#!/bin/bash
# Disable the dedicated VMess/VLESS subscription hostname without deleting
# its Let's Encrypt certificate, so it can be enabled again later.
set -e
SITE_FILE="/etc/nginx/sites-available/vpn-panel-xray-sub"
SITE_LINK="/etc/nginx/sites-enabled/vpn-panel-xray-sub"
rm -f "$SITE_LINK" "$SITE_FILE"
if command -v nginx >/dev/null 2>&1; then
  nginx -t
  systemctl is-active --quiet nginx && systemctl reload nginx || true
fi
echo "XRAY_SUB_DOMAIN_DISABLED"
