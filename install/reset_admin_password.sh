#!/bin/bash
###############################################################################
# Reset (or create) a panel admin account directly from SSH — useful when
# you're locked out of the web panel.
#
# Usage: sudo bash /opt/vpn-panel/scripts/reset_admin_password.sh <username> <new_password>
#
# If <username> already exists, its password is updated. Otherwise a new
# superadmin account with that username is created.
###############################################################################
set -e

USERNAME="$1"
PASSWORD="$2"

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
  echo "Usage: reset_admin_password.sh <username> <new_password>" >&2
  exit 1
fi

cd /opt/vpn-panel/backend
source venv/bin/activate
python3 -m app.init_admin "$USERNAME" "$PASSWORD"
deactivate

systemctl restart vpn-panel-api
echo "Done. You can now log in to the panel with username '${USERNAME}'."
