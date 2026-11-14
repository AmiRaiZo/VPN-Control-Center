#!/bin/bash
# Graceful classic-PPP handover: keep the old data path until the replacement
# pppd and interface are confirmed alive, then retire only the exact old PID.
set -u
[ "$(id -u)" -eq 0 ] || exit 0
OLD_PID="${1:-0}"
NEW_PID="${2:-0}"
OLD_IFACE="${3:-}"
NEW_IFACE="${4:-}"
[[ "$OLD_PID" =~ ^[0-9]+$ ]] || exit 0
[[ "$NEW_PID" =~ ^[0-9]+$ ]] || exit 0
[ "$OLD_PID" -gt 1 ] && [ "$NEW_PID" -gt 1 ] && [ "$OLD_PID" -ne "$NEW_PID" ] || exit 0

# Give the replacement hook time to finish central admission, route/NAT setup
# and tc limits. This overlap is deliberate and removes the visible traffic gap.
sleep 4

[ -r "/proc/${NEW_PID}/comm" ] || exit 0
[ "$(cat "/proc/${NEW_PID}/comm" 2>/dev/null)" = "pppd" ] || exit 0
if [ -n "$NEW_IFACE" ] && [ ! -d "/sys/class/net/${NEW_IFACE}" ]; then
  exit 0
fi
[ -r "/proc/${OLD_PID}/comm" ] || exit 0
[ "$(cat "/proc/${OLD_PID}/comm" 2>/dev/null)" = "pppd" ] || exit 0

# Do not cut an in-flight speed test/download. Watch the old interface for a
# short idle window; close it as soon as traffic has been quiet for ~6 seconds,
# with a hard upper bound of ~40 seconds so repeated modem retries cannot pile
# up stale PPP processes forever.
read_total() {
  local rx=0 tx=0
  [ -r "/sys/class/net/${OLD_IFACE}/statistics/rx_bytes" ] && rx=$(cat "/sys/class/net/${OLD_IFACE}/statistics/rx_bytes" 2>/dev/null || echo 0)
  [ -r "/sys/class/net/${OLD_IFACE}/statistics/tx_bytes" ] && tx=$(cat "/sys/class/net/${OLD_IFACE}/statistics/tx_bytes" 2>/dev/null || echo 0)
  echo $((rx + tx))
}
LAST=$(read_total)
IDLE=0
for _ in $(seq 1 20); do
  sleep 2
  [ -r "/proc/${NEW_PID}/comm" ] && [ "$(cat "/proc/${NEW_PID}/comm" 2>/dev/null)" = "pppd" ] || exit 0
  [ -r "/proc/${OLD_PID}/comm" ] && [ "$(cat "/proc/${OLD_PID}/comm" 2>/dev/null)" = "pppd" ] || exit 0
  NOW=$(read_total)
  if [ "$NOW" = "$LAST" ]; then
    IDLE=$((IDLE + 1))
    [ "$IDLE" -ge 3 ] && break
  else
    IDLE=0
    LAST="$NOW"
  fi
done

kill -TERM "$OLD_PID" 2>/dev/null || exit 0
logger -t vpn-panel-handover "retired old PPP after seamless handover old_pid=${OLD_PID} new_pid=${NEW_PID} old_iface=${OLD_IFACE:-unknown} new_iface=${NEW_IFACE:-unknown}"
exit 0
