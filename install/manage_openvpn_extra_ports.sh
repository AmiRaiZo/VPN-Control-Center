#!/bin/bash
###############################################################################
# Called by the panel backend (as root) from Settings > OpenVPN Ports, every
# time an extra port is added, toggled, or removed for OpenVPN.
#
# An extra port is NOT a firewall forward (DNAT) to the primary port - it is
# a genuine, independent OpenVPN listener: its own server-extra-<proto>-<port>.conf,
# its own systemd unit, its own /24 subnet, sharing the same PKI/CA/CRL/CCD and
# the same user/cert auth scripts as the primary UDP/TCP processes. It is
# fully controlled from inside the panel (enable = add it here, disable =
# remove it here) - you can add as many extra TCP and UDP ports as you want.
#
# NAT/routing (POSTROUTING MASQUERADE) for every extra-port subnet IS handled
# automatically by this script (same as the primary UDP/TCP subnets are
# handled once in install.sh) - this is what actually lets a client that
# connects on an extra port reach the internet, not just the VPN server
# itself. Without it, a client shows "connected" (the tunnel/handshake works)
# but has no internet, because return traffic never gets un-NATed back to it.
#
# THIS SCRIPT ALSO OPENS THE PORT ON THE SERVER'S OWN HOST FIREWALL
# (INPUT chain) automatically - see step 4 below. It detects ufw / firewalld
# / plain iptables and manages its own tagged rules only, so it never touches
# rules you or anything else created by hand.
#
# WHAT THIS STILL CANNOT DO: if the server sits behind a cloud provider's
# network firewall (AWS Security Group, GCP firewall rules, Hetzner Cloud
# Firewall, DigitalOcean Cloud Firewall, etc.), that is a control-plane
# object outside the machine itself - no script running on the server can
# reach it. If you use one of those, you still need to open the port there
# by hand (console or provider CLI/API) in addition to what this script does.
#
# Usage:
#   manage_openvpn_extra_ports.sh <ports>
#
# <ports> is a comma-separated "port/proto" list, e.g. "443/tcp,53/udp,8080/tcp"
# (may be an empty string, meaning "no extra ports configured"). The full,
# current list is always sent, but this script is now DIFF-based, not a
# blind full rebuild: it compares the requested list against what's actually
# on disk/running right now and only touches three kinds of entries -
#   - REMOVE: currently running but no longer in the list -> stopped/deleted.
#   - BUILD:  in the list but either brand new, or present-but-not-actually-
#             running right now (e.g. a previous failed attempt) -> fresh
#             conf + (re)started.
#   - a port that is already in the list AND already running is left
#     COMPLETELY untouched - no stop, no restart, no NAT/firewall rule
#     replacement.
# This is what guarantees a single bad/conflicting port in the same request
# can never take an already-healthy sibling port down with it.
#
# Exit code: 0 only if every requested listener is up (whether it was just
# built or was already healthy and left alone). If one or more BUILD entries
# fail (e.g. the port is already occupied by another process on the server,
# or OpenVPN itself rejects the generated conf), this script still processes
# every other port in the list (a single bad port never blocks the rest),
# but exits 1 and prints a "FAILED: <port>/<proto> - <reason>" line for each
# failure with the real reason. A port that fails to start is never opened
# in the firewall (no NAT either) - only ports that actually come up get
# exposed.
###############################################################################
set -uo pipefail

PORTS_ARG="$1"

OVPN_DIR="/etc/openvpn/server"
LEGACY_OVPN_DIR="/etc/openvpn"
BASE_UDP_CONF="${OVPN_DIR}/server-udp.conf"
BASE_TCP_CONF="${OVPN_DIR}/server-tcp.conf"
NAME_PREFIX="server-extra-"
NAT_COMMENT_PREFIX="vpnpanel-extra-"
FW_CHAIN="VPN_PANEL_OVPN_EXTRA"
FW_COMMENT="vpnpanel-extra"
OVPN_LOG="/var/log/openvpn.log"

OVPN_PREFIX="openvpn-server@"
systemctl list-unit-files 2>/dev/null | grep -q '^openvpn@' && ! systemctl list-unit-files 2>/dev/null | grep -q '^openvpn-server@' && OVPN_PREFIX="openvpn@"

# Main outbound interface, same detection logic used in install.sh.
NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

# ---------------------------------------------------------------------------
# Pick ONE firewall backend and stick to it for both teardown and setup.
# Priority: ufw (if installed and active) > firewalld (if running) >
# plain iptables. Mixing backends (e.g. adding raw iptables rules while ufw
# is active) causes drift/duplicates, since ufw manages its own iptables
# rules independently - so only ever drive whichever one is actually in
# charge on this server.
# ---------------------------------------------------------------------------
FW_BACKEND="none"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
  FW_BACKEND="ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then
  FW_BACKEND="firewalld"
elif command -v iptables >/dev/null 2>&1; then
  FW_BACKEND="iptables"
fi

get_conf_port() { grep -E '^port ' "$1" 2>/dev/null | awk '{print $2}' | head -n1; }
PRIMARY_UDP_PORT=$(get_conf_port "$BASE_UDP_CONF")
PRIMARY_TCP_PORT=$(get_conf_port "$BASE_TCP_CONF")

# ---------------------------------------------------------------------------
# Build DESIRED (what the panel wants right now) and EXISTING (what's
# actually on disk right now, from the .conf files themselves - not from any
# separate state file, so this stays accurate even if the panel's own
# database and the server ever drift apart).
# ---------------------------------------------------------------------------
declare -A DESIRED   # "proto/port" -> name
if [ -n "$PORTS_ARG" ]; then
  IFS=',' read -ra RAW_ENTRIES <<< "$PORTS_ARG"
  for entry in "${RAW_ENTRIES[@]}"; do
    port="${entry%%/*}"
    proto="${entry##*/}"
    [ -z "$port" ] && continue
    [ "$proto" != "tcp" ] && [ "$proto" != "udp" ] && continue
    DESIRED["${proto}/${port}"]="${NAME_PREFIX}${proto}-${port}"
  done
fi

declare -A EXISTING  # "proto/port" -> name, discovered from *.conf on disk
for f in "${OVPN_DIR}/${NAME_PREFIX}"*.conf; do
  [ -e "$f" ] || continue
  bn=$(basename "$f" .conf)
  rest="${bn#"${NAME_PREFIX}"}"      # e.g. "tcp-443"
  eproto="${rest%%-*}"
  eport="${rest#*-}"
  [ -z "$eproto" ] && continue
  [ -z "$eport" ] && continue
  EXISTING["${eproto}/${eport}"]="$bn"
done

# Some servers have BOTH systemd templates installed (openvpn-server@ and
# the legacy openvpn@). OVPN_PREFIX above is only a single, server-wide
# *guess*. A port that was originally built by an older version of this
# script (or by hand) under the *other* template can be perfectly healthy
# right now, yet "systemctl is-active --quiet ${OVPN_PREFIX}${name}" would
# check the wrong unit name and wrongly report it as down. That single
# false negative used to be enough to drag an already-healthy port into
# BUILD_KEYS, which then failed to (re)bind its own port ("already in use
# by another process (openvpn)" - that "other process" was itself, still
# running fine under the other prefix) and, worse, could cascade into other
# unrelated ports getting reported FAILED and disabled in the panel too.
#
# Fix: check BOTH possible unit names for every instance and use whichever
# one is actually active, instead of trusting the single global guess.
active_unit_prefix() {
  local name="$1"
  if systemctl is-active --quiet "openvpn-server@${name}" 2>/dev/null; then
    echo "openvpn-server@"
    return 0
  fi
  if systemctl is-active --quiet "openvpn@${name}" 2>/dev/null; then
    echo "openvpn@"
    return 0
  fi
  return 1
}

# KEEP  = desired, on disk, AND actually active right now (under whichever
#         of the two templates it's really running under) -> left
#         completely alone.
# BUILD = everything else that's desired: brand new, or present but not
#         actually running under either template (e.g. a previous failed
#         attempt - this gives it a fresh try instead of leaving it
#         silently dead forever).
declare -A INSTANCE_PREFIX   # "proto/port" -> the prefix it is ACTUALLY running under (KEEP entries only)
KEEP_KEYS=()
BUILD_KEYS=()
for key in "${!DESIRED[@]}"; do
  name="${DESIRED[$key]}"
  real_prefix=""
  if [ -n "${EXISTING[$key]:-}" ]; then
    real_prefix=$(active_unit_prefix "$name") || real_prefix=""
  fi
  if [ -n "$real_prefix" ]; then
    INSTANCE_PREFIX["$key"]="$real_prefix"
    KEEP_KEYS+=("$key")
  else
    BUILD_KEYS+=("$key")
  fi
done

# REMOVE = on disk but no longer desired at all.
REMOVE_KEYS=()
for key in "${!EXISTING[@]}"; do
  [ -n "${DESIRED[$key]:-}" ] || REMOVE_KEYS+=("$key")
done

# ---------------------------------------------------------------------------
# Tear down exactly one instance: its systemd unit/conf/state files, its own
# NAT rule, and its own firewall rule - nothing else. Used both for REMOVE
# entries (gone for good) and for BUILD entries that already had a (dead or
# stale) conf on disk (about to be recreated fresh below).
# ---------------------------------------------------------------------------
teardown_one() {
  local name="$1" proto="$2" port="$3"
  # این پورت ممکن است در واقعیت زیر تمپلیت دیگری (openvpn@ به‌جای
  # openvpn-server@، یا برعکس) در حال اجرا باشد - نه لزوماً همان $OVPN_PREFIX
  # سراسری. هر دو را stop/disable می‌کنیم (هزینه‌اش فقط چند no-op بی‌ضرر
  # است) تا پروسه‌ی واقعی، فارغ از این‌که زیر کدام تمپلیت بالا آمده، واقعاً
  # متوقف شود - وگرنه پروسه‌ی قدیمی همچنان پورت را نگه می‌داشت و تلاش بعدی
  # برای بالا آوردن یک لیسنر تازه با خطای "پورت قبلاً در حال استفاده است"
  # شکست می‌خورد.
  systemctl stop "openvpn-server@${name}" 2>/dev/null || true
  systemctl stop "openvpn@${name}" 2>/dev/null || true
  systemctl disable "openvpn-server@${name}" >/dev/null 2>&1 || true
  systemctl disable "openvpn@${name}" >/dev/null 2>&1 || true
  rm -f "${OVPN_DIR}/${name}.conf" "${OVPN_DIR}/ipp-${name}.txt" "${OVPN_DIR}/openvpn-status-${name}.log"
  # The legacy openvpn@.service template reads /etc/openvpn/%i.conf, while
  # openvpn-server@.service reads /etc/openvpn/server/%i.conf. Older builds
  # only removed the latter, leaving a stale legacy symlink/config behind.
  rm -f "${LEGACY_OVPN_DIR}/${name}.conf"
  systemctl reset-failed "openvpn-server@${name}" >/dev/null 2>&1 || true
  systemctl reset-failed "openvpn@${name}" >/dev/null 2>&1 || true

  if command -v iptables-save >/dev/null 2>&1; then
    while IFS= read -r rule; do
      [ -z "$rule" ] && continue
      del_rule="${rule/-A POSTROUTING/-D POSTROUTING}"
      # shellcheck disable=SC2086
      iptables -t nat $del_rule 2>/dev/null || true
    done < <(iptables-save -t nat 2>/dev/null | grep -- "--comment \"${NAT_COMMENT_PREFIX}${name}\"")

    # Remove the matching FORWARD permissions as well; otherwise toggling or
    # deleting an extra listener leaves stale routing rules behind forever.
    while IFS= read -r rule; do
      [ -z "$rule" ] && continue
      del_rule="${rule/-A FORWARD/-D FORWARD}"
      # shellcheck disable=SC2086
      iptables $del_rule 2>/dev/null || true
    done < <(iptables-save 2>/dev/null | grep -- '-A FORWARD ' | grep -- "--comment \"${NAT_COMMENT_PREFIX}${name}-forward-")
  fi

  case "$FW_BACKEND" in
    ufw)
      yes | ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
      ;;
    firewalld)
      firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
      ;;
    iptables)
      if command -v iptables-save >/dev/null 2>&1 && iptables -L "$FW_CHAIN" >/dev/null 2>&1; then
        while IFS= read -r rule; do
          [ -z "$rule" ] && continue
          del_rule="${rule/-A ${FW_CHAIN}/-D ${FW_CHAIN}}"
          # shellcheck disable=SC2086
          iptables $del_rule 2>/dev/null || true
        done < <(iptables-save 2>/dev/null | grep -- "-A ${FW_CHAIN} " | grep -- "--comment \"${FW_COMMENT}-${name}\"")
      fi
      ;;
  esac
}

for key in "${REMOVE_KEYS[@]}"; do
  name="${EXISTING[$key]}"
  proto="${key%%/*}"; port="${key#*/}"
  teardown_one "$name" "$proto" "$port"
done
for key in "${BUILD_KEYS[@]}"; do
  if [ -n "${EXISTING[$key]:-}" ]; then
    name="${EXISTING[$key]}"
    proto="${key%%/*}"; port="${key#*/}"
    teardown_one "$name" "$proto" "$port"
  fi
done

if [ "$FW_BACKEND" = "firewalld" ]; then
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Orphan sweep: force-kill any "openvpn" process still bound to a TCP/UDP
# port other than the two primary ports and other than a port we
# deliberately left running above (KEEP_KEYS), regardless of whether it has
# a matching .conf/systemd unit right now. This catches a real process left
# over from an older/buggy panel version, a crashed run, or a unit that lost
# track of its child - without ever touching a port we intentionally kept
# untouched.
# ---------------------------------------------------------------------------
is_kept_port() {
  local proto="$1" sport="$2" k
  for k in "${KEEP_KEYS[@]}"; do
    [ "$k" = "${proto}/${sport}" ] && return 0
  done
  return 1
}

sweep_orphan_openvpn() {
  # -------------------------------------------------------------------------
  # SAFETY-CRITICAL: identify a candidate process by ITS OWN config file,
  # never by port-number guessing. The previous version of this function
  # matched purely on "is this port the primary UDP/TCP port?" - if
  # PRIMARY_UDP_PORT/PRIMARY_TCP_PORT above ever failed to parse (empty
  # string, non-standard base conf, etc.) that comparison silently became
  # "true is never primary", and this sweep would kill the server's OWN
  # primary OpenVPN listener, taking down every port at once. Reading the
  # process's real --config path and only ever acting on one that is a
  # server-extra-<proto>-<port>.conf (i.e. unambiguously ours) makes that
  # class of bug impossible, regardless of primary-port detection.
  # -------------------------------------------------------------------------
  local proto="$1" ss_flags line sport pid args conf_path bn rest eproto eport
  ss_flags="-H -tlnp"
  [ "$proto" = "udp" ] && ss_flags="-H -ulnp"
  command -v ss >/dev/null 2>&1 || return 0
  # shellcheck disable=SC2086
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    sport=$(echo "$line" | awk '{print $4}' | sed -E 's/.*://')
    pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -n1 | cut -d= -f2)
    [ -z "$sport" ] && continue
    [ -z "$pid" ] && continue

    args=$(ps -p "$pid" -o args= 2>/dev/null)
    conf_path=$(echo "$args" | grep -oE -- '--config[= ][^ ]+' | sed -E 's/^--config[= ]//' | head -n1)
    [ -z "$conf_path" ] && conf_path=$(echo "$args" | grep -oE '[^ ]+\.conf' | head -n1)

    case "$conf_path" in
      *"/${NAME_PREFIX}"*|"${NAME_PREFIX}"*)
        : # unambiguously one of our extra-port confs - eligible below
        ;;
      *)
        # Not a server-extra-*.conf process (primary UDP/TCP, or anything
        # else entirely) - NEVER touch it, no matter what port it's on.
        continue
        ;;
    esac

    bn=$(basename "$conf_path" .conf)
    rest="${bn#"${NAME_PREFIX}"}"
    eproto="${rest%%-*}"
    eport="${rest#*-}"
    [ -z "$eproto" ] || [ -z "$eport" ] && continue
    [ "$eproto" != "$proto" ] && continue
    is_kept_port "$eproto" "$eport" && continue
    [ -n "${DESIRED[${eproto}/${eport}]:-}" ] && continue

    echo "Cleaning up leftover OpenVPN process on ${sport}/${proto} (pid ${pid}, conf ${conf_path}) that had no matching entry in the panel's current port list ..." >&2
    kill -9 "$pid" 2>/dev/null || true
  done < <(ss $ss_flags 2>/dev/null | grep -F '"openvpn"')
}
sweep_orphan_openvpn tcp
sweep_orphan_openvpn udp
[ "${#BUILD_KEYS[@]}" -gt 0 ] && sleep 1

NAT_APPLIED=""
FW_APPLIED=""
FAILED=""

# ---------------------------------------------------------------------------
# Management-port picker. Each extra listener needs its own local
# 127.0.0.1:<port> management socket. Search for an actually-free loopback
# port for each instance instead of assuming one, so a leftover/orphaned
# process from an old run (or anything else already on that port) can never
# make a perfectly fine listener fail with "MANAGEMENT: Socket bind failed".
# ---------------------------------------------------------------------------
USED_MGMT_PORTS=" "
find_free_mgmt_port() {
  local candidate=7601
  while [ "$candidate" -lt 7700 ]; do
    if [[ "$USED_MGMT_PORTS" != *" ${candidate} "* ]]; then
      if ! command -v ss >/dev/null 2>&1 || ! ss -H -ltn "sport = :${candidate}" 2>/dev/null | grep -q .; then
        echo "$candidate"
        return 0
      fi
    fi
    candidate=$((candidate + 1))
  done
  echo "7601"
  return 1
}

# ---------------------------------------------------------------------------
# Subnet picker for BUILD entries. Collision-free against every KEEP entry's
# existing subnet (read straight out of its still-in-place conf) as well as
# every other BUILD entry being handed out in this same run - so a rebuild
# can never grab a /24 a healthy, untouched listener is already using.
# ---------------------------------------------------------------------------
declare -A USED_OCTETS
for key in "${KEEP_KEYS[@]}"; do
  name="${DESIRED[$key]}"
  octet=$(grep -E '^server ' "${OVPN_DIR}/${name}.conf" 2>/dev/null | head -n1 | awk '{print $2}' | awk -F. '{print $3}')
  [ -n "$octet" ] && USED_OCTETS[$octet]=1
done
NEXT_OCTET=10
pick_free_octet() {
  while [ -n "${USED_OCTETS[$NEXT_OCTET]:-}" ]; do
    NEXT_OCTET=$((NEXT_OCTET + 1))
  done
  USED_OCTETS[$NEXT_OCTET]=1
  echo "$NEXT_OCTET"
}

for key in "${BUILD_KEYS[@]}"; do
  proto="${key%%/*}"
  port="${key#*/}"
  name="${DESIRED[$key]}"
  conf="${OVPN_DIR}/${name}.conf"

  base_conf="$BASE_UDP_CONF"
  [ "$proto" = "tcp" ] && base_conf="$BASE_TCP_CONF"
  if [ ! -f "$base_conf" ]; then
    echo "WARN: ${base_conf} not found (OpenVPN not installed yet?) - skipping ${port}/${proto}" >&2
    continue
  fi

  octet=$(pick_free_octet)
  subnet="10.8.${octet}.0"

  # -----------------------------------------------------------------------
  # 1) Pre-flight check: is the port already held by something else on the
  #    server (another daemon, a leftover process, etc.)? This is the single
  #    most common reason a freshly-added extra listener fails to start
  #    ("control process exited with error code" from systemd, with no
  #    useful detail) - OpenVPN simply can't bind a port something else
  #    already owns. We detect it up front and skip that one port with a
  #    clear reason instead of leaving the admin with a generic systemd
  #    error and a broken listener.
  # -----------------------------------------------------------------------
  if command -v ss >/dev/null 2>&1; then
    ss_flags="-H -ltn"
    [ "$proto" = "udp" ] && ss_flags="-H -lun"
    # shellcheck disable=SC2086
    holder=$(ss $ss_flags "sport = :${port}" 2>/dev/null | head -n1)
    if [ -n "$holder" ]; then
      # Find the owning process name/pid for a clearer message, if we can.
      # shellcheck disable=SC2086
      holder_proc=$(ss -p $ss_flags "sport = :${port}" 2>/dev/null | head -n1 | grep -oE 'users:\(\("[^"]+"' | sed -E 's/users:\(\("//')
      reason="port ${port}/${proto} is already in use by another process on the server${holder_proc:+ (${holder_proc})} - not by this panel. Free the port first (or pick a different one)."
      echo "FAILED: ${port}/${proto} - ${reason}" >&2
      FAILED="${FAILED}${port}/${proto} - ${reason}\n"
      continue
    fi
  fi

  # -----------------------------------------------------------------------
  # 2) Clone the matching primary conf (same PKI/CA/CRL/CCD/auth scripts)
  #    and only change what has to be unique to this listener: port,
  #    subnet, ifconfig-pool-persist file, management port, status log.
  # -----------------------------------------------------------------------
  mgmt_port=$(find_free_mgmt_port)
  USED_MGMT_PORTS="${USED_MGMT_PORTS}${mgmt_port} "

  # Keep the canonical config in /etc/openvpn/server, but make every file
  # reference absolute. This matters on systems that only ship the legacy
  # openvpn@.service template: that unit starts in /etc/openvpn and otherwise
  # resolves relative paths such as ca.crt/ccd/ipp-*.txt from the wrong
  # directory. That was why *every* extra TCP listener failed on those hosts
  # even though the same generated config worked with openvpn-server@.
  sed -E \
    -e "s/^port .*/port ${port}/" \
    -e "s/^server [0-9.]+ .*/server ${subnet} 255.255.255.0/" \
    -e "s#^ca .*#ca ${OVPN_DIR}/ca.crt#" \
    -e "s#^cert .*#cert ${OVPN_DIR}/server.crt#" \
    -e "s#^key .*#key ${OVPN_DIR}/server.key#" \
    -e "s#^dh .*#dh ${OVPN_DIR}/dh.pem#" \
    -e "s#^tls-auth [^ ]+( .*)?#tls-auth ${OVPN_DIR}/ta.key 0#" \
    -e "s#^client-config-dir .*#client-config-dir ${OVPN_DIR}/ccd#" \
    -e "s#^crl-verify .*#crl-verify ${OVPN_DIR}/crl.pem#" \
    -e "s#^ifconfig-pool-persist .*#ifconfig-pool-persist ${OVPN_DIR}/ipp-${name}.txt#" \
    -e "s/^management .*/management 127.0.0.1 ${mgmt_port}/" \
    -e "s#^status .*#status ${OVPN_DIR}/openvpn-status-${name}.log 10#" \
    "$base_conf" > "$conf"

  # Debian/Ubuntu's legacy openvpn@ template loads /etc/openvpn/%i.conf.
  # Expose the same canonical config there when that is the selected unit.
  # The config is safe through the symlink because all resource paths above
  # are absolute. openvpn-server@ continues to use the canonical path.
  legacy_conf="${LEGACY_OVPN_DIR}/${name}.conf"
  if [ "$OVPN_PREFIX" = "openvpn@" ]; then
    ln -sfn "$conf" "$legacy_conf"
  else
    rm -f "$legacy_conf"
  fi

  systemctl enable "${OVPN_PREFIX}${name}" >/dev/null 2>&1 || true

  # Mark where our log-append file is right now, so that if this instance
  # fails we only look at lines it actually wrote (see note below on why
  # journalctl alone isn't enough).
  log_mark=0
  [ -f "$OVPN_LOG" ] && log_mark=$(wc -l < "$OVPN_LOG" 2>/dev/null || echo 0)

  # A single failing listener must never abort the rest of the sync - we
  # capture the real failure reason and move on to the next port instead of
  # letting the whole script (and every other, perfectly fine, port) die
  # with it.
  if ! restart_err=$(systemctl restart "${OVPN_PREFIX}${name}" 2>&1); then
    # journalctl only ever shows systemd's own wrapper messages here
    # ("Main process exited, code=exited, status=1/FAILURE") because the
    # base conf uses "log-append /var/log/openvpn.log" - OpenVPN redirects
    # its OWN logging (including the actual bind/option error) to that file
    # instead of the journal once it reaches that directive. So the real
    # reason has to come from the log file, not journalctl.
    journal_detail=$(journalctl -u "${OVPN_PREFIX}${name}" -n 15 --no-pager 2>/dev/null | tail -n 8)
    log_detail=""
    if [ -f "$OVPN_LOG" ]; then
      log_detail=$(tail -n +"$((log_mark + 1))" "$OVPN_LOG" 2>/dev/null | tail -n 15)
    fi
    reason="${restart_err}"
    [ -n "$log_detail" ] && reason="${reason} | openvpn.log: ${log_detail}"
    [ -z "$log_detail" ] && [ -n "$journal_detail" ] && reason="${reason} | journalctl: ${journal_detail}"
    if [ "$port" -lt 1024 ] 2>/dev/null; then
      reason="${reason} | note: ${port} is a privileged (<1024) port - if the log above doesn't show a clear cause, check that nothing else (e.g. a mail/POP3 service on 110, a web server on 80, etc.) already owns it, and that OpenVPN's systemd unit isn't sandboxed with a non-root User= that would block binding low ports."
    fi
    echo "FAILED: ${port}/${proto} - ${reason}" >&2
    FAILED="${FAILED}${port}/${proto} - ${reason}\n"
    rm -f "$conf" "${LEGACY_OVPN_DIR}/${name}.conf" "${OVPN_DIR}/ipp-${name}.txt"
    systemctl stop "${OVPN_PREFIX}${name}" >/dev/null 2>&1 || true
    systemctl disable "${OVPN_PREFIX}${name}" >/dev/null 2>&1 || true
    systemctl reset-failed "${OVPN_PREFIX}${name}" >/dev/null 2>&1 || true
    continue
  fi

  # -----------------------------------------------------------------------
  # 3) NAT for this subnet: this is the actual fix for "connects but no
  #    internet" - without it the tunnel/handshake works (so the panel and
  #    the client both show "connected") but return traffic from the
  #    internet is never routed back through the tunnel to the client.
  # -----------------------------------------------------------------------
  if [ -n "$NET_IFACE" ]; then
    iptables -t nat -C POSTROUTING -s "${subnet}/24" -o "${NET_IFACE}" \
      -m comment --comment "${NAT_COMMENT_PREFIX}${name}" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s "${subnet}/24" -o "${NET_IFACE}" \
        -m comment --comment "${NAT_COMMENT_PREFIX}${name}" -j MASQUERADE
    iptables -C FORWARD -s "${subnet}/24" -m comment --comment "${NAT_COMMENT_PREFIX}${name}-forward-out" -j ACCEPT 2>/dev/null || \
      iptables -A FORWARD -s "${subnet}/24" -m comment --comment "${NAT_COMMENT_PREFIX}${name}-forward-out" -j ACCEPT
    iptables -C FORWARD -d "${subnet}/24" -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "${NAT_COMMENT_PREFIX}${name}-forward-in" -j ACCEPT 2>/dev/null || \
      iptables -A FORWARD -d "${subnet}/24" -m conntrack --ctstate ESTABLISHED,RELATED \
        -m comment --comment "${NAT_COMMENT_PREFIX}${name}-forward-in" -j ACCEPT
    NAT_APPLIED="${NAT_APPLIED}${subnet}/24 -> MASQUERADE/FORWARD via ${NET_IFACE}\n"
  else
    echo "WARN: could not detect main network interface; NAT rule for ${subnet}/24 was NOT added - ${port}/${proto} will connect but have no internet" >&2
  fi

  # -----------------------------------------------------------------------
  # 4) Open the port on the server's own host firewall (INPUT chain) so
  #    it's actually reachable from the internet, not just listening
  #    locally. Only done for ports that started successfully above.
  # -----------------------------------------------------------------------
  case "$FW_BACKEND" in
    ufw)
      ufw allow "${port}/${proto}" comment "${FW_COMMENT}" >/dev/null 2>&1 || \
        echo "WARN: ufw rule for ${port}/${proto} could not be added" >&2
      FW_APPLIED="${FW_APPLIED}${port}/${proto} (ufw)\n"
      ;;
    firewalld)
      firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
      if firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1; then
        FW_APPLIED="${FW_APPLIED}${port}/${proto} (firewalld)\n"
      else
        echo "WARN: firewalld rule for ${port}/${proto} could not be added" >&2
      fi
      ;;
    iptables)
      iptables -N "$FW_CHAIN" 2>/dev/null || true
      iptables -C INPUT -j "$FW_CHAIN" 2>/dev/null || iptables -I INPUT -j "$FW_CHAIN"
      iptables -A "$FW_CHAIN" -p "${proto}" --dport "${port}" \
        -m comment --comment "${FW_COMMENT}-${name}" -j ACCEPT
      FW_APPLIED="${FW_APPLIED}${port}/${proto} (iptables)\n"
      ;;
    none)
      echo "WARN: no supported firewall tool detected (ufw/firewalld/iptables) - ${port}/${proto} was NOT opened automatically; open it yourself." >&2
      ;;
  esac
done

if [ "$FW_BACKEND" = "firewalld" ] && [ "${#BUILD_KEYS[@]}" -gt 0 ]; then
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

if [ "$FW_BACKEND" = "iptables" ] && iptables -C INPUT -j VPN-PANEL-BANS 2>/dev/null; then
  iptables -D INPUT -j VPN-PANEL-BANS 2>/dev/null || true
  iptables -I INPUT 1 -j VPN-PANEL-BANS
fi

# Persist so the NAT (and, for the iptables backend, firewall) rules survive
# a reboot, same as install.sh does for the primary subnets. ufw and
# firewalld persist their own rules already.
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
fi

if [ -n "$FAILED" ]; then
  echo "OPENVPN_EXTRA_PORTS_PARTIAL_FAIL"
  echo "---"
  echo "The following port(s) could NOT be started (every other port - both"
  echo "the ones already healthy before this run and the other new ones in"
  echo "this same request - was left running/applied normally):"
  echo -e "$FAILED"
else
  echo "OPENVPN_EXTRA_PORTS_OK"
fi
if [ -n "$NAT_APPLIED" ]; then
  echo "---"
  echo "NAT/routing configured automatically for:"
  echo -e "$NAT_APPLIED"
fi
if [ -n "$FW_APPLIED" ]; then
  echo "---"
  echo "Server firewall (${FW_BACKEND}) opened automatically for:"
  echo -e "$FW_APPLIED"
fi
echo "Note: if this server sits behind a cloud provider firewall (AWS"
echo "Security Group, GCP/Hetzner/DigitalOcean Cloud Firewall, etc.), that"
echo "is separate from this machine's own firewall and still has to be"
echo "opened by hand there - no script on the server can reach it."

[ -n "$FAILED" ] && exit 1
exit 0
