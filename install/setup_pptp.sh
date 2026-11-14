#!/bin/bash
# Install the Poptop PPTP server from APT when available, otherwise build the
# verified upstream release.  Ubuntu 24.04/Noble removed the pptpd binary
# package while retaining PPP 2.4.9, so the fallback applies the upstream-
# recommended PPP 2.4 compatibility source before compiling.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  # shellcheck source=apt_preflight.sh
  source "$SCRIPT_DIR/apt_preflight.sh"
fi

PPTPD_VERSION="${PPTPD_VERSION:-1.5.0}"
PPTPD_SHA256="6a724284b1ce00ea23f7d7608d081843a10c8a8d87d951cb2ea86e70aa1b4e77"
PPTPD_PRIMARY_URL="https://downloads.sourceforge.net/project/poptop/pptpd/pptpd-${PPTPD_VERSION}/pptpd-${PPTPD_VERSION}.tar.gz"
PPTPD_FALLBACK_URL="https://deb.debian.org/debian/pool/main/p/pptpd/pptpd_${PPTPD_VERSION}.orig.tar.gz"
STATE_DIR="/var/lib/vpn-panel"
VERSION_FILE="$STATE_DIR/pptpd-source-version"
FORCE=0
START_SERVICE=0

for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --start) START_SERVICE=1 ;;
    --install-only) START_SERVICE=0 ;;
    *) echo "ERROR: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }
STARTED_AT=$(date +%s)

wait_for_apt_lock() {
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
    if [ "$waited" -ge 300 ]; then
      echo "ERROR: timed out waiting for APT/dpkg lock" >&2
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
  dpkg --force-confdef --force-confold --configure -a >/dev/null 2>&1 || true
}

apt_package_available() {
  local candidate
  candidate=$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/{print $2; exit}')
  [ -n "$candidate" ] && [ "$candidate" != "(none)" ]
}

install_missing_packages() {
  local missing=() pkg
  for pkg in "$@"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' || missing+=("$pkg")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    wait_for_apt_lock
    if declare -F vpn_panel_install_packages >/dev/null 2>&1; then
      vpn_panel_install_packages "${missing[@]}"
    else
      apt-get -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=600 -o Acquire::Retries=4 \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        install -y --no-install-recommends "${missing[@]}"
    fi
  fi
}

normalize_pptp_runtime_config() {
  mkdir -p /etc/ppp /var/lib/vpn-panel
  [ -e /etc/pptpd.conf ] || : > /etc/pptpd.conf
  [ -e /etc/ppp/pptpd-options ] || : > /etc/ppp/pptpd-options

  # Old/manual configurations are the most common reason for a repaired PPTP
  # service to exit immediately: a stale `listen` address, duplicate pool
  # directives, an abbreviated remote range, or the optional logwtmp plugin
  # left behind by another distro build. Rebuild only the structural lines and
  # preserve harmless custom directives.
  python3 - /etc/pptpd.conf <<'PYCONF'
from pathlib import Path
import ipaddress, re, sys
p = Path(sys.argv[1])
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
kept = []
for raw in lines:
    s = raw.strip()
    if not s or s.startswith(('#', ';')):
        kept.append(raw)
        continue
    key = s.split(None, 1)[0].lower()
    if key in {'option', 'localip', 'remoteip', 'listen', 'pidfile', 'logwtmp'}:
        continue
    kept.append(raw)
# Full start/end addresses are accepted consistently by both packaged 1.4.x
# and source-built 1.5.x daemons. Binding to all local addresses avoids an old
# public IP making the daemon fail after a server migration.
base = [
    'option /etc/ppp/pptpd-options',
    'localip 192.168.43.1',
    'remoteip 192.168.43.10-192.168.43.250',
]
text = '\n'.join(base + [x for x in kept if x.strip()]).rstrip() + '\n'
p.write_text(text, encoding='utf-8')
PYCONF

  python3 - /etc/ppp/pptpd-options <<'PYOPTS'
from pathlib import Path
import re, sys
p = Path(sys.argv[1])
lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
# Remove optional/legacy plugins which can be ABI-incompatible with the host
# pppd and are not required by the panel's own accounting hooks.
clean = []
for raw in lines:
    s = raw.strip().lower()
    if 'pptpd-logwtmp' in s or s == 'logwtmp':
        continue
    clean.append(raw)
required = [
    'name pptpd', 'ipcp-accept-local', 'ipcp-accept-remote',
    'nodefaultroute', 'asyncmap 0', 'refuse-pap', 'refuse-chap',
    'refuse-mschap', 'require-mschap-v2', 'require-mppe-128',
    'ms-dns 8.8.8.8', 'ms-dns 8.8.4.4', 'proxyarp', 'nobsdcomp',
    'novj', 'novjccomp', 'nologfd', 'mtu 1400', 'mru 1400',
    'nodeflate', 'nopcomp', 'noaccomp',
]
seen = {re.split(r'\s+', x.strip(), 1)[0].lower() for x in clean if x.strip() and not x.lstrip().startswith(('#',';'))}
for item in required:
    key = item.split(None, 1)[0].lower()
    if key not in seen:
        clean.append(item); seen.add(key)
p.write_text('\n'.join(clean).rstrip() + '\n', encoding='utf-8')
PYOPTS

  touch /etc/ppp/chap-secrets
  chmod 600 /etc/pptpd.conf /etc/ppp/pptpd-options /etc/ppp/chap-secrets
}

create_systemd_unit() {
  cat > /etc/systemd/system/pptpd.service <<'UNIT'
[Unit]
Description=PoPToP Point to Point Tunneling Server
Documentation=man:pptpd(8) man:pptpd.conf(5)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/pptpd.conf

[Service]
Type=simple
ExecStartPre=/bin/rm -f /run/pptpd.pid /var/run/pptpd.pid /run/pptpd/pptpd.pid
ExecStart=/usr/sbin/pptpd --fg
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=10
KillMode=control-group
RuntimeDirectory=pptpd
RuntimeDirectoryMode=0755
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

pptpd_ready() {
  [ -x /usr/sbin/pptpd ] && systemctl cat pptpd.service >/dev/null 2>&1
}

clean_stale_pptpd_runtime() {
  systemctl stop pptpd.service >/dev/null 2>&1 || true
  for _ in 1 2; do
    pgrep -x pptpd >/dev/null 2>&1 || break
    pkill -TERM -x pptpd >/dev/null 2>&1 || true
    sleep 1
  done
  pgrep -x pptpd >/dev/null 2>&1 && pkill -KILL -x pptpd >/dev/null 2>&1 || true
  rm -f /run/pptpd.pid /var/run/pptpd.pid /run/pptpd/pptpd.pid

  # A stale untracked pptpd process is safe to terminate; an unrelated owner
  # must be reported instead of silently stealing TCP/1723.
  local owner_lines owner_pids pid comm
  owner_lines="$(ss -H -ltnp 2>/dev/null | awk '$4 ~ /:1723$/ {print}' || true)"
  if [ -n "$owner_lines" ]; then
    owner_pids="$(printf '%s\n' "$owner_lines" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"
    for pid in $owner_pids; do
      comm="$(ps -p "$pid" -o comm= 2>/dev/null | xargs || true)"
      if [ "$comm" = "pptpd" ]; then
        kill -KILL "$pid" >/dev/null 2>&1 || true
      else
        echo "ERROR: TCP/1723 is occupied by ${comm:-unknown} (pid=${pid:-unknown})" >&2
        return 1
      fi
    done
    sleep 0.5
  fi
}

start_and_verify_pptpd() {
  normalize_pptp_runtime_config
  create_systemd_unit
  clean_stale_pptpd_runtime
  systemctl reset-failed pptpd.service >/dev/null 2>&1 || true
  systemctl enable pptpd.service >/dev/null 2>&1 || true
  systemctl start pptpd.service
  local i
  for i in $(seq 1 30); do
    if systemctl is-active --quiet pptpd.service \
       && pgrep -x pptpd >/dev/null 2>&1 \
       && ss -H -ltn 2>/dev/null | grep -Eq '[:.]1723([[:space:]]|$)'; then
      rm -f "$STATE_DIR/pptpd-last-error.log"
      return 0
    fi
    sleep 0.5
  done
  {
    echo "PPTP_RUNTIME_REPAIR_FAILED $(date -Is)"
    systemctl status pptpd.service --no-pager -l || true
    journalctl -u pptpd.service -n 100 --no-pager || true
    echo "--- pptpd.conf ---"
    sed -n '1,160p' /etc/pptpd.conf || true
    echo "--- pptpd-options ---"
    sed -n '1,200p' /etc/ppp/pptpd-options || true
    echo "--- tcp/1723 ---"
    ss -ltnp | grep -E '[:.]1723([[:space:]]|$)' || true
  } > "$STATE_DIR/pptpd-last-error.log" 2>&1
  cat "$STATE_DIR/pptpd-last-error.log" >&2
  return 1
}

if [ "$FORCE" -eq 0 ] && pptpd_ready; then
  echo "[*] PPTP server binary is already installed; repairing configuration and systemd ownership."
  normalize_pptp_runtime_config
  create_systemd_unit
  if [ "$START_SERVICE" -eq 1 ]; then
    start_and_verify_pptpd
  fi
  exit 0
fi

mkdir -p "$STATE_DIR"
export DEBIAN_FRONTEND=noninteractive
if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then
  echo "[*] Refreshing APT package indexes for standalone PPTP installation..."
  wait_for_apt_lock
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=4 update -y
fi

# Prefer the distribution package on releases where it still exists.
if apt_package_available pptpd; then
  echo "[*] Installing PPTP server from the Ubuntu/Debian repository..."
  install_missing_packages ppp iptables-persistent pptpd
  create_systemd_unit
else
  echo "[*] pptpd is absent from this Ubuntu repository; building verified Poptop ${PPTPD_VERSION} from source..."
  install_missing_packages \
    ca-certificates curl build-essential autoconf automake libtool pkg-config \
    ppp ppp-dev libwrap0-dev iptables-persistent

  TMP_DIR=$(mktemp -d /tmp/vpn-panel-pptpd.XXXXXX)
  trap 'rm -rf "$TMP_DIR"' EXIT
  ARCHIVE="$TMP_DIR/pptpd-${PPTPD_VERSION}.tar.gz"

  if ! curl --fail --location --retry 4 --retry-all-errors --connect-timeout 20 \
      -o "$ARCHIVE" "$PPTPD_PRIMARY_URL"; then
    echo "[!] Primary Poptop mirror failed; trying the Debian source mirror..." >&2
    curl --fail --location --retry 4 --retry-all-errors --connect-timeout 20 \
      -o "$ARCHIVE" "$PPTPD_FALLBACK_URL"
  fi

  echo "${PPTPD_SHA256}  ${ARCHIVE}" | sha256sum --check --status || {
    echo "ERROR: pptpd source checksum mismatch" >&2
    exit 3
  }

  SRC_DIR="$TMP_DIR/src"
  mkdir -p "$SRC_DIR"
  tar -xzf "$ARCHIVE" -C "$SRC_DIR" --strip-components=1

  # Ubuntu 24.04 ships ppp-dev 2.4.9.  pptpd 1.5.0's logwtmp plugin was
  # switched to the PPP 2.5 API; upstream explicitly recommends reverting
  # that change for PPP 2.4.  Replace only this plugin with the compatible
  # implementation used before that commit.
  if [ ! -f /usr/include/pppd/options.h ]; then
    echo "[*] Applying PPP 2.4 compatibility source for pptpd-logwtmp..."
    cat > "$SRC_DIR/plugins/pptpd-logwtmp.c" <<'PLUGIN'
/* PPP 2.4 compatible pptpd logwtmp plugin (upstream pre-PPP-2.5 API). */
#include <unistd.h>
#include <utmp.h>
#include <string.h>
#include <pppd/pppd.h>
char pppd_version[] = VERSION;

static char pptpd_original_ip[PATH_MAX+1];
static bool pptpd_logwtmp_strip_domain = 0;

static option_t options[] = {
  { "pptpd-original-ip", o_string, pptpd_original_ip,
    "Original IP address of the PPTP connection",
    OPT_STATIC, NULL, PATH_MAX },
  { "pptpd-logwtmp-strip-domain", o_bool, &pptpd_logwtmp_strip_domain,
    "Strip domain from username before logging", OPT_PRIO | 1 },
  { NULL }
};

static char *reduce(char *user)
{
  char *sep;
  if (!pptpd_logwtmp_strip_domain) return user;
  sep = strstr(user, "//");
  if (sep != NULL) user = sep + 2;
  sep = strstr(user, "\\");
  if (sep != NULL) user = sep + 1;
  return user;
}

static void ip_up(void *opaque, int arg)
{
  char *user = reduce(peer_authname);
  if (debug)
    notice("pptpd-logwtmp.so ip-up %s %s %s", ifname, user,
       pptpd_original_ip);
  logwtmp(ifname, user, pptpd_original_ip);
}

static void ip_down(void *opaque, int arg)
{
  if (debug)
    notice("pptpd-logwtmp.so ip-down %s", ifname);
  logwtmp(ifname, "", "");
}

void plugin_init(void)
{
  add_options(options);
  add_notifier(&ip_up_notifier, ip_up, NULL);
  add_notifier(&ip_down_notifier, ip_down, NULL);
  if (debug)
    notice("pptpd-logwtmp: PPP 2.4 compatibility build");
}
PLUGIN
  fi

  cd "$SRC_DIR"
  ./configure --prefix=/usr --sbindir=/usr/sbin --sysconfdir=/etc \
    --localstatedir=/var --libdir=/usr/lib
  make -j"$(nproc 2>/dev/null || echo 1)"
  make install
  cd /

  [ -x /usr/sbin/pptpd ] || { echo "ERROR: source build did not install /usr/sbin/pptpd" >&2; exit 4; }
  create_systemd_unit
  printf '%s %s\n' "$PPTPD_VERSION" "$PPTPD_SHA256" > "$VERSION_FILE"
fi

/usr/sbin/pptpd --version >/dev/null 2>&1 || {
  echo "ERROR: installed pptpd binary failed its version check" >&2
  exit 5
}

normalize_pptp_runtime_config
create_systemd_unit
systemctl enable pptpd.service >/dev/null 2>&1 || true
if [ "$START_SERVICE" -eq 1 ]; then
  start_and_verify_pptpd || { echo "ERROR: pptpd did not become active after automatic runtime repair" >&2; exit 6; }
fi

echo "[*] PPTP server installation completed in $(( $(date +%s) - STARTED_AT )) seconds."
