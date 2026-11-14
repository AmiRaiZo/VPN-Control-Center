#!/bin/bash
# Full host preparation for VPN Panel fresh installations.
# The functions are safe to call repeatedly and intentionally avoid touching
# existing panel databases, certificates or protocol configuration files.


vpn_panel_bootstrap_log() { printf '[bootstrap] %s\n' "$*"; }
vpn_panel_bootstrap_warn() { printf '[bootstrap] WARNING: %s\n' "$*" >&2; }

vpn_panel_bootstrap_dns() {
  if getent ahostsv4 deb.nodesource.com >/dev/null 2>&1 && getent ahostsv4 pypi.org >/dev/null 2>&1; then
    return 0
  fi
  vpn_panel_bootstrap_warn "DNS resolution is not healthy; applying a reversible fallback resolver configuration."
  mkdir -p /var/backups/vpn-panel-bootstrap
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
    mkdir -p /etc/systemd/resolved.conf.d
    [ -f /etc/systemd/resolved.conf.d/vpn-panel.conf ] || cat > /etc/systemd/resolved.conf.d/vpn-panel.conf <<'RESOLVED'
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=9.9.9.9 1.0.0.1
DNSSEC=allow-downgrade
RESOLVED
    systemctl enable --now systemd-resolved >/dev/null 2>&1 || true
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
  fi
  if ! grep -Eq '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf 2>/dev/null; then
    cp -a /etc/resolv.conf "/var/backups/vpn-panel-bootstrap/resolv.conf.$(date +%s)" 2>/dev/null || true
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
  fi
  for _ in $(seq 1 15); do
    getent ahostsv4 deb.nodesource.com >/dev/null 2>&1 && return 0
    sleep 2
  done
  vpn_panel_bootstrap_warn "DNS still does not resolve public package hosts. The provider/network DNS must allow outbound UDP/TCP 53."
  return 1
}

vpn_panel_bootstrap_clock() {
  timedatectl set-ntp true >/dev/null 2>&1 || true
  systemctl enable --now systemd-timesyncd.service >/dev/null 2>&1 || true
  for _ in $(seq 1 10); do
    timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes && return 0
    sleep 1
  done
  vpn_panel_bootstrap_warn "NTP has not confirmed synchronization yet; installation will continue and re-check later."
}

vpn_panel_bootstrap_swap() {
  local mem_kb swap_kb swapfile=/swapfile-vpn-panel
  mem_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  swap_kb=$(awk '/SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "${mem_kb:-0}" -lt 1800000 ] && [ "${swap_kb:-0}" -lt 262144 ]; then
    vpn_panel_bootstrap_log "Low-memory server detected; creating a 1 GB swap file to prevent package/build failures."
    if [ ! -f "$swapfile" ]; then
      fallocate -l 1G "$swapfile" 2>/dev/null || dd if=/dev/zero of="$swapfile" bs=1M count=1024 status=none
      chmod 600 "$swapfile"
      mkswap "$swapfile" >/dev/null
    fi
    swapon "$swapfile" 2>/dev/null || true
    grep -qF "$swapfile none swap sw 0 0" /etc/fstab 2>/dev/null || echo "$swapfile none swap sw 0 0" >> /etc/fstab
  fi
}

vpn_panel_bootstrap_kernel() {
  local modules=(tun ppp_generic ppp_mppe l2tp_ppp l2tp_netlink ip_gre gre af_key esp4 xfrm_user nf_conntrack nf_conntrack_pptp)
  mkdir -p /etc/modules-load.d /dev/net
  : > /etc/modules-load.d/vpn-panel.conf
  for module in "${modules[@]}"; do
    echo "$module" >> /etc/modules-load.d/vpn-panel.conf
    modprobe "$module" >/dev/null 2>&1 || true
  done
  if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 666 /dev/net/tun 2>/dev/null || true
  fi
  cat > /etc/sysctl.d/99-vpn-panel.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.core.somaxconn=4096
SYSCTL
  sysctl --system >/dev/null 2>&1 || true
}

vpn_panel_bootstrap_base() {
  [ "$(id -u)" -eq 0 ] || { echo "bootstrap_host.sh must run as root" >&2; return 1; }
  local prepare_vpn="${1:-1}"
  local arch free_kb
  arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
  case "$arch" in
    amd64|arm64|x86_64|aarch64) ;;
    *) vpn_panel_bootstrap_warn "Architecture ${arch} is not in the tested list." ;;
  esac
  free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
  if [ "${free_kb:-0}" -lt 2500000 ]; then
    echo "ERROR: at least 2.5 GB of free disk space is required for a reliable full installation." >&2
    return 1
  fi

  vpn_panel_bootstrap_dns || true
  if declare -F vpn_panel_apt_get >/dev/null 2>&1; then
    vpn_panel_apt_get update
  else
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=4 update
  fi
  local packages=(
    ca-certificates curl wget jq gnupg lsb-release software-properties-common
    apt-transport-https unzip zip tar xz-utils gzip bzip2 rsync acl
    openssl dnsutils iproute2 iptables nftables net-tools netcat-openbsd socat
    procps psmisc util-linux kmod cron logrotate
  )
  if declare -F vpn_panel_install_packages >/dev/null 2>&1; then
    vpn_panel_install_packages "${packages[@]}"
  else
    DEBIAN_FRONTEND=noninteractive apt-get -y install "${packages[@]}"
  fi
  vpn_panel_bootstrap_dns || true
  vpn_panel_bootstrap_clock
  vpn_panel_bootstrap_swap
  if [ "$prepare_vpn" = "1" ]; then
    vpn_panel_bootstrap_kernel
  else
    vpn_panel_bootstrap_log "Management prerequisites only; VPN kernel/sysctl preparation deferred."
  fi
  install -d -m 0755 /var/lib/vpn-panel /var/lib/vpn-panel/branding /var/log/vpn-panel
  export VPN_PANEL_BOOTSTRAP_APT_READY=1
  vpn_panel_bootstrap_log "Base operating-system prerequisites are ready."
}

vpn_panel_firewall_allow() {
  local proto="$1" port="$2" label="${3:-vpn-panel}"
  [ -n "$port" ] || return 0
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${port}/${proto}" comment "$label" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
  else
    iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p "$proto" --dport "$port" -m comment --comment "$label" -j ACCEPT 2>/dev/null || true
  fi
}

vpn_panel_firewall_allow_protocol() {
  local proto="$1" label="${2:-vpn-panel}"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow proto "$proto" from any to any comment "$label" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-protocol="$proto" >/dev/null 2>&1 || true
  else
    iptables -C INPUT -p "$proto" -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p "$proto" -m comment --comment "$label" -j ACCEPT 2>/dev/null || true
  fi
}

vpn_panel_prepare_firewall() {
  local panel_port="$1" l2tp_port="$2" ovpn_udp="$3" ovpn_tcp="$4" sstp_port="$5" oc_port="$6"
  vpn_panel_firewall_allow tcp "$panel_port" vpnpanel-panel
  vpn_panel_firewall_allow tcp 80 vpnpanel-http
  vpn_panel_firewall_allow tcp 443 vpnpanel-https
  vpn_panel_firewall_allow udp 500 vpnpanel-ipsec
  vpn_panel_firewall_allow udp 4500 vpnpanel-ipsec-nat
  vpn_panel_firewall_allow udp "$l2tp_port" vpnpanel-l2tp
  vpn_panel_firewall_allow tcp 1723 vpnpanel-pptp
  vpn_panel_firewall_allow_protocol gre vpnpanel-pptp-gre
  vpn_panel_firewall_allow_protocol esp vpnpanel-ipsec-esp
  vpn_panel_firewall_allow_protocol ah vpnpanel-ipsec-ah
  vpn_panel_firewall_allow udp "$ovpn_udp" vpnpanel-openvpn
  vpn_panel_firewall_allow tcp "$ovpn_tcp" vpnpanel-openvpn
  vpn_panel_firewall_allow tcp "$sstp_port" vpnpanel-sstp
  vpn_panel_firewall_allow tcp "$oc_port" vpnpanel-openconnect
  vpn_panel_firewall_allow udp "$oc_port" vpnpanel-openconnect
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  vpn_panel_bootstrap_log "Host firewall rules for the panel and VPN protocols are ready."
  vpn_panel_bootstrap_warn "A provider/cloud security group is outside the server OS. If the provider blocks ports, its API credentials are required to change that external firewall."
}
