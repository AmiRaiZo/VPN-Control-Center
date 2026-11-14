#!/bin/bash
# قطع دستی یک کاربر OpenVPN با استفاده از management interface.
# چون OpenVPN همیشه با دو پروسه‌ی هم‌زمان اجرا می‌شود (UDP و TCP)، کاربر ممکن
# است از هرکدام وصل شده باشد؛ برای اطمینان روی هر دو management port امتحان
# می‌شود (کاربر متصل، در یکی از آن‌ها است - kill روی دیگری فقط یک no-op بی‌خطر
# است).
# نیازمند: management 127.0.0.1 7505 (udp) و management 127.0.0.1 7506 (tcp) در سرور.conf ها
#
# اگر آرگومان دوم (آی‌پی) داده شود، فقط همان یک سشن مشخص با client-kill قطع
# می‌شود (بر اساس Client ID که از خروجی "status 2" و تطبیق آی‌پی پیدا می‌شود)؛
# در غیر این صورت مثل قبل همه‌ی سشن‌های آن کاربر با "kill" قطع می‌شوند.
USERNAME="$1"
IP="$2"
if [ -z "$USERNAME" ]; then
  exit 1
fi

# پورت‌های اضافه (Settings > پورت‌های OpenVPN) هرکدام management interface
# مستقل خودشان را روی یک پورت پویا (7601-7699، انتخاب‌شده توسط
# manage_openvpn_extra_ports.sh) دارند که هیچ‌جا در دیتابیس ذخیره نمی‌شود -
# فقط داخل خودِ کانفیگ آن instance. بدون این، دکمه‌ی قطع برای کاربری که از
# یک پورت اضافه وصل شده هیچ‌وقت کار نمی‌کرد.
ALL_PORTS="7505 7506"
for conf in /etc/openvpn/server/server-extra-*.conf; do
  [ -f "$conf" ] || continue
  mgmt=$(grep -E '^management 127\.0\.0\.1 ' "$conf" | awk '{print $3}')
  [ -n "$mgmt" ] && ALL_PORTS="$ALL_PORTS $mgmt"
done

kill_all_on_port() {
  local port="$1"
  python3 - "$port" "$USERNAME" << 'PYEOF'
import socket, sys
port, username = int(sys.argv[1]), sys.argv[2]
try:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.settimeout(3)
        s.sendall(f"kill {username}\n".encode())
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
        except socket.timeout:
            pass
except OSError:
    pass
PYEOF
}

kill_single_on_port() {
  local port="$1"
  python3 - "$port" "$USERNAME" "$IP" << 'PYEOF'
import socket, sys
port, username, ip = int(sys.argv[1]), sys.argv[2], sys.argv[3]

def query(port, cmd):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.settimeout(3)
        s.sendall((cmd + "\n").encode())
        data = b""
        try:
            while b"\r\nEND" not in data and b"\nEND" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data.decode(errors="ignore")

try:
    status = query(port, "status 2")
except OSError:
    sys.exit(0)

cid = None
for line in status.splitlines():
    parts = line.split(",")
    if len(parts) > 10 and parts[0] == "CLIENT_LIST" and parts[1] == username and parts[2].startswith(ip + ":"):
        cid = parts[10]
        break

if cid:
    try:
        query(port, f"client-kill {cid}")
    except OSError:
        pass
PYEOF
}

for port in $ALL_PORTS; do
  if [ -n "$IP" ]; then
    kill_single_on_port "$port"
  else
    kill_all_on_port "$port"
  fi
done
exit 0
