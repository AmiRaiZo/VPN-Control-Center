#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${VPN_PANEL_INSTALL_DIR:-/opt/vpn-panel}"
PYTHON_BIN="${VPN_PANEL_PYTHON:-$INSTALL_DIR/backend/venv/bin/python}"
[ -x "$PYTHON_BIN" ] || PYTHON_BIN="$INSTALL_DIR/backend/.venv/bin/python"
[ -x "$PYTHON_BIN" ] || PYTHON_BIN="$(command -v python3 || true)"

if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
  echo "DNS_AUDIT_ERROR python runtime not found" >&2
  exit 2
fi
if [ ! -d "$INSTALL_DIR/backend/app" ]; then
  echo "DNS_AUDIT_ERROR backend not found at $INSTALL_DIR/backend" >&2
  exit 2
fi

cd "$INSTALL_DIR/backend"
exec "$PYTHON_BIN" - <<'PYDNSAUDIT'
from __future__ import annotations

from app.database import SessionLocal
from app.models import Setting
from app.schemas import VpnProtocolSettings
from app.services.protocol_dns import (
    ProtocolDnsError,
    _dns_module_available,
    _resolve_paths,
    _verify_written,
    normalize_dns_servers,
)

PROTOCOLS = ("l2tp", "pptp", "openvpn", "sstp", "ikev2", "openconnect")

db = SessionLocal()
try:
    rows = {row.key: row.value for row in db.query(Setting).all()}
finally:
    db.close()


def coerce(name, default):
    if name not in rows or rows[name] is None:
        return default
    raw = rows[name]
    if isinstance(default, bool):
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default
    return str(raw)


def model_defaults():
    model = VpnProtocolSettings()
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


payload = VpnProtocolSettings(**{
    name: coerce(name, value) for name, value in model_defaults().items()
})
failures = []
checked = 0

for protocol in PROTOCOLS:
    dns1 = getattr(payload, f"{protocol}_dns1", "")
    dns2 = getattr(payload, f"{protocol}_dns2", "")
    try:
        expected = normalize_dns_servers(protocol, dns1, dns2)
    except ProtocolDnsError as exc:
        failures.append(f"{protocol}: invalid database DNS: {exc}")
        print(f"DNS_AUDIT_FAIL protocol={protocol} reason=invalid_database_dns detail={exc}")
        continue

    # accel-ppp's DNS plugin is optional.  Some valid SSTP builds do not
    # provide libdns.so and intentionally omit both the `dns` module and the
    # [dns] section.  The apply phase already leaves that config untouched;
    # audit must mirror the same capability check instead of turning the
    # expected warning into a fatal update rollback.
    if protocol == "sstp" and not _dns_module_available():
        print(
            f"DNS_AUDIT_SKIP protocol={protocol} "
            f"reason=dns_module_not_installed expected={','.join(expected)}"
        )
        continue

    paths = _resolve_paths(protocol, None)
    if not paths:
        print(f"DNS_AUDIT_SKIP protocol={protocol} reason=config_not_installed expected={','.join(expected)}")
        continue

    protocol_ok = True
    for path in paths:
        checked += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            _verify_written(protocol, text, expected)
        except Exception as exc:
            protocol_ok = False
            failures.append(f"{protocol}:{path}: {exc}")
            print(f"DNS_AUDIT_FAIL protocol={protocol} file={path} expected={','.join(expected)} detail={exc}")
        else:
            print(f"DNS_AUDIT_OK protocol={protocol} file={path} dns={','.join(expected)}")
    if protocol_ok:
        print(f"DNS_AUDIT_PROTOCOL_OK protocol={protocol} files={len(paths)}")

if failures:
    print(f"DNS_AUDIT_RESULT status=failed checked_files={checked} failures={len(failures)}")
    raise SystemExit(1)
print(f"DNS_AUDIT_RESULT status=ok checked_files={checked} failures=0")
PYDNSAUDIT
