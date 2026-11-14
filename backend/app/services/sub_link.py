"""
ساخت آدرس‌های عمومی اشتراک کاربران.

اولویت صفحه‌ی عمومی اشتراک:
  1) دامنه‌ی عمومی اشتراک (sub_domain)
  2) دامنه‌ی پنل
  3) IP + پورت پنل

اولویت لینک خام VMess/VLESS:
  1) دامنه‌ی اختصاصی Xray subscription (xray_sub_domain)
  2) دامنه‌ی عمومی اشتراک
  3) دامنه‌ی پنل
  4) IP + پورت پنل
"""
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Setting


PANEL_ENV_FILE = Path(os.environ.get("VPN_PANEL_ENV_FILE", "/opt/vpn-panel/panel.env"))
PANEL_NGINX_SITE = Path(os.environ.get("VPN_PANEL_NGINX_SITE", "/etc/nginx/sites-available/vpn-panel"))
NGINX_ENABLED_DIR = Path(os.environ.get("VPN_PANEL_NGINX_ENABLED_DIR", "/etc/nginx/sites-enabled"))


def get_setting(db: Session, key: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def _safe_port(value, default: int) -> int:
    try:
        port = int(value)
        return port if 1 <= port <= 65535 else default
    except (TypeError, ValueError):
        return default


def _https_origin(domain: str, port: int = 443) -> str:
    port_part = "" if port == 443 else f":{port}"
    return f"https://{domain}{port_part}"


def _read_runtime_panel_port() -> int | None:
    """Read the public Nginx port selected by the installer.

    Older installs sometimes kept ``panel_port=80`` in the database after the
    installer fell back to 8000.  Subscription and QR URLs must follow the
    actual public listener, not that stale default.
    """
    env_file = PANEL_ENV_FILE
    try:
        if env_file.is_file():
            match = re.search(r"(?m)^PANEL_PORT=(?:[\"']?)(\d+)", env_file.read_text(errors="ignore"))
            if match:
                port = _safe_port(match.group(1), 0)
                if port:
                    return port
    except OSError:
        pass

    nginx_site = PANEL_NGINX_SITE
    try:
        if nginx_site.is_file():
            ports = [int(value) for value in re.findall(r"(?m)^\s*listen\s+(?:\[::\]:)?(\d+)", nginx_site.read_text(errors="ignore"))]
            ports = [port for port in ports if port not in {80, 443}] or ports
            if ports:
                return _safe_port(ports[0], 0) or None
    except (OSError, ValueError):
        pass
    return None


def _nginx_config_paths() -> list[Path]:
    """Return panel-related Nginx configs without following the same file twice."""
    candidates = [PANEL_NGINX_SITE]
    try:
        if NGINX_ENABLED_DIR.is_dir():
            candidates.extend(sorted(path for path in NGINX_ENABLED_DIR.iterdir() if path.is_file() or path.is_symlink()))
    except OSError:
        pass
    result: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _listen_details(value: str) -> tuple[int, bool] | None:
    args = value.split()
    if not args or args[0].startswith("unix:"):
        return None
    listener = args[0].replace("[::]", "")
    match = re.search(r"(?::|^)(\d+)$", listener)
    if not match:
        return None
    port = _safe_port(match.group(1), 0)
    if not port:
        return None
    return port, any(arg.lower() == "ssl" for arg in args[1:])


def _nginx_public_origin(domain: str | None) -> str | None:
    """Discover the externally usable origin for an exact server_name.

    The panel can listen internally on 8080 while Nginx exposes the same domain
    on HTTPS/443. Telegram has no browser request origin to copy, so blindly
    using PANEL_PORT produced links such as https://domain:8080 that work on
    some desktops but fail on phones. Prefer the real public TLS listener.
    """
    wanted = (domain or "").strip().lower()
    if not wanted:
        return None
    candidates: list[tuple[int, str]] = []
    for path in _nginx_config_paths():
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for block in _iter_nginx_server_blocks(text):
            names: set[str] = set()
            for match in re.finditer(r"(?m)^\s*server_name\s+([^;]+);", block):
                names.update(token.strip().lower() for token in match.group(1).split() if token.strip())
            if wanted not in names:
                continue
            for match in re.finditer(r"(?m)^\s*listen\s+([^;]+);", block):
                details = _listen_details(match.group(1))
                if not details:
                    continue
                port, ssl = details
                scheme = "https" if ssl else "http"
                if ssl and port == 443:
                    score = 100
                elif ssl:
                    score = 90
                elif port == 80:
                    score = 70
                elif port == 443:
                    score = 65
                else:
                    score = 40
                candidates.append((score, _origin(wanted, scheme, port)))
    return max(candidates, default=(0, ""), key=lambda item: item[0])[1] or None


def _iter_nginx_server_blocks(text: str):
    """Yield top-level ``server { ... }`` blocks from an Nginx config.

    A plain regular expression is unsafe here because ``location`` blocks are
    nested.  This tiny brace-depth parser is deliberately conservative and
    only needs to understand the generated vpn-panel site.
    """
    lines = text.splitlines()
    collecting = False
    depth = 0
    current: list[str] = []
    for raw in lines:
        line = raw.split("#", 1)[0]
        if not collecting:
            if re.search(r"\bserver\s*\{", line):
                collecting = True
                depth = line.count("{") - line.count("}")
                current = [raw]
                if depth <= 0:
                    yield "\n".join(current)
                    collecting = False
            continue
        current.append(raw)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            yield "\n".join(current)
            collecting = False
            current = []


def _nginx_panel_scheme(domain: str | None, port: int) -> str | None:
    """Return the protocol actually configured on the public panel listener.

    ``domain_ssl_status`` can remain ``active`` after an emergency access
    repair rewrites the public listener as plain HTTP.  Generating
    ``https://domain:8080`` in that state causes Chrome's
    ``ERR_SSL_PROTOCOL_ERROR``.  The Nginx listener is the runtime source of
    truth, so subscription links follow it instead of a stale database flag.
    """
    try:
        text = PANEL_NGINX_SITE.read_text(errors="ignore")
    except OSError:
        return None

    wanted_domain = (domain or "").strip().lower()
    fallback: str | None = None
    for block in _iter_nginx_server_blocks(text):
        names: set[str] = set()
        for match in re.finditer(r"(?m)^\s*server_name\s+([^;]+);", block):
            names.update(token.strip().lower() for token in match.group(1).split() if token.strip())
        domain_matches = not wanted_domain or wanted_domain in names or "_" in names
        if not domain_matches:
            continue
        for match in re.finditer(r"(?m)^\s*listen\s+([^;]+);", block):
            args = match.group(1).split()
            listener = args[0].strip() if args else ""
            port_match = re.search(r"(?::|^)(\d+)$", listener.replace("[::]", ""))
            if not port_match or int(port_match.group(1)) != int(port):
                continue
            scheme = "https" if any(arg.lower() == "ssl" for arg in args[1:]) else "http"
            if wanted_domain and wanted_domain in names:
                return scheme
            fallback = fallback or scheme
    return fallback


def _normalize_request_origin(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _origin(host: str, scheme: str, port: int) -> str:
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}{'' if int(port) == default else f':{int(port)}'}"


def _fallback_panel_origin(db: Session, request_origin: str | None = None) -> str:
    # The request that produced the user list is the strongest signal of the
    # address the operator can actually open. Use it unless a dedicated
    # subscription domain is configured (handled by build_sub_origin).
    normalized_request = _normalize_request_origin(request_origin)
    if normalized_request:
        return normalized_request

    domain = (get_setting(db, "domain") or "").strip() or None
    domain_active = get_setting(db, "domain_ssl_status") == "active"

    # Telegram-generated links have no request_origin. Inspect every enabled
    # Nginx site and prefer the exact public listener for the configured
    # domain (normally HTTPS/443), not the internal PANEL_PORT such as 8080.
    discovered = _nginx_public_origin(domain)
    if discovered:
        return discovered

    panel_port = _read_runtime_panel_port() or _safe_port(get_setting(db, "panel_port"), 80)
    scheme = _nginx_panel_scheme(domain, panel_port)
    host = domain or get_settings().PUBLIC_SERVER_IP

    if domain and domain_active:
        # Only include a non-standard port when Nginx explicitly confirms that
        # TLS is served on that exact listener. Otherwise 8080 is typically an
        # internal HTTP port behind the public HTTPS reverse proxy.
        if scheme == "https":
            return _origin(domain, "https", panel_port)
        return _https_origin(domain, 443)

    if not scheme:
        scheme = "http"
    return _origin(host, scheme, panel_port)


def _dedicated_public_origin(domain: str, configured_port: int) -> str:
    """Return a phone-safe public origin for a dedicated subscription domain.

    Legacy installations often stored the panel's *internal* 8080 listener in
    ``sub_domain_port`` even though the domain is publicly terminated on
    HTTPS/443.  Emitting ``https://domain:8080`` then causes
    ERR_SSL_PROTOCOL_ERROR on phones.  The effective Nginx listener wins; a
    custom port is kept only when Nginx explicitly serves TLS on that port.
    """
    discovered = _nginx_public_origin(domain)
    if discovered:
        return discovered
    port = _safe_port(configured_port, 443)
    if port == 443:
        return _https_origin(domain, 443)
    if _nginx_panel_scheme(domain, port) == "https":
        return _https_origin(domain, port)
    # Unknown/non-TLS ports (especially 8080) are assumed to be internal.
    return _https_origin(domain, 443)


def build_sub_origin(db: Session, request_origin: str | None = None) -> str:
    sub_domain = (get_setting(db, "sub_domain") or "").strip()
    sub_domain_active = get_setting(db, "sub_domain_status") == "active"
    if sub_domain and sub_domain_active:
        return _dedicated_public_origin(
            sub_domain,
            _safe_port(get_setting(db, "sub_domain_port"), 443),
        )
    return _fallback_panel_origin(db, request_origin=request_origin)


def build_xray_sub_origin(db: Session, request_origin: str | None = None) -> str:
    domain = get_setting(db, "xray_sub_domain")
    active = get_setting(db, "xray_sub_domain_status") == "active"
    if domain and active:
        return _dedicated_public_origin(
            domain,
            _safe_port(get_setting(db, "xray_sub_domain_port"), 443),
        )
    return build_sub_origin(db, request_origin=request_origin)


def build_sub_link(db: Session, token: str, request_origin: str | None = None) -> str:
    if not token:
        return ""
    return f"{build_sub_origin(db, request_origin=request_origin)}/sub/{token}"


def build_xray_sub_link(db: Session, token: str, request_origin: str | None = None) -> str:
    if not token:
        return ""
    return f"{build_xray_sub_origin(db, request_origin=request_origin)}/api/sub/{token}/xray-sub"
