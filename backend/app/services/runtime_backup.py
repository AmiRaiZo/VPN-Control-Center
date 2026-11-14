from __future__ import annotations

import base64
import hashlib
import os
import stat
import subprocess
import shutil
import tempfile
from pathlib import Path
from typing import Iterable

# Files outside the SQL database that define the visible panel identity and the
# exact protocol/server identity delivered to existing clients.  These paths are
# intentionally explicit: restore must never be able to write an arbitrary path
# supplied by an uploaded JSON file.
RUNTIME_DIRECTORY_ROOTS: tuple[Path, ...] = (
    Path("/etc/letsencrypt"),
    Path("/etc/accel-ppp/sstp-certs"),
    Path("/etc/ocserv/ocserv-certs"),
    Path("/etc/ipsec.d/certs"),
    Path("/etc/ipsec.d/private"),
    Path("/etc/ipsec.d/cacerts"),
    Path("/etc/vpn-panel/xray"),
    # Back up the complete OpenVPN server runtime tree. Older versions only
    # allowed the CCD subdirectory while separately globbing server-extra-*
    # configs, which caused those legitimate configs to be collected and then
    # rejected as "outside the safe boundary". The whole server directory is
    # a fixed trusted restore root and contains every listener/extra-port/CCD
    # setting needed on controller and node servers.
    Path("/etc/openvpn/server"),
    Path("/etc/systemd/system/openvpn-server@.service.d"),
    Path("/etc/systemd/system/openvpn@.service.d"),
    Path("/etc/systemd/system/vpn-panel-node-register.service.d"),
    Path("/etc/systemd/resolved.conf.d"),
    Path("/var/lib/vpn-panel/branding"),
    Path("/opt/vpn-panel/data/telegram-media"),
)

RUNTIME_EXACT_PATHS: tuple[Path, ...] = (
    Path("/etc/nginx/sites-available/vpn-panel"),
    Path("/etc/nginx/sites-available/vpn-panel-sub"),
    Path("/etc/nginx/sites-available/vpn-panel-xray-sub"),
    Path("/etc/nginx/sites-enabled/vpn-panel"),
    Path("/etc/nginx/sites-enabled/vpn-panel-sub"),
    Path("/etc/nginx/sites-enabled/vpn-panel-xray-sub"),
    Path("/etc/nginx/sites-available/vpn-panel-recovery"),
    Path("/etc/nginx/sites-enabled/vpn-panel-recovery"),
    Path("/etc/nginx/vpn-panel-reject"),
    Path("/etc/default/xl2tpd"),
    Path("/etc/ppp/options.xl2tpd"),
    Path("/etc/xl2tpd/xl2tpd.conf"),
    Path("/etc/pptpd.conf"),
    Path("/etc/ppp/pptpd-options"),
    Path("/etc/ppp/chap-secrets"),
    Path("/etc/openvpn/server/server-udp.conf"),
    Path("/etc/openvpn/server/server-tcp.conf"),
    Path("/etc/openvpn/server-udp.conf"),
    Path("/etc/openvpn/server-tcp.conf"),
    Path("/etc/accel-ppp/sstp.conf"),
    Path("/etc/ipsec.conf"),
    Path("/etc/ipsec.secrets"),
    Path("/etc/strongswan.conf"),
    Path("/etc/ipsec.d/.ikev2-ssl-domain"),
    Path("/etc/ocserv/ocserv.conf"),
    Path("/etc/ocserv/ocpasswd"),
    Path("/etc/sysctl.d/99-vpn-panel.conf"),
    Path("/etc/sysctl.d/99-vpn-panel-forwarding.conf"),
    Path("/etc/sysctl.d/99-vpn-panel-routing.conf"),
    Path("/etc/modules-load.d/vpn-panel.conf"),
    Path("/etc/modules-load.d/l2tp.conf"),
    Path("/etc/vpn-panel-l2tp-interface"),
    Path("/etc/systemd/system/accel-ppp-sstp.service"),
    Path("/etc/systemd/system/vpn-panel-xray-vmess.service"),
    Path("/etc/systemd/system/vpn-panel-xray-vless.service"),
    Path("/etc/systemd/system/vpn-panel-node-register.service"),
    Path("/etc/systemd/system/vpn-panel-node-register.timer"),
    Path("/var/lib/vpn-panel/node-registration.env"),
)

RUNTIME_GLOBS: tuple[str, ...] = (
    "/etc/openvpn/server/server-extra-*.conf",
    "/etc/systemd/system/openvpn-server@server-extra-*.service.d/*",
)

MAX_RUNTIME_FILE_BYTES = 12 * 1024 * 1024
MAX_RUNTIME_BUNDLE_BYTES = 32 * 1024 * 1024


def _lexical(path: Path) -> Path:
    return Path(os.path.normpath(str(path)))


def _under(path: Path, root: Path) -> bool:
    path = _lexical(path)
    root = _lexical(root)
    return path == root or root in path.parents


def path_is_allowed(path: Path) -> bool:
    path = _lexical(path)
    if any(path == _lexical(item) for item in RUNTIME_EXACT_PATHS):
        return True
    return any(_under(path, root) for root in RUNTIME_DIRECTORY_ROOTS)


def _symlink_target_allowed(path: Path, target: str) -> bool:
    if not target or "\x00" in target:
        return False
    target_path = Path(target)
    candidate = target_path if target_path.is_absolute() else path.parent / target_path
    return path_is_allowed(_lexical(candidate))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _entry_for(path: Path, warnings: list[str], budget: list[int]) -> dict | None:
    try:
        info = path.lstat()
    except OSError as exc:
        warnings.append(f"خواندن فایل زمان بکاپ ناموفق بود: {path} ({exc})")
        return None

    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            warnings.append(f"خواندن لینک زمان بکاپ ناموفق بود: {path} ({exc})")
            return None
        if not _symlink_target_allowed(path, target):
            warnings.append(f"لینک خارج از محدوده امن در بکاپ رد شد: {path} -> {target}")
            return None
        return {"path": str(path), "type": "symlink", "target": target, "mode": _mode(path)}

    if stat.S_ISDIR(info.st_mode):
        return {"path": str(path), "type": "directory", "mode": _mode(path)}

    if not stat.S_ISREG(info.st_mode):
        warnings.append(f"فایل غیرعادی در بکاپ رد شد: {path}")
        return None

    size = int(info.st_size)
    if size > MAX_RUNTIME_FILE_BYTES:
        warnings.append(f"فایل بزرگ‌تر از حد مجاز بکاپ رد شد: {path} ({size} bytes)")
        return None
    if budget[0] + size > MAX_RUNTIME_BUNDLE_BYTES:
        warnings.append("حجم فایل‌های هویتی/تنظیماتی سرور از سقف امن بکاپ عبور کرد؛ بخشی از فایل‌ها وارد بکاپ نشد.")
        return None
    try:
        content = path.read_bytes()
    except OSError as exc:
        warnings.append(f"خواندن فایل زمان بکاپ ناموفق بود: {path} ({exc})")
        return None
    budget[0] += len(content)
    return {
        "path": str(path),
        "type": "file",
        "mode": _mode(path),
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "content_b64": base64.b64encode(content).decode("ascii"),
    }


def _iter_root(root: Path) -> Iterable[Path]:
    if root.is_symlink() or root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    yield root
    try:
        children = sorted(root.rglob("*"), key=lambda p: (len(p.parts), str(p)))
    except OSError:
        children = []
    for child in children:
        # pathlib.rglob does not recurse through directory symlinks, which is
        # exactly what a backup parser needs: preserve the link, never follow it.
        yield child


def export_runtime_bundle() -> tuple[dict, list[str]]:
    warnings: list[str] = []
    budget = [0]
    candidates: dict[str, Path] = {}

    for root in RUNTIME_DIRECTORY_ROOTS:
        for path in _iter_root(root):
            candidates[str(path)] = path
    for path in RUNTIME_EXACT_PATHS:
        if path.exists() or path.is_symlink():
            candidates[str(path)] = path
    for pattern in RUNTIME_GLOBS:
        for path in sorted(Path("/").glob(pattern.lstrip("/"))):
            candidates[str(path)] = path
            # Include a globbed directory's children as well.
            if path.is_dir() and not path.is_symlink():
                for child in _iter_root(path):
                    candidates[str(child)] = child

    entries: list[dict] = []
    for raw in sorted(candidates, key=lambda value: (len(Path(value).parts), value)):
        path = candidates[raw]
        if not path_is_allowed(path):
            warnings.append(f"مسیر خارج از محدوده امن در بکاپ رد شد: {path}")
            continue
        entry = _entry_for(path, warnings, budget)
        if entry is not None:
            entries.append(entry)

    return {
        "format": 1,
        "entries": entries,
        "file_bytes": budget[0],
        "entry_count": len(entries),
    }, warnings


def _remove_existing_for_replace(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists() and not path.is_dir():
        path.unlink(missing_ok=True)


def import_runtime_bundle(bundle: dict | None, *, replace_existing: bool = False) -> tuple[int, list[str]]:
    if not bundle:
        return 0, []
    if not isinstance(bundle, dict) or int(bundle.get("format") or 0) != 1:
        return 0, ["فرمت فایل‌های هویتی/تنظیماتی سرور پشتیبانی نمی‌شود."]
    raw_entries = bundle.get("entries")
    if not isinstance(raw_entries, list):
        return 0, ["لیست فایل‌های هویتی/تنظیماتی بکاپ معتبر نیست."]

    warnings: list[str] = []
    validated: list[tuple[Path, dict]] = []
    seen: set[str] = set()
    total = 0
    for raw in raw_entries:
        if not isinstance(raw, dict):
            warnings.append("یک ردیف نامعتبر از فایل‌های سرور رد شد.")
            continue
        path = _lexical(Path(str(raw.get("path") or "")))
        if not path.is_absolute() or str(path) in seen or not path_is_allowed(path):
            warnings.append(f"مسیر نامعتبر/تکراری فایل بکاپ رد شد: {path}")
            continue
        kind = str(raw.get("type") or "")
        if kind not in {"directory", "file", "symlink"}:
            warnings.append(f"نوع نامعتبر فایل بکاپ رد شد: {path}")
            continue
        if kind == "symlink" and not _symlink_target_allowed(path, str(raw.get("target") or "")):
            warnings.append(f"لینک ناامن فایل بکاپ رد شد: {path}")
            continue
        if kind == "file":
            try:
                content = base64.b64decode(str(raw.get("content_b64") or ""), validate=True)
            except Exception:
                warnings.append(f"محتوای base64 فایل بکاپ خراب است: {path}")
                continue
            expected_size = int(raw.get("size") or 0)
            expected_sha = str(raw.get("sha256") or "").lower()
            if len(content) != expected_size or hashlib.sha256(content).hexdigest() != expected_sha:
                warnings.append(f"هش/اندازه فایل بکاپ هم‌خوان نیست: {path}")
                continue
            if len(content) > MAX_RUNTIME_FILE_BYTES or total + len(content) > MAX_RUNTIME_BUNDLE_BYTES:
                warnings.append(f"حجم فایل بکاپ خارج از حد مجاز است: {path}")
                continue
            raw["_decoded"] = content
            total += len(content)
        seen.add(str(path))
        validated.append((path, raw))

    restored = 0
    if replace_existing:
        # Validation above is complete before anything is removed. Exact restore
        # clears only the hard-coded allowlist, never a path supplied by JSON.
        for path in sorted(RUNTIME_EXACT_PATHS, key=lambda item: len(item.parts), reverse=True):
            try:
                if path.is_symlink() or path.is_file():
                    path.unlink(missing_ok=True)
                elif path.exists() and not path.is_dir():
                    path.unlink(missing_ok=True)
            except OSError as exc:
                warnings.append(f"پاک‌سازی فایل قدیمی قبل از بازیابی ناموفق بود: {path} ({exc})")
        for root in sorted(RUNTIME_DIRECTORY_ROOTS, key=lambda item: len(item.parts), reverse=True):
            try:
                if root.is_symlink() or root.is_file():
                    root.unlink(missing_ok=True)
                elif root.exists():
                    shutil.rmtree(root)
            except OSError as exc:
                warnings.append(f"پاک‌سازی پوشه قدیمی قبل از بازیابی ناموفق بود: {root} ({exc})")

    # Directories first, then regular files, and symlinks last.
    for path, raw in sorted(
        (item for item in validated if item[1].get("type") == "directory"),
        key=lambda item: (len(item[0].parts), str(item[0])),
    ):
        try:
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                _remove_existing_for_replace(path)
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, int(raw.get("mode") or 0o755) & 0o777)
            restored += 1
        except OSError as exc:
            warnings.append(f"بازیابی پوشه ناموفق بود: {path} ({exc})")

    for path, raw in sorted(
        (item for item in validated if item[1].get("type") == "file"),
        key=lambda item: str(item[0]),
    ):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _remove_existing_for_replace(path)
            fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw["_decoded"])
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(tmp_name, int(raw.get("mode") or 0o600) & 0o777)
                os.replace(tmp_name, path)
            finally:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
            restored += 1
        except OSError as exc:
            warnings.append(f"بازیابی فایل ناموفق بود: {path} ({exc})")

    for path, raw in sorted(
        (item for item in validated if item[1].get("type") == "symlink"),
        key=lambda item: str(item[0]),
    ):
        target = str(raw.get("target") or "")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() or path.exists():
                if path.is_dir() and not path.is_symlink():
                    warnings.append(f"به‌دلیل وجود پوشه، لینک بکاپ جایگزین نشد: {path}")
                    continue
                path.unlink(missing_ok=True)
            os.symlink(target, path)
            restored += 1
        except OSError as exc:
            warnings.append(f"بازیابی لینک ناموفق بود: {path} ({exc})")

    return restored, warnings


def restart_restored_runtime() -> list[str]:
    """Best-effort reload after exact file restoration.

    Each service name has distro variants.  A failed optional unit is reported
    as a warning, not an exception, so the database restore can still finish and
    the operator receives the exact service that needs manual attention.
    """
    warnings: list[str] = []
    commands = (
        (["nginx", "-t"], "بررسی تنظیمات Nginx"),
        (["systemctl", "reload", "nginx"], "بارگذاری Nginx"),
        (["systemctl", "restart", "xl2tpd"], "L2TP"),
        (["systemctl", "restart", "pptpd"], "PPTP"),
        (["systemctl", "restart", "openvpn-server@server-udp"], "OpenVPN UDP"),
        (["systemctl", "restart", "openvpn-server@server-tcp"], "OpenVPN TCP"),
        (["systemctl", "restart", "accel-ppp-sstp"], "SSTP"),
        (["systemctl", "restart", "strongswan-starter"], "IKEv2/strongSwan"),
        (["systemctl", "restart", "ocserv"], "OpenConnect"),
    )
    for command, label in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            warnings.append(f"{label} بعد از بازیابی اجرا نشد: {exc}")
            continue
        if result.returncode != 0:
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()[-500:]
            warnings.append(f"{label} بعد از بازیابی ناموفق بود: {detail or 'exit ' + str(result.returncode)}")
    return warnings
