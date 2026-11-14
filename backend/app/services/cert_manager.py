"""
مدیریت سرتیفیکیت اختصاصی هر کاربر OpenVPN.

قبلاً همه‌ی کاربران با یک CA/tls-auth مشترک و فقط یوزر/پس وصل می‌شدند
(verify-client-cert none). این ماژول برای هر کاربر یک سرتیفیکیت کلاینت
جداگانه (امضاشده با همان CA سرور، از طریق easy-rsa) می‌سازد تا:
  - سرور OpenVPN واقعاً یک سرتیفیکیت معتبر از هر کلاینت بخواهد
    (server.conf دیگر verify-client-cert none ندارد)
  - در صورت حذف کاربر، سرتیفیکیتش هم باطل (revoke) شود و از طریق CRL
    دیگر قابل استفاده نباشد، حتی اگر فایل .ovpn قبلی هنوز دست کاربر باشد.

توجه: سرتیفیکیت همیشه لازم است و به‌تنهایی کافی است؛ یوزر/پس یک لایه‌ی
اضافه‌ی اختیاری است که به‌ازای هر کاربر روشن/خاموش می‌شود (VpnUser.openvpn_auth_mode،
ببینید vpn_manager.build_client_ovpn و openvpn_auth.sh). چک‌های
enable/فعال‌بودن/انقضا/حجم/تعداد دستگاه هم جدا در client-connect
(openvpn_connect.sh -> API داخلی) انجام می‌شود، نه بخشی از خودِ احراز هویت TLS.
"""
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

import requests
from pathlib import Path

from app.config import get_settings
from app.proc_utils import BASH

settings = get_settings()


class CertError(Exception):
    pass


def _easyrsa_dir() -> str:
    return settings.EASYRSA_DIR


def _cert_path(username: str) -> str:
    return os.path.join(_easyrsa_dir(), "pki", "issued", f"{username}.crt")


def _key_path(username: str) -> str:
    return os.path.join(_easyrsa_dir(), "pki", "private", f"{username}.key")


def _remove_fixed_req_cn_from_vars() -> None:
    """Remove a CA-only EASYRSA_REQ_CN override from an existing vars file.

    EasyRSA's ``build-client-full <name>`` already receives the client common
    name as a positional argument. A persistent ``EASYRSA_REQ_CN`` left in
    ``vars`` makes EasyRSA 3.1.x reject that command as two competing common
    names. The CA has already been created at this point, so keeping that
    override is unnecessary and breaks every future client certificate.
    """
    vars_path = os.path.join(_easyrsa_dir(), "vars")
    if not os.path.isfile(vars_path):
        return
    try:
        original = Path(vars_path).read_text()
    except OSError:
        return
    filtered = "\n".join(
        line for line in original.splitlines()
        if not re.search(r"(?:^|\s)(?:set_var\s+)?EASYRSA_REQ_CN(?:\s|=)", line)
    )
    if original.endswith("\n"):
        filtered += "\n"
    if filtered == original:
        return
    fd, temp_path = tempfile.mkstemp(prefix=".vars-vpn-panel-", dir=_easyrsa_dir(), text=True)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(filtered)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, os.stat(vars_path).st_mode & 0o777)
        except OSError:
            pass
        os.replace(temp_path, vars_path)
    finally:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass


def _remove_partial_client_request(username: str) -> None:
    """Clean only incomplete client artifacts before retrying certificate creation."""
    if os.path.exists(_cert_path(username)):
        return
    candidates = (
        os.path.join(_easyrsa_dir(), "pki", "reqs", f"{username}.req"),
        os.path.join(_easyrsa_dir(), "pki", "private", f"{username}.key"),
        os.path.join(_easyrsa_dir(), "pki", "inline", f"{username}.inline"),
    )
    for path in candidates:
        try:
            if os.path.isfile(path):
                os.unlink(path)
        except OSError:
            pass


def has_client_cert(username: str) -> bool:
    return os.path.exists(_cert_path(username)) and os.path.exists(_key_path(username))


def _clean_pem(raw: str, begin_marker: str) -> str:
    """easy-rsa فایل صادرشده را همراه با متن خوانای openssl (Certificate:
    Data: ...) قبل از خودِ PEM ذخیره می‌کند. اکثر کلاینت‌های دسکتاپ این متن
    اضافه را نادیده می‌گیرند، ولی برخی کلاینت‌های موبایل (OpenVPN Connect)
    روی پارس‌کردنش سخت‌گیرند و کل کانفیگ را رد می‌کنند. این تابع فقط همان
    بلوک PEM واقعی (بین BEGIN و END) را نگه می‌دارد."""
    start = raw.find(begin_marker)
    if start == -1:
        return raw.strip()
    end_marker = begin_marker.replace("BEGIN", "END")
    end = raw.find(end_marker, start)
    if end == -1:
        return raw[start:].strip()
    end += len(end_marker)
    return raw[start:end].strip() + "\n"


def read_client_cert(username: str) -> tuple[str, str] | None:
    """برگرداندن (cert_pem, key_pem) اگر سرتیفیکیت این کاربر از قبل ساخته شده باشد.
    خروجی همیشه یک PEM تمیز است (بدون متن توضیحی openssl)."""
    if not has_client_cert(username):
        return None
    with open(_cert_path(username)) as f:
        cert_pem = _clean_pem(f.read(), "-----BEGIN CERTIFICATE-----")
    with open(_key_path(username)) as f:
        raw_key = f.read()
        key_begin = "-----BEGIN PRIVATE KEY-----" if "-----BEGIN PRIVATE KEY-----" in raw_key \
            else "-----BEGIN RSA PRIVATE KEY-----"
        key_pem = _clean_pem(raw_key, key_begin)
    return cert_pem, key_pem



def validate_client_cert_pair(username: str) -> tuple[bool, str]:
    """Validate that the stored client cert/key are a usable canonical pair.

    A backup restore or an old multi-node release can leave two syntactically
    valid PEM files that do not belong together, are signed by a previous CA,
    are expired, or no longer match the active EasyRSA serial.  Embedding such
    files produces an .ovpn download that looks correct but fails during TLS.
    """
    cert_path = _cert_path(username)
    key_path = _key_path(username)
    ca_path = settings.OPENVPN_CA_PATH
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        return False, "missing_cert_or_key"
    openssl = shutil.which("openssl")
    if not openssl:
        # Installation requires OpenSSL, but fail closed if the binary vanished.
        return False, "openssl_not_found"

    def _run(args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [openssl, *args], capture_output=True, text=True,
            timeout=20, check=False,
        )

    try:
        cert_pub = _run(["x509", "-in", cert_path, "-pubkey", "-noout"])
        key_pub = _run(["pkey", "-in", key_path, "-pubout"])
        if cert_pub.returncode != 0 or key_pub.returncode != 0:
            return False, "invalid_pem"
        normalize = lambda value: "".join(str(value or "").split())
        if normalize(cert_pub.stdout) != normalize(key_pub.stdout):
            return False, "certificate_private_key_mismatch"

        expiry = _run(["x509", "-in", cert_path, "-checkend", "0", "-noout"])
        if expiry.returncode != 0:
            return False, "certificate_expired"

        if not os.path.isfile(ca_path):
            return False, "canonical_ca_missing"
        verified = _run(["verify", "-CAfile", ca_path, cert_path])
        if verified.returncode != 0:
            return False, "certificate_not_signed_by_canonical_ca"

        subject = _run(["x509", "-in", cert_path, "-noout", "-subject", "-nameopt", "RFC2253"])
        if subject.returncode != 0:
            return False, "certificate_subject_unreadable"
        # Usernames are restricted by the API; an exact CN check prevents a
        # restored file from authenticating under another database identity.
        subject_text = str(subject.stdout or "").strip()
        if not re.search(rf"(?:^|,)CN={re.escape(username)}(?:,|$)", subject_text.replace("subject=", "")):
            return False, "certificate_common_name_mismatch"

        active_serial = _active_client_index_serial(username)
        if active_serial:
            serial_result = _run(["x509", "-in", cert_path, "-noout", "-serial"])
            if serial_result.returncode != 0 or "=" not in serial_result.stdout:
                return False, "certificate_serial_unreadable"
            file_serial = serial_result.stdout.split("=", 1)[1].strip().lstrip("0").upper() or "0"
            index_serial = str(active_serial).strip().lstrip("0").upper() or "0"
            if file_serial != index_serial:
                return False, "certificate_active_serial_mismatch"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"openssl_validation_failed:{type(exc).__name__}"
    return True, "ok"


def read_client_public_cert(username: str) -> str | None:
    """Return only the public client certificate when it exists.

    OpenVPN servers never need a copy of a client private key to keep an
    already-issued client profile working.  Keeping this helper separate from
    :func:`read_client_cert` lets disaster-recovery backups preserve the
    public certificate/serial state without incorrectly treating a missing
    server-side copy of the *client-owned* private key as server data loss.
    """
    path = Path(_cert_path(username))
    if not path.is_file():
        return None
    try:
        return _clean_pem(path.read_text(encoding="utf-8", errors="replace"), "-----BEGIN CERTIFICATE-----")
    except OSError:
        return None


def _active_client_index_serial(username: str) -> str | None:
    """Return the EasyRSA serial for the active certificate of ``username``.

    EasyRSA keeps the authoritative issued/revoked state in ``pki/index.txt``.
    A client certificate may still be recoverable from ``certs_by_serial`` when
    the friendly ``pki/issued/<username>.crt`` file was accidentally removed.
    """
    index_path = Path(_easyrsa_dir()) / "pki" / "index.txt"
    try:
        lines = index_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    expected = f"/CN={username}"
    for line in reversed(lines):
        fields = line.split("\t")
        if len(fields) < 6 or fields[0].strip().upper() != "V":
            continue
        subject = fields[-1].strip()
        if subject == expected or subject.endswith(expected):
            serial = fields[3].strip()
            return serial or None
    return None


def _recover_client_cert_from_archive(username: str) -> bool:
    """Recover a missing friendly cert file without rotating the user's key.

    EasyRSA stores a second copy of every issued certificate under its serial.
    Restoring that copy preserves the exact certificate already embedded in an
    existing .ovpn profile and is therefore safe to perform during backup.
    """
    cert_path = Path(_cert_path(username))
    if cert_path.is_file():
        return True
    serial = _active_client_index_serial(username)
    if not serial:
        return False
    archive = Path(_easyrsa_dir()) / "pki" / "certs_by_serial"
    candidates = []
    for value in {serial, serial.upper(), serial.lower()}:
        candidates.extend((archive / f"{value}.pem", archive / f"{value}.crt"))
    source = next((item for item in candidates if item.is_file()), None)
    if source is None:
        return False
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    raw = source.read_text(encoding="utf-8", errors="replace")
    cert_path.write_text(_clean_pem(raw, "-----BEGIN CERTIFICATE-----"), encoding="utf-8")
    try:
        cert_path.chmod(0o644)
    except OSError:
        pass
    return True


def export_client_cert_backup_record(username: str) -> dict | None:
    """Describe an active client certificate for a full backup.

    A client private key is client-owned material.  Older panel versions kept a
    convenience copy on the server so the same profile could be downloaded
    again, but OpenVPN does not need that private key to authenticate an
    existing profile after server restore.  Therefore an active EasyRSA serial
    plus the controller PKI/index/CRL is sufficient for continuity.

    The returned record is intentionally metadata/public-certificate only.  It
    allows restore diagnostics and a later explicit profile reissue without
    downgrading the whole fleet backup merely because the convenience key copy
    is gone.
    """
    serial = _active_client_index_serial(username)
    if not serial:
        return None
    _recover_client_cert_from_archive(username)
    public_cert = read_client_public_cert(username)
    return {
        "status": "active",
        "serial": serial,
        "certificate": public_cert,
        "server_private_key_present": Path(_key_path(username)).is_file(),
        "existing_profiles_remain_valid": True,
        "profile_reissue_required_for_redownload": not Path(_key_path(username)).is_file(),
    }


def repair_or_generate_client_cert(username: str) -> tuple[tuple[str, str], str]:
    """Return a complete client cert/key pair, repairing safe cases first.

    Result status is one of ``existing``, ``recovered`` or ``generated``.
    A valid EasyRSA index entry with a missing private key is *not* rotated
    automatically: revoking it during a backup would immediately break the
    user's currently installed .ovpn file. In that rare case the caller gets a
    precise error and the administrator can intentionally regenerate/download
    a new profile.
    """
    existing = read_client_cert(username)
    if existing:
        valid, detail = validate_client_cert_pair(username)
        if valid:
            return existing, "existing"
        if _active_client_index_serial(username):
            raise CertError(f"جفت سرتیفیکیت/کلید OpenVPN معتبر نیست: {detail}")
        # No authoritative active record points at these broken leftovers; the
        # cleanup/generation path below can replace them safely.

    if _recover_client_cert_from_archive(username):
        recovered = read_client_cert(username)
        if recovered:
            valid, detail = validate_client_cert_pair(username)
            if valid:
                return recovered, "recovered"
            if _active_client_index_serial(username):
                raise CertError(f"سرتیفیکیت بازیابی‌شده OpenVPN معتبر نیست: {detail}")

    active_serial = _active_client_index_serial(username)
    if active_serial:
        missing = []
        if not os.path.isfile(_cert_path(username)):
            missing.append("سرتیفیکیت")
        if not os.path.isfile(_key_path(username)):
            missing.append("کلید خصوصی")
        raise CertError(
            "برای این کاربر یک رکورد فعال EasyRSA وجود دارد، اما "
            + " و ".join(missing or ["فایل‌های سرتیفیکیت"])
            + " روی سرور قابل بازیابی امن نیست. برای رفع قطعی، پروفایل OpenVPN جدید را دانلود کنید تا گواهی جایگزین صادر شود."
        )

    # No active issued record exists, so incomplete leftovers are not usable by
    # any current profile and may be removed before issuing the first cert.
    for candidate in (
        _cert_path(username),
        _key_path(username),
        os.path.join(_easyrsa_dir(), "pki", "reqs", f"{username}.req"),
        os.path.join(_easyrsa_dir(), "pki", "inline", f"{username}.inline"),
    ):
        try:
            if os.path.isfile(candidate):
                os.unlink(candidate)
        except OSError:
            pass

    generated = generate_client_cert(username)
    return generated, "generated"


def write_client_cert(username: str, cert_pem: str, key_pem: str):
    """نوشتن مستقیم سرتیفیکیت/کلید یک کاربر (بدون ساخت تازه با easy-rsa) -
    برای بازیابی بکاپ، وقتی سرتیفیکیت خودِ همان کاربر از سرور مبدا در دسترس
    است. برخلاف generate_client_cert اصلاً به CA/index.txt سرور دست نمی‌زند؛
    فقط فایل‌های cert/key این یک کاربر را می‌نویسد (باید بعد از
    import_pki_bundle صدا زده شود تا CA/index.txt سرور مقصد از قبل با همین
    سرتیفیکیت سازگار شده باشد، وگرنه بعداً revoke همین کاربر ممکن است
    نتواند سریال متناظرش را در index.txt پیدا کند)."""
    os.makedirs(os.path.dirname(_cert_path(username)), exist_ok=True)
    os.makedirs(os.path.dirname(_key_path(username)), exist_ok=True)
    with open(_cert_path(username), "w") as f:
        f.write(cert_pem)
    with open(_key_path(username), "w") as f:
        f.write(key_pem)
    os.chmod(_key_path(username), 0o600)


# ---------------------------------------------------------------------------
# انتقال کامل PKI بین سرورها (برای بکاپ/بازیابی)
#
# مشکلی که این بخش حل می‌کند: هر نصب تازه‌ی پنل (install.sh) یک CA کاملاً
# جدید و تصادفی برای OpenVPN می‌سازد. یعنی اگر فقط دیتابیس (یوزرها/ادمین‌ها)
# را به سرور دیگری منتقل کنیم و سرتیفیکیت هر کاربر را از نو با CA سرور مقصد
# بسازیم (کاری که قبلاً در routers/backup.py انجام می‌شد)، هر فایل .ovpn ای
# که کاربر از قبل از سرور مبدا دانلود کرده بود دیگر کار نمی‌کند - چون آن
# فایل، سرتیفیکیت CA سرور مبدا را داخل خودش دارد و سرور مقصد آن را
# نمی‌شناسد. راه‌حل: کل PKI (کلید خصوصی CA، سرتیفیکیت/کلید خودِ سرور، dh،
# ta.key، CRL و دفترداری easy-rsa) عیناً از سرور مبدا به مقصد کپی می‌شود -
# بعد از این کار سرور مقصد دقیقاً همان CA سرور مبدا را دارد و همه‌ی
# فایل‌های .ovpn قدیمی (و PSK/رمز عبور L2TP-PPTP که جداگانه در بکاپ هست)
# بدون نیاز به دانلود دوباره کار می‌کنند.
# ---------------------------------------------------------------------------

# (bundle_key, مسیر نسبی به EASYRSA_DIR, آیا برای یک PKI معتبر الزامی است)
_PKI_FILES = [
    ("ca_cert", os.path.join("pki", "ca.crt"), True),
    ("ca_key", os.path.join("pki", "private", "ca.key"), True),
    ("server_cert", os.path.join("pki", "issued", "server.crt"), True),
    ("server_key", os.path.join("pki", "private", "server.key"), True),
    ("dh", os.path.join("pki", "dh.pem"), True),
    ("ta_key", "ta.key", True),
    ("crl", os.path.join("pki", "crl.pem"), True),
    # فایل‌های دفترداری easy-rsa: برای build/revoke آینده لازم‌اند ولی نبودشان
    # نباید کل export را متوقف کند (نسخه‌های قدیمی‌تر easy-rsa اسم‌های کمی
    # متفاوت دارند)
    ("index", os.path.join("pki", "index.txt"), False),
    ("index_attr", os.path.join("pki", "index.txt.attr"), False),
    ("serial", os.path.join("pki", "serial"), False),
    ("crlnumber", os.path.join("pki", "crlnumber"), False),
]

# بعد از نوشتن در خودِ دایرکتوری easy-rsa، همین فایل‌ها باید در مسیرهای
# واقعی‌ای هم که خودِ پروسه‌ی OpenVPN از آن‌ها می‌خواند (install.sh، بخش cp)
# بازنویسی شوند - وگرنه تا ری‌استارت بعدی نصب دستی، سرور همچنان CA قدیمی
# خودش را استفاده می‌کند.
_PKI_DEPLOY_PATHS = {
    "server_cert": "/etc/openvpn/server/server.crt",
    "server_key": "/etc/openvpn/server/server.key",
    "dh": "/etc/openvpn/server/dh.pem",
}


def validate_pki_bundle(bundle: dict | None) -> tuple[bool, str]:
    """Validate the controller-wide OpenVPN PKI snapshot.

    A combined profile can safely fail over between any number of nodes only
    when all of them trust the same CA and use the same tls-auth key.  The
    controller therefore owns one canonical full EasyRSA bundle and mirrors it
    to every node.  This validator is intentionally strict before private CA
    material received from a node is adopted as that canonical bundle.
    """
    if not isinstance(bundle, dict):
        return False, "bundle_not_object"
    required = {key for key, _rel, is_required in _PKI_FILES if is_required}
    missing = sorted(key for key in required if not str(bundle.get(key) or "").strip())
    if missing:
        return False, "missing:" + ",".join(missing)
    markers = {
        "ca_cert": "-----BEGIN CERTIFICATE-----",
        "ca_key": "-----BEGIN",
        "server_cert": "-----BEGIN CERTIFICATE-----",
        "server_key": "-----BEGIN",
        "dh": "-----BEGIN DH PARAMETERS-----",
    }
    for key, marker in markers.items():
        if marker not in str(bundle.get(key) or ""):
            return False, f"invalid_{key}"
    ta_key = str(bundle.get("ta_key") or "")
    if "OpenVPN Static key V1" not in ta_key:
        return False, "invalid_ta_key"
    return True, "ok"


def pki_bundle_fingerprint(bundle: dict | None) -> str:
    valid, _detail = validate_pki_bundle(bundle)
    if not valid:
        return ""
    # Only public CA + tls-auth are required to match for one client profile to
    # authenticate everywhere.  Including the full bundle hash is useful for
    # runtime reload bookkeeping, but this compact public fingerprint is stable
    # and safe to expose in diagnostics.
    public = {
        "ca_cert": str(bundle.get("ca_cert") or ""),
        "ta_key": str(bundle.get("ta_key") or ""),
    }
    return hashlib.sha256(
        json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _ensure_easyrsa_pki_layout() -> None:
    """Restore the complete EasyRSA directory skeleton safely.

    Controller-wide PKI synchronization serializes files, not empty
    directories.  EasyRSA validates more than ``pki/reqs`` before issuing a
    certificate: a CA workspace also needs ``pki/certs_by_serial`` and newer
    EasyRSA releases use several revoked/renewed subdirectories.  Recreate the
    standard directory tree without calling ``init-pki`` so existing CA keys,
    serials, indexes and certificates are never rotated or overwritten.
    """
    base = Path(_easyrsa_dir()) / "pki"
    public_dirs = (
        "issued",
        "reqs",
        "certs_by_serial",
        "inline",
        "expired",
        "revoked",
        "revoked/certs_by_serial",
        "revoked/reqs_by_serial",
        "renewed",
        "renewed/issued",
        "renewed/certs_by_serial",
    )
    private_dirs = (
        "private",
        "revoked/private_by_serial",
    )
    for relative in public_dirs:
        path = base / relative
        path.mkdir(parents=True, exist_ok=True)
    for relative in private_dirs:
        path = base / relative
        path.mkdir(parents=True, exist_ok=True)
        try:
            path.chmod(0o700)
        except OSError:
            pass


def _prepare_easyrsa_workspace() -> None:
    base = Path(_easyrsa_dir())
    if (base / "easyrsa").exists():
        _ensure_easyrsa_pki_layout()
        return
    base.parent.mkdir(parents=True, exist_ok=True)
    make_cadir = shutil.which("make-cadir")
    if make_cadir:
        result = subprocess.run(
            [make_cadir, str(base)], capture_output=True, text=True, timeout=30, check=False
        )
        if result.returncode == 0 and (base / "easyrsa").exists():
            return
    source = Path("/usr/share/easy-rsa")
    if source.exists():
        if base.exists():
            shutil.rmtree(base)
        shutil.copytree(source, base)
    if not (base / "easyrsa").exists():
        raise CertError("ابزار EasyRSA روی کنترلر نصب نیست")
    _ensure_easyrsa_pki_layout()


def _adopt_pki_from_active_node(db) -> tuple[dict[str, str] | None, object | None]:
    """Fetch one existing node PKI to preserve already-issued profiles.

    This is mainly an upgrade bridge for management-only controllers from old
    releases: those controllers had no local EasyRSA directory, so every node
    created a different CA.  The first reachable node becomes the canonical
    source once; the exact bundle is then pushed to all remaining nodes.
    """
    from app.models import VpnNode

    nodes = db.query(VpnNode).filter(VpnNode.enabled == True).order_by(  # noqa: E712
        VpnNode.status.desc(), VpnNode.weight.desc(), VpnNode.id
    ).all()
    for node in nodes:
        try:
            response = requests.get(
                f"{str(node.api_url).rstrip('/')}/api/node-agent/openvpn-pki/export",
                headers={"X-Node-Token": str(node.api_token or "")},
                timeout=20,
                verify=bool(getattr(node, "verify_tls", True)),
            )
            response.raise_for_status()
            payload = response.json()
            bundle = payload.get("openvpn_pki") if isinstance(payload, dict) else None
            valid, _detail = validate_pki_bundle(bundle)
            if valid:
                return bundle, node
        except Exception:
            continue
    return None, None


def ensure_controller_openvpn_pki(db, *, allow_generate: bool = True) -> dict[str, str]:
    """Return the canonical controller PKI, adopting/generating it if needed.

    Order is deliberate:
      1. Keep an existing controller PKI unchanged.
      2. On upgrades, adopt a reachable node's PKI so old .ovpn files continue
         to work instead of silently rotating the CA/tls-auth key.
      3. On a fresh controller with no nodes, generate one canonical PKI.

    The fresh generator is a small installer helper so package/bootstrap logic
    stays outside the API process.
    """
    current = export_pki_bundle()
    valid, _detail = validate_pki_bundle(current)
    if valid:
        return current  # type: ignore[return-value]

    bundle, source_node = _adopt_pki_from_active_node(db)
    if bundle:
        _prepare_easyrsa_workspace()
        warnings = import_pki_bundle(bundle)
        current = export_pki_bundle()
        valid, detail = validate_pki_bundle(current)
        if not valid:
            source_name = str(getattr(source_node, "name", "node"))
            raise CertError(f"پذیرش PKI نود «{source_name}» کامل نشد: {detail}; {'; '.join(warnings)}")
        # Do not mark even the source node compatible yet. The following full
        # controller sync deliberately restarts its OpenVPN daemons and only the
        # node's runtime acknowledgement can make it eligible for the combined
        # profile.
        return current  # type: ignore[return-value]

    if not allow_generate:
        raise CertError("PKI مشترک OpenVPN روی کنترلر وجود ندارد و هیچ نود قابل دسترسی برای بازیابی آن پیدا نشد")

    # Never rotate an established fleet merely because all nodes are offline or
    # still run an older release without the private export endpoint.  That
    # would invalidate every previously downloaded profile.  The safe recovery
    # is to update/reconnect at least one node first, adopt its existing PKI, and
    # then fan it out to the rest. Fresh controllers have no node rows and may
    # generate a new canonical bundle normally.
    from app.models import VpnNode
    if db.query(VpnNode).filter(VpnNode.enabled == True).count():  # noqa: E712
        raise CertError(
            "نود فعال ثبت شده است اما PKI آن قابل دریافت نیست؛ ابتدا حداقل یک نود را به نسخه جدید آپدیت و آنلاین کنید تا کلیدهای قبلی حفظ شوند"
        )

    helper = Path("/opt/vpn-panel/scripts/ensure_openvpn_controller_pki.sh")
    if not helper.exists():
        # Development/test tree fallback. Production updates deploy the helper
        # to /opt before this function is called.
        helper = Path(__file__).resolve().parents[3] / "install" / "ensure_openvpn_controller_pki.sh"
    result = subprocess.run(
        [str(helper), "--generate-if-missing"],
        capture_output=True, text=True, timeout=900, check=False,
    )
    if result.returncode != 0:
        detail = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
        raise CertError(f"ساخت PKI مشترک OpenVPN ناموفق بود: {detail[-1200:]}")
    current = export_pki_bundle()
    valid, detail = validate_pki_bundle(current)
    if not valid:
        raise CertError(f"PKI مشترک OpenVPN بعد از ساخت معتبر نیست: {detail}")
    return current  # type: ignore[return-value]


def export_pki_bundle() -> dict[str, str] | None:
    """خواندن کل PKI سرور OpenVPN این سرور. اگر یکی از فایل‌های الزامی پیدا
    نشود (یعنی OpenVPN اصلاً روی این سرور نصب نشده) None برمی‌گرداند."""
    base = _easyrsa_dir()
    bundle: dict[str, str] = {}
    for key, rel, required in _PKI_FILES:
        path = os.path.join(base, rel)
        if not os.path.exists(path):
            if required:
                return None
            continue
        with open(path) as f:
            bundle[key] = f.read()
    return bundle


def import_pki_bundle(bundle: dict) -> list[str]:
    """نوشتن یک PKI کامل (خروجی export_pki_bundle سرور مبدا) روی این سرور -
    هم در خودِ دایرکتوری easy-rsa و هم در مسیرهای واقعی‌ای که OpenVPN از
    آن‌ها می‌خواند. CA/سرتیفیکیت سرور قبلیِ همین سرور کاملاً بازنویسی
    می‌شود. سرویس OpenVPN را خودش ری‌استارت نمی‌کند - این کار به عهده‌ی
    صدازننده (routers/backup.py) است. خروجی: لیست هشدارها."""
    warnings: list[str] = []
    base = _easyrsa_dir()
    if not os.path.exists(os.path.join(base, "easyrsa")):
        return ["easy-rsa روی این سرور پیدا نشد؛ بازیابی PKI انجام نشد (پنل درست نصب شده؟)"]

    for key, rel, required in _PKI_FILES:
        content = bundle.get(key)
        if content is None:
            if required:
                warnings.append(f"فایل PKI «{key}» در بکاپ نبود؛ نادیده گرفته شد")
            continue
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        if key in ("ca_key", "server_key"):
            os.chmod(path, 0o600)

    for key, deploy_path in _PKI_DEPLOY_PATHS.items():
        content = bundle.get(key)
        if content is None:
            continue
        os.makedirs(os.path.dirname(deploy_path), exist_ok=True)
        with open(deploy_path, "w") as f:
            f.write(content)
        os.chmod(deploy_path, 0o600 if key == "server_key" else 0o644)

    # ca.crt/ta.key/crl.pem مقصدشان از قبل در config.py مشخص است (همان
    # چیزی که build_client_ovpn و خودِ سرور OpenVPN می‌خوانند)
    deploy_from_settings = {
        "ca_cert": settings.OPENVPN_CA_PATH,
        "ta_key": settings.OPENVPN_TA_PATH,
        "crl": settings.OPENVPN_CRL_PATH,
    }
    for key, deploy_path in deploy_from_settings.items():
        content = bundle.get(key)
        if content is None:
            continue
        os.makedirs(os.path.dirname(deploy_path), exist_ok=True)
        with open(deploy_path, "w") as f:
            f.write(content)
        os.chmod(deploy_path, 0o644)

    # Empty EasyRSA directories are not represented in the JSON bundle.
    # Restore them immediately so the controller can issue client certificates
    # without requiring a manual ``easyrsa init-pki`` (which would be unsafe on
    # an already populated PKI).
    _ensure_easyrsa_pki_layout()
    return warnings


def generate_client_cert(username: str) -> tuple[str, str]:
    """ساخت سرتیفیکیت جدید برای کاربر (اگر از قبل وجود داشته باشد، همان را
    برمی‌گرداند - عملیات idempotent است). با easy-rsa و همان CA سروری که
    موقع نصب پنل ساخته شده کار می‌کند."""
    existing = read_client_cert(username)
    if existing:
        return existing

    easyrsa_bin = os.path.join(_easyrsa_dir(), "easyrsa")
    if not os.path.exists(easyrsa_bin):
        raise CertError("easy-rsa روی سرور پیدا نشد (پنل درست نصب نشده؟)")

    lock_path = os.path.join(_easyrsa_dir(), ".vpn-panel-client-cert.lock")
    os.makedirs(_easyrsa_dir(), exist_ok=True)
    with open(lock_path, "a+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        # Another request may have created the same certificate while this
        # request was waiting for the EasyRSA lock.
        existing = read_client_cert(username)
        if existing:
            return existing

        _ensure_easyrsa_pki_layout()
        _remove_fixed_req_cn_from_vars()
        _remove_partial_client_request(username)
        env = os.environ.copy()
        env.pop("EASYRSA_REQ_CN", None)
        env["EASYRSA_BATCH"] = "1"
        result = subprocess.run(
            [BASH, easyrsa_bin, "--batch", "build-client-full", username, "nopass"],
            cwd=_easyrsa_dir(),
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode != 0:
            detail = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
            raise CertError(f"ساخت سرتیفیکیت ناموفق بود: {detail[-1200:]}")

    cert = read_client_cert(username)
    if not cert:
        raise CertError("سرتیفیکیت ساخته شد ولی فایل آن روی دیسک پیدا نشد")
    return cert



def _revoke_active_client_index_record(username: str) -> bool:
    """Revoke an active EasyRSA index row when its cert file was lost.

    ``easyrsa revoke`` normally needs the issued certificate file.  A damaged
    installation can still have the authoritative active row in ``index.txt``
    while both the friendly certificate and serial archive copy are missing.
    In that exact case an explicit profile-download request must be able to
    retire the old serial and issue a replacement.  Updating the OpenSSL index
    under the same per-client lock and then regenerating the CRL is equivalent
    to the bookkeeping EasyRSA performs during revoke, without fabricating a
    private key or silently rotating credentials during background backup.
    """
    index_path = Path(_easyrsa_dir()) / "pki" / "index.txt"
    easyrsa_bin = Path(_easyrsa_dir()) / "easyrsa"
    if not index_path.is_file() or not easyrsa_bin.is_file():
        return False

    lock_path = Path(_easyrsa_dir()) / ".vpn-panel-client-cert.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            raw_lines = index_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            expected = f"/CN={username}"
            changed = False
            for idx in range(len(raw_lines) - 1, -1, -1):
                line = raw_lines[idx]
                newline = "\n" if line.endswith("\n") else ""
                fields = line.rstrip("\r\n").split("\t")
                if len(fields) < 6 or fields[0].strip().upper() != "V":
                    continue
                subject = fields[-1].strip()
                if subject != expected and not subject.endswith(expected):
                    continue
                fields[0] = "R"
                fields[2] = datetime.now(timezone.utc).strftime("%y%m%d%H%M%SZ")
                raw_lines[idx] = "\t".join(fields) + newline
                changed = True
                break
            if not changed:
                return _active_client_index_serial(username) is None

            fd, tmp_name = tempfile.mkstemp(prefix=".index-vpn-panel-", dir=str(index_path.parent), text=True)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.writelines(raw_lines)
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    os.chmod(tmp_name, index_path.stat().st_mode & 0o777)
                except OSError:
                    pass
                os.replace(tmp_name, index_path)
            finally:
                try:
                    if os.path.exists(tmp_name):
                        os.unlink(tmp_name)
                except OSError:
                    pass

            result = subprocess.run(
                [BASH, str(easyrsa_bin), "--batch", "gen-crl"],
                cwd=_easyrsa_dir(),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                detail = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
                raise CertError(f"بازسازی CRL پس از ابطال رکورد قدیمی ناموفق بود: {detail[-1000:]}")
            crl_src = Path(_easyrsa_dir()) / "pki" / "crl.pem"
            if crl_src.is_file():
                crl_dst = Path(settings.OPENVPN_CRL_PATH)
                crl_dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(crl_src, crl_dst)
                try:
                    crl_dst.chmod(0o644)
                except OSError:
                    pass
            return True
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def get_client_profile_credentials(username: str) -> tuple[str, str, str]:
    """Return one stable client cert/key pair for every downloadable profile.

    The combined profile and every per-node profile for a user must embed the
    *same* certificate and private key.  Older releases could enter this repair
    path concurrently from several download buttons; one request could revoke
    the certificate while another request was still building a file, leaving a
    freshly downloaded profile invalid.  A dedicated profile-issuance lock now
    serializes the complete inspect/repair/reissue transaction.

    The status is one of ``existing``, ``recovered``, ``generated`` or
    ``reissued``.  Callers use it to synchronize the updated EasyRSA index/CRL
    to every node only when PKI state actually changed.
    """
    lock_path = os.path.join(_easyrsa_dir(), ".vpn-panel-profile-download.lock")
    os.makedirs(_easyrsa_dir(), exist_ok=True)
    with open(lock_path, "a+") as profile_lock:
        fcntl.flock(profile_lock.fileno(), fcntl.LOCK_EX)
        try:
            try:
                pair, status = repair_or_generate_client_cert(username)
                return pair[0], pair[1], status
            except CertError:
                active_serial = _active_client_index_serial(username)
                if not active_serial:
                    raise

            # Revoke normally uses the issued public certificate.  If even the
            # serial archive copy is gone, retire the authoritative EasyRSA
            # index row directly and regenerate the CRL before issuing a new
            # certificate.  This is an explicit download action, never a
            # background backup repair.
            _recover_client_cert_from_archive(username)
            revoke_client_cert(username)
            if _active_client_index_serial(username):
                if not _revoke_active_client_index_record(username):
                    raise CertError("رکورد فعال قبلی OpenVPN قابل ابطال امن نبود؛ صدور پروفایل جدید متوقف شد")
            for candidate in (
                _cert_path(username),
                _key_path(username),
                os.path.join(_easyrsa_dir(), "pki", "reqs", f"{username}.req"),
                os.path.join(_easyrsa_dir(), "pki", "inline", f"{username}.inline"),
            ):
                try:
                    if os.path.isfile(candidate):
                        os.unlink(candidate)
                except OSError:
                    pass
            cert_pem, key_pem = generate_client_cert(username)
            return cert_pem, key_pem, "reissued"
        finally:
            fcntl.flock(profile_lock.fileno(), fcntl.LOCK_UN)


def regenerate_client_cert_for_download(username: str) -> tuple[str, str]:
    """Backward-compatible wrapper for callers that only need the pair."""
    cert_pem, key_pem, _status = get_client_profile_credentials(username)
    return cert_pem, key_pem


def read_sstp_cert() -> str | None:
    """سرتیفیکیت (عمومی، بدون کلید خصوصی) TLS سرور SSTP را برمی‌گرداند تا از
    صفحه‌ی ساب قابل دانلود باشد. برخلاف سرتیفیکیت‌های OpenVPN، این یک
    سرتیفیکیت مشترک برای همه‌ی کاربران است (متعلق به خودِ سرور SSTP، نه هر
    کاربر جدا)؛ نگاه کنید به install/setup_sstp.sh که همین فایل را می‌سازد.
    اگر زیرساخت SSTP روی این سرور نصب نشده باشد یا فایل پیدا نشود، None
    برمی‌گردد.
    """
    path = get_settings().SSTP_CERT_PATH
    if not os.path.exists(path):
        return None

    with open(path) as f:
        raw = f.read()

    # فقط بلوک‌های CERTIFICATE را نگه می‌داریم (fullchain.pem می‌تواند چند
    # سرتیفیکیت - leaf + intermediate - داشته باشد؛ کلید خصوصی هرگز نباید
    # اینجا باشد ولی برای اطمینان فیلتر می‌شود تا چیزی جز سرتیفیکیت عمومی
    # به کاربر داده نشود).
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    certs = []
    idx = 0
    while True:
        start = raw.find(begin, idx)
        if start == -1:
            break
        stop = raw.find(end, start)
        if stop == -1:
            break
        stop += len(end)
        certs.append(raw[start:stop].strip())
        idx = stop

    if not certs:
        return None
    return "\n".join(certs) + "\n"


def revoke_client_cert(username: str):
    """باطل کردن سرتیفیکیت کاربر (موقع حذف کاربر) و به‌روزرسانی CRL سرور،
    تا حتی با فایل .ovpn قدیمی هم دیگر نتواند وصل شود. اگر سرتیفیکیتی
    برای این کاربر ساخته نشده بود، بی‌صدا رد می‌شود."""
    if not os.path.isfile(_cert_path(username)):
        _recover_client_cert_from_archive(username)
    if not os.path.isfile(_cert_path(username)):
        return

    easyrsa_bin = os.path.join(_easyrsa_dir(), "easyrsa")
    if not os.path.exists(easyrsa_bin):
        return

    subprocess.run(
        [BASH, easyrsa_bin, "--batch", "revoke", username],
        cwd=_easyrsa_dir(),
        capture_output=True, text=True, timeout=60, check=False,
    )
    result = subprocess.run(
        [BASH, easyrsa_bin, "--batch", "gen-crl"],
        cwd=_easyrsa_dir(),
        capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode == 0:
        crl_src = os.path.join(_easyrsa_dir(), "pki", "crl.pem")
        if os.path.exists(crl_src):
            with open(crl_src) as src, open(settings.OPENVPN_CRL_PATH, "w") as dst:
                dst.write(src.read())
            # crl.pem بعد از drop-privileges (کاربر nobody) هم باید خوانده
            # شود؛ برخلاف panel.env این فایل محرمانه نیست (فقط لیست سریال
            # سرتیفیکیت‌های باطل‌شده)، پس world-readable مشکلی ندارد.
            os.chmod(settings.OPENVPN_CRL_PATH, 0o644)
