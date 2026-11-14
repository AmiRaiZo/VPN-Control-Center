from __future__ import annotations

import base64
import hashlib
import os
import re
import selectors
import shlex
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings
from app.services.security_hardening import ensure_private_file, secret_bytes

try:
    import paramiko
except Exception:  # pragma: no cover - update installs dependency before API restart
    paramiko = None

settings = get_settings()
_JOBS: dict[str, dict[str, Any]] = {}
_LOCK = threading.RLock()
_MAX_LINES = 5000


def _fernet() -> Fernet:
    key = secret_bytes(settings.DATA_ENCRYPTION_KEY, label="DATA_ENCRYPTION_KEY")
    return Fernet(base64.urlsafe_b64encode(key))


def _legacy_fernet() -> Fernet:
    # Read-only migration path for credentials encrypted before v2.3.192.
    digest = hashlib.sha256(settings.JWT_SECRET.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_password(value: str | None) -> str | None:
    if not value:
        return None
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_password(value: str | None) -> str | None:
    if not value:
        return None
    encoded = value.encode("ascii")
    for box in (_fernet(), _legacy_fernet()):
        try:
            return box.decrypt(encoded).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError):
            continue
    return None


def _append(job_id: str, text: str) -> None:
    if text is None:
        return
    chunks = str(text).replace("\r", "").splitlines() or [""]
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        for line in chunks:
            job["lines"].append(line[-6000:])
            m = re.search(r"\[(\d{1,3})%\]", line)
            if m:
                job["progress"] = max(int(job.get("progress") or 0), min(99, int(m.group(1))))
        if len(job["lines"]) > _MAX_LINES:
            job["lines"] = job["lines"][-_MAX_LINES:]
        job["updated_at"] = time.time()


def _new_job(kind: str, title: str) -> str:
    job_id = uuid.uuid4().hex
    with _LOCK:
        _JOBS[job_id] = {
            "id": job_id, "kind": kind, "title": title, "state": "queued",
            "lines": [], "progress": 0, "created_at": time.time(), "updated_at": time.time(),
            "returncode": None,
        }
    return job_id


def get_job(job_id: str) -> dict | None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return None
        return {**job, "output": "\n".join(job.get("lines") or [])}


_HOST_KEY_LOCK = threading.RLock()


class _PersistentTOFUPolicy(paramiko.MissingHostKeyPolicy if paramiko else object):
    """Persist the first observed host key and reject every later key change."""

    def missing_host_key(self, client, hostname, key):
        policy = str(settings.SSH_HOST_KEY_POLICY or "tofu").strip().lower()
        if policy == "reject":
            raise paramiko.SSHException(
                f"SSH host key for {hostname} is not trusted; add it to {settings.SSH_KNOWN_HOSTS_PATH}"
            )
        if policy != "tofu":
            raise paramiko.SSHException("SSH_HOST_KEY_POLICY must be 'tofu' or 'reject'")
        path = Path(settings.SSH_KNOWN_HOSTS_PATH)
        with _HOST_KEY_LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path.parent.chmod(0o700)
            except OSError:
                pass
            client._host_keys.add(hostname, key.get_name(), key)
            client.save_host_keys(str(path))
            ensure_private_file(path)


def _connect(host: str, port: int, username: str, password: str, timeout: int = 15):
    if paramiko is None:
        raise RuntimeError("کتابخانه SSH هنوز نصب نشده است؛ یک‌بار سرویس پنل را بعد از آپدیت ری‌استارت کنید")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    known_hosts = Path(settings.SSH_KNOWN_HOSTS_PATH)
    if known_hosts.exists():
        try:
            client.load_host_keys(str(known_hosts))
        except OSError as exc:
            raise RuntimeError(f"فایل اعتماد SSH قابل خواندن نیست: {exc}") from exc
    client.set_missing_host_key_policy(_PersistentTOFUPolicy())
    try:
        client.connect(
            hostname=host, port=int(port), username=username, password=password,
            look_for_keys=False, allow_agent=False, timeout=timeout,
            banner_timeout=timeout, auth_timeout=timeout,
        )
    except getattr(paramiko, "BadHostKeyException") as exc:
        raise RuntimeError(
            "کلید میزبان SSH تغییر کرده است؛ اتصال برای جلوگیری از حمله میانی متوقف شد"
        ) from exc
    return client


def _run_channel(job_id: str, client, command: str, timeout_seconds: int) -> int:
    _append(job_id, "$ " + command)
    transport = client.get_transport()
    if not transport:
        raise RuntimeError("SSH transport is not available")
    channel = transport.open_session(timeout=15)
    channel.get_pty(term="xterm", width=160, height=48)
    channel.exec_command(command)
    started = time.monotonic()
    while True:
        emitted = False
        if channel.recv_ready():
            _append(job_id, channel.recv(65536).decode("utf-8", "replace"))
            emitted = True
        if channel.recv_stderr_ready():
            _append(job_id, channel.recv_stderr(65536).decode("utf-8", "replace"))
            emitted = True
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if time.monotonic() - started > timeout_seconds:
            channel.close()
            raise TimeoutError(f"SSH command exceeded {timeout_seconds} seconds")
        if not emitted:
            time.sleep(0.12)
    return int(channel.recv_exit_status())


def start_ssh_job(*, host: str, port: int, username: str, password: str, command: str,
                  title: str = "SSH", timeout_seconds: int = 300) -> str:
    job_id = _new_job("ssh", title)

    def runner():
        with _LOCK:
            _JOBS[job_id]["state"] = "running"
        client = None
        try:
            client = _connect(host, port, username, password)
            _append(job_id, f"[ssh] connected to {username}@{host}:{port}")
            rc = _run_channel(job_id, client, command, timeout_seconds)
            with _LOCK:
                job = _JOBS[job_id]
                job["returncode"] = rc
                job["state"] = "success" if rc == 0 else "failed"
                job["progress"] = 100 if rc == 0 else int(job.get("progress") or 0)
                job["finished_at"] = time.time()
        except Exception as exc:
            _append(job_id, f"ERROR: {exc}")
            with _LOCK:
                job = _JOBS[job_id]
                job["returncode"] = -1
                job["state"] = "failed"
                job["finished_at"] = time.time()
        finally:
            if client:
                client.close()

    threading.Thread(target=runner, daemon=True, name=f"node-ssh-{job_id[:8]}").start()
    return job_id



def start_local_shell_job(*, command: str, title: str = "ترمینال سرور فعلی", timeout_seconds: int = 300) -> str:
    """Run a superadmin command locally and stream output to the glass console.

    The API endpoint that calls this function is restricted to the primary
    superadmin. Commands run in a non-interactive login shell so normal system
    PATH and shell features work, while the timeout kills the whole process
    group to avoid orphan installers or diagnostics.
    """
    job_id = _new_job("local-shell", title)

    def runner():
        with _LOCK:
            _JOBS[job_id]["state"] = "running"
        process = None
        try:
            _append(job_id, "$ " + command)
            env = os.environ.copy()
            env.setdefault("TERM", "xterm-256color")
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            process = subprocess.Popen(
                ["/bin/bash", "-lc", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                start_new_session=True,
            )
            started = time.monotonic()
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                events = selector.select(timeout=0.2)
                for key, _mask in events:
                    chunk = key.fileobj.readline()
                    if chunk:
                        _append(job_id, chunk)
                if process.poll() is not None:
                    remainder = process.stdout.read()
                    if remainder:
                        _append(job_id, remainder)
                    break
                if time.monotonic() - started > timeout_seconds:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        time.sleep(0.5)
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    raise TimeoutError(f"Local command exceeded {timeout_seconds} seconds")
            selector.close()
            rc = int(process.returncode or 0)
            with _LOCK:
                job = _JOBS[job_id]
                job["returncode"] = rc
                job["state"] = "success" if rc == 0 else "failed"
                job["progress"] = 100 if rc == 0 else int(job.get("progress") or 0)
                job["finished_at"] = time.time()
        except Exception as exc:
            _append(job_id, f"ERROR: {exc}")
            with _LOCK:
                job = _JOBS[job_id]
                job["returncode"] = -1
                job["state"] = "failed"
                job["finished_at"] = time.time()
        finally:
            if process and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass

    threading.Thread(target=runner, daemon=True, name=f"local-shell-{job_id[:8]}").start()
    return job_id

def action_command(action: str) -> tuple[str, int]:
    commands = {
        "status": ("set -o pipefail; echo '[10%] Panel status'; systemctl --no-pager --full status vpn-panel-api nginx || true; "
                   "echo '[45%] VPN services'; systemctl --no-pager --full status openvpn-server@server-udp openvpn-server@server-tcp strongswan-starter xl2tpd pptpd ocserv accel-ppp-sstp vpn-panel-xray-vmess vpn-panel-xray-vless || true; "
                   "echo '[80%] Listeners'; ss -lntup; echo '[100%] done'", 120),
        "logs": ("set -o pipefail; echo '[10%] backend'; journalctl -u vpn-panel-api -n 250 --no-pager; "
                 "echo '[45%] nginx'; journalctl -u nginx -n 100 --no-pager; "
                 "echo '[65%] OpenVPN'; journalctl -u openvpn-server@server-udp -u openvpn-server@server-tcp -n 180 --no-pager; "
                 "echo '[100%] done'", 120),
        "restart_panel": ("set -e; echo '[20%] restarting'; systemctl restart vpn-panel-api nginx; sleep 2; "
                          "systemctl is-active vpn-panel-api nginx; echo '[100%] restart complete'", 120),
        "install_all": ("set -o pipefail; bash /opt/vpn-panel/scripts/install_protocol.sh all", 3600),
        "update": ("set -e; cd /opt/vpn-panel/backend; echo '[3%] starting update'; "
                   "/opt/vpn-panel/backend/venv/bin/python - <<'PYUP'\n"
                   "from app.database import SessionLocal\nfrom app.services.update_manager import start_update\n"
                   "from fastapi import HTTPException\n"
                   "db=SessionLocal()\ntry:\n"
                   " try:\n  print(start_update(db))\n"
                   " except HTTPException as exc:\n"
                   "  if exc.status_code == 409:\n   print({'ok': True, 'already_running': True, 'message': str(exc.detail)})\n"
                   "  else:\n   raise\n"
                   "finally:\n db.close()\nPYUP\n"
                   "for i in $(seq 1 450); do [ -f /opt/vpn-panel/update-progress.json ] && cat /opt/vpn-panel/update-progress.json; "
                   "state=$(python3 -c 'import json; print(json.load(open(\"/opt/vpn-panel/update-progress.json\")).get(\"state\",\"\"))' 2>/dev/null || true); "
                   "[ \"$state\" = success ] && break; [ \"$state\" = failed ] && break; sleep 2; done; "
                   "cat /opt/vpn-panel/update.log; test \"$state\" = success", 1200),
    }
    if action not in commands:
        raise ValueError("عملیات نود نامعتبر است")
    return commands[action]


def start_remote_install_job(payload: dict, controller_url: str, controller_token: str) -> str:
    job_id = _new_job("install", f"Install node {payload['node_name']}")
    archive = Path("/opt/vpn-panel/release-source.tar.gz")

    def runner():
        with _LOCK:
            _JOBS[job_id]["state"] = "running"
        client = None
        try:
            if not archive.is_file():
                raise RuntimeError("بسته نصب این نسخه روی کنترلر پیدا نشد؛ همین نسخه را یک‌بار از بخش آپدیت نصب کنید")
            client = _connect(payload["host"], payload["ssh_port"], payload["ssh_username"], payload["ssh_password"], timeout=20)
            _append(job_id, "[5%] SSH connected")
            sftp = client.open_sftp()
            remote_archive = "/tmp/vpn-panel-release-source.tar.gz"
            sent = {"value": 0}
            def callback(done, total):
                pct = 5 + int((done / max(1, total)) * 15)
                if pct > sent["value"]:
                    sent["value"] = pct
                    _append(job_id, f"[{pct}%] uploading release bundle")
            sftp.put(str(archive), remote_archive, callback=callback)
            sftp.close()
            env = {
                "UNATTENDED": "1", "VPN_PANEL_FORCE_FRESH_INSTALL": "1", "SERVER_ROLE": "node",
                "CONTROLLER_URL": controller_url.rstrip("/"), "CONTROLLER_TOKEN": controller_token,
                "CONTROLLER_VERIFY_TLS": "1" if payload.get("verify_controller_tls", True) else "0",
                "NODE_NAME": payload["node_name"], "NODE_PUBLIC_URL": payload["node_public_url"].rstrip("/"),
                "NODE_VERIFY_TLS": "1" if payload.get("verify_node_tls", True) else "0",
                "SERVER_IP": payload["host"], "PANEL_PORT": str(payload.get("panel_port", 8080)),
                "ADMIN_USER": payload.get("admin_username") or "admin", "ADMIN_PASS": payload["admin_password"],
                "LICENSE_KEY": payload.get("license_key") or "",
            }
            prefix = " ".join(f"{key}={shlex.quote(str(value))}" for key, value in env.items())
            cmd = (
                "set -e; rm -rf /tmp/vpn-panel-node-install; mkdir -p /tmp/vpn-panel-node-install; "
                f"tar -xzf {remote_archive} -C /tmp/vpn-panel-node-install; "
                "cd /tmp/vpn-panel-node-install; "
                f"{prefix} bash install/install.sh"
            )
            rc = _run_channel(job_id, client, cmd, 5400)
            with _LOCK:
                job = _JOBS[job_id]
                job["returncode"] = rc
                job["state"] = "success" if rc == 0 else "failed"
                job["progress"] = 100 if rc == 0 else int(job.get("progress") or 0)
                job["finished_at"] = time.time()
        except Exception as exc:
            _append(job_id, f"ERROR: {exc}")
            with _LOCK:
                job = _JOBS[job_id]
                job["returncode"] = -1
                job["state"] = "failed"
                job["finished_at"] = time.time()
        finally:
            if client:
                client.close()

    threading.Thread(target=runner, daemon=True, name=f"node-install-{job_id[:8]}").start()
    return job_id
