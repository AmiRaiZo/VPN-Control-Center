from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models import Setting

BRANDING_DIR = Path(os.environ.get("VPN_PANEL_BRANDING_DIR", "/var/lib/vpn-panel/branding"))
MAX_IMAGE_BYTES = 10 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {
    "jpeg": ("image/jpeg", ".jpg"),
    "png": ("image/png", ".png"),
    "webp": ("image/webp", ".webp"),
}
ASSET_KEYS = {"logo", "hero"}
TEXT_KEYS = (
    "brand_name",
    "hero_badge",
    "hero_title",
    "hero_subtitle",
    "hero_footer",
    "login_footer_note",
)


def _row(db: Session, key: str) -> Setting | None:
    return db.query(Setting).filter(Setting.key == key).first()


def raw_setting(db: Session, key: str) -> str | None:
    row = _row(db, key)
    return row.value if row is not None else None


def set_setting(db: Session, key: str, value: str | None) -> None:
    row = _row(db, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def asset_path(kind: str) -> Path | None:
    if kind not in ASSET_KEYS:
        return None
    for suffix in (".png", ".jpg", ".webp"):
        candidate = BRANDING_DIR / f"{kind}{suffix}"
        if candidate.is_file():
            return candidate
    return None


def delete_asset(kind: str) -> None:
    if kind not in ASSET_KEYS:
        raise ValueError("invalid branding asset")
    for suffix in (".png", ".jpg", ".webp"):
        try:
            (BRANDING_DIR / f"{kind}{suffix}").unlink(missing_ok=True)
        except OSError:
            pass


def save_asset(kind: str, content: bytes, declared_type: str | None = None) -> Path:
    if kind not in ASSET_KEYS:
        raise ValueError("invalid branding asset")
    if not content:
        raise ValueError("image is empty")
    if len(content) > MAX_IMAGE_BYTES:
        raise ValueError("image is larger than 10 MB")

    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        detected = "png"
    elif content.startswith(b"\xff\xd8\xff"):
        detected = "jpeg"
    elif len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        detected = "webp"
    else:
        detected = None
    if detected not in ALLOWED_IMAGE_TYPES:
        raise ValueError("only PNG, JPEG and WebP images are accepted")
    mime, suffix = ALLOWED_IMAGE_TYPES[detected]
    declared = (declared_type or "").split(";", 1)[0].strip().lower()
    accepted_declared_types = {
        mime,
        "application/octet-stream",
        "binary/octet-stream",
        "",
    }
    # Some browsers and Android file pickers use these non-standard aliases.
    if detected == "jpeg":
        accepted_declared_types.update({"image/jpg", "image/pjpeg"})
    elif detected == "png":
        accepted_declared_types.add("image/x-png")
    if declared not in accepted_declared_types:
        raise ValueError("uploaded file content does not match its image type")

    try:
        BRANDING_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(BRANDING_DIR, 0o755)
        delete_asset(kind)
        destination = BRANDING_DIR / f"{kind}{suffix}"
        temporary = BRANDING_DIR / f".{kind}.{os.getpid()}.tmp"
        temporary.write_bytes(content)
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
        return destination
    except OSError as exc:
        raise ValueError(f"could not save image on the server: {exc.strerror or exc}") from exc


def get_branding(db: Session) -> dict[str, Any]:
    logo = asset_path("logo")
    hero = asset_path("hero")
    logo_version = int(logo.stat().st_mtime_ns) if logo else 0
    hero_version = int(hero.stat().st_mtime_ns) if hero else 0
    enabled_raw = raw_setting(db, "branding_hero_enabled")
    login_footer_note = raw_setting(db, "branding_login_footer_note") or ""
    if login_footer_note in {
        "نشست مدیریتی با بستن مرورگر پایان می‌یابد.",
        "The admin session ends when the browser is closed.",
    }:
        login_footer_note = ""

    result: dict[str, Any] = {
        "hero_enabled": enabled_raw != "0" if enabled_raw is not None else True,
        # None means "use the built-in translated default". An explicit empty
        # string means the administrator intentionally wants that element hidden.
        "brand_name": raw_setting(db, "branding_brand_name"),
        "hero_badge": raw_setting(db, "branding_hero_badge"),
        "hero_title": raw_setting(db, "branding_hero_title"),
        "hero_subtitle": raw_setting(db, "branding_hero_subtitle"),
        "hero_footer": raw_setting(db, "branding_hero_footer"),
        "login_footer_note": login_footer_note,
        "logo_url": f"/api/meta/branding/logo?v={logo_version}" if logo else None,
        "hero_image_url": f"/api/meta/branding/hero?v={hero_version}" if hero else None,
        "has_logo": bool(logo),
        "has_hero_image": bool(hero),
    }
    return result
