from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

_ZONE_TAB_FILES = (
    Path('/usr/share/zoneinfo/zone1970.tab'),
    Path('/usr/share/zoneinfo/zone.tab'),
)


def _run(command: list[str], *, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, 'LC_ALL': 'C.UTF-8', 'LANG': 'C.UTF-8'},
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise RuntimeError(detail or f"Command failed: {' '.join(command)}")
    return result


def country_timezones() -> dict[str, list[str]]:
    countries: dict[str, set[str]] = {}
    for filename in _ZONE_TAB_FILES:
        if not filename.exists():
            continue
        try:
            lines = filename.read_text(encoding='utf-8').splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            codes = [item.strip().upper() for item in parts[0].split(',') if item.strip()]
            timezone_name = parts[2].strip()
            if not timezone_name:
                continue
            for code in codes:
                countries.setdefault(code, set()).add(timezone_name)
        if countries:
            break
    return {code: sorted(zones) for code, zones in sorted(countries.items())}


def timezone_names() -> list[str]:
    try:
        names = {
            name for name in available_timezones()
            if name and not name.startswith(('posix/', 'right/'))
        }
    except Exception:
        names = set()
    if not names:
        for zones in country_timezones().values():
            names.update(zones)
    names.add('UTC')
    return sorted(names)


def validate_timezone(timezone_name: str) -> str:
    value = str(timezone_name or '').strip()
    if not value or value.startswith('/') or '..' in value.split('/'):
        raise ValueError('منطقه زمانی معتبر نیست')
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as exc:
        raise ValueError('منطقه زمانی روی این سرور نصب نیست') from exc
    return value


def current_timezone() -> str:
    if shutil.which('timedatectl'):
        result = _run(['timedatectl', 'show', '--property=Timezone', '--value'], check=False)
        value = (result.stdout or '').strip()
        if result.returncode == 0 and value:
            return value
    timezone_file = Path('/etc/timezone')
    try:
        value = timezone_file.read_text(encoding='utf-8').strip()
        if value:
            return value
    except OSError:
        pass
    try:
        target = Path('/etc/localtime').resolve()
        marker = '/usr/share/zoneinfo/'
        raw = str(target)
        if marker in raw:
            return raw.split(marker, 1)[1]
    except OSError:
        pass
    tzinfo = datetime.now().astimezone().tzinfo
    return getattr(tzinfo, 'key', None) or str(tzinfo or 'UTC')


def _timedatectl_bool(property_name: str) -> bool | None:
    if not shutil.which('timedatectl'):
        return None
    result = _run(['timedatectl', 'show', f'--property={property_name}', '--value'], check=False)
    if result.returncode != 0:
        return None
    value = (result.stdout or '').strip().lower()
    if value in {'yes', 'true', '1'}:
        return True
    if value in {'no', 'false', '0'}:
        return False
    return None


def status() -> dict:
    local_now = datetime.now().astimezone()
    return {
        'timezone': current_timezone(),
        'local_time': local_now.isoformat(timespec='seconds'),
        'utc_time': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'ntp_enabled': _timedatectl_bool('NTP'),
        'ntp_synchronized': _timedatectl_bool('NTPSynchronized'),
    }


def _set_timezone(timezone_name: str) -> None:
    timedatectl_error: Exception | None = None
    if shutil.which('timedatectl'):
        try:
            _run(['timedatectl', 'set-timezone', timezone_name])
            return
        except Exception as exc:
            timedatectl_error = exc

    zone_path = Path('/usr/share/zoneinfo') / timezone_name
    if not zone_path.is_file():
        raise RuntimeError('فایل منطقه زمانی روی سرور پیدا نشد')
    try:
        localtime_path = Path('/etc/localtime')
        temporary = Path('/etc/localtime.vpn-panel-new')
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(zone_path)
        os.replace(temporary, localtime_path)
        Path('/etc/timezone').write_text(timezone_name + '\n', encoding='utf-8')
    except OSError as exc:
        if timedatectl_error:
            raise RuntimeError(f'{timedatectl_error}; fallback failed: {exc}') from exc
        raise RuntimeError(str(exc)) from exc


def _set_ntp(enabled: bool) -> None:
    if not shutil.which('timedatectl'):
        raise RuntimeError('timedatectl برای تغییر همگام‌سازی خودکار ساعت نصب نیست')
    _run(['timedatectl', 'set-ntp', 'true' if enabled else 'false'])


def _parse_manual_datetime(value: str, timezone_name: str) -> datetime:
    raw = str(value or '').strip()
    if not raw:
        raise ValueError('تاریخ و ساعت دستی الزامی است')
    try:
        parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('فرمت تاریخ و ساعت دستی معتبر نیست') from exc
    target_zone = ZoneInfo(timezone_name)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(target_zone).replace(tzinfo=None)
    if parsed.year < 2020 or parsed.year > 2100:
        raise ValueError('سال ساعت دستی باید بین ۲۰۲۰ تا ۲۱۰۰ باشد')
    return parsed


def _set_manual_time(value: str, timezone_name: str) -> None:
    parsed = _parse_manual_datetime(value, timezone_name)
    formatted = parsed.strftime('%Y-%m-%d %H:%M:%S')
    if shutil.which('timedatectl'):
        result = _run(['timedatectl', 'set-time', formatted], check=False)
        if result.returncode == 0:
            return
        timedatectl_detail = (result.stderr or result.stdout or '').strip()
    else:
        timedatectl_detail = 'timedatectl not found'
    if shutil.which('date'):
        result = _run(['date', '--set', formatted], check=False)
        if result.returncode == 0:
            return
        date_detail = (result.stderr or result.stdout or '').strip()
    else:
        date_detail = 'date command not found'
    raise RuntimeError(f'{timedatectl_detail}; {date_detail}')


def apply(*, mode: str, timezone_name: str, manual_datetime: str | None = None) -> dict:
    selected_mode = str(mode or '').strip().lower()
    if selected_mode not in {'auto', 'manual'}:
        raise ValueError('حالت تنظیم ساعت باید خودکار یا دستی باشد')
    timezone_name = validate_timezone(timezone_name)

    # Validate manual input before touching timezone/NTP. This prevents a typo
    # in the form from leaving the host with NTP disabled or a changed zone.
    if selected_mode == 'manual':
        _parse_manual_datetime(manual_datetime or '', timezone_name)

    previous_timezone = current_timezone()
    previous_ntp = _timedatectl_bool('NTP')
    try:
        _set_timezone(timezone_name)
        os.environ['TZ'] = timezone_name
        if hasattr(time, 'tzset'):
            time.tzset()

        if selected_mode == 'auto':
            _set_ntp(True)
        else:
            _set_ntp(False)
            _set_manual_time(manual_datetime or '', timezone_name)
    except Exception:
        # Best-effort rollback. Never hide the original command error.
        try:
            if previous_timezone and previous_timezone != timezone_name:
                _set_timezone(previous_timezone)
                os.environ['TZ'] = previous_timezone
                if hasattr(time, 'tzset'):
                    time.tzset()
        except Exception:
            pass
        try:
            if previous_ntp is not None:
                _set_ntp(previous_ntp)
        except Exception:
            pass
        raise

    return status()
