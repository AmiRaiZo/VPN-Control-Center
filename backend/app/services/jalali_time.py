from __future__ import annotations

from datetime import datetime

_FA_DIGITS = str.maketrans('0123456789', '۰۱۲۳۴۵۶۷۸۹')


def gregorian_to_jalali(gy: int, gm: int, gd: int) -> tuple[int, int, int]:
    """Convert a Gregorian date to Jalali using the public jalaali algorithm."""
    g_days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    j_days_in_month = [31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29]

    gy -= 1600
    gm -= 1
    gd -= 1

    g_day_no = 365 * gy + (gy + 3) // 4 - (gy + 99) // 100 + (gy + 399) // 400
    for index in range(gm):
        g_day_no += g_days_in_month[index]
    if gm > 1 and ((gy + 1600) % 4 == 0 and ((gy + 1600) % 100 != 0 or (gy + 1600) % 400 == 0)):
        g_day_no += 1
    g_day_no += gd

    j_day_no = g_day_no - 79
    j_np = j_day_no // 12053
    j_day_no %= 12053

    jy = 979 + 33 * j_np + 4 * (j_day_no // 1461)
    j_day_no %= 1461

    if j_day_no >= 366:
        jy += (j_day_no - 1) // 365
        j_day_no = (j_day_no - 1) % 365

    jm = 0
    while jm < 11 and j_day_no >= j_days_in_month[jm]:
        j_day_no -= j_days_in_month[jm]
        jm += 1

    return jy, jm + 1, j_day_no + 1


def format_jalali_datetime(value: datetime | None = None, *, persian_digits: bool = True) -> str:
    value = value or datetime.now().astimezone()
    if value.tzinfo is None:
        value = value.astimezone()
    jy, jm, jd = gregorian_to_jalali(value.year, value.month, value.day)
    text = f"{jy:04d}/{jm:02d}/{jd:02d} - {value.hour:02d}:{value.minute:02d}:{value.second:02d}"
    return text.translate(_FA_DIGITS) if persian_digits else text


def jalali_filename_stamp(value: datetime | None = None) -> str:
    value = value or datetime.now().astimezone()
    if value.tzinfo is None:
        value = value.astimezone()
    jy, jm, jd = gregorian_to_jalali(value.year, value.month, value.day)
    return f"{jy:04d}{jm:02d}{jd:02d}-{value.hour:02d}{value.minute:02d}{value.second:02d}"
