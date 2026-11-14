"""Telegram media layout helpers.

Telegram clients choose inline-keyboard geometry themselves.  The main-menu
animation can therefore look narrower than the keyboard on mobile even though
both belong to the same message.  For GIF uploads we widen only the logical
canvas (without stretching/re-encoding frames) so the media bubble visually
matches the keyboard more closely.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Optional, Tuple

# The current mobile Telegram layout in private chats is roughly two times as
# wide as the visible menu animation height.  2.05 leaves a tiny safety margin
# while keeping the original picture untouched and centered.
MAIN_MENU_GIF_ASPECT = 2.05
_MAX_GIF_DIMENSION = 4096


def gif_dimensions(data: bytes) -> Optional[Tuple[int, int]]:
    if len(data) < 10 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    width = int.from_bytes(data[6:8], "little")
    height = int.from_bytes(data[8:10], "little")
    if width <= 0 or height <= 0:
        return None
    return width, height


def gif_dimensions_from_path(path: str | Path) -> Optional[Tuple[int, int]]:
    try:
        with open(path, "rb") as handle:
            return gif_dimensions(handle.read(10))
    except OSError:
        return None


def _skip_sub_blocks(data: bytearray, pos: int) -> int:
    size_total = len(data)
    while pos < size_total:
        block_size = data[pos]
        pos += 1
        if block_size == 0:
            return pos
        pos += block_size
        if pos > size_total:
            raise ValueError("truncated GIF sub-block")
    raise ValueError("unterminated GIF sub-block")


def normalize_main_menu_gif_bytes(content: bytes) -> bytes:
    """Widen and center a GIF canvas without decoding or stretching frames.

    The compressed image data is left byte-for-byte intact.  Only the logical
    screen width and every frame's horizontal offset are adjusted.  This keeps
    animation quality, duration and file size essentially unchanged.
    """
    dimensions = gif_dimensions(content)
    if dimensions is None or len(content) < 13:
        return content
    width, height = dimensions
    target_width = min(
        _MAX_GIF_DIMENSION,
        max(width, int(math.ceil(height * MAIN_MENU_GIF_ASPECT))),
    )
    if target_width <= width:
        return content

    output = bytearray(content)
    output[6:8] = target_width.to_bytes(2, "little")
    horizontal_padding = (target_width - width) // 2

    # Skip logical screen descriptor and optional global colour table.
    packed = output[10]
    pos = 13
    if packed & 0x80:
        global_table_size = 3 * (2 ** ((packed & 0x07) + 1))
        pos += global_table_size
    if pos > len(output):
        return content

    saw_frame = False
    try:
        while pos < len(output):
            marker = output[pos]
            if marker == 0x3B:  # trailer
                return bytes(output) if saw_frame else content
            if marker == 0x21:  # extension block
                pos += 2  # introducer + extension label
                pos = _skip_sub_blocks(output, pos)
                continue
            if marker != 0x2C:  # image descriptor
                return content
            if pos + 10 > len(output):
                return content

            saw_frame = True
            left = int.from_bytes(output[pos + 1:pos + 3], "little")
            frame_width = int.from_bytes(output[pos + 5:pos + 7], "little")
            centered_left = min(
                max(0, target_width - frame_width),
                left + horizontal_padding,
            )
            output[pos + 1:pos + 3] = centered_left.to_bytes(2, "little")

            frame_packed = output[pos + 9]
            pos += 10
            if frame_packed & 0x80:
                local_table_size = 3 * (2 ** ((frame_packed & 0x07) + 1))
                pos += local_table_size
            if pos >= len(output):
                return content
            pos += 1  # LZW minimum code size
            pos = _skip_sub_blocks(output, pos)
    except (ValueError, OverflowError):
        return content
    return content


def normalize_main_menu_gif_file(path: str | Path) -> Optional[Tuple[int, int]]:
    """Normalize an existing GIF atomically and return its final dimensions."""
    target = Path(path)
    try:
        original = target.read_bytes()
    except OSError:
        return None
    normalized = normalize_main_menu_gif_bytes(original)
    if normalized != original:
        temporary = target.with_name(f".{target.name}.layout.tmp")
        try:
            temporary.write_bytes(normalized)
            try:
                os.chmod(temporary, target.stat().st_mode & 0o777)
            except OSError:
                os.chmod(temporary, 0o640)
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return gif_dimensions(normalized)
