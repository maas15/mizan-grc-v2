#!/usr/bin/env python3
"""Bundle Amiri TTF for Render when apt-get fonts are unavailable."""
from __future__ import annotations

import os
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), '..')
FONT_DIR = os.path.join(ROOT, 'static', 'fonts')
TARGET = os.path.join(FONT_DIR, 'Amiri-Regular.ttf')
URL = (
    'https://github.com/google/fonts/raw/main/ofl/amiri/Amiri-Regular.ttf'
)


def main() -> int:
    import sys

    ver = sys.version_info
    if ver >= (3, 14):
        raise RuntimeError(
            f'Python {ver.major}.{ver.minor}.{ver.micro} is unsupported; '
            'pin runtime.txt to python-3.12.10 (ReportLab breaks on 3.14+)')
    try:
        from reportlab.lib.pagesizes import A4  # noqa: F401
    except RecursionError as exc:
        raise RuntimeError(
            'reportlab import failed with RecursionError — '
            'use Python 3.12.x via runtime.txt') from exc
    os.makedirs(FONT_DIR, exist_ok=True)
    if os.path.isfile(TARGET) and os.path.getsize(TARGET) > 10_000:
        print(f'[FONT-REG] bundled font already present: {TARGET}', flush=True)
        return 0
    print(f'[FONT-REG] downloading Amiri to {TARGET} ...', flush=True)
    urllib.request.urlretrieve(URL, TARGET)
    size = os.path.getsize(TARGET)
    if size < 10_000:
        raise RuntimeError(f'downloaded font too small: {size} bytes')
    print(f'[FONT-REG] Arabic font bundled successfully size={size}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
