#!/usr/bin/env python3
"""Acquire the supported Amiri TTF when apt Noto fonts are unavailable.

Search order at PDF registration (app._ensure_arabic_pdf_font) is unchanged:
  1. Noto Sans / Naskh Arabic (preferred when the OS provides it)
  2. Bundled Amiri (this script)
  3. DejaVu Sans (last-resort fallback; still registered if selected)
  4. Liberation / glob Arabic faces

DejaVu remains a supported last-resort registration target. It is not an
evidence exemption: arabic_reshaper + DejaVu can paint corrupted Arabic
while ActualText stays logical, and the returned-bytes gate must still
refuse that disagreement.

Amiri-Regular.ttf is SIL Open Font License 1.1. The file is downloaded,
checksum-verified, and kept out of git (static/fonts/*.ttf). Do not treat
an untracked local copy as a clean-checkout prerequisite unless this
script has verified AMIRI_SHA256.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), '..')
FONT_DIR = os.path.join(ROOT, 'static', 'fonts')
TARGET = os.path.join(FONT_DIR, 'Amiri-Regular.ttf')
# google/fonts commit that added Amiri 1.002. Pin the blob, not branch tip.
AMIRI_COMMIT = '39d11bc313031c9f68e21a297ce5e4a15cc5365e'
URL = (
    'https://raw.githubusercontent.com/google/fonts/'
    f'{AMIRI_COMMIT}/ofl/amiri/Amiri-Regular.ttf'
)
AMIRI_SHA256 = (
    'ab391c4147d054c48976e98322ad0eefe1427aa0e0502a12a4c75d80a70cfcd7'
)
AMIRI_MIN_BYTES = 400_000


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_font(path: str) -> str:
    """Return the verified sha256 or raise. Never accept a short/mismatched file."""
    if not os.path.isfile(path):
        raise RuntimeError(f'Amiri font missing: {path}')
    size = os.path.getsize(path)
    if size < AMIRI_MIN_BYTES:
        raise RuntimeError(f'downloaded font too small: {size} bytes')
    digest = sha256_file(path)
    if digest != AMIRI_SHA256:
        raise RuntimeError(
            f'Amiri checksum mismatch: got {digest} expected {AMIRI_SHA256}')
    return digest


def _download(url: str, dest: str) -> None:
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='amiri-', suffix='.ttf', dir=parent)
    os.close(fd)
    try:
        urllib.request.urlretrieve(url, tmp)
        digest = verify_font(tmp)
        os.replace(tmp, dest)
        print(
            f'[FONT-REG] Arabic font bundled successfully '
            f'size={os.path.getsize(dest)} sha256={digest}',
            flush=True,
        )
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main() -> int:
    ver = sys.version_info
    if ver >= (3, 14):
        raise RuntimeError(
            f'Python {ver.major}.{ver.minor}.{ver.micro} is unsupported; '
            'add .python-version (3.12.10) or set PYTHON_VERSION=3.12.10 '
            'on Render — ReportLab breaks on 3.14+')
    try:
        from reportlab.lib.pagesizes import A4  # noqa: F401
    except RecursionError as exc:
        raise RuntimeError(
            'reportlab import failed with RecursionError — '
            'use Python 3.12.x via .python-version or PYTHON_VERSION') from exc
    os.makedirs(FONT_DIR, exist_ok=True)
    if os.path.isfile(TARGET):
        try:
            digest = verify_font(TARGET)
            print(
                f'[FONT-REG] bundled font already present: {TARGET} '
                f'sha256={digest}',
                flush=True,
            )
            return 0
        except RuntimeError as exc:
            print(f'[FONT-REG] replacing unverified Amiri: {exc}', flush=True)
            try:
                os.unlink(TARGET)
            except OSError:
                pass
    print(f'[FONT-REG] downloading Amiri to {TARGET} ...', flush=True)
    _download(URL, TARGET)
    verify_font(TARGET)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
