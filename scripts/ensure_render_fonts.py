#!/usr/bin/env python3
"""Acquire supported Arabic TTFs when apt Noto fonts are unavailable.

Search order at PDF registration (app._ensure_arabic_pdf_font):
  1. OS Noto Sans / Naskh Arabic (preferred when present)
  2. Bundled Noto Sans Arabic (this script)
  3. Bundled Amiri (OFL fallback)
  4. DejaVu Sans (last-resort; still registered if selected)
  5. Liberation / glob Arabic faces

DejaVu and Amiri remain supported fallbacks. Neither is an evidence
exemption: arabic_reshaper plus those faces can paint extra or
corrupted Arabic/Latin while ActualText stays logical, and the
returned-bytes gate must still refuse that disagreement.

Noto and Amiri are SIL Open Font License 1.1. Files are downloaded,
checksum-verified, and kept out of git (static/fonts/*.ttf). An
untracked local copy is not a clean-checkout prerequisite until this
script has verified the pinned SHA-256.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import urllib.request
from typing import Dict, List

ROOT = os.path.join(os.path.dirname(__file__), '..')
FONT_DIR = os.path.join(ROOT, 'static', 'fonts')

# googlefonts/noto-fonts hinted Regular. Pin the blob, not branch tip.
NOTO_COMMIT = '6cfca385c8757fadf537923d59a671116a865d48'
# google/fonts commit that added Amiri 1.002.
AMIRI_COMMIT = '39d11bc313031c9f68e21a297ce5e4a15cc5365e'

FONTS: List[Dict[str, object]] = [
    {
        'name': 'NotoSansArabic-Regular.ttf',
        'url': (
            'https://raw.githubusercontent.com/googlefonts/noto-fonts/'
            f'{NOTO_COMMIT}/hinted/ttf/NotoSansArabic/'
            'NotoSansArabic-Regular.ttf'
        ),
        'sha256': (
            'ceea25b464a656dc3b26849bab9356740401af62aedf1bfa8b7f0d9b75925b1b'
        ),
        'min_bytes': 200_000,
    },
    {
        'name': 'Amiri-Regular.ttf',
        'url': (
            'https://raw.githubusercontent.com/google/fonts/'
            f'{AMIRI_COMMIT}/ofl/amiri/Amiri-Regular.ttf'
        ),
        'sha256': (
            'ab391c4147d054c48976e98322ad0eefe1427aa0e0502a12a4c75d80a70cfcd7'
        ),
        'min_bytes': 400_000,
    },
]

# Backward-compatible aliases used by existing tests.
AMIRI_SHA256 = str(FONTS[1]['sha256'])
AMIRI_MIN_BYTES = int(FONTS[1]['min_bytes'])
URL = str(FONTS[1]['url'])
TARGET = os.path.join(FONT_DIR, 'Amiri-Regular.ttf')
NOTO_SHA256 = str(FONTS[0]['sha256'])


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_font(
        path: str,
        expected_sha: str | None = None,
        min_bytes: int | None = None,
) -> str:
    """Return the verified sha256 or raise. Never accept a short/mismatched file."""
    if expected_sha is None:
        expected_sha = AMIRI_SHA256
    if min_bytes is None:
        min_bytes = AMIRI_MIN_BYTES
    if not os.path.isfile(path):
        raise RuntimeError(f'font missing: {path}')
    size = os.path.getsize(path)
    if size < int(min_bytes):
        raise RuntimeError(f'downloaded font too small: {size} bytes')
    digest = sha256_file(path)
    if digest != expected_sha:
        raise RuntimeError(
            f'font checksum mismatch: got {digest} expected {expected_sha}')
    return digest


def _download(url: str, dest: str, expected_sha: str, min_bytes: int) -> None:
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='font-', suffix='.ttf', dir=parent)
    os.close(fd)
    try:
        urllib.request.urlretrieve(url, tmp)
        digest = verify_font(tmp, expected_sha, min_bytes)
        os.replace(tmp, dest)
        print(
            f'[FONT-REG] font bundled successfully path={dest} '
            f'size={os.path.getsize(dest)} sha256={digest}',
            flush=True,
        )
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ensure_one(spec: Dict[str, object]) -> int:
    dest = os.path.join(FONT_DIR, str(spec['name']))
    expected = str(spec['sha256'])
    minimum = int(spec['min_bytes'])
    url = str(spec['url'])
    if os.path.isfile(dest):
        try:
            digest = verify_font(dest, expected, minimum)
            print(
                f'[FONT-REG] bundled font already present: {dest} '
                f'sha256={digest}',
                flush=True,
            )
            return 0
        except RuntimeError as exc:
            print(f'[FONT-REG] replacing unverified font: {exc}', flush=True)
            try:
                os.unlink(dest)
            except OSError:
                pass
    print(f'[FONT-REG] downloading {spec["name"]} to {dest} ...', flush=True)
    _download(url, dest, expected, minimum)
    verify_font(dest, expected, minimum)
    return 0


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
    for spec in FONTS:
        ensure_one(spec)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
