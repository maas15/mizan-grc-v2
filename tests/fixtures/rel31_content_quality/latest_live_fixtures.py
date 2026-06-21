"""Byte-exact latest live export fixtures (استراتيجية الأمن السيبراني 36/63)."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Dict, Tuple

from tests.fixtures.rel31_content_quality.uploaded_fixtures import (
    sections_from_uploaded_docx_text,
)

FIXTURE_DIR = Path(__file__).resolve().parent
DOCX_LATEST = FIXTURE_DIR / 'cyber_strategy_36_actual.docx'
PDF_LATEST = FIXTURE_DIR / 'cyber_strategy_63_actual.pdf'

LATEST_DOCX_SHA256 = (
    '487368c1c5ef49bbed9a535bd0c36fa01d57afa2eef29f5c24a8c8becc29b197')
LATEST_PDF_SHA256 = (
    '855b74754cb13548646ee61e78f38802bf6a00fd9310ecaaf54a42908a0e867c')

_DOCX_SOURCE_CANDIDATES = (
    Path('/mnt/data/استراتيجية الأمن السيبراني (36).docx'),
    Path(r'C:\Users\dell\Downloads\استراتيجية الأمن السيبراني (36).docx'),
)
_PDF_SOURCE_CANDIDATES = (
    Path('/mnt/data/استراتيجية الأمن السيبراني (63).pdf'),
    Path(r'C:\Users\dell\Downloads\استراتيجية الأمن السيبراني (63).pdf'),
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _copy_if_missing(dst: Path, candidates, expected_sha: str) -> None:
    if dst.is_file() and _sha256_bytes(dst.read_bytes()) == expected_sha:
        return
    for src in candidates:
        if src.is_file():
            data = src.read_bytes()
            if _sha256_bytes(data) == expected_sha:
                dst.write_bytes(data)
                return
            shutil.copy2(src, dst)
            return
    if not dst.is_file():
        raise FileNotFoundError(
            f'missing byte-exact fixture {dst.name}; '
            f'expected sha256={expected_sha}')


def ensure_latest_live_fixtures() -> Tuple[Path, Path]:
    _copy_if_missing(DOCX_LATEST, _DOCX_SOURCE_CANDIDATES, LATEST_DOCX_SHA256)
    _copy_if_missing(PDF_LATEST, _PDF_SOURCE_CANDIDATES, LATEST_PDF_SHA256)
    if _sha256_bytes(DOCX_LATEST.read_bytes()) != LATEST_DOCX_SHA256:
        raise ValueError('latest DOCX fixture sha mismatch')
    if _sha256_bytes(PDF_LATEST.read_bytes()) != LATEST_PDF_SHA256:
        raise ValueError('latest PDF fixture sha mismatch')
    return DOCX_LATEST, PDF_LATEST


def verify_latest_byte_identical() -> Dict[str, str]:
    ensure_latest_live_fixtures()
    return {
        'docx_fixture_sha256': LATEST_DOCX_SHA256,
        'pdf_fixture_sha256': LATEST_PDF_SHA256,
        'docx_bytes_match_uploaded': True,
        'pdf_bytes_match_uploaded': True,
    }


def sections_from_latest_docx_text(text: str) -> Dict[str, str]:
    return sections_from_uploaded_docx_text(text)
