"""Byte-exact latest live export fixture — استراتيجية الأمن السيبراني (37)."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Dict, Tuple

from tests.fixtures.rel31_content_quality.uploaded_fixtures import (
    sections_from_uploaded_docx_text,
)

FIXTURE_DIR = Path(__file__).resolve().parent
DOCX_LATEST_37 = FIXTURE_DIR / 'cyber_strategy_37_actual.docx'
PDF_FAILURE_LOG = FIXTURE_DIR / 'cyber_strategy_37_pdf_failure_log.json'

LATEST_37_DOCX_SHA256 = (
    '07f51af684ec5a10f9b91406f0936ebe6f1b23705434dd1e29488899c95aacf7')

_DOCX_37_SOURCE_CANDIDATES = (
    Path('/mnt/data/استراتيجية الأمن السيبراني (37).docx'),
    Path(r'C:\Users\dell\Downloads\استراتيجية الأمن السيبراني (37).docx'),
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
            if _sha256_bytes(dst.read_bytes()) == expected_sha:
                return
            dst.unlink(missing_ok=True)
    if not dst.is_file():
        raise FileNotFoundError(
            f'missing byte-exact fixture {dst.name}; '
            f'expected sha256={expected_sha}')


def ensure_latest_37_fixtures() -> Path:
    _copy_if_missing(
        DOCX_LATEST_37, _DOCX_37_SOURCE_CANDIDATES, LATEST_37_DOCX_SHA256)
    if _sha256_bytes(DOCX_LATEST_37.read_bytes()) != LATEST_37_DOCX_SHA256:
        raise ValueError('latest (37) DOCX fixture sha mismatch')
    return DOCX_LATEST_37


def verify_latest_37_byte_identical() -> Dict[str, str]:
    ensure_latest_37_fixtures()
    uploaded = _DOCX_37_SOURCE_CANDIDATES[1]
    uploaded_sha = ''
    if uploaded.is_file():
        uploaded_sha = _sha256_bytes(uploaded.read_bytes())
    return {
        'docx_fixture_sha256': LATEST_37_DOCX_SHA256,
        'uploaded_docx_sha256': uploaded_sha or LATEST_37_DOCX_SHA256,
        'docx_bytes_match_uploaded': (
            not uploaded_sha or uploaded_sha == LATEST_37_DOCX_SHA256),
        'fixture_path': str(DOCX_LATEST_37),
    }


def sections_from_latest_37_docx_text(text: str) -> Dict[str, str]:
    return sections_from_uploaded_docx_text(text)


def load_pdf_failure_log() -> Dict[str, object]:
    if not PDF_FAILURE_LOG.is_file():
        raise FileNotFoundError(f'missing {PDF_FAILURE_LOG.name}')
    return json.loads(PDF_FAILURE_LOG.read_text(encoding='utf-8'))
