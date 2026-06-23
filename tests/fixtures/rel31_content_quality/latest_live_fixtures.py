"""Byte-exact latest live export fixtures (استراتيجية الأمن السيبراني 37)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

from tests.fixtures.rel31_content_quality.latest37_live_fixtures import (
    DOCX_LATEST_37,
    LATEST_37_DOCX_SHA256,
    ensure_latest_37_fixtures,
    sections_from_latest_37_docx_text,
    verify_latest_37_byte_identical,
)

FIXTURE_DIR = Path(__file__).resolve().parent
DOCX_LATEST = DOCX_LATEST_37
LATEST_DOCX_SHA256 = LATEST_37_DOCX_SHA256

# Legacy PDF fixture retained for parity tests that still reference (63).
PDF_LATEST = FIXTURE_DIR / 'cyber_strategy_63_actual.pdf'
LATEST_PDF_SHA256 = (
    '855b74754cb13548646ee61e78f38802bf6a00fd9310ecaaf54a42908a0e867c')


def ensure_latest_live_fixtures() -> Tuple[Path, Path]:
    docx = ensure_latest_37_fixtures()
    return docx, PDF_LATEST


def verify_latest_byte_identical() -> Dict[str, str]:
    out = verify_latest_37_byte_identical()
    out['pdf_fixture_sha256'] = LATEST_PDF_SHA256
    return out


def sections_from_latest_docx_text(text: str) -> Dict[str, str]:
    return sections_from_latest_37_docx_text(text)
