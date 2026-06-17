"""Byte-exact uploaded export fixtures (استراتيجية الأمن السيبراني 34/61)."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Dict, Tuple

FIXTURE_DIR = Path(__file__).resolve().parent
DOCX_ACTUAL = FIXTURE_DIR / 'cyber_strategy_34_actual.docx'
PDF_ACTUAL = FIXTURE_DIR / 'cyber_strategy_61_actual.pdf'

# SHA256 of the exact user-uploaded files (Downloads export 34/61).
UPLOADED_DOCX_SHA256 = (
    '5324d3edefdc14c84c621398ea4bfb63820913445345739f60b1581e92519bc3')
UPLOADED_PDF_SHA256 = (
    'd6d4c995749e46efe6eb196b91453c75f39eb942a9f0a1f7bfbd3052d3955256')

_UPLOAD_SOURCE_CANDIDATES = (
    Path('/mnt/data/استراتيجية الأمن السيبراني (34).docx'),
    Path(r'C:\Users\dell\Downloads\استراتيجية الأمن السيبراني (34).docx'),
)
_PDF_SOURCE_CANDIDATES = (
    Path('/mnt/data/استراتيجية الأمن السيبراني (61).pdf'),
    Path(r'C:\Users\dell\Downloads\استراتيجية الأمن السيبراني (61).pdf'),
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


def ensure_uploaded_fixtures() -> Tuple[Path, Path]:
    """Ensure byte-exact uploaded DOCX/PDF fixtures are present."""
    _copy_if_missing(DOCX_ACTUAL, _UPLOAD_SOURCE_CANDIDATES, UPLOADED_DOCX_SHA256)
    _copy_if_missing(PDF_ACTUAL, _PDF_SOURCE_CANDIDATES, UPLOADED_PDF_SHA256)
    docx_sha = _sha256_bytes(DOCX_ACTUAL.read_bytes())
    pdf_sha = _sha256_bytes(PDF_ACTUAL.read_bytes())
    if docx_sha != UPLOADED_DOCX_SHA256:
        raise ValueError(
            f'DOCX fixture sha mismatch: {docx_sha} != {UPLOADED_DOCX_SHA256}')
    if pdf_sha != UPLOADED_PDF_SHA256:
        raise ValueError(
            f'PDF fixture sha mismatch: {pdf_sha} != {UPLOADED_PDF_SHA256}')
    return DOCX_ACTUAL, PDF_ACTUAL


def verify_byte_identical_to_uploaded() -> Dict[str, str]:
    """Return sha256 proof that fixtures match uploaded files."""
    ensure_uploaded_fixtures()
    return {
        'docx_fixture_sha256': UPLOADED_DOCX_SHA256,
        'pdf_fixture_sha256': UPLOADED_PDF_SHA256,
        'docx_bytes_match_uploaded': True,
        'pdf_bytes_match_uploaded': True,
    }


def sections_from_uploaded_docx_text(text: str) -> Dict[str, str]:
    """Build canonical section dict from flat uploaded DOCX extracted text."""
    from domains.cyber.fixtures_ar import technical_sections
    from release_engine.rel31_acceptance_checks import (
        _risk_register_blob,
        _trace_matrix_blob,
        flat_pillar_initiative_blob,
    )

    sections = dict(technical_sections())
    pillars = flat_pillar_initiative_blob(text)
    if pillars.strip():
        sections['pillars'] = (
            '## 2. الركائز الاستراتيجية\n\n' + pillars.strip() + '\n')
    kpi_idx = text.rfind('نسبة محاولات الدخول الفاشلة الشاذة')
    if kpi_idx < 0:
        kpi_idx = text.rfind('مؤشرات الأداء الرئيسية')
    if kpi_idx >= 0:
        end = len(text)
        for end_m in (
                'العامل\nالوزن\nالدرجة',
                'تقييم الثقة والمخاطر',
                'صيغة الاحتساب',
                'خطة المعالجة',
                'سجل المخاطر',
        ):
            pos = text.find(end_m, kpi_idx + 40)
            if pos > kpi_idx:
                end = min(end, pos)
        sections['kpis'] = (
            '## 6. مؤشرات الأداء الرئيسية\n\n'
            + text[kpi_idx:end].strip() + '\n')
    risk = _risk_register_blob(text)
    if risk.strip():
        sections['confidence'] = (
            '## 7. تقييم الثقة والمخاطر\n\n' + risk.strip() + '\n')
    trace = _trace_matrix_blob(text)
    if trace.strip():
        sections['traceability'] = (
            '## 13. مصفوفة تتبع الأطر المرجعية\n\n' + trace.strip() + '\n')
    if 'المحددةفي' in text:
        sections['environment'] = (
            (sections.get('environment') or '')
            + '\nالسياسات المحددةفي المنظمة.\n')
    return sections
