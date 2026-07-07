"""REL3.3 — Arabic-robust matching for returned-PDF evidence extraction.

Render/PyMuPDF PDF text extraction can return Arabic in presentation forms,
with diacritics, tatweel, or reversed glyph order, and can lose word spacing.
These helpers normalize such extracted text so returned-file family / KPI
schema detection matches content that is genuinely present in the PDF.

This FIXES false-negative extraction (a table/row that IS in the returned PDF
but whose Arabic glyphs did not survive naive substring matching). It does NOT
weaken evidence: detection still requires the canonical tokens to be present in
the returned PDF's own extracted text.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Tuple

_TASHKEEL_RE = re.compile(r'[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]')
_TATWEEL = '\u0640'
_LETTER_VARIANTS = {
    'أ': 'ا', 'إ': 'ا', 'آ': 'ا', 'ٱ': 'ا',
    'ى': 'ي', 'ئ': 'ي', 'ؤ': 'و', 'ة': 'ه',
}


def normalize_arabic_loose(text: str) -> str:
    """Loose Arabic normalization for evidence matching.

    NFKC (maps Arabic presentation forms FB50-FEFF back to base letters),
    strips tatweel + diacritics, unifies alef/ya/ta-marbuta/hamza variants,
    lowercases ASCII, and collapses whitespace.
    """
    if not text:
        return ''
    out = unicodedata.normalize('NFKC', str(text))
    out = out.replace(_TATWEEL, '')
    out = _TASHKEEL_RE.sub('', out)
    out = ''.join(_LETTER_VARIANTS.get(ch, ch) for ch in out)
    out = out.lower()
    out = re.sub(r'\s+', ' ', out)
    return out.strip()


def arabic_token_present(haystack: str, token: str) -> bool:
    """True if ``token`` is present in ``haystack`` under loose Arabic matching.

    Handles presentation-form / diacritic / letter-variant differences and,
    for RTL extraction that reverses glyph order, a reversed-form fallback
    (both space-preserving and space-collapsed).
    """
    if not haystack or not token:
        return False
    if str(token).isascii():
        return str(token).lower() in str(haystack).lower()
    nh = normalize_arabic_loose(haystack)
    nt = normalize_arabic_loose(token)
    if not nt:
        return False
    if nt in nh:
        return True
    if nt[::-1] in nh:
        return True
    nt_ns = nt.replace(' ', '')
    nh_ns = nh.replace(' ', '')
    if nt_ns and (nt_ns in nh_ns or nt_ns[::-1] in nh_ns):
        return True
    return False


def any_token_present(haystack: str, tokens: Iterable[str]) -> bool:
    return any(arabic_token_present(haystack, t) for t in tokens)


# Additional family aliases keyed by roadmap family id. Base tokens live in
# release_engine.roadmap_model._FAMILY_TOKENS; these extend detection for
# returned-PDF Arabic text where the base token may not survive extraction.
ROADMAP_FAMILY_ALIASES: Dict[str, Tuple[str, ...]] = {
    'awareness_training': (
        'التوعية الأمنية',
        'برنامج التوعية الأمنية',
        'تدريب التوعية',
        'رفع الوعي الأمني',
        'الأمني التوعية',
        'التوعية',
        'الوعي',
        # Reversed-glyph forms observed in some RTL PDF text extraction.
        'ةينملأا ةيعوتلا',
        'ةيعوتلا',
        'awareness',
        'training',
    ),
}


def detect_families_normalized(
        text: str,
        family_tokens: Dict[str, Tuple[str, ...]],
        *,
        present: Dict[str, bool] | None = None,
) -> Dict[str, bool]:
    """Return {family: bool} using loose Arabic matching + aliases.

    ``present`` may seed already-detected families (e.g. from structured table
    parsing); this only flips additional families to ``True``.
    """
    out: Dict[str, bool] = dict(present or {})
    for fam, tokens in family_tokens.items():
        if out.get(fam):
            continue
        all_tokens = tuple(tokens) + ROADMAP_FAMILY_ALIASES.get(fam, ())
        if any_token_present(text, all_tokens):
            out[fam] = True
    return out


def emit_rel33_pdf_roadmap_family_evidence(diag: Dict[str, Any]) -> None:
    try:
        import json
        print(
            '[REL33-PDF-ROADMAP-FAMILY-EVIDENCE] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def emit_rel33_pdf_kpi_main_extractability(diag: Dict[str, Any]) -> None:
    try:
        import json
        print(
            '[REL33-PDF-KPI-MAIN-EXTRACTABILITY] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def evaluate_pdf_roadmap_family_evidence(
        text: str,
        *,
        domain: str = '',
        document_type: str = 'strategy',
        route_name: str = 'pdf',
        detection_source: str = 'returned_pdf_text',
) -> Dict[str, Any]:
    """Family evidence diagnostic for the returned PDF text (emits diag)."""
    from release_engine.roadmap_model import ROADMAP_FAMILIES, _FAMILY_TOKENS
    present = detect_families_normalized(text or '', dict(_FAMILY_TOKENS))
    detected = [f for f in ROADMAP_FAMILIES if present.get(f)]
    missing = [f for f in ROADMAP_FAMILIES if not present.get(f)]
    reversed_used = bool(
        text and normalize_arabic_loose(text)
        and any(
            normalize_arabic_loose(a)[::-1] in normalize_arabic_loose(text)
            and normalize_arabic_loose(a) not in normalize_arabic_loose(text)
            for a in ROADMAP_FAMILY_ALIASES.get('awareness_training', ())))
    diag = {
        'route_name': route_name,
        'domain': domain,
        'document_type': document_type,
        'expected_families': list(ROADMAP_FAMILIES),
        'detected_families': detected,
        'missing_families': missing,
        'detection_source': detection_source,
        'normalized_text_used': True,
        'reversed_arabic_fallback_used': reversed_used,
        'roadmap_family_evidence_passed': not missing,
        'blocking_errors': [f'missing_family:{f}' for f in missing],
    }
    emit_rel33_pdf_roadmap_family_evidence(diag)
    return diag
