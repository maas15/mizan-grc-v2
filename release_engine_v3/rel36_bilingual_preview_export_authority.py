"""REL36 — bilingual preview and authoritative export routing.

Keeps REL3.3 compiler-first Arabic-only. English strategy preview/DOCX/PDF
must still use the same authoritative export contract and visible-output
cleanup as Arabic. Frozen/canonical artifacts are not mutated.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel33_authority import (
    REL33_AUTHORITATIVE_DOMAINS,
)
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel34_visible_output_quality import (
    sanitize_visible_export_text,
    visible_text_has_internal_markers,
)


REL36_STRATEGY_DOCUMENT_TYPES = frozenset({
    'strategy', 'strategy_document', 'strategy document',
})

REL36_KPI_MAIN_HEADERS_AR: Tuple[str, ...] = (
    '#', 'وصف المؤشر', 'النوع', 'القيمة المستهدفة',
    'صيغة الاحتساب', 'مصدر', 'التكرار', 'المالك',
)
REL36_KPI_MAIN_HEADERS_EN: Tuple[str, ...] = (
    '#', 'KPI Description', 'Type', 'Target Value',
    'Calculation Formula', 'Source', 'Frequency', 'Owner',
)
REL36_KPI_FORMULA_HEADERS_AR: Tuple[str, ...] = (
    '#', 'المؤشر', 'صيغة الاحتساب', 'مصدر البيانات',
)
REL36_KPI_FORMULA_HEADERS_EN: Tuple[str, ...] = (
    '#', 'Indicator', 'Calculation Formula', 'Data Source',
)

# Alias detection only — visible English output still renders English labels.
_KPI_MAIN_HEADER_ALIASES_EN = {
    'KPI Description': ('kpi description', 'indicator', 'وصف المؤشر'),
    'Type': ('type', 'النوع'),
    'Target Value': ('target value', 'target', 'القيمة المستهدفة'),
    'Calculation Formula': (
        'calculation formula', 'formula', 'صيغة الاحتساب'),
    'Source': ('source', 'مصدر', 'مصدر البيانات'),
    'Frequency': ('frequency', 'التكرار'),
    'Owner': ('owner', 'المالك'),
}
_ARABIC_KPI_HEADER_TOKENS = (
    'مصدر', 'المالك', 'التكرار', 'وصف المؤشر', 'صيغة الاحتساب',
    'القيمة المستهدفة', 'مصدر البيانات',
)


def normalize_rel36_lang(lang: str) -> str:
    raw = str(lang or '').strip().lower()
    if raw in ('ar', 'arabic', 'عربي', 'العربية'):
        return 'ar'
    if raw in ('en', 'english', 'eng'):
        return 'en'
    return raw or 'ar'


def is_rel36_bilingual_export_authoritative(
        *,
        domain: str = 'cyber',
        lang: str = 'en',
        document_type: str = 'strategy',
        flags: Optional[Dict[str, Any]] = None) -> bool:
    """True for REL33-domain strategy exports in Arabic or English.

    Does not expand compiler-first / generation authority.
    """
    flags = flags or {'rel3': True, 'rel31': True}
    if not flags.get('rel31') or not flags.get('rel3'):
        return False
    dcode = _normalize_rel31_domain_code(domain)
    if dcode not in REL33_AUTHORITATIVE_DOMAINS:
        return False
    nlang = normalize_rel36_lang(lang)
    if nlang not in ('ar', 'en'):
        return False
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype in ('', 'strategy document'):
        dtype = 'strategy'
    return dtype in REL36_STRATEGY_DOCUMENT_TYPES


def kpi_main_headers(lang: str) -> Tuple[str, ...]:
    return (
        REL36_KPI_MAIN_HEADERS_AR
        if normalize_rel36_lang(lang) == 'ar'
        else REL36_KPI_MAIN_HEADERS_EN
    )


def kpi_formula_headers(lang: str) -> Tuple[str, ...]:
    return (
        REL36_KPI_FORMULA_HEADERS_AR
        if normalize_rel36_lang(lang) == 'ar'
        else REL36_KPI_FORMULA_HEADERS_EN
    )


def _norm_header(value: str) -> str:
    return ' '.join(str(value or '').strip().split()).lower()


def header_matches_expected(got: str, expected: str, lang: str) -> bool:
    g = _norm_header(got)
    e = _norm_header(expected)
    if g == e:
        return True
    if normalize_rel36_lang(lang) != 'en':
        return False
    aliases = _KPI_MAIN_HEADER_ALIASES_EN.get(expected) or ()
    return g in aliases


def headers_match_kpi_main(headers: Sequence[str], lang: str) -> bool:
    expected = kpi_main_headers(lang)
    if len(headers) != len(expected):
        return False
    return all(
        header_matches_expected(headers[i], expected[i], lang)
        for i in range(len(expected)))


def english_visible_has_arabic_kpi_headers(text: str) -> bool:
    blob = str(text or '')
    return any(tok in blob for tok in _ARABIC_KPI_HEADER_TOKENS)


def sanitize_visible_preview_text(text: str, lang: str = 'ar') -> str:
    """Visible preview/HTML/TXT/Print cleanup. Does not touch frozen bytes."""
    return sanitize_visible_export_text(text, normalize_rel36_lang(lang))


def sanitize_visible_preview_sections(
        sections: Any, lang: str = 'ar') -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in normalize_preview_sections(sections).items():
        if str(key).startswith('_'):
            out[str(key)] = value
            continue
        out[str(key)] = sanitize_visible_preview_text(value, lang)
    return out


def _section_to_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for k in ('content', 'text', 'markdown', 'body', 'html'):
            raw = value.get(k)
            if isinstance(raw, str) and raw.strip():
                return raw
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def normalize_preview_sections(sections: Any) -> Dict[str, str]:
    if not isinstance(sections, dict):
        return {}
    return {
        str(k): _section_to_text(v)
        for k, v in sections.items()
        if not str(k).startswith('_') or str(k) in ('_document_type',)
    }


def bind_saved_preview_payload(
        payload: Optional[Dict[str, Any]],
        *,
        expected_domain: str = '',
        expected_lang: str = '',
        expected_document_type: str = 'strategy',
) -> Dict[str, Any]:
    """Bind saved strategy id/content for preview. Fail closed with diagnostic."""
    src = dict(payload or {})
    sid = src.get('strategy_id') or src.get('id') or src.get('artifact_id')
    sections = normalize_preview_sections(src.get('sections'))
    content_json = src.get('content_json')
    if isinstance(content_json, str):
        try:
            content_json = json.loads(content_json)
        except Exception:  # noqa: BLE001
            content_json = None
    lang = normalize_rel36_lang(
        src.get('language') or src.get('lang') or expected_lang or 'ar')
    domain = str(src.get('domain') or expected_domain or '')
    document_type = str(
        src.get('document_type') or expected_document_type or 'strategy'
    ).strip().lower() or 'strategy'
    blocking: List[str] = []
    if not sid:
        blocking.append('rel36_saved_preview_strategy_id_missing')
    if not sections and not (
            isinstance(content_json, dict)
            and (content_json.get('sections') or content_json.get('content'))):
        blocking.append('rel36_saved_preview_content_missing')
    if expected_domain and domain:
        exp = _normalize_rel31_domain_code(expected_domain)
        got = _normalize_rel31_domain_code(domain)
        if exp and got and exp != got:
            blocking.append(
                f'rel36_saved_preview_domain_mismatch:{got}:{exp}')
    if expected_lang:
        exp_l = normalize_rel36_lang(expected_lang)
        if exp_l and lang and exp_l != lang:
            blocking.append(
                f'rel36_saved_preview_lang_mismatch:{lang}:{exp_l}')
    visible_sections = sanitize_visible_preview_sections(sections, lang)
    bound = {
        'success': not blocking,
        'id': sid,
        'strategy_id': sid,
        'sections': visible_sections,
        'content_json': content_json,
        'domain': domain,
        'language': lang,
        'document_type': document_type,
        'blocking_errors': blocking,
        'preview_bound': not blocking,
    }
    if blocking:
        bound['error'] = (
            'saved_preview_content_missing:'
            f'strategy_id={sid or "none"};domain={domain or "none"};'
            f'lang={lang};document_type={document_type};'
            + ','.join(blocking)
        )
        bound['success'] = False
    return bound


def evaluate_rel36_bilingual_export_authority(
        *,
        route: str,
        lang: str,
        domain: str,
        document_type: str,
        output_type: str,
        selected_exporter: str = '',
        authoritative_path_used: bool = False,
        legacy_builder_attempted: bool = False,
        docx_bypass_detected: bool = False,
        pdf_professional_renderer_used: bool = False,
        blocking_errors: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    blockers = [str(b) for b in (blocking_errors or []) if b]
    allowed = is_rel36_bilingual_export_authoritative(
        domain=domain, lang=lang, document_type=document_type)
    if legacy_builder_attempted and output_type == 'docx':
        blockers.append(
            'rel32_docx_export_bypass_detected:_build_docx_bytes')
    if allowed and not authoritative_path_used and output_type in (
            'docx', 'pdf'):
        blockers.append(
            f'rel36_authoritative_path_not_used:{output_type}')
    passed = (
        allowed
        and authoritative_path_used
        and not legacy_builder_attempted
        and not docx_bypass_detected
        and not blockers
    )
    return {
        'tag': 'REL36-BILINGUAL-EXPORT-AUTHORITY',
        'route': route,
        'lang': normalize_rel36_lang(lang),
        'domain': _normalize_rel31_domain_code(domain) or domain,
        'document_type': str(document_type or 'strategy'),
        'output_type': output_type,
        'selected_exporter': selected_exporter,
        'authoritative_path_used': bool(authoritative_path_used),
        'legacy_builder_attempted': bool(legacy_builder_attempted),
        'docx_bypass_detected': bool(docx_bypass_detected),
        'pdf_professional_renderer_used': bool(pdf_professional_renderer_used),
        'blocking_errors': blockers,
        'passed': passed,
    }


def emit_rel36_bilingual_export_authority(diag: Dict[str, Any]) -> None:
    try:
        print(
            f"[REL36-BILINGUAL-EXPORT-AUTHORITY] {json.dumps(diag, ensure_ascii=False)}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        print('[REL36-BILINGUAL-EXPORT-AUTHORITY] emit_failed', flush=True)


def preview_visible_has_family_markers(text: str) -> bool:
    return visible_text_has_internal_markers(text)
