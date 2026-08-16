"""PR-REL2.8 — route-bound actual export evidence (no preview-only pass for DOCX/PDF)."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from release_engine.rel27_export_checks import (
    REQUIRED_PILLAR_NAME_VARIANTS,
    check_export_model_drift,
    check_kpi_canonical,
    check_roadmap_coverage,
)

ROUTE_CHANNELS = {
    'preview': {
        'allowed': ('preview',),
        'required': ('preview',),
    },
    'docx': {
        'allowed': ('preview', 'docx'),
        'required': ('docx',),
    },
    'pdf': {
        'allowed': ('preview', 'docx', 'pdf'),
        'required': ('pdf',),
    },
    'finalize': {
        'allowed': ('preview', 'docx', 'pdf'),
        'required': ('preview', 'docx', 'pdf'),
    },
}

PILLAR_HEADING_MARKERS = (
    'الركائز الاستراتيجية',
    'الركائز',
)

NEXT_MAJOR_HEADING_RE = re.compile(r'^##\s+(?!#)', re.MULTILINE)


def normalize_route(route_name: str) -> str:
    r = (route_name or '').strip().lower()
    if r in ('docx', 'generate-docx', 'docx_export', 'api_generate_docx'):
        return 'docx'
    if r in ('pdf', 'generate-pdf', 'pdf_export', 'api_generate_pdf'):
        return 'pdf'
    if r in ('preview', 'preview_export'):
        return 'preview'
    if r in ('finalize', 'generation', 'save', 'seal', 'artifact'):
        return 'finalize'
    return 'preview' if not r else r


def sha256_bytes(data: bytes) -> str:
    if not data:
        return ''
    return hashlib.sha256(data).hexdigest()


_PILLAR_NEXT_SECTION_MARKERS = (
    'البيئة التنظيمية',
    'تحليل الفجوات',
    'خارطة الطريق',
    'مؤشرات الأداء',
    'تقييم الثقة',
    'نموذج الحوكمة',
    'مصفوفة تتبع',
)


def _slice_tail_after_marker(text: str, idx: int, marker: str) -> str:
    tail = text[idx + len(marker):]
    end = len(tail)
    for nxt in _PILLAR_NEXT_SECTION_MARKERS:
        pos = tail.find(nxt)
        if pos > 0:
            end = min(end, pos)
    m = NEXT_MAJOR_HEADING_RE.search(tail)
    if m:
        end = min(end, m.start())
    return tail[:end]


def pillar_body_after_heading(blob: str, *, domain: str = '') -> str:
    """Pillar body slice — prefer occurrence with canonical pillar names (skip TOC)."""
    from release_engine.rel27_export_checks import required_pillar_name_variants
    text = blob or ''
    marker = ''
    for m in sorted(PILLAR_HEADING_MARKERS, key=len, reverse=True):
        if m in text:
            marker = m
            break
    if not marker:
        return ''
    positions: List[int] = []
    start = 0
    while True:
        idx = text.find(marker, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + 1
    if not positions:
        return ''
    name_variants = required_pillar_name_variants(domain)
    best_section = ''
    best_score = -1
    for idx in positions:
        section = _slice_tail_after_marker(text, idx, marker)
        score = sum(
            1 for variants in name_variants
            if _pillar_variant_present(section, variants))
        if score > best_score:
            best_score = score
            best_section = section
    if best_score > 0:
        return best_section
    return _slice_tail_after_marker(text, positions[-1], marker)


def _pillar_section_after_heading(blob: str) -> str:
    return pillar_body_after_heading(blob)


def _pillar_variant_present(section: str, variants: Tuple[str, ...]) -> bool:
    """True when any variant appears in section (incl. PDF reversed Arabic)."""
    if any(v in section for v in variants):
        return True
    try:
        from release_engine_v3.rel33_pdf_evidence_norm import (
            arabic_token_present,
        )
        for v in variants:
            if arabic_token_present(section or '', v):
                return True
            # Mixed Arabic+Latin titles (e.g. … MLOps): match Arabic span alone.
            ar_only = ''.join(
                ch if (ord(ch) > 127 or ch.isspace()) else ' '
                for ch in (v or '')).strip()
            ar_only = ' '.join(ar_only.split())
            if ar_only and arabic_token_present(section or '', ar_only):
                return True
    except Exception:  # noqa: BLE001
        pass
    return False


def check_pillars_after_strategic_heading(
        blob: str, *, domain: str = '') -> List[str]:
    """Hard evidence: four pillar names must appear after strategic pillars heading."""
    from release_engine.rel27_export_checks import required_pillar_name_variants
    if not _pillar_heading_present(blob or ''):
        return []
    variants_all = required_pillar_name_variants(domain)
    section = pillar_body_after_heading(blob or '', domain=domain)
    # PDF card layouts can place pillar titles outside the naive post-heading
    # slice (or reverse glyph order across page breaks). Accept full-blob
    # evidence when the heading is present and all domain pillar names appear.
    scan = section if section.strip() else (blob or '')

    def _missing(in_text: str) -> List[str]:
        return [
            variants[0] for variants in variants_all
            if not _pillar_variant_present(in_text, variants)
        ]

    missing = _missing(scan)
    if missing and scan is not (blob or ''):
        missing = _missing(blob or '')
    if missing:
        return ['missing_pillars_after_heading']
    return []


def _pillar_heading_present(blob: str) -> bool:
    if any(m in (blob or '') for m in PILLAR_HEADING_MARKERS):
        return True
    try:
        from release_engine_v3.rel33_pdf_evidence_norm import arabic_token_present
        return any(
            arabic_token_present(blob or '', m) for m in PILLAR_HEADING_MARKERS)
    except Exception:  # noqa: BLE001
        return False


def check_roadmap_visible_drift(
        exported_blob: str,
        *,
        internal_row_count: Optional[int] = None,
        domain: str = '',
) -> List[str]:
    """Block when visible extracted roadmap rows diverge from internal canonical count."""
    # Count-only: use a known domain so family resolution never blank→raises.
    # Family defects are handled elsewhere with the real domain.
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        dcode = normalize_domain_code(str(domain or ''), default='') or 'cyber'
    except Exception:  # noqa: BLE001
        dcode = str(domain or '').strip().lower() or 'cyber'
    road = check_roadmap_coverage(exported_blob or '', domain=dcode)
    visible = int(road.get('visible_row_count') or 0)
    blockers: List[str] = []
    if visible and visible < 10:
        blockers.append(f'roadmap_row_count:{visible}')
    if internal_row_count is not None and visible > 0:
        if abs(internal_row_count - visible) >= 3 or (
                internal_row_count >= 10 and visible < 10):
            blockers.append('rel2_export_model_drift:roadmap_visible_row_count')
    return blockers


def exported_section_hashes_from_text(
        text: str,
        *,
        hash_fn: Optional[Callable[[str], str]] = None,
) -> Dict[str, str]:
    from release_engine.rel27_export_checks import _split_sections_from_export_text
    from release_engine.section_parity import (
        PARITY_SECTION_KEYS,
        _LEGACY_MAP,
        _section_hash,
    )

    split = _split_sections_from_export_text(text or '')
    return {
        key: _section_hash(
            (split.get(_LEGACY_MAP[key]) or '').strip(), hash_fn)
        for key in PARITY_SECTION_KEYS
    }


def _channel_passed(
        checked: bool,
        defects: Dict[str, Any],
        has_defects_fn,
) -> bool:
    if not checked:
        return False
    return not has_defects_fn(defects)


def apply_route_bound_verdict(
        *,
        route_name: str,
        preview_text: str,
        docx_text: str,
        pdf_text: str,
        preview_def: Dict[str, Any],
        docx_def: Dict[str, Any],
        pdf_def: Dict[str, Any],
        preview_text_checked: bool,
        docx_bytes_checked: bool,
        pdf_bytes_checked: bool,
        pdf_text_extraction_unreliable: bool,
        blocking: List[str],
        has_defects_fn,
        canonical_sections: Optional[Dict[str, str]] = None,
        hash_fn=None,
        pdf_render_fallback_ok: bool = False,
        arabic_font_registered: bool = True,
        internal_roadmap_row_count: Optional[int] = None,
        domain: str = '',
        document_type: str = 'strategy',
) -> Dict[str, Any]:
    """Compute route-specific pass flags; defaults are False until evidence checked."""
    route = normalize_route(route_name)
    # REL3.3 — the pillar-after-heading evidence is a strategy-only
    # completeness check. A risk artifact has no strategic-pillars section
    # (it is compiled risk-native, not as a strategy), so applying it would
    # falsely block risk exports. Scoped to risk types to preserve the exact
    # strategy and gap_assessment behavior.
    _dtype = str(document_type or 'strategy').strip().lower()
    _strategy_section_checks = _dtype not in ('risk', 'risk_assessment')
    channels = ROUTE_CHANNELS.get(route, ROUTE_CHANNELS['preview'])

    preview_export_evidence_passed = _channel_passed(
        preview_text_checked, preview_def, has_defects_fn)
    docx_export_evidence_passed = _channel_passed(
        docx_bytes_checked, docx_def, has_defects_fn)

    pdf_pass_from_actual_bytes = False
    pdf_pass_from_render_fallback = False
    if pdf_bytes_checked and not pdf_text_extraction_unreliable:
        pdf_pass_from_actual_bytes = _channel_passed(
            True, pdf_def, has_defects_fn)
        pdf_export_evidence_passed = pdf_pass_from_actual_bytes
    elif pdf_bytes_checked and pdf_text_extraction_unreliable:
        pdf_pass_from_render_fallback = bool(
            pdf_render_fallback_ok
            and docx_export_evidence_passed
            and arabic_font_registered)
        pdf_export_evidence_passed = pdf_pass_from_render_fallback
    else:
        pdf_export_evidence_passed = False

    # Hard pillar-after-heading checks on actual export text (strategy only)
    if _strategy_section_checks:
        for prefix, text, checked in (
                ('docx', docx_text, docx_bytes_checked),
                ('pdf', pdf_text, pdf_bytes_checked and not pdf_text_extraction_unreliable),
        ):
            if not checked or not text:
                continue
            for defect in check_pillars_after_strategic_heading(
                    text, domain=domain):
                err = f'rel2_actual_export_evidence_failed:{prefix}:{defect}'
                if err not in blocking:
                    blocking.append(err)
                if prefix == 'docx':
                    docx_export_evidence_passed = False
                if prefix == 'pdf':
                    pdf_export_evidence_passed = False
                    pdf_pass_from_actual_bytes = False

    # Section parity against actual exported text (not internal hashes only)
    if _strategy_section_checks:
        for prefix, text, checked in (
                ('docx', docx_text, docx_bytes_checked),
                ('pdf', pdf_text, pdf_bytes_checked and not pdf_text_extraction_unreliable),
        ):
            if not checked or not text:
                continue
            if check_pillars_after_strategic_heading(text, domain=domain):
                parity_err = 'rel2_section_parity_failed:pillars:actual_text_missing'
                if parity_err not in blocking:
                    blocking.append(parity_err)

    # Roadmap visible drift on exported channels.
    # REL3.3 — the roadmap model-drift / visible-row-count gate is a
    # strategy-only export check (a risk artifact has no strategy roadmap
    # section; its treatment/priority tables are legitimately counted as
    # "visible rows" and would falsely trip rel2_export_model_drift:
    # roadmap_visible_row_count). Scope to strategy-like document types
    # (strategy + gap_assessment) and skip for risk/risk_assessment. This
    # does NOT suppress the blocker globally — strategy exports still run it.
    if _strategy_section_checks:
        for prefix, text, checked in (
                ('docx', docx_text, docx_bytes_checked),
                ('pdf', pdf_text, pdf_bytes_checked and not pdf_text_extraction_unreliable),
        ):
            if not checked or not text:
                continue
            internal = internal_roadmap_row_count
            if internal is None and canonical_sections:
                from release_engine.roadmap_model import _parse_roadmap_rows
                internal = len(_parse_roadmap_rows(
                    canonical_sections.get('roadmap') or ''))
            for drift in check_roadmap_visible_drift(
                    text, internal_row_count=internal, domain=domain):
                err = drift if drift.startswith('rel2_') else (
                    f'rel2_actual_export_evidence_failed:{prefix}:{drift}')
                if err not in blocking:
                    blocking.append(err)
                if prefix == 'docx':
                    docx_export_evidence_passed = False
                if prefix == 'pdf':
                    pdf_export_evidence_passed = False

    # KPI / risk / traceability visible invalid aggregate blockers
    for prefix, defects, checked, passed_flag in (
            ('docx', docx_def, docx_bytes_checked, 'docx'),
            ('pdf', pdf_def, pdf_bytes_checked and not pdf_text_extraction_unreliable, 'pdf'),
    ):
        if not checked:
            continue
        kpi_defects = defects.get('kpi_defects') or []
        if kpi_defects:
            err = 'rel2_actual_export_evidence_failed:kpi_visible_invalid'
            if err not in blocking:
                blocking.append(err)
            if passed_flag == 'docx':
                docx_export_evidence_passed = False
            else:
                pdf_export_evidence_passed = False
        risk_defects = defects.get('risk_defects') or []
        if risk_defects:
            err = f'rel2_actual_export_evidence_failed:{prefix}:empty_risk_treatment'
            if err not in blocking:
                blocking.append(err)
            if 'rel2_actual_export_evidence_failed:empty_risk_treatment' not in blocking:
                blocking.append(
                    'rel2_actual_export_evidence_failed:empty_risk_treatment')
            if passed_flag == 'docx':
                docx_export_evidence_passed = False
            else:
                pdf_export_evidence_passed = False
        trace_defects = defects.get('traceability_defects') or []
        if trace_defects:
            err = 'rel2_actual_export_evidence_failed:traceability_visible_invalid'
            if err not in blocking:
                blocking.append(err)
            if passed_flag == 'docx':
                docx_export_evidence_passed = False
            else:
                pdf_export_evidence_passed = False

    route_blocker = ''
    route_evidence_passed = False

    if route == 'preview':
        if not preview_text_checked:
            route_blocker = 'rel2_actual_export_evidence_failed:preview:not_checked'
            blocking.append(route_blocker)
        route_evidence_passed = preview_export_evidence_passed and preview_text_checked
    elif route == 'docx':
        if not docx_bytes_checked:
            route_blocker = 'rel2_actual_export_evidence_failed:docx_bytes_not_checked'
            if route_blocker not in blocking:
                blocking.append(route_blocker)
        route_evidence_passed = (
            docx_bytes_checked and docx_export_evidence_passed)
    elif route == 'pdf':
        if not pdf_bytes_checked and not pdf_text_extraction_unreliable:
            route_blocker = 'rel2_actual_export_evidence_failed:pdf_bytes_not_checked'
            if route_blocker not in blocking:
                blocking.append(route_blocker)
        elif pdf_text_extraction_unreliable and not pdf_render_fallback_ok:
            route_blocker = (
                'rel2_actual_export_evidence_failed:pdf_render_fallback_required')
            if route_blocker not in blocking:
                blocking.append(route_blocker)
        route_evidence_passed = pdf_bytes_checked and (
            pdf_pass_from_actual_bytes or pdf_pass_from_render_fallback)
        if pdf_text_extraction_unreliable and pdf_bytes_checked:
            route_evidence_passed = (
                pdf_pass_from_render_fallback and docx_bytes_checked)
    elif route == 'finalize':
        if not preview_text_checked:
            blocking.append(
                'rel2_actual_export_evidence_failed:preview:not_checked')
        if not docx_bytes_checked:
            blocking.append(
                'rel2_actual_export_evidence_failed:docx_bytes_not_checked')
        if not pdf_bytes_checked and not pdf_text_extraction_unreliable:
            blocking.append(
                'rel2_actual_export_evidence_failed:pdf_bytes_not_checked')
        route_evidence_passed = (
            preview_export_evidence_passed
            and docx_export_evidence_passed
            and (
                pdf_pass_from_actual_bytes
                or pdf_pass_from_render_fallback))
    else:
        route_evidence_passed = preview_export_evidence_passed

    blocking = list(dict.fromkeys(blocking))
    if route_blocker and not route_evidence_passed:
        pass
    elif not route_evidence_passed and blocking:
        route_blocker = blocking[0]

    export_return_allowed = route_evidence_passed

    exported_docx_hashes = (
        exported_section_hashes_from_text(docx_text, hash_fn=hash_fn)
        if docx_bytes_checked and docx_text else {})
    exported_pdf_hashes = (
        exported_section_hashes_from_text(pdf_text, hash_fn=hash_fn)
        if pdf_bytes_checked and pdf_text
        and not pdf_text_extraction_unreliable else {})

    return {
        'requested_route': route,
        'allowed_evidence_channels': list(channels['allowed']),
        'required_evidence_channels': list(channels['required']),
        'preview_export_evidence_passed': preview_export_evidence_passed,
        'docx_export_evidence_passed': docx_export_evidence_passed,
        'pdf_export_evidence_passed': pdf_export_evidence_passed,
        'preview_pass_used_for_preview_only': (
            route == 'preview' and preview_export_evidence_passed),
        'docx_pass_from_actual_bytes': (
            docx_bytes_checked and docx_export_evidence_passed),
        'pdf_pass_from_actual_bytes': pdf_pass_from_actual_bytes,
        'pdf_pass_from_render_fallback': pdf_pass_from_render_fallback,
        'route_evidence_passed': route_evidence_passed,
        'route_evidence_blocker': route_blocker,
        'export_return_allowed': export_return_allowed,
        'actual_export_evidence_passed': route_evidence_passed,
        'export_evidence_passed': route_evidence_passed,
        'exported_docx_section_hashes': exported_docx_hashes,
        'exported_pdf_section_hashes': exported_pdf_hashes,
        'exported_text_hash_available': bool(
            exported_docx_hashes or exported_pdf_hashes),
        'blocking_errors': blocking,
    }


def emit_returned_file_fingerprint(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-RETURNED-FILE-FINGERPRINT] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def build_returned_file_fingerprint(
        *,
        route_name: str,
        strategy_id: str = '',
        final_hash: str = '',
        returned_bytes: bytes = b'',
        evidence_bytes: bytes = b'',
        export_return_allowed: bool = False,
        blocking_error_if_any: str = '',
) -> Dict[str, Any]:
    ret_sha = sha256_bytes(returned_bytes)
    ev_sha = sha256_bytes(evidence_bytes)
    payload = {
        'route_name': normalize_route(route_name),
        'strategy_id': strategy_id or '',
        'final_hash': final_hash or '',
        'returned_bytes_sha256': ret_sha,
        'evidence_bytes_sha256': ev_sha,
        'returned_equals_evidence_bytes': bool(
            ret_sha and ev_sha and ret_sha == ev_sha),
        'export_return_allowed': export_return_allowed,
        'blocking_error_if_any': blocking_error_if_any or '',
    }
    emit_returned_file_fingerprint(payload)
    return payload
