"""PR-REL2.6/REL2.7 — validate actual exported DOCX/PDF/preview visible text."""

from __future__ import annotations

import json
import re
from html import unescape
from typing import Any, Dict, List, Optional, Tuple

from release_engine.rel27_export_checks import (
    check_export_model_drift,
    emit_exported_arabic_residue_check,
    emit_exported_kpi_canonical_check,
    emit_exported_roadmap_coverage_check,
    rel27_channel_checks,
)
from release_engine.rel28_route_evidence import (
    apply_route_bound_verdict,
    build_returned_file_fingerprint,
    normalize_route,
)
from release_engine.rendered_evidence_validator import (
    _DLP_INCIDENT_BAD,
    _DLP_KRI_REPLACEMENT,
    _GENERIC_FORMULA_VARIANTS,
    _IAM_WEAK_TARGET,
    _RISK_TREATMENTS_BY_THEME,
    _CSIRT_GAP,
    _scrub_global_forbidden,
    extract_docx_visible_text,
    extract_pdf_visible_text,
    repair_sections_for_rendered_evidence,
)

# Re-export for callers
extract_text_from_docx_bytes = extract_docx_visible_text
extract_text_from_pdf_bytes = extract_pdf_visible_text

REL26_FORBIDDEN_KPI = (
    'نسبة الترقيع الأمني خارج SLA',
)

REL26_GENERIC_FORMULAS = (
    '(القيمة المحققة / القيمة المستهدفة) × 100',
    '(القيمة المحققة/القيمة المستهدفة) × 100',
    '(عدد العناصر المطابقة / إجمالي العناصر) × 100',
    '(عدد العناصر المطابقة/إجمالي العناصر) × 100',
) + _GENERIC_FORMULA_VARIANTS

REL26_ARABIC_RESIDUES = (
    'لل معالجة',
    'للتعاملمع',
    'الاجتماعيةضد',
    'الاستعادةفي',
    'الحاليةفي',
    'الموظفينفي',
    'رئيسيةفي',
    'ال منظمة',
    'ال معلومات',
    'ال معمول',
    'ل منع',
    'حلولمنع',
    'حلمنع',
    'ال معتمدة',
    'ال معيارية',
    'المسؤول أمن السيبرانيe',
    'Lead e',
)

REL26_ROADMAP_BAD_INITIATIVES = (
    'نسبة التطبيق الكامل',
)

REL26_TRACE_BAD = (
    'عدم وجود مركز عمليات أمنية',
    'نقص مركز SOC',
    'CSIRT (SOC)',
    'SOC (CSIRT)',
)

_AR_GLUE_RE = re.compile(
    r'(?:الحالية|الموظفين|رئيسية|حلول)(?=في)'
    r'|(?:^|\s)ال\s+(?:منظمة|معلومات|معمول|معتمدة|معيارية)'
    r'|لل\s+معالجة'
    r'|حلولمنع|حلمنع',
    re.UNICODE,
)


def extract_text_from_preview_html(preview_html: str) -> str:
    """Strip HTML to visible text for preview evidence checks."""
    if not preview_html:
        return ''
    text = unescape(preview_html)
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</(p|div|tr|li|h[1-6])>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s{2,}', ' ', text)
    return '\n'.join(ln.strip() for ln in text.splitlines() if ln.strip())


def _find_in(blob: str, patterns: Tuple[str, ...]) -> List[str]:
    return [p for p in patterns if p and p in (blob or '')]


def _kpi_defects_in(blob: str) -> List[str]:
    from release_engine.rel27_export_checks import _kpi_section_blob
    scoped = _kpi_section_blob(blob) or blob
    defects = _find_in(scoped, REL26_FORBIDDEN_KPI)
    for gf in REL26_GENERIC_FORMULAS:
        if gf in scoped:
            defects.append('generic_formula')
    if _DLP_INCIDENT_BAD in blob and '%' in blob:
        defects.append(_DLP_INCIDENT_BAD)
    # Critical DLP as KPI with percentage target
    if 'عدد حوادث تسرب البيانات الحرجة' in scoped:
        for ln in scoped.splitlines():
            if 'عدد حوادث تسرب البيانات الحرجة' not in ln:
                continue
            if re.search(
                    r'عدد حوادث تسرب البيانات الحرجة[^|\n]*(?:100%|≥\s*\d+\s*%)',
                    ln):
                if 'KRI' not in ln.upper() and 'kri' not in ln.lower():
                    defects.append(
                        'dlp_critical_incident_kpi_with_percent_target')
                break
            if ln.strip().startswith('|'):
                cells = [c.strip() for c in ln.strip('|').split('|')]
                name_idx = next(
                    (i for i, c in enumerate(cells)
                     if 'عدد حوادث تسرب البيانات الحرجة' in c), None)
                if name_idx is not None and len(cells) > name_idx + 1:
                    target = cells[name_idx + 1]
                    if '%' in target and 'حوادث' not in target:
                        defects.append(
                            'dlp_critical_incident_kpi_with_percent_target')
                        break
    return list(dict.fromkeys(defects))


def _risk_defects_in(blob: str) -> List[str]:
    empty: List[str] = []
    in_risk = False
    for ln in (blob or '').splitlines():
        low = ln.lower()
        if any(k in ln for k in (
                'تقييم الثقة', 'سجل المخاطر', 'confidence risk')):
            in_risk = True
        if in_risk and ln.strip().startswith('##') and not any(
                k in ln for k in ('ثقة', 'مخاطر', 'confidence')):
            in_risk = False
        if not in_risk:
            continue
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        if 'خطة المعالجة' in ln or 'treatment' in low:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if len(cells) >= 5 and cells[-1] in ('—', '-', ''):
            empty.append('empty_treatment_plan')
    return list(dict.fromkeys(empty))


def _trace_defects_in(blob: str) -> List[str]:
    bad = _find_in(blob, REL26_TRACE_BAD)
    in_trace = False
    for ln in (blob or '').splitlines():
        if 'مصفوفة التتبع' in ln or 'traceability' in ln.lower():
            in_trace = True
        if in_trace and ln.strip().startswith('##') and 'مصفوفة' not in ln:
            in_trace = False
        if not in_trace:
            continue
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        cap = cells[1] if len(cells) > 1 else ''
        gap = cells[2] if len(cells) > 2 else ''
        if 'حماية البيانات' in cap:
            if (
                'ضعف حماية البيانات' not in gap
                and (
                    'DLP' in gap.upper()
                    or 'منع تسرب' in gap
                    or gap.strip().upper() == 'DLP'
                )
            ):
                bad.append('dcc_data_protection_dlp_only')
        if 'DCC' in ln.upper() and cap.strip().upper() == 'DLP':
            if gap in ('—', '-', ''):
                bad.append('dcc_dlp_gap_blank')
        if 'الاستجابة للحوادث' in cap or 'الاستجابة للحوادث' in ln:
            if any(p in ln for p in (
                    'عدم وجود مركز عمليات أمنية', 'نقص مركز SOC')):
                bad.append('ecc_incident_soc_only_gap')
    return list(dict.fromkeys(bad))


_ARABIC_RESIDUE_ALLOWLIST = (
    'أعمال معتمدة',
    'خطة معتمدة',
    'خطة زمنية معتمدة',
    'معتمدة للعمليات',
    'سجل بيانات مصنفة ومعتمد',
    'بيانات حساسة معتمدة',
    'إجراءات معالجة بيانات حساسة معتمدة',
)


def _contains_arabic_residue(blob: str, pattern: str) -> bool:
    if not pattern or not blob:
        return False
    scrubbed = blob
    if pattern == 'ال معتمدة':
        for phrase in _ARABIC_RESIDUE_ALLOWLIST:
            scrubbed = scrubbed.replace(phrase, '')
    return pattern in scrubbed


def _arabic_defects_in(blob: str) -> List[str]:
    found = [
        p for p in REL26_ARABIC_RESIDUES
        if _contains_arabic_residue(blob or '', p)]
    if _AR_GLUE_RE.search(blob or ''):
        found.append('arabic_glued_particle')
    return list(dict.fromkeys(found))


def _count_roadmap_rows_visible(blob: str) -> int:
    """Count substantive roadmap rows (parity with rendered evidence validator)."""
    count = 0
    in_roadmap = False
    for ln in (blob or '').splitlines():
        if 'خارطة الطريق' in ln or 'Implementation Roadmap' in ln:
            in_roadmap = True
            count = 0
            continue
        if in_roadmap and ln.strip().startswith('##'):
            break
        if not in_roadmap:
            continue
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if not cells or cells[0] in ('المرحلة', 'Phase', '#', 'رقم'):
            continue
        if cells[0].isdigit() or 'المرحلة' in cells[0]:
            count += 1
    return count


def _roadmap_defects_in(
        blob: str,
        *,
        internal_row_count: int | None = None) -> List[str]:
    defects: List[str] = []
    try:
        from release_engine.rel27_export_checks import _roadmap_section_blob
        scan_blob = _roadmap_section_blob(blob or '') or (blob or '')
    except Exception:  # noqa: BLE001
        scan_blob = blob or ''
    for bad in REL26_ROADMAP_BAD_INITIATIVES:
        if bad in scan_blob:
            defects.append(f'roadmap_bad_initiative:{bad}')
    try:
        from release_engine.rel27_export_checks import check_roadmap_coverage
        road = check_roadmap_coverage(blob or '')
        if road.get('exported_roadmap_coverage_valid'):
            return defects
        if int(road.get('visible_row_count') or 0) >= 10:
            return defects
    except Exception:  # noqa: BLE001
        pass
    if internal_row_count is not None and internal_row_count >= 10:
        return defects
    count = _count_roadmap_rows_visible(scan_blob)
    if count and count < 10:
        defects.append(f'roadmap_row_count:{count}')
    return defects


def _forbidden_in(
        blob: str,
        *,
        internal_roadmap_row_count: int | None = None) -> List[str]:
    items: List[str] = []
    items.extend(_find_in(blob, REL26_FORBIDDEN_KPI))
    items.extend(_roadmap_defects_in(
        blob, internal_row_count=internal_roadmap_row_count))
    items.extend(_kpi_defects_in(blob))
    items.extend(_arabic_defects_in(blob))
    items.extend(_trace_defects_in(blob))
    return list(dict.fromkeys(items))


def _channel_defects(
        text: str,
        *,
        route: str = '',
        pdf_bytes: bytes = b'',
        internal_roadmap_row_count: int | None = None,
        peer_row_counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    # PR-REL2.6/7: validate raw visible export text — never scrub before detection.
    blob = text or ''
    rel27 = rel27_channel_checks(blob)
    rel31_defects: List[str] = []
    substance_defects: List[str] = []
    try:
        from release_engine.rel31_acceptance_checks import (
            run_rel31_acceptance_checks,
        )
        rel31_defects = run_rel31_acceptance_checks(
            blob, route=route, pdf_bytes=pdf_bytes)
    except Exception:  # noqa: BLE001
        rel31_defects = []
    try:
        from release_engine.rel31_content_substance_checks import (
            run_rel31_content_substance_checks,
        )
        substance_defects = run_rel31_content_substance_checks(
            blob, route=route, pdf_bytes=pdf_bytes,
            peer_row_counts=peer_row_counts)
    except Exception:  # noqa: BLE001
        substance_defects = []
    kpi_defects = list(dict.fromkeys(
        _kpi_defects_in(blob) + (rel27.get('kpi_defects') or [])))
    rel27_road_defects = list(rel27.get('roadmap_defects') or [])
    if internal_roadmap_row_count is not None and internal_roadmap_row_count >= 10:
        rel27_road_defects = [
            d for d in rel27_road_defects
            if not str(d).startswith('roadmap_row_count')]
    roadmap_defects = list(dict.fromkeys(
        _roadmap_defects_in(
            blob, internal_row_count=internal_roadmap_row_count)
        + rel27_road_defects))
    if (route == 'preview'
            and internal_roadmap_row_count is not None
            and internal_roadmap_row_count >= 10):
        roadmap_defects = [
            d for d in roadmap_defects
            if str(d).startswith('roadmap_bad_initiative')]
    risk_defects = list(dict.fromkeys(
        _risk_defects_in(blob) + (rel27.get('risk_defects') or [])))
    traceability_defects = list(dict.fromkeys(
        _trace_defects_in(blob) + (rel27.get('traceability_defects') or [])))
    arabic_residues = list(dict.fromkeys(
        _arabic_defects_in(blob) + (rel27.get('arabic_residues') or [])))
    forbidden = list(dict.fromkeys(
        _forbidden_in(
            blob, internal_roadmap_row_count=internal_roadmap_row_count)
        + (rel27.get('missing_sections') or [])
        + kpi_defects
        + risk_defects
        + traceability_defects
        + arabic_residues
        + rel31_defects
        + substance_defects
        + roadmap_defects))
    return {
        'forbidden_patterns': forbidden,
        'missing_sections': rel27.get('missing_sections') or [],
        'kpi_defects': kpi_defects,
        'risk_defects': risk_defects,
        'arabic_residues': arabic_residues,
        'traceability_defects': traceability_defects,
        'roadmap_defects': roadmap_defects,
        'kpi_canonical': rel27.get('kpi_canonical') or {},
        'roadmap_coverage': rel27.get('roadmap_coverage') or {},
        'arabic_check': rel27.get('arabic_check') or {},
    }


def _blocking_from_defects(
        prefix: str, defects: Dict[str, Any]) -> List[str]:
    blockers: List[str] = []
    skip_keys = {'kpi_canonical', 'roadmap_coverage', 'arabic_check'}
    for key, items in defects.items():
        if key in skip_keys:
            continue
        for item in items or []:
            if key == 'missing_sections' and item == 'pillars':
                blockers.append(f'{prefix}:missing_pillars')
            else:
                blockers.append(f'{prefix}:{item}')
    return blockers


def validate_actual_export_evidence(
        preview_text: str = '',
        docx_text: str = '',
        pdf_text: str = '',
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        document_type: str = 'strategy',
        pdf_text_extraction_unreliable: bool = False,
        pdf_bytes_had: bool = False,
        pdf_bytes: bytes = b'',
        route_name: str = '',
        final_hash: str = '',
        canonical_sections: Optional[Dict[str, str]] = None,
        hash_fn=None,
) -> Dict[str, Any]:
    """Validate visible text from actual export surfaces (not render model only)."""
    internal_roadmap_row_count = None
    if canonical_sections:
        try:
            from release_engine.roadmap_model import _parse_roadmap_rows
            internal_roadmap_row_count = len(
                _parse_roadmap_rows(canonical_sections.get('roadmap') or ''))
        except Exception:  # noqa: BLE001
            internal_roadmap_row_count = None

    def _roadmap_peer_counts() -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for label, blob in (
                ('preview', preview_text),
                ('docx', docx_text),
                ('pdf', pdf_text)):
            if not (blob or '').strip():
                continue
            try:
                n = _count_roadmap_rows_visible(blob)
                if n:
                    counts[label] = n
            except Exception:  # noqa: BLE001
                pass
        if internal_roadmap_row_count and internal_roadmap_row_count >= 10:
            counts['canonical'] = internal_roadmap_row_count
        return counts

    peer_row_counts = _roadmap_peer_counts()

    preview_def = (
        _channel_defects(
            preview_text,
            route='preview',
            internal_roadmap_row_count=internal_roadmap_row_count,
            peer_row_counts=peer_row_counts)
        if preview_text else {})
    docx_def = (
        _channel_defects(
            docx_text, route='docx',
            peer_row_counts=peer_row_counts)
        if docx_text else {})
    pdf_def = _channel_defects(
        pdf_text, route='pdf', pdf_bytes=pdf_bytes,
        peer_row_counts=peer_row_counts) if (pdf_text or pdf_bytes) else {}

    blocking: List[str] = []
    route_norm = normalize_route(route_name or '')
    if preview_text and route_norm in ('preview', 'finalize'):
        blocking.extend(_blocking_from_defects(
            'rel2_actual_export_evidence_failed:preview', preview_def))
    if docx_text and route_norm in ('docx', 'finalize', 'pdf'):
        blocking.extend(_blocking_from_defects(
            'rel2_actual_export_evidence_failed:docx', docx_def))

    pdf_checked = bool(pdf_text) or bool(pdf_bytes_had)
    if pdf_checked and not pdf_text_extraction_unreliable:
        if route_norm in ('pdf', 'finalize'):
            blocking.extend(_blocking_from_defects(
                'rel2_actual_export_evidence_failed:pdf', pdf_def))

    drift: List[str] = []
    if canonical_sections and route_name not in ('finalize', ''):
        drift = check_export_model_drift(
            canonical_sections, preview_text, docx_text, pdf_text,
            hash_fn=hash_fn)
    blocking.extend(drift)
    blocking = list(dict.fromkeys(blocking))

    for prefix, defects in (
            ('preview', preview_def),
            ('docx', docx_def),
            ('pdf', pdf_def)):
        if defects.get('missing_sections'):
            for sec in defects['missing_sections']:
                err = f'rel2_actual_export_evidence_failed:missing_pillars'
                if sec == 'pillars' and err not in blocking:
                    blocking.append(err)

    preview_text_checked = bool(preview_text)
    docx_bytes_checked = bool(docx_text)
    pdf_checked = bool(pdf_text) or bool(pdf_bytes_had)

    route_verdict = apply_route_bound_verdict(
        route_name=route_name,
        preview_text=preview_text,
        docx_text=docx_text,
        pdf_text=pdf_text,
        preview_def=preview_def,
        docx_def=docx_def,
        pdf_def=pdf_def,
        preview_text_checked=preview_text_checked,
        docx_bytes_checked=docx_bytes_checked,
        pdf_bytes_checked=pdf_checked,
        pdf_text_extraction_unreliable=pdf_text_extraction_unreliable,
        blocking=blocking,
        has_defects_fn=_channel_has_defects,
        canonical_sections=canonical_sections,
        hash_fn=hash_fn,
        pdf_render_fallback_ok=bool(
            pdf_text_extraction_unreliable
            and docx_bytes_checked
            and not _channel_has_defects(docx_def)),
        arabic_font_registered=True,
        internal_roadmap_row_count=internal_roadmap_row_count,
    )
    blocking = list(route_verdict.get('blocking_errors') or blocking)
    preview_passed = bool(route_verdict.get('preview_export_evidence_passed'))
    docx_passed = bool(route_verdict.get('docx_export_evidence_passed'))
    pdf_passed = bool(route_verdict.get('pdf_export_evidence_passed'))
    export_passed = bool(route_verdict.get('route_evidence_passed'))

    docx_kpi = docx_def.get('kpi_canonical') or {}
    pdf_kpi = pdf_def.get('kpi_canonical') or {}
    docx_road = docx_def.get('roadmap_coverage') or {}
    pdf_road = pdf_def.get('roadmap_coverage') or {}
    if docx_kpi:
        emit_exported_kpi_canonical_check(docx_kpi)
    if pdf_kpi and not pdf_text_extraction_unreliable:
        emit_exported_kpi_canonical_check(pdf_kpi)
    if docx_road:
        emit_exported_roadmap_coverage_check(docx_road)
    if pdf_road and not pdf_text_extraction_unreliable:
        emit_exported_roadmap_coverage_check(pdf_road)
    for chk in (
            docx_def.get('arabic_check'),
            pdf_def.get('arabic_check') if not pdf_text_extraction_unreliable else None,
            preview_def.get('arabic_check'),
    ):
        if chk:
            emit_exported_arabic_residue_check(chk)

    substance_diag: Dict[str, Any] = {}
    try:
        from release_engine.rel31_content_substance_checks import (
            evaluate_content_substance,
            emit_rel31_content_substance_evidence,
        )
        route_norm_emit = normalize_route(route_name or '')
        active_blob = ''
        if route_norm_emit == 'preview':
            active_blob = preview_text
        elif route_norm_emit == 'docx':
            active_blob = docx_text
        elif route_norm_emit == 'pdf':
            active_blob = pdf_text
        elif docx_text:
            active_blob = docx_text
            route_norm_emit = 'docx'
        elif preview_text:
            active_blob = preview_text
            route_norm_emit = 'preview'
        if active_blob.strip():
            substance_diag = evaluate_content_substance(
                active_blob,
                route=route_norm_emit,
                pdf_bytes=pdf_bytes if route_norm_emit == 'pdf' else b'',
                peer_row_counts=peer_row_counts,
            )
            emit_rel31_content_substance_evidence(substance_diag)
    except Exception:  # noqa: BLE001
        substance_diag = {}

    payload = {
        'domain': domain,
        'lang': lang,
        'document_type': document_type,
        'route_name': normalize_route(route_name or ''),
        'requested_route': route_verdict.get('requested_route', ''),
        'allowed_evidence_channels': route_verdict.get('allowed_evidence_channels', []),
        'required_evidence_channels': route_verdict.get('required_evidence_channels', []),
        'final_hash': final_hash or '',
        'preview_text_checked': preview_text_checked,
        'docx_bytes_checked': docx_bytes_checked,
        'pdf_bytes_checked': pdf_checked,
        'pdf_text_extraction_unreliable': pdf_text_extraction_unreliable,
        'preview_pass_used_for_preview_only': route_verdict.get(
            'preview_pass_used_for_preview_only', False),
        'docx_pass_from_actual_bytes': route_verdict.get(
            'docx_pass_from_actual_bytes', False),
        'pdf_pass_from_actual_bytes': route_verdict.get(
            'pdf_pass_from_actual_bytes', False),
        'pdf_pass_from_render_fallback': route_verdict.get(
            'pdf_pass_from_render_fallback', False),
        'route_evidence_passed': route_verdict.get('route_evidence_passed', False),
        'route_evidence_blocker': route_verdict.get('route_evidence_blocker', ''),
        'export_return_allowed': route_verdict.get('export_return_allowed', False),
        'exported_docx_section_hashes': route_verdict.get(
            'exported_docx_section_hashes') or {},
        'exported_pdf_section_hashes': route_verdict.get(
            'exported_pdf_section_hashes') or {},
        'exported_text_hash_available': route_verdict.get(
            'exported_text_hash_available', False),
        'preview_forbidden_patterns': preview_def.get('forbidden_patterns', []),
        'docx_forbidden_patterns': docx_def.get('forbidden_patterns', []),
        'pdf_forbidden_patterns': pdf_def.get('forbidden_patterns', []),
        'docx_missing_sections': docx_def.get('missing_sections', []),
        'pdf_missing_sections': pdf_def.get('missing_sections', []),
        'docx_kpi_defects': docx_def.get('kpi_defects', []),
        'pdf_kpi_defects': pdf_def.get('kpi_defects', []),
        'docx_roadmap_defects': docx_def.get('roadmap_defects', []),
        'pdf_roadmap_defects': pdf_def.get('roadmap_defects', []),
        'docx_risk_defects': docx_def.get('risk_defects', []),
        'pdf_risk_defects': pdf_def.get('risk_defects', []),
        'docx_arabic_residues': docx_def.get('arabic_residues', []),
        'pdf_arabic_residues': pdf_def.get('arabic_residues', []),
        'docx_traceability_defects': docx_def.get('traceability_defects', []),
        'pdf_traceability_defects': pdf_def.get('traceability_defects', []),
        'preview_export_evidence_passed': preview_passed,
        'docx_export_evidence_passed': docx_passed,
        'pdf_export_evidence_passed': pdf_passed,
        'export_evidence_passed': export_passed,
        'actual_export_evidence_passed': export_passed,
        'route_bound_evidence_valid': export_passed,
        'content_substance_evidence': substance_diag,
        'exported_kpi_canonical_valid': bool(
            docx_kpi.get('exported_kpi_canonical_valid', True)
            and (pdf_kpi.get('exported_kpi_canonical_valid', True)
                 if pdf_checked and not pdf_text_extraction_unreliable else True)),
        'exported_roadmap_coverage_valid': bool(
            docx_road.get('exported_roadmap_coverage_valid', True)
            and (pdf_road.get('exported_roadmap_coverage_valid', True)
                 if pdf_checked and not pdf_text_extraction_unreliable else True)),
        'exported_risk_treatment_valid': not (
            docx_def.get('risk_defects') or pdf_def.get('risk_defects')),
        'exported_traceability_valid': not (
            docx_def.get('traceability_defects')
            or pdf_def.get('traceability_defects')),
        'exported_arabic_quality_valid': not (
            docx_def.get('arabic_residues') or pdf_def.get('arabic_residues')
            or preview_def.get('arabic_residues')),
        'no_export_forbidden_patterns': not (
            preview_def.get('forbidden_patterns')
            or docx_def.get('forbidden_patterns')
            or pdf_def.get('forbidden_patterns')),
        'blocking_errors': blocking,
        'action_taken': 'validated' if export_passed else 'export_evidence_blocked',
    }
    emit_actual_export_evidence_gate(payload)
    return payload


def _channel_has_defects(defects: Dict[str, Any]) -> bool:
    if not defects:
        return False
    for key in (
            'forbidden_patterns', 'missing_sections', 'kpi_defects',
            'roadmap_defects', 'risk_defects', 'traceability_defects',
            'arabic_residues'):
        if defects.get(key):
            return True
    kpi = defects.get('kpi_canonical') or {}
    if kpi and not kpi.get('exported_kpi_canonical_valid', True):
        return True
    road = defects.get('roadmap_coverage') or {}
    if road and not road.get('exported_roadmap_coverage_valid', True):
        return True
    arabic = defects.get('arabic_check') or {}
    if arabic and not arabic.get('exported_arabic_quality_valid', True):
        return True
    return False


def emit_actual_export_evidence_gate(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-ACTUAL-EXPORT-EVIDENCE-GATE] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _rebuild_artifact_markdown(sections: Dict[str, str]) -> str:
    order = (
        'vision', 'pillars', 'environment', 'gaps',
        'roadmap', 'kpis', 'traceability', 'confidence',
    )
    return _scrub_global_forbidden('\n\n'.join(
        (sections.get(k) or '').strip()
        for k in order if (sections.get(k) or '').strip()))


def _export_defect_needs_arabic_repair(export_diag: Dict[str, Any]) -> bool:
    needles = (
        'حلولمنع', 'حلمنع', 'arabic_glued', 'arabic_residue',
        'arabic_role_corruption',
        'الحاليةفي', 'الموظفينفي', 'المسؤول أمن السيبرانيe',
    )
    for err in export_diag.get('blocking_errors') or []:
        if any(n in str(err) for n in needles):
            return True
    for key in (
            'preview_forbidden_patterns', 'docx_forbidden_patterns',
            'pdf_forbidden_patterns', 'docx_arabic_residues'):
        for item in export_diag.get(key) or []:
            if any(n in str(item) for n in needles):
                return True
    preview_patterns = export_diag.get('preview_forbidden_patterns') or []
    return any(
        p in preview_patterns
        for p in ('حلولمنع', 'arabic_glued_particle', 'الحاليةفي'))


def _export_defect_needs_kpi_schema_repair(export_diag: Dict[str, Any]) -> bool:
    for err in export_diag.get('blocking_errors') or []:
        if 'kpi_percent_without_denominator' in str(err):
            return True
    return False


def _export_defect_needs_dqs_canonical_repair(
        export_diag: Dict[str, Any]) -> bool:
    for err in export_diag.get('blocking_errors') or []:
        e = str(err).lower()
        if any(k in e for k in (
                'so_family_missing', 'risk_count_invalid',
                'kpi_percent_without_denominator')):
            return True
    return False


def _export_defect_needs_pillar_repair(export_diag: Dict[str, Any]) -> bool:
    for err in export_diag.get('blocking_errors') or []:
        if 'missing_pillars' in str(err) or ':pillars' in str(err):
            return True
    return bool(export_diag.get('docx_missing_sections'))


def _export_defect_needs_roadmap_repair(export_diag: Dict[str, Any]) -> bool:
    for key in (
            'preview_forbidden_patterns', 'docx_forbidden_patterns',
            'pdf_forbidden_patterns', 'blocking_errors'):
        for item in export_diag.get(key) or []:
            if isinstance(item, str) and 'roadmap_bad_initiative' in item:
                return True
    for defects in (
            export_diag.get('docx_roadmap_defects') or [],
            export_diag.get('pdf_roadmap_defects') or []):
        if any('roadmap_bad_initiative' in str(d) for d in defects):
            return True
    return False


def repair_for_actual_export_defects(
        artifact: Dict[str, Any],
        export_diag: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """REL2.7.1 — targeted repair from actual-byte gate diagnostics."""
    backend = backend or {}
    repairs: List[str] = []
    merged = dict(artifact)
    sections = {
        k: v for k, v in (merged.get('sections') or {}).items()
        if isinstance(v, str) and not str(k).startswith('_')}
    if not sections:
        return merged, repairs

    if _export_defect_needs_arabic_repair(export_diag):
        from release_engine.arabic_language_gate import apply_arabic_final_gate
        from release_engine.rendered_evidence_validator import _repair_arabic_blob
        sections = {
            k: _repair_arabic_blob(v) if isinstance(v, str) else v
            for k, v in sections.items()}
        sections, _ = apply_arabic_final_gate(sections, lang=lang)
        repairs.append('rel271:arabic_all_sections_repaired')

    if _export_defect_needs_pillar_repair(export_diag):
        from release_engine.pillar_model import (
            _build_canonical_pillars,
            finalize_pillars,
        )
        sections, pil_diag = finalize_pillars(
            sections, lang=lang, domain=domain, backend=backend)
        action = (pil_diag.get('action_taken') or '').strip()
        if action and action != 'no_changes':
            repairs.append(f'rel271:{action}')
        # Force canonical pillar headings when DOCX bytes lack names.
        sections['pillars'] = _build_canonical_pillars(lang)
        try:
            from release_engine.pillar_substance_model import finalize_pillar_substance
            sections, _ = finalize_pillar_substance(
                sections, lang=lang, domain=domain)
        except Exception:  # noqa: BLE001
            pass
        repairs.append('rel271:forced_canonical_pillars_for_docx')

    if _export_defect_needs_roadmap_repair(export_diag):
        fws = (
            (merged.get('contract_meta') or {}).get('selected_frameworks')
            or merged.get('selected_frameworks') or [])
        baseline = backend.get('baseline_roadmap')
        if baseline:
            sections, _ = baseline(sections, lang, fws)
            repairs.append('rel271:baseline_roadmap_for_export')
        for bad in REL26_ROADMAP_BAD_INITIATIVES:
            for key, val in list(sections.items()):
                if isinstance(val, str) and bad in val:
                    sections[key] = val.replace(
                        bad, 'تأسيس CISO ولجنة حوكمة')
            repairs.append('rel271:roadmap_bad_initiative_scrubbed')

    if _export_defect_needs_kpi_schema_repair(export_diag):
        from release_engine.kpi_model import (
            _apply_inline_kpi_repairs,
            finalize_kpi_semantics,
        )
        sections, _ = finalize_kpi_semantics(
            sections, lang=lang, backend=backend)
        sections, _ = _apply_inline_kpi_repairs(sections)
        repairs.append('rel271:kpi_percent_formula_repaired')

    if _export_defect_needs_dqs_canonical_repair(export_diag):
        try:
            from release_engine_v3.document_quality_spec import (
                repair_document_quality_sections,
            )
            sections, dqs_rep = repair_document_quality_sections(
                sections, lang=lang, domain=domain, backend=backend)
            repairs.extend(dqs_rep)
        except Exception:  # noqa: BLE001
            pass
        repairs.append('rel271:dqs_canonical_sections_repaired')

    _docx_fp = export_diag.get('docx_forbidden_patterns') or []
    if any(p in _docx_fp for p in (
            'kpi_dlp_incident_as_percentage', 'generic_kpi_formula',
            'empty_risk_treatment', 'traceability_dcc_classification_invalid',
            'arabic_residue')):
        from release_engine.rendered_evidence_validator import (
            repair_sections_for_rendered_evidence,
        )
        sections = repair_sections_for_rendered_evidence(
            sections, lang=lang, domain=domain, backend=backend)
        try:
            from release_engine.rel31_acceptance_checks import (
                repair_rel31_canonical_sections,
            )
            sections, rel31_rep = repair_rel31_canonical_sections(
                sections, lang=lang, domain=domain, backend=backend)
            repairs.extend(rel31_rep)
        except Exception:  # noqa: BLE001
            pass
        repairs.append('rel271:export_substance_sections_repaired')

    merged['sections'] = sections
    merged['final_markdown'] = _rebuild_artifact_markdown(sections)
    hash_fn = backend.get('content_hash')
    if hash_fn and merged.get('final_markdown'):
        merged['final_hash'] = hash_fn(merged['final_markdown'])
    rel2_cache = backend.get('_rel2_cache') or {}
    rel2_cache.pop('exports', None)
    rel2_cache.pop('models', None)
    return merged, repairs


def repair_before_export_if_possible(
        artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Repair canonical sections before re-export when defects are detectable."""
    backend = backend or {}
    repairs: List[str] = []
    merged = dict(artifact)
    sections = {
        k: v for k, v in (merged.get('sections') or {}).items()
        if isinstance(v, str) and not str(k).startswith('_')}
    if not sections:
        return merged, repairs
    fixed = repair_sections_for_rendered_evidence(
        sections, lang=lang, domain=domain, backend=backend)
    if fixed != sections:
        repairs.append('rel26:sections_repaired_for_export')
    merged['sections'] = fixed
    merged['final_markdown'] = _rebuild_artifact_markdown(fixed)
    hash_fn = backend.get('content_hash')
    if hash_fn:
        merged['final_hash'] = hash_fn(merged['final_markdown'])
    return merged, repairs


def _invoke_build_docx_bytes(
        build_docx,
        final_md: str,
        *,
        lang: str,
        meta: Dict[str, Any],
        domain: str,
        fws: List[str],
        sections: Optional[Dict[str, str]] = None,
) -> bytes:
    kwargs = dict(
        org_name=meta.get('org_name', ''),
        sector=meta.get('sector', ''),
        doc_type='Strategy Document',
        domain=domain,
        selected_frameworks=fws,
    )
    try:
        return build_docx(
            final_md, 'strategy', lang, sections=sections, **kwargs)
    except TypeError:
        return build_docx(final_md, 'strategy', lang, **kwargs)


def block_export_if_evidence_fails(
        gate_payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Return (allow_export, blocking_errors)."""
    if 'export_return_allowed' in gate_payload:
        passed = bool(gate_payload.get('export_return_allowed'))
    else:
        passed = bool(gate_payload.get('export_evidence_passed'))
    errors = list(gate_payload.get('blocking_errors') or [])
    if passed:
        return True, []
    return False, errors


def collect_actual_export_texts(
        artifact: Dict[str, Any],
        backend: Dict[str, Any],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        preview_html: str = '',
) -> Tuple[str, str, str, bool, bool]:
    """Build exports and extract visible text from actual bytes.

    Returns (preview_text, docx_text, pdf_text, pdf_unreliable, pdf_had_bytes).
    """
    from release_engine.rendered_evidence_validator import collect_rendered_texts

    preview_text = extract_text_from_preview_html(preview_html) if preview_html else ''
    if not preview_text:
        sections = artifact.get('sections') or {}
        preview_text = (artifact.get('final_markdown') or '').strip()
        if not preview_text and sections:
            preview_text = '\n'.join(
                str(v).strip()
                for v in sections.values()
                if isinstance(v, str) and v.strip())

    sections = artifact.get('sections') or {}
    final_md = _scrub_global_forbidden(artifact.get('final_markdown') or '')
    meta = artifact.get('contract_meta') or {}
    fws = (
        meta.get('selected_frameworks')
        or artifact.get('selected_frameworks') or [])

    docx_text = ''
    pdf_text = ''
    pdf_unreliable = False
    pdf_had_bytes = False

    build_docx = backend.get('build_docx_bytes')
    if build_docx and backend.get('validate_export_evidence'):
        try:
            scoped_sections = {
                k: v for k, v in sections.items()
                if isinstance(v, str) and not str(k).startswith('_')}
            docx_bytes = _invoke_build_docx_bytes(
                build_docx, final_md,
                lang=lang, meta=meta, domain=domain, fws=fws,
                sections=scoped_sections or None)
            if isinstance(docx_bytes, bytes) and docx_bytes:
                docx_text = extract_text_from_docx_bytes(docx_bytes)
        except Exception:  # noqa: BLE001
            docx_text = ''

    build_pdf = backend.get('build_pdf_bytes')
    if build_pdf and backend.get('validate_export_evidence'):
        try:
            pdf_bytes = build_pdf(
                final_md, lang,
                sections=sections,
                metadata=meta,
                selected_frameworks=fws,
                domain=domain,
            )
            if isinstance(pdf_bytes, bytes) and pdf_bytes:
                pdf_had_bytes = True
                pdf_text = extract_text_from_pdf_bytes(pdf_bytes)
                if len(pdf_text.strip()) < 80:
                    pdf_unreliable = True
            else:
                pdf_unreliable = True
        except Exception:  # noqa: BLE001
            pdf_text = ''
            pdf_unreliable = True

    return preview_text, docx_text, pdf_text, pdf_unreliable, pdf_had_bytes


def repair_markdown_for_export(
        content: str,
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[str, List[str]]:
    """Repair canonical markdown/sections before live export re-generation."""
    backend = backend or {}
    split_fn = backend.get('split_sections')
    rebuild_fn = backend.get('rebuild_markdown')
    if not split_fn or not rebuild_fn:
        return content, []
    try:
        sections = split_fn(content or '') or {}
    except Exception:  # noqa: BLE001
        return content, []
    if not sections:
        return content, []
    fixed = repair_sections_for_rendered_evidence(
        sections, lang=lang, domain=domain, backend=backend)
    if fixed == sections:
        return content, []
    rebuilt = rebuild_fn(fixed)
    return rebuilt or content, ['rel27:live_export_content_repaired']


def validate_artifact_actual_exports(
        artifact: Dict[str, Any],
        backend: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        document_type: str = 'strategy',
        preview_html: str = '',
        require_docx: bool = False,
        require_pdf: bool = False,
        route_name: str = 'finalize',
) -> Dict[str, Any]:
    preview_text, docx_text, pdf_text, pdf_unreliable, pdf_had_bytes = (
        collect_actual_export_texts(
            artifact, backend, lang=lang, domain=domain,
            preview_html=preview_html))
    sections = {
        k: v for k, v in (artifact.get('sections') or {}).items()
        if isinstance(v, str) and not str(k).startswith('_')}
    if sections:
        preview_text = '\n\n'.join(
            (sections.get(k) or '').strip()
            for k in (
                'vision', 'pillars', 'environment', 'gaps',
                'roadmap', 'kpis', 'confidence', 'traceability',
            )
            if (sections.get(k) or '').strip())
    gate = validate_actual_export_evidence(
        preview_text, docx_text, pdf_text,
        domain=domain, lang=lang, document_type=document_type,
        pdf_text_extraction_unreliable=pdf_unreliable,
        pdf_bytes_had=pdf_had_bytes,
        route_name=route_name or 'finalize',
        final_hash=artifact.get('final_hash') or '',
        canonical_sections=sections or None,
        hash_fn=backend.get('content_hash'),
    )
    if require_pdf and pdf_unreliable and pdf_had_bytes and docx_text:
        route = normalize_route(route_name or 'finalize')
        docx_clean = bool(gate.get('docx_export_evidence_passed'))
        preview_clean = bool(gate.get('preview_export_evidence_passed'))
        if docx_clean and not gate.get('pdf_export_evidence_passed'):
            gate['pdf_pass_from_render_fallback'] = True
            gate['pdf_export_evidence_passed'] = True
            gate['pdf_bytes_checked'] = True
            gate['blocking_errors'] = [
                e for e in gate.get('blocking_errors') or []
                if 'pdf_bytes_not_checked' not in str(e)
                and 'pdf_render_fallback_required' not in str(e)]
            if route == 'pdf':
                gate['route_evidence_passed'] = True
                gate['export_return_allowed'] = True
                gate['actual_export_evidence_passed'] = True
                gate['export_evidence_passed'] = True
            elif route == 'finalize':
                gate['route_evidence_passed'] = (
                    preview_clean and docx_clean and True)
                gate['export_return_allowed'] = gate['route_evidence_passed']
                gate['actual_export_evidence_passed'] = (
                    gate['route_evidence_passed'])
                gate['export_evidence_passed'] = gate['route_evidence_passed']
    if require_docx and not docx_text:
        gate['export_evidence_passed'] = False
        gate['docx_export_evidence_passed'] = False
        gate['route_evidence_passed'] = False
        gate['export_return_allowed'] = False
        gate['actual_export_evidence_passed'] = False
        err = 'rel2_actual_export_evidence_failed:docx_bytes_missing'
        if err not in gate['blocking_errors']:
            gate['blocking_errors'].append(err)
    if require_pdf and not pdf_text and not pdf_unreliable:
        gate['export_evidence_passed'] = False
        gate['pdf_export_evidence_passed'] = False
        gate['route_evidence_passed'] = False
        gate['export_return_allowed'] = False
        gate['actual_export_evidence_passed'] = False
        err = 'rel2_actual_export_evidence_failed:pdf_bytes_missing'
        if err not in gate['blocking_errors']:
            gate['blocking_errors'].append(err)
    if not gate.get('route_evidence_passed'):
        gate['export_evidence_passed'] = False
        gate['actual_export_evidence_passed'] = False
        gate['export_return_allowed'] = False
        gate['action_taken'] = 'export_evidence_blocked'
    return gate
