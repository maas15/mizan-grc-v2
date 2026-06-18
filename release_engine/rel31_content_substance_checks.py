"""PR-REL3.1 — board-ready content substance checks on returned export bytes."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from release_engine.pillar_substance_model import _GENERIC_OUTPUTS
from release_engine.rel27_export_checks import (
    REL27_GENERIC_FORMULAS,
    REL27_WEAK_ROADMAP_OUTPUTS,
    ROADMAP_FAMILIES,
    check_roadmap_coverage,
)
from release_engine.rel28_route_evidence import pillar_body_after_heading
from release_engine.rel31_acceptance_checks import (
    REL31_ARABIC_RESIDUES,
    _risk_register_blob,
    _trace_matrix_blob,
    check_arabic_residue_rel31,
    check_dlp_incident_nonzero_tolerance,
    check_generic_kpi_formula,
    check_kpi_dlp_incident_as_percentage,
    check_login_anomaly_kpi_100,
    check_third_party_risk_kpi_100,
    check_traceability_dcc_classification_invalid,
    count_flat_roadmap_initiatives,
    flat_pillar_initiative_blob,
    flat_traceability_bad_mappings,
    flat_kpi_kri_section_blob,
)

GENERIC_RISK_TREATMENT = 'ضوابط تقنية وإجراءات تشغيلية ومراقبة مستمرة'

SHALLOW_PILLAR_PHRASES = frozenset(_GENERIC_OUTPUTS) | frozenset({
    'تشغيل المركز',
    'خطط الاستجابة',
    'قواعد المراقبة',
    'مخرج برنامج معتمد ومقاس',
})

_EXPECTED_TRACE_GAPS = {
    'data_classification': 'ضعف تصنيف وجرد البيانات الحساسة',
    'data_protection': 'ضعف حماية البيانات أثناء النقل والتخزين',
    'encryption': 'ضعف ضوابط التشفير وإدارة المفاتيح',
    'dlp': 'ضعف ضوابط منع تسرب البيانات',
    'ecc_incident': 'غياب فريق الاستجابة للحوادث CSIRT وخطة الاستجابة الرسمية',
}

_EXTRA_ARABIC_RESIDUES = (
    'المحددةفي',
    'ال معالجة',
    'بال منصات',
)

_LOGIN_ANOMALY_KPI = 'نسبة محاولات الدخول الفاشلة الشاذة'
_DLP_INCIDENT_KRI = 'عدد حوادث تسرب البيانات الحرجة'
_THIRD_PARTY_RISK = 'درجة مخاطر الأطراف الثالثة'


def _count_roadmap_rows_flat(blob: str) -> int:
    try:
        from release_engine.export_evidence_validator import (
            _count_roadmap_rows_visible,
        )
        visible = _count_roadmap_rows_visible(blob or '')
        if visible:
            return visible
    except Exception:  # noqa: BLE001
        pass
    road = check_roadmap_coverage(blob or '')
    return int(road.get('visible_row_count') or 0)


def _pillar_body(blob: str) -> str:
    body = pillar_body_after_heading(blob or '')
    return body if body.strip() else (blob or '')


def _is_shallow_export_output(text: str) -> bool:
    t = (text or '').strip()
    return t in SHALLOW_PILLAR_PHRASES or t in _GENERIC_OUTPUTS


def _pillar_table_output_owner(cells: List[str]) -> Tuple[str, str]:
    """Return (output_cell, owner_cell) from a pillar initiative row."""
    if len(cells) >= 5:
        return cells[2], cells[-1]
    if len(cells) == 4:
        return cells[2], cells[-1]
    if len(cells) == 3:
        return cells[-1], ''
    return '', ''


def check_shallow_pillar_rows(blob: str) -> List[str]:
    """Shallow/generic pillar initiative outputs in export text."""
    if re.search(r'^###\s+حوكمة', blob or '', re.MULTILINE):
        section = _pillar_body(blob)
    else:
        section = flat_pillar_initiative_blob(blob) or _pillar_body(blob)
    if not section.strip():
        return ['shallow_pillar_section_missing']
    shallow: List[str] = []
    in_table = False
    for ln in section.splitlines():
        if 'المبادرة' in ln or 'المخرج' in ln:
            in_table = True
            continue
        if not in_table or not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if len(cells) < 2:
            continue
        out_cell, _owner = _pillar_table_output_owner(cells)
        if _is_shallow_export_output(out_cell):
            shallow.append(out_cell[:80])
    if not shallow:
        for ln in section.splitlines():
            stripped = (ln or '').strip()
            if _is_shallow_export_output(stripped):
                shallow.append(stripped[:80])
    if not shallow:
        use_line_scan = not re.search(
            r'^###\s+حوكمة', section, re.MULTILINE)
        if use_line_scan:
            for ln in section.splitlines():
                stripped = (ln or '').strip()
                if _is_shallow_export_output(stripped):
                    shallow.append(stripped[:80])
    return list(dict.fromkeys(shallow))[:12]


def check_pillar_owner_missing(blob: str) -> List[str]:
    """Pillar tables with em-dash or empty owner cells."""
    if re.search(r'^###\s+حوكمة', blob or '', re.MULTILINE):
        section = _pillar_body(blob)
    else:
        section = flat_pillar_initiative_blob(blob) or _pillar_body(blob)
    missing: List[str] = []
    in_table = False
    for ln in section.splitlines():
        if 'المبادرة' in ln or 'المخرج' in ln or 'المالك' in ln:
            in_table = True
            continue
        if not in_table or not ln.strip().startswith('|'):
            continue
        if '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if len(cells) >= 4:
            _out, owner = _pillar_table_output_owner(cells)
            if owner in ('—', '-', '', 'N/A', 'n/a'):
                missing.append(owner or 'empty_owner')
    if not missing:
        lines = section.splitlines()
        for i, ln in enumerate(lines):
            stripped = (ln or '').strip()
            if stripped in SHALLOW_PILLAR_PHRASES or _is_shallow_export_output(stripped):
                for j in range(i + 1, min(i + 4, len(lines))):
                    if lines[j].strip() in ('—', '-'):
                        missing.append('—')
                        break
    return list(dict.fromkeys(missing))[:8]


def check_kpi_semantic_defects(blob: str, *, route: str = '') -> List[str]:
    text = blob or ''
    route_n = (route or '').lower()
    if route_n in ('docx', 'pdf'):
        scoped = flat_kpi_kri_section_blob(text)
        if scoped.strip():
            text = scoped
    defects: List[str] = []
    defects.extend(check_kpi_dlp_incident_as_percentage(text))
    defects.extend(check_generic_kpi_formula(text))
    defects.extend(check_third_party_risk_kpi_100(text))
    defects.extend(check_login_anomaly_kpi_100(text))
    defects.extend(check_dlp_incident_nonzero_tolerance(text))
    if _LOGIN_ANOMALY_KPI in text:
        for ln in text.splitlines():
            if _LOGIN_ANOMALY_KPI not in ln:
                continue
            if re.search(r'KPI', ln, re.I) and re.search(
                    r'100%|≥\s*\d+\s*%', ln):
                defects.append('kpi_login_anomaly_as_100_percent')
            if '100%' in ln and 'KRI' not in ln.upper():
                defects.append('kpi_login_anomaly_invalid_target')
    if _DLP_INCIDENT_KRI in text:
        for ln in text.splitlines():
            if _DLP_INCIDENT_KRI not in ln:
                continue
            if re.search(r'KPI', ln, re.I) and 'KRI' not in ln.upper():
                defects.append('dlp_incident_must_be_kri')
            if re.search(r'≥\s*95%|100%', ln) and 'حوادث' not in ln:
                defects.append('dlp_incident_percent_target')
    if _THIRD_PARTY_RISK in text:
        idx = text.find(_THIRD_PARTY_RISK)
        window = text[idx:idx + 160]
        if re.search(r'100%', window) and 'KRI' in window.upper():
            if re.search(
                    r'المنجز|المخطط|completion|×\s*100', window, re.I):
                defects.append('third_party_risk_completion_formula')
    for gf in REL27_GENERIC_FORMULAS:
        if gf in text:
            defects.append('generic_kpi_formula')
    return list(dict.fromkeys(defects))


def check_generic_risk_treatments(blob: str) -> List[str]:
    risk_blob = _risk_register_blob(blob)
    if not risk_blob.strip():
        return []
    generic: List[str] = []
    count = 0
    for ln in risk_blob.splitlines():
        if GENERIC_RISK_TREATMENT in ln:
            count += 1
            generic.append(GENERIC_RISK_TREATMENT)
        if ln.strip() in ('—', '-'):
            generic.append('empty_treatment')
    if count >= 2:
        generic.append('repeated_generic_treatment')
    return list(dict.fromkeys(generic))


def check_traceability_bad_mappings(blob: str) -> List[str]:
    defects = list(check_traceability_dcc_classification_invalid(blob))
    defects.extend(flat_traceability_bad_mappings(blob))
    trace = _trace_matrix_blob(blob)
    if not trace.strip():
        if any(m in (blob or '') for m in (
                'مصفوفة تتبع', 'مصفوفة التتبع', 'مجال القدرة', 'الفجوة المرتبطة')):
            return defects or ['traceability_matrix_missing']
        return defects
    try:
        from release_engine.traceability_substance_model import (
            _cap_col_idx,
            _detect_family,
            _gap_col_idx,
            _parse_trace_rows,
            _bad_mapping,
            pdf_trace_extract_artifact,
            is_diagnostic_gap_label,
        )
        for trace_text in (trace,):
            _lines, hdr, rows = _parse_trace_rows(trace_text)
            if hdr >= 0 and rows:
                cap_idx = _cap_col_idx(_lines[hdr])
                gap_idx = _gap_col_idx(_lines[hdr])
                for cells in rows:
                    fam = _detect_family(cells, cap_idx)
                    gap = cells[gap_idx] if len(cells) > gap_idx else ''
                    cap = cells[cap_idx] if len(cells) > cap_idx else fam
                    if pdf_trace_extract_artifact(cap) or pdf_trace_extract_artifact(gap):
                        continue
                    if is_diagnostic_gap_label(cap):
                        continue
                    if fam and _bad_mapping(fam, gap):
                        defects.append(f'trace_gap_mismatch:{cap}')
                return list(dict.fromkeys(defects))
    except Exception:  # noqa: BLE001
        pass
    return list(dict.fromkeys(defects))


def check_arabic_residues_substance(blob: str) -> List[str]:
    residues: List[str] = []
    if check_arabic_residue_rel31(blob):
        residues.append('arabic_residue')
    text = blob or ''
    for pat in REL31_ARABIC_RESIDUES + _EXTRA_ARABIC_RESIDUES:
        if pat == 'ال معتمد':
            if re.search(r'(?<![\u0600-\u06FF])ال معتمد(?!ة)', text):
                residues.append(pat)
            continue
        if pat in text:
            residues.append(pat)
    if re.search(r'المسؤول أمن السيبراني\s*e', text, re.I):
        residues.append('المسؤول أمن السيبرانيe')
    if re.search(r'المسؤول أمن السيبراني\s*Lead', text, re.I):
        residues.append('المسؤول أمن السيبرانيLead')
    return list(dict.fromkeys(residues))


def check_roadmap_substance(blob: str) -> Tuple[int, List[str]]:
    road = check_roadmap_coverage(blob or '')
    flat_rows = count_flat_roadmap_initiatives(blob)
    parsed_rows = int(road.get('distinct_row_count') or 0)
    count = int(road.get('visible_row_count') or _count_roadmap_rows_flat(blob))
    defects = list(road.get('defects') or [])
    if flat_rows and flat_rows < 10 and parsed_rows < 10:
        count = min(count, flat_rows) if count else flat_rows
        defects.append(f'roadmap_row_count:{flat_rows}')
    elif count < 10 and parsed_rows < 10 and flat_rows < 10:
        defects.append(f'roadmap_row_count:{count}')
    for weak in road.get('weak_outputs') or []:
        if any(w in str(weak) for w in REL27_WEAK_ROADMAP_OUTPUTS):
            defects.append('roadmap_weak_output')
    missing = list(road.get('missing_families') or [])
    return count, list(dict.fromkeys(defects + [
        f'missing_family:{f}' for f in missing]))


def evaluate_content_substance(
        blob: str,
        *,
        route: str = 'docx',
        pdf_bytes: bytes = b'',
        peer_row_counts: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Full substance diagnostic for one export channel."""
    peer_row_counts = peer_row_counts or {}
    shallow = check_shallow_pillar_rows(blob)
    owners = check_pillar_owner_missing(blob)
    row_count, road_defects = check_roadmap_substance(blob)
    kpi_defects = check_kpi_semantic_defects(blob, route=route)
    risk_generic = check_generic_risk_treatments(blob)
    trace_bad = check_traceability_bad_mappings(blob)
    arabic = check_arabic_residues_substance(blob)

    drift = False
    if peer_row_counts:
        counts = [c for c in peer_row_counts.values() if c > 0]
        active = row_count if row_count > 0 else 0
        if counts and active:
            drift = max(counts) - min(counts + [active]) > 2
        elif len(counts) >= 2:
            drift = max(counts) - min(counts) > 2

    blocking: List[str] = []
    if shallow:
        blocking.append('shallow_pillar_outputs')
    if owners:
        blocking.append('pillar_owner_missing')
    blocking.extend(road_defects)
    if drift:
        blocking.append('roadmap_preview_docx_pdf_drift')
    blocking.extend(kpi_defects)
    blocking.extend(risk_generic)
    blocking.extend(trace_bad)
    if arabic:
        blocking.append('arabic_residue')

    passed = not blocking
    return {
        'route_name': route,
        'pillar_depth_valid': not shallow and not owners,
        'shallow_pillar_rows': shallow,
        'pillar_owner_missing': owners,
        'roadmap_visible_row_count': row_count,
        'roadmap_required_families_missing': [
            d.replace('missing_family:', '')
            for d in road_defects if d.startswith('missing_family:')],
        'roadmap_preview_docx_pdf_consistent': not drift,
        'kpi_semantic_defects': kpi_defects,
        'risk_generic_treatments': risk_generic,
        'traceability_bad_mappings': trace_bad,
        'arabic_residues': arabic,
        'content_substance_passed': passed,
        'blocking_errors': list(dict.fromkeys(blocking)),
    }


def run_rel31_content_substance_checks(
        blob: str,
        *,
        route: str = 'docx',
        pdf_bytes: bytes = b'',
        peer_row_counts: Optional[Dict[str, int]] = None,
) -> List[str]:
    """Return standardized substance defect codes."""
    diag = evaluate_content_substance(
        blob, route=route, pdf_bytes=pdf_bytes,
        peer_row_counts=peer_row_counts)
    if diag.get('content_substance_passed'):
        return []
    return list(diag.get('blocking_errors') or [])


def emit_rel31_content_substance_evidence(
        diag: Dict[str, Any]) -> Dict[str, Any]:
    try:
        print(
            '[REL3-CONTENT-SUBSTANCE-EVIDENCE] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
    return diag


def rel31_substance_blockers(route: str, defects: List[str]) -> List[str]:
    route_n = (route or 'docx').lower()
    return [
        f'rel3_content_substance_failed:{route_n}:{d}'
        for d in defects
    ]


def repair_rel31_content_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Canonical rel24-style substance repairs before export."""
    from release_engine.pillar_substance_model import finalize_pillar_substance
    from release_engine.roadmap_substance_model import finalize_roadmap_substance
    from release_engine.kpi_substance_model import finalize_kpi_substance
    from release_engine.risk_treatment_model import finalize_risk_treatment
    from release_engine.traceability_substance_model import (
        finalize_traceability_substance,
    )
    from release_engine.arabic_language_gate import apply_arabic_final_gate
    from release_engine.rendered_evidence_validator import (
        _repair_arabic_blob,
        repair_sections_for_rendered_evidence,
    )

    backend = dict(backend or {})
    repairs: List[str] = []
    out = dict(sections or {})

    out, pil = finalize_pillar_substance(out, lang=lang, domain=domain)
    if pil.get('action_taken') and pil.get('action_taken') != 'validated':
        repairs.append(f'rel31_substance:{pil.get("action_taken")}')

    out, road = finalize_roadmap_substance(
        out, lang=lang, domain=domain, backend=backend)
    if road.get('action_taken') and road.get('action_taken') != 'validated':
        repairs.append(f'rel31_substance:{road.get("action_taken")}')

    out, kpi = finalize_kpi_substance(out, lang=lang, backend=backend)
    if kpi.get('action_taken') and kpi.get('action_taken') != 'validated':
        repairs.append(f'rel31_substance:{kpi.get("action_taken")}')

    out, risk = finalize_risk_treatment(out, lang=lang)
    if risk.get('action_taken') and risk.get('action_taken') != 'validated':
        repairs.append(f'rel31_substance:{risk.get("action_taken")}')

    out, trace = finalize_traceability_substance(out, lang=lang)
    if trace.get('action_taken') and trace.get('action_taken') != 'validated':
        repairs.append(f'rel31_substance:{trace.get("action_taken")}')

    out = repair_sections_for_rendered_evidence(
        out, lang=lang, domain=domain, backend=backend)
    repairs.append('rel31_substance:rendered_evidence_pipeline')

    out = {
        k: _repair_arabic_blob(v) if isinstance(v, str) else v
        for k, v in out.items()}
    out, _ = apply_arabic_final_gate(out, lang=lang)
    repairs.append('rel31_substance:arabic_final_gate')

    return out, list(dict.fromkeys(repairs))
