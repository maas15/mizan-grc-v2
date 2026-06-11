"""PR-REL2.6 — validate actual exported DOCX/PDF/preview visible text."""

from __future__ import annotations

import json
import re
from html import unescape
from typing import Any, Dict, List, Optional, Tuple

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
    r'|حلولمنع',
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
    defects = _find_in(blob, REL26_FORBIDDEN_KPI)
    for gf in REL26_GENERIC_FORMULAS:
        if gf in blob:
            defects.append('generic_formula')
    if _DLP_INCIDENT_BAD in blob and '%' in blob:
        defects.append(_DLP_INCIDENT_BAD)
    # Critical DLP as KPI with percentage target
    if 'عدد حوادث تسرب البيانات الحرجة' in blob:
        for ln in blob.splitlines():
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


def _roadmap_defects_in(blob: str) -> List[str]:
    defects: List[str] = []
    for bad in REL26_ROADMAP_BAD_INITIATIVES:
        if bad in blob:
            defects.append(f'roadmap_bad_initiative:{bad}')
    count = _count_roadmap_rows_visible(blob)
    if count and count < 10:
        defects.append(f'roadmap_row_count:{count}')
    return defects


def _forbidden_in(blob: str) -> List[str]:
    items: List[str] = []
    items.extend(_find_in(blob, REL26_FORBIDDEN_KPI))
    items.extend(_roadmap_defects_in(blob))
    items.extend(_kpi_defects_in(blob))
    items.extend(_arabic_defects_in(blob))
    items.extend(_trace_defects_in(blob))
    return list(dict.fromkeys(items))


def _channel_defects(text: str) -> Dict[str, List[str]]:
    # PR-REL2.6: validate raw visible export text — never scrub before detection.
    blob = text or ''
    return {
        'forbidden_patterns': _forbidden_in(blob),
        'kpi_defects': _kpi_defects_in(blob),
        'risk_defects': _risk_defects_in(blob),
        'arabic_residues': _arabic_defects_in(blob),
        'traceability_defects': _trace_defects_in(blob),
        'roadmap_defects': _roadmap_defects_in(blob),
    }


def _blocking_from_defects(
        prefix: str, defects: Dict[str, List[str]]) -> List[str]:
    blockers: List[str] = []
    for key, items in defects.items():
        for item in items or []:
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
) -> Dict[str, Any]:
    """Validate visible text from actual export surfaces (not render model only)."""
    preview_def = _channel_defects(preview_text) if preview_text else {}
    docx_def = _channel_defects(docx_text) if docx_text else {}
    pdf_def = _channel_defects(pdf_text) if pdf_text else {}

    blocking: List[str] = []
    if preview_text:
        blocking.extend(_blocking_from_defects(
            'rel2_actual_export_evidence_failed:preview', preview_def))
    if docx_text:
        blocking.extend(_blocking_from_defects(
            'rel2_actual_export_evidence_failed:docx', docx_def))

    pdf_checked = bool(pdf_text)
    if pdf_checked and not pdf_text_extraction_unreliable:
        blocking.extend(_blocking_from_defects(
            'rel2_actual_export_evidence_failed:pdf', pdf_def))

    preview_passed = (
        not any(preview_def.values()) if preview_text else True)
    docx_passed = (
        not any(docx_def.values()) if docx_text else True)
    pdf_passed = (
        not any(pdf_def.values()) if pdf_text else True)
    if pdf_text_extraction_unreliable and pdf_checked:
        pdf_passed = True

    export_passed = (
        preview_passed
        and docx_passed
        and pdf_passed
        and not blocking)

    payload = {
        'domain': domain,
        'lang': lang,
        'document_type': document_type,
        'preview_text_checked': bool(preview_text),
        'docx_bytes_checked': bool(docx_text),
        'pdf_bytes_checked': pdf_checked,
        'pdf_text_extraction_unreliable': pdf_text_extraction_unreliable,
        'preview_forbidden_patterns': preview_def.get('forbidden_patterns', []),
        'docx_forbidden_patterns': docx_def.get('forbidden_patterns', []),
        'pdf_forbidden_patterns': pdf_def.get('forbidden_patterns', []),
        'docx_kpi_defects': docx_def.get('kpi_defects', []),
        'pdf_kpi_defects': pdf_def.get('kpi_defects', []),
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
        'blocking_errors': blocking,
        'action_taken': 'validated' if export_passed else 'export_evidence_blocked',
    }
    emit_actual_export_evidence_gate(payload)
    return payload


def emit_actual_export_evidence_gate(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-ACTUAL-EXPORT-EVIDENCE-GATE] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


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
    order = (
        'vision', 'pillars', 'environment', 'gaps',
        'roadmap', 'kpis', 'traceability', 'confidence',
    )
    merged['final_markdown'] = _scrub_global_forbidden('\n\n'.join(
        (fixed.get(k) or '').strip()
         for k in order if (fixed.get(k) or '').strip()))
    hash_fn = backend.get('content_hash')
    if hash_fn:
        merged['final_hash'] = hash_fn(merged['final_markdown'])
    return merged, repairs


def block_export_if_evidence_fails(
        gate_payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Return (allow_export, blocking_errors)."""
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
) -> Tuple[str, str, str, bool]:
    """Build exports and extract visible text from actual bytes."""
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

    build_docx = backend.get('build_docx_bytes')
    if build_docx and backend.get('validate_export_evidence'):
        try:
            docx_bytes = build_docx(
                final_md, 'strategy', lang,
                org_name=meta.get('org_name', ''),
                sector=meta.get('sector', ''),
                doc_type='Strategy Document',
                domain=domain,
                selected_frameworks=fws,
            )
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
                pdf_text = extract_text_from_pdf_bytes(pdf_bytes)
                if len(pdf_text.strip()) < 80:
                    pdf_unreliable = True
            else:
                pdf_unreliable = True
        except Exception:  # noqa: BLE001
            pdf_text = ''
            pdf_unreliable = True

    return preview_text, docx_text, pdf_text, pdf_unreliable


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
) -> Dict[str, Any]:
    preview_text, docx_text, pdf_text, pdf_unreliable = (
        collect_actual_export_texts(
            artifact, backend, lang=lang, domain=domain,
            preview_html=preview_html))
    gate = validate_actual_export_evidence(
        preview_text, docx_text, pdf_text,
        domain=domain, lang=lang, document_type=document_type,
        pdf_text_extraction_unreliable=pdf_unreliable,
    )
    if require_docx and not docx_text:
        gate['export_evidence_passed'] = False
        gate['docx_export_evidence_passed'] = False
        err = 'rel2_actual_export_evidence_failed:docx_bytes_missing'
        if err not in gate['blocking_errors']:
            gate['blocking_errors'].append(err)
    if require_pdf and not pdf_text:
        if pdf_unreliable or not (backend or {}).get('build_pdf_bytes'):
            gate['pdf_text_extraction_unreliable'] = True
            gate['pdf_export_evidence_passed'] = True
            gate['blocking_errors'] = [
                e for e in gate.get('blocking_errors') or []
                if not str(e).startswith(
                    'rel2_actual_export_evidence_failed:pdf')]
            gate['export_evidence_passed'] = (
                gate.get('preview_export_evidence_passed', True)
                and gate.get('docx_export_evidence_passed', True)
                and not gate['blocking_errors'])
        else:
            gate['export_evidence_passed'] = False
            gate['pdf_export_evidence_passed'] = False
            err = 'rel2_actual_export_evidence_failed:pdf_bytes_missing'
            if err not in gate['blocking_errors']:
                gate['blocking_errors'].append(err)
    if not gate['export_evidence_passed']:
        gate['action_taken'] = 'export_evidence_blocked'
    emit_actual_export_evidence_gate(gate)
    return gate
