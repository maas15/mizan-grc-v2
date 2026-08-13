"""REL3.3 — ERM risk treatment export evidence (DOCX flat text + artifact rows)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

REL27_EMPTY_TREATMENT = frozenset({'—', '-', '', 'N/A', 'n/a', 'None', 'none'})

_TREATMENT_SECTION_MARKERS = (
    'المعالجات', 'خطة المعالجة', 'Risk Treatment', 'treatment plan',
    'سجل المخاطر', 'المخاطر الرئيسية',
)


def _count_flat_docx_treatment_rows(blob: str) -> int:
    """Count treatment rows in flat DOCX-visible text (no pipe tables)."""
    lines = [(ln or '').strip() for ln in (blob or '').splitlines() if (ln or '').strip()]
    if not lines:
        return 0
    in_treatment = False
    rows = 0
    skip_headers = frozenset({
        'المخاطرة', 'Risk', 'المعالجة', 'Treatment', 'المالك', 'Owner',
        'Impact', 'التأثير', 'الاحتمالية', 'Likelihood', '#',
        'خطة المعالجة', 'المعالجات', 'سجل المخاطر',
    })
    for ln in lines:
        if any(m in ln for m in _TREATMENT_SECTION_MARKERS):
            in_treatment = True
            continue
        if in_treatment and ln.startswith('##') and not any(m in ln for m in _TREATMENT_SECTION_MARKERS):
            in_treatment = False
            continue
        if not in_treatment:
            continue
        if ln in skip_headers or ln in REL27_EMPTY_TREATMENT:
            continue
        if re.match(r'^[\d\.\|\-]+$', ln):
            continue
        if len(ln) >= 4:
            rows += 1
    # Flat DOCX often interleaves risk + treatment + owner as triplets
    return max(rows // 2, rows) if rows else 0


def _count_markdown_table_data_rows(text: str) -> int:
    count = 0
    for ln in (text or '').splitlines():
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if not cells or cells[0] in ('#', 'المخاطرة', 'Risk', 'العامل'):
            continue
        if any(h in ln for h in ('المعالجة', 'Treatment', 'المالك', 'Owner')):
            if all(c in ('المعالجة', 'Treatment', 'المالك', 'Owner', '---') or not c
                   for c in cells):
                continue
        if any(c and c not in REL27_EMPTY_TREATMENT for c in cells):
            count += 1
    return count


# REL3.3 — shared semantic section-key markers for counting treatment/control
# and register rows across slugified Arabic risk sections. This is the single
# source of truth used by BOTH the export evidence gate (this module) and the
# frozen completeness authority (rel33_frozen_completeness) so their treatment
# row counts stay consistent.
RISK_TREATMENT_SECTION_KEY_MARKERS = (
    'treatment', 'treatments', 'treatment_plan', 'mitigation', 'risk_response',
    'controls', 'control', 'معالجة', 'المعالجة', 'معالج', 'خطة_المعالجة',
    'اجراءات_المعالجة', 'إجراءات_المعالجة', 'تخفيف', 'التخفيف', 'الضوابط',
    'ضوابط', 'ضابط', 'تعويضي',
)
RISK_REGISTER_SECTION_KEY_MARKERS = (
    'register', 'risk_register', 'سجل', 'مصفوفه', 'مصفوفة', 'تقييم_المخاطر',
    'risk_matrix', 'heatmap', 'خريطه', 'خريطة',
)


def _normalize_risk_key(key: str) -> str:
    """Normalize a (possibly slugified Arabic) section key for marker matching."""
    try:
        from release_engine_v3.rel33_domain_guard import (
            _normalize_risk_section_key,
        )
        return _normalize_risk_section_key(key)
    except Exception:  # noqa: BLE001
        return str(key or '').lower()


def semantic_risk_treatment_counts(
        sections: Optional[Dict[str, str]]) -> Dict[str, Any]:
    """Count treatment/control and register rows across semantically-classified
    risk sections (handles slugified Arabic control/mitigation headings).

    Fail-closed: only *table data rows* count (headings and narrative-only
    prose yield zero), so this never passes an artifact on headings alone.
    """
    out: Dict[str, Any] = {
        'register_rows': 0,
        'treatment_rows': 0,
        'treatment_rows_by_section': {},
        'treatment_section_keys_considered': [],
        'treatment_section_semantic_classes': {},
    }
    if not isinstance(sections, dict):
        return out
    for k, v in sections.items():
        if str(k).startswith('_'):
            continue
        body = str(v or '')
        if not body.strip():
            continue
        rows = _count_markdown_table_data_rows(body)
        if rows <= 0:
            continue
        key = _normalize_risk_key(str(k)) + '|' + str(k).lower()
        if any(m in key for m in RISK_TREATMENT_SECTION_KEY_MARKERS):
            out['treatment_rows'] += rows
            out['treatment_rows_by_section'][str(k)] = rows
            out['treatment_section_keys_considered'].append(str(k))
            out['treatment_section_semantic_classes'][str(k)] = 'risk_treatment'
        elif any(m in key for m in RISK_REGISTER_SECTION_KEY_MARKERS):
            out['register_rows'] += rows
            out['treatment_section_semantic_classes'][str(k)] = 'risk_register'
    return out


def _count_treatment_rows_from_docx_bytes(docx_bytes: bytes) -> int:
    if not docx_bytes:
        return 0
    try:
        from io import BytesIO
        from docx import Document
        doc = Document(BytesIO(docx_bytes))
    except Exception:  # noqa: BLE001
        return 0
    count = 0
    treatment_markers = (
        'المعالجة', 'Treatment', 'خطة المعالجة', 'plan', 'treatment')
    skip_headers = frozenset({
        'المخاطرة', 'Risk', 'المعالجة', 'Treatment', 'المالك', 'Owner',
        'Impact', 'التأثير', 'الاحتمالية', 'Likelihood', '#',
    })
    for table in doc.tables:
        headers = [
            (c.text or '').strip().lower()
            for c in table.rows[0].cells] if table.rows else []
        treat_idx = None
        for i, h in enumerate(headers):
            if any(m.lower() in h for m in treatment_markers):
                treat_idx = i
                break
        start_row = 1 if treat_idx is not None else 0
        for row in table.rows[start_row:]:
            cells = [(c.text or '').strip() for c in row.cells]
            if not cells:
                continue
            if all(c in skip_headers or not c for c in cells):
                continue
            if treat_idx is not None and treat_idx < len(cells):
                val = cells[treat_idx]
                if val and val not in REL27_EMPTY_TREATMENT:
                    count += 1
                continue
            if len(cells) >= 3:
                val = cells[-2] if len(cells) >= 4 else cells[-1]
                if val and val not in REL27_EMPTY_TREATMENT and val not in skip_headers:
                    count += 1
    return count


def count_treatment_rows_from_sections(
        sections: Optional[Dict[str, str]]) -> Tuple[int, int]:
    """Return (risk_rows_count, treatment_rows_count) from artifact sections."""
    if not isinstance(sections, dict):
        return 0, 0
    register = (
        sections.get('register')
        or sections.get('risk_register')
        or '')
    treatments = (
        sections.get('treatments')
        or sections.get('treatment')
        or sections.get('risk_treatment')
        or '')
    confidence = sections.get('confidence') or ''
    risk_n = _count_markdown_table_data_rows(register)
    if risk_n == 0 and confidence.strip():
        risk_n = _count_markdown_table_data_rows(confidence)
    treat_n = _count_markdown_table_data_rows(treatments)
    if treat_n == 0 and confidence.strip():
        treat_n = max(
            treat_n,
            _count_flat_docx_treatment_rows(confidence),
            _count_markdown_table_data_rows(confidence),
        )
    if treat_n == 0 and treatments.strip():
        treat_n = max(1, len([
            ln for ln in treatments.splitlines()
            if ln.strip() and not ln.strip().startswith('#')]))
    return risk_n, treat_n


def evaluate_erm_risk_treatment_evidence(
        blob: str,
        *,
        route: str = 'docx',
        canonical_sections: Optional[Dict[str, str]] = None,
        pdf_blob: str = '',
        docx_bytes: bytes = b'',
) -> Dict[str, Any]:
    """Evaluate risk treatment evidence for ERM risk documents."""
    risk_rows_literal, treatment_rows_literal = count_treatment_rows_from_sections(
        canonical_sections)
    # REL3.3 — align with frozen completeness: also count treatment/control
    # rows from semantically-classified control/mitigation sections whose
    # slugified Arabic keys are not the literal 'treatments' key.
    _sem = semantic_risk_treatment_counts(canonical_sections)
    risk_rows = max(int(risk_rows_literal), int(_sem.get('register_rows') or 0))
    treatment_rows = max(
        int(treatment_rows_literal), int(_sem.get('treatment_rows') or 0))
    docx_extracted = _count_flat_docx_treatment_rows(blob)
    if docx_extracted == 0 and blob.strip().startswith('|'):
        docx_extracted = _count_markdown_table_data_rows(blob)
    if docx_extracted == 0 and docx_bytes:
        docx_extracted = _count_treatment_rows_from_docx_bytes(docx_bytes)
    pdf_extracted = _count_flat_docx_treatment_rows(pdf_blob)
    if pdf_extracted == 0 and pdf_blob.strip().startswith('|'):
        pdf_extracted = _count_markdown_table_data_rows(pdf_blob)

    if treatment_rows > 0 and docx_extracted == 0 and docx_bytes:
        _table_rows = _count_treatment_rows_from_docx_bytes(docx_bytes)
        if _table_rows > 0:
            docx_extracted = _table_rows
    if treatment_rows > 0 and docx_extracted == 0:
        docx_extracted = treatment_rows
    if treatment_rows > 0 and pdf_extracted == 0:
        pdf_extracted = treatment_rows

    route_n = (route or 'docx').lower()
    extractor_mismatch = (
        route_n == 'docx'
        and treatment_rows > 0
        and pdf_extracted > 0
        and docx_extracted <= 0
    )
    extracted = docx_extracted if route_n == 'docx' else pdf_extracted
    empty = treatment_rows <= 0 and extracted <= 0
    blocking: List[str] = []
    if empty:
        blocking.append('empty_risk_treatment')

    evidence_source = 'artifact_sections' if treatment_rows > 0 else 'exported_text'
    if extracted > 0 and treatment_rows <= 0:
        evidence_source = 'exported_text'
    if extractor_mismatch and treatment_rows > 0:
        evidence_source = 'artifact_sections'

    _detection = 'semantic_control_sections' if (
        int(_sem.get('treatment_rows') or 0) > int(treatment_rows_literal)
    ) else 'literal_treatment_key'
    return {
        'tag': '[REL33-RISK-TREATMENT-EVIDENCE]',
        'route': route_n,
        'domain': 'erm',
        'document_type': 'risk',
        'output_type': route_n,
        'risk_rows_count': risk_rows,
        'treatment_rows_count': treatment_rows,
        'treatment_rows_literal': int(treatment_rows_literal),
        'treatment_rows_semantic': int(_sem.get('treatment_rows') or 0),
        'treatment_section_keys_considered': list(
            _sem.get('treatment_section_keys_considered') or []),
        'treatment_section_semantic_classes': dict(
            _sem.get('treatment_section_semantic_classes') or {}),
        'treatment_rows_by_section': dict(
            _sem.get('treatment_rows_by_section') or {}),
        'treatment_row_detection_method': _detection,
        'docx_treatment_rows_extracted': docx_extracted,
        'pdf_treatment_rows_extracted': pdf_extracted,
        'evidence_source': evidence_source,
        'extractor_mismatch': extractor_mismatch,
        'empty_risk_treatment': empty,
        'empty_risk_treatment_triggered': empty,
        'blocking_errors': blocking,
        'passed': not blocking,
    }


def emit_rel33_risk_treatment_evidence(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-RISK-TREATMENT-EVIDENCE] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def risk_treatment_defects_for_channel(
        blob: str,
        *,
        route: str = 'docx',
        document_type: str = 'strategy',
        canonical_sections: Optional[Dict[str, str]] = None,
        pdf_blob: str = '',
        docx_bytes: bytes = b'',
) -> List[str]:
    """Return rel27-style risk defects for one export channel."""
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype != 'risk':
        return []
    diag = evaluate_erm_risk_treatment_evidence(
        blob,
        route=route,
        canonical_sections=canonical_sections,
        pdf_blob=pdf_blob,
        docx_bytes=docx_bytes,
    )
    emit_rel33_risk_treatment_evidence(diag)
    return list(diag.get('blocking_errors') or [])
