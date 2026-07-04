"""REL3.2 — returned-file KPI main schema consistency evidence."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from release_engine_v3.rel32_preview_table_dom import (
    evaluate_preview_dom_binding_check,
    extract_table_dom_binding,
)
from release_engine_v3.rel32_table_schema_binding import (
    REL32_KPI_MAIN_EXPECTED_SCHEMA_AR,
    emit_rel32_kpi_main_schema_consistency_diag,
    evaluate_kpi_main_schema_consistency,
    find_kpi_main_table,
    rebind_table_spec,
)


def _cells_from_markdown_row(line: str) -> List[str]:
    return [c.strip() for c in line.strip('|').split('|')]


def _kpi_main_section_blob(blob: str) -> str:
    try:
        from release_engine.rel27_export_checks import _kpi_section_blob
        return _kpi_section_blob(blob or '')
    except Exception:  # noqa: BLE001
        return blob or ''


def extract_kpi_main_header_labels_from_text(blob: str) -> List[str]:
    """Extract KPI main header labels from returned DOCX/PDF/preview text."""
    section = _kpi_main_section_blob(blob)
    expected = list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR)
    for ln in section.splitlines():
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = _cells_from_markdown_row(ln)
        if not cells:
            continue
        blob_ln = ' '.join(cells).lower()
        if not any(k in blob_ln for k in ('مؤشر', 'kpi', 'indicator', 'وصف')):
            continue
        if cells[0] in ('#', 'رقم') or 'وصف المؤشر' in ln or 'المؤشر' in ln:
            return cells
    lines = [ln.strip() for ln in section.splitlines() if ln.strip()]
    for i, ln in enumerate(lines):
        if ln != expected[0]:
            continue
        window = lines[i:i + len(expected)]
        if window == expected:
            return list(expected)
    return []


def _extract_main_kpi_rows(blob: str) -> List[List[str]]:
    try:
        from release_engine.rel27_export_checks import _extract_kpi_main_rows
        return _extract_kpi_main_rows(blob or '')
    except Exception:  # noqa: BLE001
        return []


def evaluate_kpi_main_schema_from_model(
        model: Optional[Dict[str, Any]],
        *,
        route_name: str,
        lang: str = 'ar',
) -> Dict[str, Any]:
    tbl = find_kpi_main_table((model or {}).get('blocks') or {})
    if not tbl:
        diag = evaluate_kpi_main_schema_consistency(
            route_name=route_name,
            header_labels=[],
            rows=[],
            lang=lang,
        )
        diag['blocking_errors'] = ['rel32_kpi_main_table_missing']
        diag['kpi_main_schema_passed'] = False
        emit_rel32_kpi_main_schema_consistency_diag(diag)
        return diag
    rebound = rebind_table_spec(dict(tbl), lang=lang) or tbl
    diag = evaluate_kpi_main_schema_consistency(
        route_name=route_name,
        header_labels=rebound.get('header') or [],
        rows=rebound.get('rows') or [],
        bound_rows=rebound.get('bound_rows') or [],
        lang=lang,
    )
    emit_rel32_kpi_main_schema_consistency_diag(diag)
    return diag


def evaluate_kpi_main_schema_from_preview_html(
        html_text: str,
        *,
        route_name: str = 'preview',
) -> Dict[str, Any]:
    dom = extract_table_dom_binding(html_text or '')
    headers = dom.get('header_labels_from_dom') or []
    cells = dom.get('first_row_cells') or []
    dom_check = evaluate_preview_dom_binding_check(html_text or '', 'kpi_main')
    diag = evaluate_kpi_main_schema_consistency(
        route_name=route_name,
        header_labels=headers,
        rows=[cells] if cells else [],
        lang='ar',
    )
    if dom_check.get('blocking_errors'):
        diag['blocking_errors'] = list(dict.fromkeys(
            (diag.get('blocking_errors') or [])
            + (dom_check.get('blocking_errors') or [])))
        diag['kpi_main_schema_passed'] = not diag['blocking_errors']
    emit_rel32_kpi_main_schema_consistency_diag(diag)
    return diag


def evaluate_kpi_main_schema_from_export_text(
        blob: str,
        *,
        route_name: str,
        lang: str = 'ar',
) -> Dict[str, Any]:
    headers = extract_kpi_main_header_labels_from_text(blob)
    rows = _extract_main_kpi_rows(blob)
    diag = evaluate_kpi_main_schema_consistency(
        route_name=route_name,
        header_labels=headers,
        rows=rows,
        lang=lang,
    )
    if not headers:
        diag['blocking_errors'] = list(dict.fromkeys(
            (diag.get('blocking_errors') or [])
            + ['rel32_kpi_main_header_not_found_in_export_text']))
        diag['kpi_main_schema_passed'] = False
    emit_rel32_kpi_main_schema_consistency_diag(diag)
    return diag


def merge_kpi_main_schema_blockers(
        gate: Dict[str, Any],
        diag: Dict[str, Any],
) -> Dict[str, Any]:
    if diag.get('kpi_main_schema_passed'):
        gate['rel32_kpi_main_schema_consistency'] = diag
        return gate
    gate['blocking_errors'] = list(dict.fromkeys(
        (gate.get('blocking_errors') or [])
        + (diag.get('blocking_errors') or [])))
    gate['rel32_kpi_main_schema_consistency'] = diag
    return gate
