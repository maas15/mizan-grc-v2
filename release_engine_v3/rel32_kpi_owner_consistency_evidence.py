"""REL3.2 — returned-file KPI owner consistency evidence."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple

from release_engine_v3.rel32_kpi_main_schema_evidence import (
    _extract_main_kpi_rows,
    extract_kpi_main_header_labels_from_text,
)
from release_engine_v3.rel32_table_schema_binding import (
    REL32_KPI_MAIN_EXPECTED_SCHEMA_AR,
    _repair_kpi_row_dict,
    bind_table_row,
    emit_rel32_kpi_owner_consistency_diag,
    evaluate_kpi_owner_consistency,
    find_kpi_main_table,
    rebind_table_spec,
)


class _KpiTableRowsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_kpi = False
        self._in_thead = False
        self._in_tbody = False
        self._in_row = False
        self._in_th = False
        self._in_td = False
        self._buf = ''
        self.headers: List[str] = []
        self.rows: List[List[str]] = []
        self._row_cells: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_d = dict(attrs)
        if tag == 'div' and attrs_d.get('data-table-id') == 'kpi_main':
            self._in_kpi = True
        if not self._in_kpi:
            return
        if tag == 'thead':
            self._in_thead = True
        elif tag == 'tbody':
            self._in_tbody = True
        elif tag == 'tr' and (self._in_thead or self._in_tbody):
            self._in_row = True
            self._buf = ''
            self._row_cells = []
        elif tag == 'th' and self._in_row and self._in_thead:
            self._in_th = True
            self._buf = ''
        elif tag == 'td' and self._in_row and self._in_tbody:
            self._in_td = True
            self._buf = ''

    def handle_endtag(self, tag: str) -> None:
        if tag == 'div' and self._in_kpi:
            self._in_kpi = False
        if not self._in_kpi and tag != 'div':
            return
        if tag == 'thead':
            self._in_thead = False
        elif tag == 'tbody':
            self._in_tbody = False
        elif tag == 'tr' and self._in_row:
            self._in_row = False
            if self._in_tbody and self._row_cells:
                self.rows.append(self._row_cells)
        elif tag == 'th' and self._in_th:
            self.headers.append(re.sub(r'\s+', ' ', self._buf).strip())
            self._in_th = False
        elif tag == 'td' and self._in_td:
            self._row_cells.append(re.sub(r'\s+', ' ', self._buf).strip())
            self._in_td = False

    def handle_data(self, data: str) -> None:
        if self._in_th or self._in_td:
            self._buf += data


def _bound_rows_from_cells(
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
        *,
        lang: str = 'ar',
        repair: bool = True,
) -> List[Dict[str, str]]:
    br: List[Dict[str, str]] = []
    hdr = list(headers or REL32_KPI_MAIN_EXPECTED_SCHEMA_AR)
    for ri, r in enumerate(rows or [], 1):
        rd, _ = bind_table_row(hdr, list(r), 'kpi_main', row_index=ri, lang=lang)
        br.append(_repair_kpi_row_dict(rd) if repair else rd)
    return br


def evaluate_kpi_owner_consistency_from_model(
        model: Optional[Dict[str, Any]],
        *,
        route_name: str,
        lang: str = 'ar',
) -> Dict[str, Any]:
    tbl = find_kpi_main_table((model or {}).get('blocks') or {})
    if not tbl:
        diag = evaluate_kpi_owner_consistency(route_name=route_name, bound_rows=[])
        diag['blocking_errors'] = ['rel32_kpi_main_table_missing']
        diag['kpi_owner_consistency_passed'] = False
        emit_rel32_kpi_owner_consistency_diag(diag)
        return diag
    rebound = rebind_table_spec(dict(tbl), lang=lang) or tbl
    br = list(rebound.get('bound_rows') or [])
    diag = evaluate_kpi_owner_consistency(
        route_name=route_name,
        bound_rows=br,
    )
    emit_rel32_kpi_owner_consistency_diag(diag)
    return diag


def evaluate_kpi_owner_consistency_from_preview_html(
        html_text: str,
        *,
        route_name: str = 'preview',
) -> Dict[str, Any]:
    parser = _KpiTableRowsParser()
    parser.feed(html_text or '')
    headers = parser.headers or list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR)
    br = _bound_rows_from_cells(headers, parser.rows, repair=False)
    diag = evaluate_kpi_owner_consistency(
        route_name=route_name,
        bound_rows=br,
    )
    emit_rel32_kpi_owner_consistency_diag(diag)
    return diag


def evaluate_kpi_owner_consistency_from_export_text(
        blob: str,
        *,
        route_name: str,
        lang: str = 'ar',
) -> Dict[str, Any]:
    headers = extract_kpi_main_header_labels_from_text(blob)
    rows = _extract_main_kpi_rows(blob)
    br = _bound_rows_from_cells(
        headers or REL32_KPI_MAIN_EXPECTED_SCHEMA_AR, rows, lang=lang, repair=False)
    diag = evaluate_kpi_owner_consistency(
        route_name=route_name,
        bound_rows=br,
    )
    if not headers:
        diag['blocking_errors'] = list(dict.fromkeys(
            (diag.get('blocking_errors') or [])
            + ['rel32_kpi_main_header_not_found_in_export_text']))
        diag['kpi_owner_consistency_passed'] = False
    emit_rel32_kpi_owner_consistency_diag(diag)
    return diag


def merge_kpi_owner_consistency_blockers(
        gate: Dict[str, Any],
        diag: Dict[str, Any],
) -> Dict[str, Any]:
    if diag.get('kpi_owner_consistency_passed'):
        gate['rel32_kpi_owner_consistency'] = diag
        return gate
    gate['blocking_errors'] = list(dict.fromkeys(
        (gate.get('blocking_errors') or [])
        + (diag.get('blocking_errors') or [])))
    gate['rel32_kpi_owner_consistency'] = diag
    return gate
