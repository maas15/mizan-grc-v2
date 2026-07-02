"""REL32 preview table DOM binding — Python mirror for tests + diagnostics."""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple

from release_engine_v3.rel32_table_schema_binding import (
    rebind_table_spec,
    row_dict_to_cells,
    schema_header_labels,
)


def _esc(text: str) -> str:
    return html.escape(str(text or ''), quote=True)


def render_preview_table_html(
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
        *,
        schema_id: str,
        is_rtl: bool = True,
) -> str:
    """Render preview HTML using schema-key binding (mirrors rel32-preview-table-schema.js)."""
    spec = rebind_table_spec(
        {'schema': schema_id, 'header': list(headers), 'rows': [list(r) for r in rows]},
        lang='ar',
    )
    labels = schema_header_labels(schema_id, lang='ar')
    bound_rows = (spec or {}).get('bound_rows') or []
    css = {
        'kpi_main': 'kpi-summary',
        'kpi_formula': 'kpi-formula',
        'roadmap': 'roadmap',
        'gap_action': 'gap-action',
    }.get(schema_id, schema_id)
    dir_attr = ' dir="rtl"' if is_rtl else ''
    align = 'right' if is_rtl else 'left'
    parts = [
        f'<div class="table-wrapper" data-schema="{css}" data-table-id="{schema_id}"{dir_attr}>',
        f'<table class="schema-{css}"><thead><tr>',
    ]
    for lbl in labels:
        parts.append(f'<th style="text-align:{align}">{_esc(lbl)}</th>')
    parts.append('</tr></thead><tbody>')
    for row_dict in bound_rows:
        cells = row_dict_to_cells(row_dict, schema_id)
        parts.append('<tr>')
        for cell in cells:
            val = (cell or '').strip()
            if not val or val == '—':
                parts.append('<td class="cell-missing">—</td>')
            else:
                parts.append(f'<td>{_esc(val)}</td>')
        parts.append('</tr>')
    parts.append('</tbody></table></div>')
    return ''.join(parts)


class _FirstRowTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_thead = False
        self._in_tbody = False
        self._in_row = False
        self._in_th = False
        self._in_td = False
        self._row_done = False
        self._headers: List[str] = []
        self._first_row: List[str] = []
        self._buf = ''

    @property
    def headers(self) -> List[str]:
        return self._headers

    @property
    def first_row(self) -> List[str]:
        return self._first_row

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == 'thead':
            self._in_thead = True
        elif tag == 'tbody':
            self._in_tbody = True
        elif tag == 'tr' and (self._in_thead or (self._in_tbody and not self._row_done)):
            self._in_row = True
            self._buf = ''
        elif tag == 'th' and self._in_row and self._in_thead:
            self._in_th = True
            self._buf = ''
        elif tag == 'td' and self._in_row and self._in_tbody and not self._row_done:
            self._in_td = True
            self._buf = ''

    def handle_endtag(self, tag: str) -> None:
        if tag == 'thead':
            self._in_thead = False
        elif tag == 'tbody':
            self._in_tbody = False
        elif tag == 'tr' and self._in_row:
            self._in_row = False
            if self._in_tbody:
                self._row_done = True
        elif tag == 'th' and self._in_th:
            self._headers.append(re.sub(r'\s+', ' ', self._buf).strip())
            self._in_th = False
        elif tag == 'td' and self._in_td:
            self._first_row.append(re.sub(r'\s+', ' ', self._buf).strip())
            self._in_td = False

    def handle_data(self, data: str) -> None:
        if self._in_th or self._in_td:
            self._buf += data


def extract_table_dom_binding(html_text: str) -> Dict[str, Any]:
    parser = _FirstRowTableParser()
    parser.feed(html_text or '')
    by_header = {
        h: (parser.first_row[i] if i < len(parser.first_row) else '')
        for i, h in enumerate(parser.headers)
    }
    schema_binder_applied = 'data-table-id="' in (html_text or '')
    return {
        'header_labels_from_dom': parser.headers,
        'first_row_cells': parser.first_row,
        'first_row_cells_by_header': by_header,
        'schema_binder_applied': schema_binder_applied,
    }


_FREQ_RE = re.compile(
    r'^(شهري|ربع|سنو|يوم|أسبو|daily|weekly|monthly|quarter|annual|تواتر|تكرار)',
    re.I,
)
_TYPE_RE = re.compile(r'^(kpi|kri|مؤشر|kpi/kri)$', re.I)
_TARGET_RE = re.compile(r'^<\s*\d|[\d.]+\s*%|[\d.]+\s*ساع|[\d.]+\s*دقي', re.I)
_FORMULA_RE = re.compile(r'مجموع|عدد\s*الحوادث|احتساب', re.I)
_SOURCE_RE = re.compile(r'siem|soc|log|ticket|survey|report', re.I)
_PURE_SOURCE_RE = re.compile(r'^siem\s*/\s*soc$', re.I)


def _is_freq(v: str) -> bool:
    return bool(_FREQ_RE.match((v or '').strip()))


def _is_type(v: str) -> bool:
    return bool(_TYPE_RE.match((v or '').strip()))


def _pure_source_token(v: str) -> bool:
    s = (v or '').strip()
    return bool(_PURE_SOURCE_RE.match(s))


def validate_kpi_main_by_dom_index(
        headers: Sequence[str], cells: Sequence[str]) -> List[str]:
    schema_labels = schema_header_labels('kpi_main', lang='ar')
    errors: List[str] = []
    for i, lbl in enumerate(schema_labels):
        if i >= len(headers) or headers[i] != lbl:
            errors.append(f'rel32_preview_table_header_value_mismatch:kpi_main:{lbl}')
        cell = cells[i] if i < len(cells) else ''
        if lbl == 'التكرار' and cell and (not _is_freq(cell) or _pure_source_token(cell)):
            errors.append('rel32_preview_table_header_value_mismatch:kpi_main:التكرار')
        if lbl == 'مصدر' and cell and (not _SOURCE_RE.search(cell) or _is_freq(cell)):
            errors.append('rel32_preview_table_header_value_mismatch:kpi_main:مصدر')
        if lbl == 'المالك' and cell and (_is_freq(cell) or _pure_source_token(cell) or _is_type(cell)):
            errors.append('rel32_preview_table_header_value_mismatch:kpi_main:المالك')
        if lbl == 'النوع' and cell and not _is_type(cell) and 'kri' not in cell.lower():
            errors.append('rel32_preview_table_header_value_mismatch:kpi_main:النوع')
        if lbl == 'صيغة الاحتساب' and cell and _TARGET_RE.search(cell) and not _FORMULA_RE.search(cell):
            errors.append('rel32_preview_table_header_value_mismatch:kpi_main:صيغة الاحتساب')
    return errors


def validate_kpi_formula_by_dom_index(
        headers: Sequence[str], cells: Sequence[str]) -> List[str]:
    schema_labels = schema_header_labels('kpi_formula', lang='ar')
    errors: List[str] = []
    for i, lbl in enumerate(schema_labels):
        if i >= len(headers) or headers[i] != lbl:
            errors.append(f'rel32_preview_table_header_value_mismatch:kpi_formula:{lbl}')
        cell = cells[i] if i < len(cells) else ''
        if lbl == 'المؤشر' and (not cell or _TARGET_RE.search(cell or '')):
            errors.append('rel32_preview_table_header_value_mismatch:kpi_formula:المؤشر')
        if lbl == 'صيغة الاحتساب' and cell and _TARGET_RE.search(cell) and not _FORMULA_RE.search(cell):
            errors.append('rel32_preview_table_header_value_mismatch:kpi_formula:صيغة الاحتساب')
        if lbl == 'مصدر البيانات' and cell and _FORMULA_RE.search(cell) and not _SOURCE_RE.search(cell):
            errors.append('rel32_preview_table_header_value_mismatch:kpi_formula:مصدر البيانات')
    return errors


def evaluate_preview_dom_binding_check(
        html_text: str,
        schema_id: str,
) -> Dict[str, Any]:
    schema_labels = schema_header_labels(schema_id, lang='ar')
    dom = extract_table_dom_binding(html_text)
    headers = dom['header_labels_from_dom']
    cells = dom['first_row_cells']
    mismatched: List[str] = []
    blocking: List[str] = []
    if headers != schema_labels:
        mismatched.append('header_order')
        for i, lbl in enumerate(schema_labels):
            got = headers[i] if i < len(headers) else ''
            if got != lbl:
                mismatched.append(f'header:{lbl}:expected_index_{i}')
    if not dom.get('schema_binder_applied'):
        blocking.append(f'rel32_preview_table_schema_binder_not_applied:{schema_id}')
    if schema_id == 'kpi_main':
        blocking.extend(validate_kpi_main_by_dom_index(headers, cells))
    if schema_id == 'kpi_formula':
        blocking.extend(validate_kpi_formula_by_dom_index(headers, cells))
    return {
        'table_id': schema_id,
        'schema_labels': schema_labels,
        'header_labels_from_dom': headers,
        'first_row_cells': cells,
        'first_row_cells_by_header': dom['first_row_cells_by_header'],
        'mismatched_headers': mismatched,
        'preview_dom_binding_passed': not mismatched and not blocking,
        'blocking_errors': blocking,
    }


def cell_under_header(html_text: str, header_label: str) -> str:
    dom = extract_table_dom_binding(html_text)
    return str(dom['first_row_cells_by_header'].get(header_label) or '')


def dom_index_maps(headers: Sequence[str], cells: Sequence[str]) -> bool:
    """True when headers[i] maps to cells[i] for all indices (DOM order)."""
    if len(headers) != len(cells):
        return False
    return all(headers[i] and cells[i] is not None for i in range(len(headers)))
