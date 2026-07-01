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
_FORMULA_RE = re.compile(r'مجموع|عدد|/')
_SOURCE_RE = re.compile(r'siem|soc|log|ticket|survey|report', re.I)


def _is_freq(v: str) -> bool:
    return bool(_FREQ_RE.match((v or '').strip()))


def _is_type(v: str) -> bool:
    return bool(_TYPE_RE.match((v or '').strip()))


def validate_kpi_main_semantics(by_header: Dict[str, str]) -> List[str]:
    errors: List[str] = []
    owner = by_header.get('المالك', '')
    freq = by_header.get('التكرار', '')
    source = by_header.get('مصدر', '')
    typ = by_header.get('النوع', '')
    target = by_header.get('القيمة المستهدفة', '')
    formula = by_header.get('صيغة الاحتساب', '')
    if _is_freq(owner) and not _is_freq(freq):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_main:المالك')
    if _SOURCE_RE.search(freq or '') and not _SOURCE_RE.search(source or ''):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_main:التكرار')
    if _SOURCE_RE.search(owner or '') and not _SOURCE_RE.search(source or ''):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_main:المالك')
    if _is_type(target) and not _is_type(typ):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_main:النوع')
    if _TARGET_RE.search(formula or '') and not _FORMULA_RE.search(formula or ''):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_main:صيغة الاحتساب')
    if _FORMULA_RE.search(source or '') and not _SOURCE_RE.search(source or ''):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_main:مصدر')
    return errors


def validate_kpi_formula_semantics(
        by_header: Dict[str, str], headers: Sequence[str]) -> List[str]:
    errors: List[str] = []
    if 'المؤشر' not in list(headers or []):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_formula:المؤشر')
    formula = by_header.get('صيغة الاحتساب', '')
    source = by_header.get('مصدر البيانات') or by_header.get('مصدر', '')
    if _TARGET_RE.search(formula or '') and not _FORMULA_RE.search(formula or ''):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_formula:صيغة الاحتساب')
    if _FORMULA_RE.search(source or '') and not _SOURCE_RE.search(source or ''):
        errors.append('rel32_preview_table_header_value_mismatch:kpi_formula:مصدر البيانات')
    return errors


def evaluate_preview_dom_binding_check(
        html_text: str,
        schema_id: str,
) -> Dict[str, Any]:
    schema_labels = schema_header_labels(schema_id, lang='ar')
    dom = extract_table_dom_binding(html_text)
    mismatched: List[str] = []
    blocking: List[str] = []
    if dom['header_labels_from_dom'] != schema_labels:
        mismatched.append('header_order')
        for i, lbl in enumerate(schema_labels):
            got = dom['header_labels_from_dom'][i] if i < len(dom['header_labels_from_dom']) else ''
            if got != lbl:
                mismatched.append(f'header:{lbl}:expected_index_{i}')
    if not dom.get('schema_binder_applied'):
        blocking.append(f'rel32_preview_table_schema_binder_not_applied:{schema_id}')
    if schema_id == 'kpi_main':
        blocking.extend(validate_kpi_main_semantics(dom['first_row_cells_by_header']))
    if schema_id == 'kpi_formula':
        blocking.extend(validate_kpi_formula_semantics(
            dom['first_row_cells_by_header'], dom['header_labels_from_dom']))
    return {
        'table_id': schema_id,
        'schema_labels': schema_labels,
        'header_labels_from_dom': dom['header_labels_from_dom'],
        'first_row_cells_by_header': dom['first_row_cells_by_header'],
        'mismatched_headers': mismatched,
        'preview_dom_binding_passed': not mismatched and not blocking,
        'blocking_errors': blocking,
    }


def cell_under_header(html_text: str, header_label: str) -> str:
    dom = extract_table_dom_binding(html_text)
    return str(dom['first_row_cells_by_header'].get(header_label) or '')
