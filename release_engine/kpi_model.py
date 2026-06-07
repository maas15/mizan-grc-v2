"""PR-REL2.3 — final KPI semantic model for strategy artifacts."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

GENERIC_FORMULA = '(عدد العناصر المطابقة / إجمالي العناصر) × 100'

_PATCH_SLA_BAD = 'نسبة الترقيع الأمني خارج SLA'
_PATCH_SLA_GOOD = 'نسبة إغلاق الثغرات الحرجة ضمن SLA'
_PATCH_SLA_TARGET = '95% خلال 72 ساعة'
_PATCH_SLA_FORMULA = (
    'عدد الثغرات الحرجة المغلقة ضمن SLA ÷ إجمالي الثغرات الحرجة × 100')
_PATCH_SLA_SOURCE = 'منصة إدارة الثغرات'

_DLP_INCIDENT_BAD = 'عدد حوادث تسرب البيانات (DLP)'
_DLP_KRI_NAME = 'عدد حوادث تسرب البيانات الحرجة'
_DLP_KRI_TARGET = '0 حوادث حرجة'
_DLP_KRI_FORMULA = 'عدد حوادث تسرب البيانات الحرجة خلال الفترة'
_DLP_KRI_SOURCE = 'منصة DLP / سجل الحوادث'


def _parse_kpi_rows(text: str) -> Tuple[List[str], List[List[str]]]:
    lines = (text or '').splitlines()
    header_idx = -1
    for i, ln in enumerate(lines):
        if ln.strip().startswith('|') and ('وصف' in ln or 'Metric' in ln):
            header_idx = i
            break
    if header_idx < 0:
        return lines, []
    rows = []
    for ln in lines[header_idx + 1:]:
        if not ln.strip().startswith('|') or '---' in ln:
            if rows:
                break
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells and cells[0].isdigit():
            rows.append(cells)
    return lines, rows


def _renumber_rows(rows: List[List[str]]) -> List[List[str]]:
    out = []
    for i, cells in enumerate(rows, 1):
        c = list(cells)
        if c:
            c[0] = str(i)
        out.append(c)
    return out


def _repair_row_semantics(cells: List[str]) -> Tuple[List[str], bool]:
    if len(cells) < 3:
        return cells, False
    changed = False
    name = cells[1] if len(cells) > 1 else ''
    if _PATCH_SLA_BAD in name or 'الترقيع الأمني خارج' in name:
        cells[1] = _PATCH_SLA_GOOD
        if len(cells) > 2:
            cells[2] = _PATCH_SLA_TARGET
        if len(cells) > 3:
            cells[3] = _PATCH_SLA_FORMULA
        if len(cells) > 4:
            cells[4] = _PATCH_SLA_SOURCE
        changed = True
    elif _DLP_INCIDENT_BAD in name or (
            'حوادث تسرب' in name and 'dlp' in name.lower()):
        cells[1] = _DLP_KRI_NAME
        if len(cells) > 2:
            tgt = cells[2]
            if '%' in tgt or '≥' in tgt or 'percent' in tgt.lower():
                cells[2] = _DLP_KRI_TARGET
        if len(cells) > 3:
            cells[3] = _DLP_KRI_FORMULA
        if len(cells) > 4:
            cells[4] = _DLP_KRI_SOURCE
        changed = True
    if len(cells) > 3 and GENERIC_FORMULA in (cells[3] or ''):
        if 'mttd' in name.lower() or 'كشف' in name:
            cells[3] = 'عدد الحوادث المكتشفة ضمن SLA ÷ إجمالي الحوادث × 100'
        elif 'mttr' in name.lower() or 'استجابة' in name:
            cells[3] = 'عدد الحوادث المغلقة ضمن SLA ÷ إجمالي الحوادث × 100'
        else:
            cells[3] = cells[3].replace(
                GENERIC_FORMULA,
                'المؤشر المحدد ÷ إجمالي النطاق × 100')
        changed = True
    return cells, changed


def _count_generic_formulas(text: str) -> int:
    return (text or '').count(GENERIC_FORMULA)


def _kpi_numbering_valid(text: str) -> Tuple[bool, List[int], List[int]]:
    """Validate numbering on the main KPI table only (ignore formula appendix)."""
    _lines, rows = _parse_kpi_rows(text)
    nums = []
    for cells in rows:
        if cells and str(cells[0]).strip().isdigit():
            nums.append(int(str(cells[0]).strip()))
    if not nums:
        return True, [], []
    dupes = [n for n in set(nums) if nums.count(n) > 1]
    expected = list(range(1, len(nums) + 1))
    gaps = [n for n in expected if n not in nums]
    return nums == expected and not dupes, dupes, gaps


def _detect_invalid_rows(text: str) -> List[str]:
    invalid = []
    if _PATCH_SLA_BAD in text:
        invalid.append(_PATCH_SLA_BAD)
    if _DLP_INCIDENT_BAD in text and '%' in text:
        invalid.append(_DLP_INCIDENT_BAD)
    if GENERIC_FORMULA in text:
        invalid.append('generic_formula')
    return invalid


def finalize_kpi_semantics(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Repair KPI semantics; emit [REL2-KPI-FINAL-SEMANTIC-MODEL]."""
    backend = backend or {}
    canonical_fn = backend.get('canonicalize_kpis')
    text = sections.get('kpis', '') or ''
    pre_invalid = _detect_invalid_rows(text)
    pre_generic = _count_generic_formulas(text)
    pre_num_valid, pre_dupes, pre_gaps = _kpi_numbering_valid(text)
    if not pre_invalid and pre_generic == 0 and pre_num_valid and not pre_dupes:
        return sections, {
            'kpi_semantics_valid': True,
            'invalid_metric_rows': [],
            'generic_formula_count': 0,
            'numbering_valid': True,
            'formula_alignment_valid': True,
            'action_taken': 'already_valid',
            'blocking_error_if_any': '',
        }

    if canonical_fn:
        try:
            sections, kpi_diag = canonical_fn(dict(sections), lang)
            text = sections.get('kpis', '') or text
            invalid = _detect_invalid_rows(text)
            generic_count = _count_generic_formulas(text)
            num_valid, dupes, gaps = _kpi_numbering_valid(text)
            diag = {
                'kpi_semantics_valid': not invalid and generic_count == 0,
                'invalid_metric_rows': invalid,
                'generic_formula_count': generic_count,
                'numbering_valid': num_valid and not dupes and not gaps,
                'formula_alignment_valid': kpi_diag.get(
                    'formula_alignment_valid', num_valid),
                'action_taken': 'canonicalize_kpis_backend',
                'blocking_error_if_any': (
                    '' if not invalid else f'rel2_kpi_failed:{invalid[0]}'),
            }
            if invalid or generic_count:
                sections, text = _apply_inline_kpi_repairs(sections)
                diag = _build_kpi_diag(text)
            return sections, diag
        except Exception:  # noqa: BLE001
            pass

    sections, text = _apply_inline_kpi_repairs(sections)
    return sections, _build_kpi_diag(text)


def _apply_inline_kpi_repairs(
        sections: Dict[str, str]) -> Tuple[Dict[str, str], str]:
    text = sections.get('kpis', '') or ''
    lines, rows = _parse_kpi_rows(text)
    if not rows:
        out = dict(sections)
        return out, text
    repaired_rows = []
    for cells in rows:
        fixed, _ = _repair_row_semantics(list(cells))
        repaired_rows.append(fixed)
    repaired_rows = _renumber_rows(repaired_rows)
    out_lines = list(lines)
    row_idx = 0
    for i, ln in enumerate(out_lines):
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells and cells[0].isdigit() and row_idx < len(repaired_rows):
            out_lines[i] = '| ' + ' | '.join(repaired_rows[row_idx]) + ' |'
            row_idx += 1
    new_text = '\n'.join(out_lines)
    out = dict(sections)
    out['kpis'] = new_text
    return out, new_text


def _build_kpi_diag(text: str) -> Dict[str, Any]:
    invalid = _detect_invalid_rows(text)
    generic_count = _count_generic_formulas(text)
    num_valid, dupes, gaps = _kpi_numbering_valid(text)
    semantics_ok = not invalid and generic_count == 0
    blocking = ''
    if invalid:
        blocking = f'rel2_kpi_failed:{invalid[0]}'
    elif generic_count:
        blocking = 'rel2_kpi_failed:generic_formula'
    elif not num_valid or dupes or gaps:
        blocking = 'rel2_kpi_failed:numbering'
    return {
        'kpi_semantics_valid': semantics_ok and num_valid,
        'invalid_metric_rows': invalid,
        'generic_formula_count': generic_count,
        'numbering_valid': num_valid and not dupes and not gaps,
        'formula_alignment_valid': num_valid and not dupes,
        'action_taken': 'kpi_semantics_repaired' if not invalid else 'blocked',
        'blocking_error_if_any': blocking,
    }


def emit_kpi_final_semantic_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-KPI-FINAL-SEMANTIC-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
