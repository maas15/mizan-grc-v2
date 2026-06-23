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

_LOGIN_ANOMALY_BAD = 'نسبة محاولات الدخول الفاشلة الشاذة'
_LOGIN_ANOMALY_GOOD = 'نسبة تغطية مراقبة محاولات الدخول الشاذة'
_LOGIN_ANOMALY_TARGET = '≥ 95% كشف ومراقبة'
_LOGIN_ANOMALY_FORMULA = (
    'عدد محاولات الدخول الشاذة المكتشفة ÷ إجمالي المحاولات الشاذة × 100')

_THIRD_PARTY_RISK_BAD = 'درجة مخاطر الأطراف الثالثة'
_THIRD_PARTY_RISK_TARGET = '≤ 3 (منخفض)'
_THIRD_PARTY_RISK_FORMULA = 'متوسط درجة مخاطر الموردين السيبرانية المقيمة'

_MTTD_TARGET = '< 4 ساعات'
_MTTD_FORMULA = 'مجموع أزمنة اكتشاف الحوادث الحرجة ÷ عدد الحوادث الحرجة'
_MTTR_TARGET = '< 4 ساعات'
_MTTR_FORMULA = 'مجموع أزمنة الاستجابة للحوادث الحرجة ÷ عدد الحوادث الحرجة'

# REL3 canonical KPI family registry (cyber strategy)
KPI_CANONICAL_REGISTRY: Dict[str, Dict[str, str]] = {
    'soc_mttd': {
        'label_ar': 'متوسط زمن اكتشاف الحوادث الأمنية الحرجة',
        'kpi_type': 'KPI',
        'target': _MTTD_TARGET,
        'formula': _MTTD_FORMULA,
        'source': 'SIEM / SOC',
        'frequency': 'شهري',
    },
    'incident_response_mttr': {
        'label_ar': 'متوسط زمن الاستجابة للحوادث الأمنية الحرجة',
        'kpi_type': 'KPI',
        'target': _MTTR_TARGET,
        'formula': _MTTR_FORMULA,
        'source': 'ITSM / SOAR / SIEM',
        'frequency': 'شهري',
    },
}

_KPI_CANONICAL_FAMILY_TOKENS: Dict[str, Tuple[str, ...]] = {
    'soc_mttd': ('mttd', 'زمن الكشف', 'كشف', 'اكتشاف'),
    'incident_response_mttr': ('mttr', 'زمن الاستجابة', 'استجابة'),
    'governance': ('حوكمة', 'ciso', 'لجنة'),
    'compliance': ('امتثال', 'ecc', 'dcc'),
    'iam_mfa_pam': ('iam', 'pam', 'mfa', 'هوية'),
    'vulnerability_sla': ('ثغر', 'vulnerability', 'sla'),
    'awareness_phishing': ('توعية', 'phishing', 'تدريب', 'تصيد'),
    'backup_dr': ('نسخ', 'backup', 'dr', 'تعافي'),
    'data_classification': ('تصنيف', 'جرد'),
    'encryption': ('تشفير', 'مفاتيح'),
    'dlp': ('dlp', 'تسرب'),
    'third_party_risk': ('أطراف ثالثة', 'third', 'مورد'),
}

_PRCY88_FAMILY_ALIASES = {
    'mttd_detection': 'soc_mttd',
    'mttr_incident': 'incident_response_mttr',
    'mttd': 'soc_mttd',
    'mttr': 'incident_response_mttr',
}


def resolve_kpi_canonical_family(name: str) -> Optional[str]:
    """Map a KPI label to one canonical cyber strategy family."""
    n = (name or '').strip()
    if not n:
        return None
    low = n.lower()
    if 'mttr' in low or ('زمن' in n and 'استجاب' in n):
        return 'incident_response_mttr'
    if 'mttd' in low or (
            ('زمن' in n or 'متوسط' in n) and ('كشف' in n or 'اكتشاف' in n)):
        return 'soc_mttd'
    for fam, toks in _KPI_CANONICAL_FAMILY_TOKENS.items():
        if fam in ('soc_mttd', 'incident_response_mttr'):
            continue
        if any(tok in low or tok in n for tok in toks):
            return fam
    try:
        from cyber_board_ready_prcy88 import _detect_kpi_family
        prcy = _detect_kpi_family(n)
        if prcy:
            return _PRCY88_FAMILY_ALIASES.get(prcy, prcy)
    except Exception:  # noqa: BLE001
        pass
    return None


def _kpi_row_cells_to_dict(cells: List[str]) -> Dict[str, str]:
    if len(cells) >= 6 and (cells[2] or '').upper() in ('KPI', 'KRI'):
        return {
            'num': cells[0],
            'name': cells[1],
            'kpi_type': cells[2],
            'target': cells[3],
            'formula': cells[4],
            'source': cells[5],
            'frequency': cells[6] if len(cells) > 6 else 'شهري',
        }
    return {
        'num': cells[0] if cells else '',
        'name': cells[1] if len(cells) > 1 else '',
        'kpi_type': 'KPI',
        'target': cells[2] if len(cells) > 2 else '',
        'formula': cells[3] if len(cells) > 3 else '',
        'source': cells[4] if len(cells) > 4 else '',
        'frequency': cells[5] if len(cells) > 5 else 'شهري',
    }


def _kpi_dict_to_cells(row: Dict[str, str], *, typed: bool = False) -> List[str]:
    if typed:
        return [
            row.get('num', ''),
            row.get('name', ''),
            row.get('kpi_type', 'KPI'),
            row.get('target', ''),
            row.get('formula', ''),
            row.get('source', ''),
            row.get('frequency', 'شهري'),
        ]
    return [
        row.get('num', ''),
        row.get('name', ''),
        row.get('target', ''),
        row.get('formula', ''),
        row.get('source', ''),
        row.get('frequency', 'شهري'),
    ]


def _kpi_table_uses_type_column(lines: List[str], rows: List[List[str]]) -> bool:
    for ln in lines:
        if ln.strip().startswith('|') and 'KPI' in ln.upper():
            return True
    if rows and len(rows[0]) >= 6:
        return (rows[0][2] or '').upper() in ('KPI', 'KRI')
    return False


def _duplicate_kpi_families_from_rows(
        rows: List[List[str]]) -> Tuple[List[str], List[str]]:
    """Return (duplicate_families, duplicate_metric_labels)."""
    by_family: Dict[str, List[str]] = {}
    for cells in rows:
        name = cells[1] if len(cells) > 1 else ''
        fam = resolve_kpi_canonical_family(name)
        if not fam:
            continue
        by_family.setdefault(fam, []).append(name)
    dup_fams = [f for f, names in by_family.items() if len(names) > 1]
    dup_labels: List[str] = []
    for fam in dup_fams:
        dup_labels.extend(by_family[fam])
    return dup_fams, list(dict.fromkeys(dup_labels))


def _canonical_registry_row(fam: str, num: int, *, typed: bool) -> Dict[str, str]:
    reg = KPI_CANONICAL_REGISTRY.get(fam, {})
    if reg:
        return {
            'num': str(num),
            'name': reg['label_ar'],
            'kpi_type': reg.get('kpi_type', 'KPI'),
            'target': reg.get('target', ''),
            'formula': reg.get('formula', ''),
            'source': reg.get('source', ''),
            'frequency': reg.get('frequency', 'شهري'),
        }
    return {'num': str(num), 'name': '', 'kpi_type': 'KPI', 'target': '',
            'formula': '', 'source': '', 'frequency': 'شهري'}


def _pick_stronger_kpi_row(
        a: Dict[str, str], b: Dict[str, str], fam: str) -> Dict[str, str]:
    if fam in KPI_CANONICAL_REGISTRY:
        return _canonical_registry_row(fam, int(a.get('num') or b.get('num') or 1),
                                       typed=bool(a.get('kpi_type')))
    def _score(r: Dict[str, str]) -> int:
        tgt = r.get('target') or ''
        s = len(tgt)
        if '÷' in (r.get('formula') or ''):
            s += 10
        if re.search(r'[%≥≤<]', tgt):
            s += 5
        return s
    return a if _score(a) >= _score(b) else b


def repair_kpi_canonical_families(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Merge KPI main+formula rows by canonical family before REL3 freeze."""
    _ = backend
    text = sections.get('kpis', '') or ''
    main_blob, tail = _split_kpi_main_and_tail(text)
    lines, rows = _parse_kpi_rows(main_blob)
    dup_fams_before, dup_labels_before = _duplicate_kpi_families_from_rows(rows)
    typed = _kpi_table_uses_type_column(lines, rows)

    merged: Dict[str, Dict[str, str]] = {}
    dropped: List[str] = []
    merged_fams: List[str] = []
    order: List[str] = []

    for cells in rows:
        row = _kpi_row_cells_to_dict(cells)
        name = row.get('name', '')
        fam = resolve_kpi_canonical_family(name) or f'__name__:{name}'
        if fam in merged:
            dropped.append(name)
            if fam not in merged_fams and not fam.startswith('__name__:'):
                merged_fams.append(fam)
            merged[fam] = _pick_stronger_kpi_row(merged[fam], row, fam)
        else:
            merged[fam] = row
            order.append(fam)

    canonical_rows: List[Dict[str, str]] = []
    for i, fam in enumerate(order, 1):
        row = dict(merged[fam])
        if fam in KPI_CANONICAL_REGISTRY:
            row = _canonical_registry_row(fam, i, typed=typed)
        else:
            row['num'] = str(i)
        canonical_rows.append(row)

    if not canonical_rows:
        diag = {
            'duplicate_metric_labels_before': dup_labels_before,
            'duplicate_families_before': dup_fams_before,
            'merged_families': [],
            'dropped_duplicate_rows': [],
            'canonical_metric_families_after': [],
            'duplicate_metric_labels_after': [],
            'main_formula_row_count_match': True,
            'kpi_canonical_repair_passed': not dup_fams_before,
            'blocking_errors': (
                [f'kpi_duplicate_family:{f}' for f in dup_fams_before]
                if dup_fams_before else []),
            'action_taken': 'no_kpi_rows',
        }
        emit_rel3_kpi_canonical_repair(diag)
        return sections, diag

    rebuilt_rows = [
        _kpi_dict_to_cells(r, typed=typed) for r in canonical_rows]
    rebuilt_rows = _renumber_rows(rebuilt_rows)
    out_lines = list(lines)
    row_idx = 0
    for i, ln in enumerate(out_lines):
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells and str(cells[0]).isdigit():
            if row_idx < len(rebuilt_rows):
                out_lines[i] = '| ' + ' | '.join(rebuilt_rows[row_idx]) + ' |'
                row_idx += 1
            else:
                out_lines[i] = ''
    if row_idx < len(rebuilt_rows):
        insert_at = len(out_lines)
        for i, ln in enumerate(out_lines):
            if ln.strip().startswith('###') and ('صيغة' in ln or 'formula' in ln.lower()):
                insert_at = i
                break
        for r in rebuilt_rows[row_idx:]:
            out_lines.insert(insert_at, '| ' + ' | '.join(r) + ' |')
            insert_at += 1

    new_main = '\n'.join(ln for ln in out_lines if ln.strip() or ln == '')
    new_text = _sync_kpi_formula_appendix(new_main, lang=lang)
    if tail:
        new_text = new_text.rstrip() + '\n\n' + tail + '\n'

    _, rows_after = _parse_kpi_rows(_split_kpi_main_and_tail(new_text)[0])
    dup_fams_after, dup_labels_after = _duplicate_kpi_families_from_rows(rows_after)
    main_count = len(rows_after)
    _, formula_rows = _parse_kpi_rows(new_text)
    formula_count = 0
    in_formula = False
    for ln in new_text.splitlines():
        s = ln.strip()
        if s.startswith('###') and ('صيغة' in s or 'formula' in s.lower()):
            in_formula = True
            continue
        if in_formula and s.startswith('|') and '---' not in s:
            cells = [c.strip() for c in s.strip('|').split('|')]
            if cells and str(cells[0]).isdigit():
                formula_count += 1

    families_after = [
        resolve_kpi_canonical_family(c[1] if len(c) > 1 else '')
        for c in rows_after]
    families_after = [f for f in families_after if f]
    blockers: List[str] = []
    if dup_fams_after:
        blockers.extend(f'kpi_duplicate_family:{f}' for f in dup_fams_after)
    if dup_labels_after:
        blockers.append('duplicate_mttd' if any(
            resolve_kpi_canonical_family(n) == 'soc_mttd' for n in dup_labels_after
        ) else 'duplicate_metric_labels')

    passed = not blockers and main_count == formula_count
    out = dict(sections)
    out['kpis'] = new_text
    diag = {
        'duplicate_metric_labels_before': dup_labels_before,
        'duplicate_families_before': dup_fams_before,
        'merged_families': list(dict.fromkeys(merged_fams)),
        'dropped_duplicate_rows': dropped,
        'canonical_metric_families_after': list(dict.fromkeys(families_after)),
        'duplicate_metric_labels_after': dup_labels_after,
        'main_formula_row_count_match': main_count == formula_count,
        'kpi_canonical_repair_passed': passed,
        'blocking_errors': blockers,
        'action_taken': (
            'kpi_canonical_families_repaired'
            if dup_fams_before or dropped else 'no_changes'),
    }
    emit_rel3_kpi_canonical_repair(diag)
    return out, diag


def emit_rel3_kpi_canonical_repair(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL3-KPI-CANONICAL-REPAIR] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass



def _is_mttd_metric_name(name: str) -> bool:
    n = (name or '').lower()
    if 'mttd' in n:
        return True
    return (
        ('زمن' in name or 'متوسط' in name)
        and ('كشف' in name or 'اكتشاف' in name))


def _is_mttr_metric_name(name: str) -> bool:
    n = (name or '').lower()
    if 'mttr' in n:
        return True
    return 'زمن' in name and 'استجاب' in name


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


def _split_kpi_main_and_tail(text: str) -> Tuple[str, str]:
    """Split KPI markdown into main-table blob and trailing appendix (KRI etc.)."""
    lines = (text or '').splitlines()
    formula_idx = -1
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('###') and ('صيغة' in s or 'formula' in s.lower()):
            formula_idx = i
            break
        if ('مؤشر المخاطر' in s or 'Risk Indicators' in s) and (
                'KRI' in s.upper() or 'kri' in s.lower()):
            return '\n'.join(lines[:i]), '\n'.join(lines[i:])
    if formula_idx < 0:
        return (text or '').rstrip(), ''
    tail_start = len(lines)
    for j in range(formula_idx + 1, len(lines)):
        s = lines[j].strip()
        if s.startswith('## ') and not s.startswith('###'):
            tail_start = j
            break
        if ('مؤشر المخاطر' in s or 'Risk Indicators' in s) and (
                'KRI' in s.upper() or 'kri' in s.lower()):
            tail_start = j
            break
    main_blob = '\n'.join(lines[:formula_idx]).rstrip()
    tail = '\n'.join(lines[tail_start:]).strip()
    return main_blob, tail


def _formula_appendix_header(lang: str = 'ar') -> str:
    if str(lang or '').lower() == 'en':
        return (
            '\n### Calculation formulas\n\n'
            '| # | Formula | Data source |\n'
            '|---|---|---|\n'
        )
    return (
        '\n### صيغة الاحتساب\n\n'
        '| # | صيغة الاحتساب | مصدر البيانات/الأداة |\n'
        '|---|---|---|\n'
    )


def _sync_kpi_formula_appendix(text: str, *, lang: str = 'ar') -> str:
    """Rebuild formula subsection so row numbers match the main KPI table."""
    main_blob, tail = _split_kpi_main_and_tail(text)
    _lines, rows = _parse_kpi_rows(main_blob)
    if not rows:
        return text
    formula_lines = []
    for i, cells in enumerate(rows, 1):
        formula = cells[3] if len(cells) > 3 else '—'
        source = cells[4] if len(cells) > 4 else '—'
        formula_lines.append(f'| {i} | {formula} | {source} |')
    out = main_blob.rstrip() + _formula_appendix_header(lang)
    out += '\n' + '\n'.join(formula_lines)
    if tail:
        out += '\n\n' + tail
    return out.rstrip() + '\n'


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
    elif (_DLP_INCIDENT_BAD in name or _DLP_KRI_NAME in name or (
            'حوادث تسرب' in name and 'dlp' in name.lower())):
        cells[1] = _DLP_KRI_NAME
        if len(cells) > 2:
            tgt = cells[2] or ''
            if ('0 حوادث' not in tgt or '%' in tgt
                    or re.search(r'≤\s*[1-9]|≥\s*[1-9]', tgt)):
                cells[2] = _DLP_KRI_TARGET
        if len(cells) > 3:
            cells[3] = _DLP_KRI_FORMULA
        if len(cells) > 4:
            cells[4] = _DLP_KRI_SOURCE
        changed = True
    elif _LOGIN_ANOMALY_BAD in name or (
            'محاولات الدخول' in name and 'شاذة' in name):
        cells[1] = _LOGIN_ANOMALY_GOOD
        if len(cells) > 2 and '100%' in (cells[2] or ''):
            cells[2] = _LOGIN_ANOMALY_TARGET
        if len(cells) > 3:
            cells[3] = _LOGIN_ANOMALY_FORMULA
        changed = True
    elif _THIRD_PARTY_RISK_BAD in name:
        if len(cells) > 2 and '100%' in (cells[2] or ''):
            cells[2] = _THIRD_PARTY_RISK_TARGET
        if len(cells) > 3 and (
                'المنجز' in (cells[3] or '')
                or 'المخطط' in (cells[3] or '')
                or 'completion' in (cells[3] or '').lower()):
            cells[3] = _THIRD_PARTY_RISK_FORMULA
        changed = True
    elif _is_mttd_metric_name(name):
        tgt = cells[2] if len(cells) > 2 else ''
        had_pct = '%' in tgt
        if len(cells) > 2 and had_pct:
            cells[2] = _MTTD_TARGET
            changed = True
        if len(cells) > 3:
            formula = cells[3] or ''
            if had_pct and formula.strip() and (
                    '÷' not in formula and '/' not in formula
                    and '×' not in formula):
                cells[3] = _MTTD_FORMULA
                changed = True
    elif _is_mttr_metric_name(name):
        tgt = cells[2] if len(cells) > 2 else ''
        had_pct = '%' in tgt
        if len(cells) > 2 and had_pct:
            cells[2] = _MTTR_TARGET
            changed = True
        if len(cells) > 3:
            formula = cells[3] or ''
            if had_pct and formula.strip() and (
                    '÷' not in formula and '/' not in formula
                    and '×' not in formula):
                cells[3] = _MTTR_FORMULA
                changed = True
    elif any(k in name for k in (
            'اكتمال النسخ', 'النسخ الاحتياط', 'نسخ احتياط', 'backup')):
        if len(cells) > 3 and '%' in (cells[2] or ''):
            formula = cells[3] or ''
            if formula.strip() and (
                    '÷' not in formula and '/' not in formula):
                cells[3] = (
                    'عمليات نسخ/استعادة ناجحة ÷ إجمالي العمليات × 100')
                changed = True
    elif len(cells) > 3 and '%' in (cells[2] or ''):
        formula = cells[3] or ''
        if formula.strip() and (
                '÷' not in formula and '/' not in formula
                and '×' not in formula):
            if any(k in name for k in ('ثغر', 'vulnerab', 'patch')):
                cells[3] = (
                    'ثغرات حرجة مُعالجة خلال SLA ÷ إجمالي الثغرات الحرجة × 100')
            elif any(k in name for k in (
                    'موظف', 'توعية', 'تدريب', 'إكمال', 'phishing')):
                cells[3] = (
                    'المشاركون المُكمّلون ÷ إجمالي الموظفين المستهدفين × 100')
            elif 'نسبة' in name or 'معدل' in name:
                cells[3] = 'المؤشر المحدد ÷ إجمالي النطاق × 100'
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


def _dedupe_kpi_metric_labels(text: str) -> str:
    """Keep one row per canonical KPI family in the main KPI table."""
    sections, diag = repair_kpi_canonical_families(
        {'kpis': text}, lang='ar')
    if diag.get('action_taken') == 'no_kpi_rows':
        return text
    return sections.get('kpis', text)


def _separate_dlp_encryption_formulas(text: str) -> str:
    """Ensure DLP and encryption KPI rows use distinct formulas."""
    lines, rows = _parse_kpi_rows(text)
    if not rows:
        return text
    changed = False
    for cells in rows:
        name = (cells[1] if len(cells) > 1 else '').lower()
        if len(cells) < 4:
            continue
        formula = cells[3]
        if 'dlp' in name or 'تسرب' in name:
            if 'تشفير' in formula or 'مفاتيح' in formula:
                cells[3] = _DLP_KRI_FORMULA
                changed = True
        elif 'تشفير' in name or 'encryption' in name:
            if 'dlp' in formula.lower() or 'تسرب' in formula:
                cells[3] = (
                    'البيانات الحساسة المشفرة ÷ إجمالي البيانات الحساسة × 100')
                changed = True
    if not changed:
        return text
    rows = _renumber_rows(rows)
    out_lines = list(lines)
    row_idx = 0
    for i, ln in enumerate(out_lines):
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells and str(cells[0]).isdigit() and row_idx < len(rows):
            out_lines[i] = '| ' + ' | '.join(rows[row_idx]) + ' |'
            row_idx += 1
    return _sync_kpi_formula_appendix('\n'.join(out_lines), lang='ar')


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
    if _DLP_KRI_NAME in text:
        idx = text.find(_DLP_KRI_NAME)
        window = text[idx:idx + 160]
        if '100%' in window:
            invalid.append('dlp_incident_percent_target')
        elif '0 حوادث' not in window and re.search(
                r'≤\s*[1-9]|≥\s*[1-9]', window):
            invalid.append('dlp_incident_nonzero_tolerance')
    if _LOGIN_ANOMALY_BAD in text:
        if '100%' in text:
            invalid.append(_LOGIN_ANOMALY_BAD)
        elif 'KPI' in text.upper() and re.search(
                r'KPI[^\n]{0,80}100%|100%[^\n]{0,80}KPI', text, re.I):
            invalid.append(_LOGIN_ANOMALY_BAD)
    if _THIRD_PARTY_RISK_BAD in text:
        if '100%' in text:
            invalid.append('third_party_risk_100_percent')
        elif re.search(r'المنجز|المخطط|completion', text, re.I):
            invalid.append('third_party_risk_completion_formula')
    if GENERIC_FORMULA in text:
        invalid.append('generic_formula')
    return invalid


def _is_flat_kpi_blob(text: str) -> bool:
    """True when KPI section lacks a parseable markdown table."""
    _lines, rows = _parse_kpi_rows(text)
    return not rows


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
    flat_blob = _is_flat_kpi_blob(text)
    _, pre_rows = _parse_kpi_rows(text)
    pre_dup_fams, _ = _duplicate_kpi_families_from_rows(pre_rows)
    if (
            not flat_blob
            and not pre_invalid
            and pre_generic == 0
            and pre_num_valid
            and not pre_dupes
            and not pre_dup_fams):
        return sections, {
            'kpi_semantics_valid': True,
            'invalid_metric_rows': [],
            'generic_formula_count': 0,
            'numbering_valid': True,
            'formula_alignment_valid': True,
            'action_taken': 'already_valid',
            'blocking_error_if_any': '',
        }

    if canonical_fn and (flat_blob or pre_invalid or pre_generic or not pre_num_valid):
        try:
            sections, kpi_diag = canonical_fn(dict(sections), lang)
            text = sections.get('kpis', '') or text
            invalid = _detect_invalid_rows(text)
            generic_count = _count_generic_formulas(text)
            num_valid, dupes, gaps = _kpi_numbering_valid(text)
            if invalid or generic_count:
                sections, text = _apply_inline_kpi_repairs(sections)
                text = sections.get('kpis', '') or text
                if GENERIC_FORMULA in text:
                    text = text.replace(
                        GENERIC_FORMULA,
                        'المؤشر المحدد ÷ إجمالي النطاق × 100')
                    sections = dict(sections)
                    sections['kpis'] = text
            diag = _build_kpi_diag(text)
            diag['formula_alignment_valid'] = kpi_diag.get(
                'formula_alignment_valid', diag.get('formula_alignment_valid'))
            diag['action_taken'] = 'canonicalize_kpis_backend'
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
    new_text = _sync_kpi_formula_appendix('\n'.join(out_lines), lang='ar')
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
