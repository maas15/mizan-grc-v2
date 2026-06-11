"""PR-REL2.4 — KPI/KRI semantic substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from release_engine.kpi_model import (
    GENERIC_FORMULA,
    finalize_kpi_semantics,
    _parse_kpi_rows,
    _renumber_rows,
)

REQUIRED_KPI_FAMILIES = (
    'mttd',
    'mttr',
    'vulnerability_sla',
    'governance',
    'compliance',
    'iam_pam_mfa',
    'awareness',
    'backup',
    'classification',
    'encryption',
    'dlp',
)

_FAMILY_TOKENS = {
    'mttd': ('mttd', 'زمن الكشف', 'كشف'),
    'mttr': ('mttr', 'زمن الاستجابة', 'استجابة'),
    'vulnerability_sla': ('ثغرات', 'sla', 'إغلاق الثغرات'),
    'governance': ('حوكمة', 'ciso', 'لجنة'),
    'compliance': ('امتثال', 'compliance', 'ecc'),
    'iam_pam_mfa': ('iam', 'pam', 'mfa', 'هوية'),
    'awareness': ('توعية', 'تدريب', 'phishing'),
    'backup': ('نسخ', 'backup', 'تعافي', 'dr'),
    'classification': ('تصنيف', 'جرد'),
    'encryption': ('تشفير', 'مفاتيح'),
    'dlp': ('dlp', 'تسرب'),
}

_KPI_INSERTS_AR = {
    'mttd': [
        '1', 'متوسط زمن الكشف MTTD', '≤ 60 دقيقة',
        'زمن الكشف الفعلي ÷ عدد الحوادث المكتشفة',
        'SIEM/SOC', 'شهري',
    ],
    'mttr': [
        '2', 'متوسط زمن الاستجابة MTTR', '≤ 4 ساعات',
        'زمن الإغلاق الفعلي ÷ عدد الحوادث المغلقة',
        'ITSM/SOAR', 'شهري',
    ],
    'vulnerability_sla': [
        '4', 'نسبة إغلاق الثغرات الحرجة ضمن SLA', '95% خلال 72 ساعة',
        'عدد الثغرات الحرجة المغلقة ضمن SLA ÷ إجمالي الثغرات الحرجة × 100',
        'منصة إدارة الثغرات', 'شهري',
    ],
    'governance': [
        '5', 'نسبة اجتماعات لجنة الحوكمة المنفذة', '≥ 100%',
        'عدد اجتماعات اللجنة المنفذة ÷ الاجتماعات المخططة × 100',
        'سجل اللجنة', 'ربع سنوي',
    ],
    'compliance': [
        '6', 'نسبة امتثال ضوابط NCA ECC', '≥ 90%',
        'عدد الضوابط المطبقة ÷ إجمالي الضوابط المطلوبة × 100',
        'منصة الامتثال', 'ربع سنوي',
    ],
    'iam_pam_mfa': [
        '7', 'نسبة تغطية MFA للحسابات الحرجة', '≥ 95%',
        'الحسابات الحرجة المفعّل عليها MFA ÷ إجمالي الحسابات الحرجة × 100',
        'منصة IAM', 'شهري',
    ],
    'awareness': [
        '8', 'نسبة إكمال التوعية الأمنية', '≥ 90%',
        'عدد الموظفين المكملين للتوعية ÷ إجمالي الموظفين × 100',
        'منصة التوعية', 'ربع سنوي',
    ],
    'backup': [
        '9', 'نسبة نجاح اختبارات استعادة النسخ الاحتياطي', '≥ 95%',
        'اختبارات الاستعادة الناجحة ÷ إجمالي الاختبارات × 100',
        'منصة النسخ الاحتياطي', 'نصف سنوي',
    ],
    'classification': [
        '10', 'نسبة البيانات الحساسة المصنفة', '≥ 90%',
        'البيانات الحساسة المصنفة ÷ إجمالي البيانات الحساسة × 100',
        'سجل تصنيف البيانات', 'ربع سنوي',
    ],
    'encryption': [
        '11', 'نسبة البيانات الحساسة المشفرة', '≥ 95%',
        'البيانات الحساسة المشفرة ÷ إجمالي البيانات الحساسة × 100',
        'منصة إدارة المفاتيح', 'ربع سنوي',
    ],
    'dlp': [
        '12', 'نسبة تغطية DLP للبيانات الحساسة', '≥ 95%',
        'البيانات الحساسة المغطاة بضوابط DLP ÷ إجمالي البيانات الحساسة × 100',
        'منصة DLP', 'شهري',
    ],
}

_LOGIN_ANOMALY_BAD = 'نسبة محاولات الدخول الفاشلة الشاذة'


def _families_present(text: str) -> Dict[str, bool]:
    blob = (text or '').lower()
    return {
        fam: any(tok in blob for tok in toks)
        for fam, toks in _FAMILY_TOKENS.items()
    }


def _detect_invalid(text: str) -> List[str]:
    invalid = []
    if _LOGIN_ANOMALY_BAD in text:
        for ln in text.splitlines():
            if _LOGIN_ANOMALY_BAD in ln and '100%' in ln:
                invalid.append(_LOGIN_ANOMALY_BAD)
    if GENERIC_FORMULA in text:
        invalid.append('generic_formula')
    return invalid


def _repair_login_anomaly(lines: List[str], rows: List[List[str]]) -> str:
    out_lines = list(lines)
    for i, ln in enumerate(out_lines):
        if _LOGIN_ANOMALY_BAD in ln and '100%' in ln:
            out_lines[i] = ln.replace(
                '100%',
                '≥ 95% كشف ومراقبة').replace(
                _LOGIN_ANOMALY_BAD,
                'نسبة تغطية مراقبة محاولات الدخول الشاذة')
    return '\n'.join(out_lines)


def _insert_missing_families(text: str, missing: List[str]) -> str:
    lines, rows = _parse_kpi_rows(text)
    if not lines:
        return text
    for fam in missing:
        tpl = _KPI_INSERTS_AR.get(fam)
        if tpl:
            rows.append(tpl)
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
    if row_idx < len(rows):
        for r in rows[row_idx:]:
            out_lines.append('| ' + ' | '.join(r) + ' |')
    return '\n'.join(out_lines)


def finalize_kpi_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    sections, base_diag = finalize_kpi_semantics(
        sections, lang=lang, backend=backend)
    text = sections.get('kpis', '') or ''
    invalid_before = _detect_invalid(text)
    present = _families_present(text)
    missing_before = [f for f in REQUIRED_KPI_FAMILIES if not present.get(f)]

    if _LOGIN_ANOMALY_BAD in text:
        lines, _ = _parse_kpi_rows(text)
        text = _repair_login_anomaly(lines, [])
    for _ in range(2):
        if missing_before:
            text = _insert_missing_families(text, missing_before)
        present_after = _families_present(text)
        missing_before = [
            f for f in REQUIRED_KPI_FAMILIES if not present_after.get(f)]
        if not missing_before:
            break

    present_after = _families_present(text)
    missing_after = [f for f in REQUIRED_KPI_FAMILIES if not present_after.get(f)]
    invalid_after = _detect_invalid(text)
    generic_count = text.count(GENERIC_FORMULA)

    passed = not invalid_after and generic_count == 0 and not missing_after
    blocking = ''
    if invalid_after:
        blocking = f'rel2_substantive_quality_failed:kpi:{invalid_after[0]}'
    elif generic_count:
        blocking = 'rel2_substantive_quality_failed:kpi:generic_formula'
    elif missing_after:
        blocking = f'rel2_substantive_quality_failed:kpi:{missing_after[0]}'

    out = dict(sections)
    out['kpis'] = text
    diag = {
        'invalid_metric_rows_before': invalid_before,
        'invalid_metric_rows_after': invalid_after,
        'generic_formula_count': generic_count,
        'required_kpi_families_missing_before': missing_before,
        'required_kpi_families_missing_after': missing_after,
        'kpi_substance_passed': passed,
        'kpi_semantics_valid': base_diag.get('kpi_semantics_valid', True),
        'action_taken': (
            'kpi_substance_repaired'
            if invalid_before or missing_before else 'validated'),
        'blocking_error_if_any': blocking,
    }
    return out, diag


def emit_kpi_substance_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-KPI-SUBSTANCE-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
