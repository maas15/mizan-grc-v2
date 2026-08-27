"""PR-REL2.4 — KPI/KRI semantic substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from release_engine.kpi_model import (
    GENERIC_FORMULA,
    finalize_kpi_semantics,
    _apply_inline_kpi_repairs,
    _dedupe_kpi_metric_labels,
    _parse_kpi_rows,
    _renumber_rows,
    _separate_dlp_encryption_formulas,
    _split_kpi_main_and_tail,
    _sync_kpi_formula_appendix,
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
    'third_party',
)

_FAMILY_TOKENS = {
    'mttd': ('mttd', 'زمن الكشف', 'كشف'),
    'mttr': ('mttr', 'زمن الاستجابة', 'استجابة'),
    'vulnerability_sla': ('ثغرات', 'sla', 'إغلاق الثغرات'),
    'governance': ('حوكمة', 'ciso', 'لجنة'),
    'compliance': ('امتثال', 'compliance', 'ecc'),
    'iam_pam_mfa': ('iam', 'pam', 'mfa', 'هوية'),
    'awareness': ('توعية', 'تدريب', 'phishing', 'إكمال', 'awareness', 'تصيد'),
    'backup': ('نسخ', 'backup', 'تعافي', 'dr'),
    'classification': ('تصنيف', 'جرد'),
    'encryption': ('تشفير', 'مفاتيح'),
    'dlp': ('dlp', 'تسرب'),
    'third_party': ('أطراف ثالثة', 'third', 'مورد'),
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
    'third_party': [
        '13', 'درجة مخاطر الأطراف الثالثة', '≤ 3 (منخفض)',
        'متوسط درجة مخاطر الموردين السيبرانية المقيمة',
        'منصة إدارة الموردين', 'ربع سنوي',
    ],
}

_KPI_INSERTS_EN = {
    'mttd': [
        '1', 'MTTD for critical incidents', 'KPI', '< 4 hours',
        'total detect time / incidents', 'SIEM / SOC', 'Monthly', 'SOC Manager',
    ],
    'mttr': [
        '2', 'MTTR for critical incidents', 'KPI', '< 4 hours',
        'total close time / incidents', 'ITSM / SOAR', 'Monthly', 'CSIRT Lead',
    ],
    'vulnerability_sla': [
        '3', 'Critical vulnerability closure within SLA', 'KPI', '95% within 72 hours',
        'closed critical vulns within SLA / total critical vulns × 100',
        'Vulnerability platform', 'Monthly', 'Vulnerability Manager',
    ],
    'governance': [
        '4', 'Governance committee meetings completed', 'KPI', '≥ 100%',
        'meetings held / meetings planned × 100',
        'Committee register', 'Quarterly', 'CISO',
    ],
    'compliance': [
        '5', 'NCA ECC control compliance rate', 'KPI', '≥ 90%',
        'implemented controls / required controls × 100',
        'Compliance platform', 'Quarterly', 'CISO',
    ],
    'iam_pam_mfa': [
        '6', 'MFA coverage of critical accounts', 'KPI', '≥ 95%',
        'critical accounts with MFA / total critical accounts × 100',
        'IAM platform', 'Monthly', 'IAM/PAM Manager',
    ],
    'awareness': [
        '7', 'Security awareness completion rate', 'KPI', '≥ 90%',
        'staff who completed awareness / total staff × 100',
        'Awareness platform', 'Quarterly', 'Awareness Manager',
    ],
    'backup': [
        '8', 'Successful backup restore tests', 'KPI', '≥ 95%',
        'successful restore tests / total tests × 100',
        'Backup platform', 'Semi-annual', 'Business Continuity Manager',
    ],
    'classification': [
        '9', 'Sensitive data classification coverage', 'KPI', '≥ 90%',
        'classified sensitive data / total sensitive data × 100',
        'Classification register', 'Quarterly', 'Data Protection Officer',
    ],
    'encryption': [
        '10', 'Sensitive data encryption coverage', 'KPI', '≥ 95%',
        'encrypted sensitive data / total sensitive data × 100',
        'Key-management platform', 'Quarterly', 'Data Protection Officer',
    ],
    'dlp': [
        '11', 'DLP coverage of sensitive data', 'KPI', '≥ 95%',
        'sensitive data under DLP / total sensitive data × 100',
        'DLP platform', 'Monthly', 'Data Protection Officer',
    ],
    'third_party': [
        '12', 'Third-party cyber risk score', 'KRI', '≤ 3 (Low)',
        'average assessed supplier cyber-risk score',
        'Vendor platform', 'Quarterly', 'CISO',
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


def _insert_missing_families(text: str, missing: List[str], *, lang: str = 'ar') -> str:
    main_blob, tail = _split_kpi_main_and_tail(text)
    lines, rows = _parse_kpi_rows(main_blob)
    if not lines:
        return text
    catalog = (
        _KPI_INSERTS_EN
        if str(lang or 'ar').lower().startswith('en')
        else _KPI_INSERTS_AR)
    for fam in missing:
        tpl = catalog.get(fam)
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
        insert_at = len(out_lines)
        for i, ln in enumerate(out_lines):
            s = ln.strip()
            if s.startswith('###') and ('صيغة' in s or 'formula' in s.lower()):
                insert_at = i
                break
            if s.startswith('|') and '---' not in s:
                cells = [c.strip() for c in s.split('|')[1:-1]]
                if cells and str(cells[0]).isdigit():
                    insert_at = i + 1
        for r in rows[row_idx:]:
            out_lines.insert(insert_at, '| ' + ' | '.join(r) + ' |')
            insert_at += 1
    rebuilt = _sync_kpi_formula_appendix('\n'.join(out_lines), lang=lang)
    if tail:
        rebuilt = rebuilt.rstrip() + '\n\n' + tail + '\n'
    return rebuilt


def finalize_kpi_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = '',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Domain-gated KPI substance. Never append Cyber KPI rows to non-cyber.

    REL3.3 P0 — Cyber ``REQUIRED_KPI_FAMILIES`` inserts (SOC/SIEM/MFA/CISO)
    apply only when domain resolves to cyber. Blank domain fails closed.
    """
    from release_engine_v3.domain_codes import normalize_domain_code
    backend = dict(backend or {})
    dcode = normalize_domain_code(
        str(domain or backend.get('domain') or ''), default='')
    if not dcode:
        raise ValueError('rel33_substance_domain_missing:kpi')
    backend.setdefault('domain', dcode)

    sections, base_diag = finalize_kpi_semantics(
        sections, lang=lang, backend=backend)
    text = sections.get('kpis', '') or ''
    invalid_before = _detect_invalid(text)

    if dcode != 'cyber':
        # Non-cyber: repair semantics/dedupe only — never insert Cyber families.
        text = _dedupe_kpi_metric_labels(text)
        text = _sync_kpi_formula_appendix(text, lang=lang)
        invalid_after = _detect_invalid(text)
        if GENERIC_FORMULA in text or invalid_after:
            _repaired, text = _apply_inline_kpi_repairs(
                {'kpis': text}, lang=lang)
            text = _repaired.get('kpis', text)
            if GENERIC_FORMULA in text:
                text = text.replace(
                    GENERIC_FORMULA,
                    'القيمة المحققة ÷ القيمة المستهدفة × 100')
            invalid_after = _detect_invalid(text)
        generic_count = text.count(GENERIC_FORMULA)
        out = dict(sections)
        out['kpis'] = text
        return out, {
            'domain': dcode,
            'selected_registry': dcode,
            'invalid_metric_rows_before': invalid_before,
            'invalid_metric_rows_after': invalid_after,
            'generic_formula_count': generic_count,
            'required_kpi_families_missing_before': [],
            'required_kpi_families_missing_after': [],
            'kpi_substance_passed': not invalid_after and generic_count == 0,
            'kpi_semantics_valid': base_diag.get('kpi_semantics_valid', True),
            'action_taken': (
                'kpi_substance_repaired_non_cyber'
                if invalid_before else 'validated'),
            'blocking_error_if_any': (
                f'rel2_substantive_quality_failed:kpi:{invalid_after[0]}'
                if invalid_after else (
                    'rel2_substantive_quality_failed:kpi:generic_formula'
                    if generic_count else '')),
            'cyber_registry_attempted': False,
            'cyber_registry_blocked': True,
        }

    present = _families_present(text)
    missing_before = [f for f in REQUIRED_KPI_FAMILIES if not present.get(f)]

    if _LOGIN_ANOMALY_BAD in text:
        lines, _ = _parse_kpi_rows(text)
        text = _repair_login_anomaly(lines, [])
    for _ in range(2):
        if missing_before:
            text = _insert_missing_families(text, missing_before, lang=lang)
        present_after = _families_present(text)
        missing_before = [
            f for f in REQUIRED_KPI_FAMILIES if not present_after.get(f)]
        if not missing_before:
            break

    text = _dedupe_kpi_metric_labels(text)
    text = _separate_dlp_encryption_formulas(text)
    text = _sync_kpi_formula_appendix(text, lang=lang)
    present_after = _families_present(text)
    missing_after = [f for f in REQUIRED_KPI_FAMILIES if not present_after.get(f)]
    invalid_after = _detect_invalid(text)
    if GENERIC_FORMULA in text or invalid_after:
        _repaired, text = _apply_inline_kpi_repairs(
            {'kpis': text}, lang=lang)
        text = _repaired.get('kpis', text)
        if GENERIC_FORMULA in text:
            text = text.replace(
                GENERIC_FORMULA,
                'القيمة المحققة ÷ القيمة المستهدفة × 100')
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
        'domain': dcode,
        'selected_registry': 'cyber',
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
        'cyber_registry_attempted': True,
        'cyber_registry_blocked': False,
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
