"""REL3.2 — deterministic KPI Assessment Guidelines builder/repair."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from release_engine.kpi_model import (
    _parse_kpi_rows,
    resolve_kpi_canonical_family,
)
from release_engine_v3.rel32_registries import (
    KPI_CANONICAL_REGISTRY_FULL,
    REL32_CANONICAL_HEADINGS,
)

_GUIDE_HEADING_AR = '### أدلة تقييم مؤشرات الأداء'
_GUIDE_HEADING_EN = '### KPI Assessment Guidelines'

_PER_KPI_GUIDE_RE = re.compile(
    r'(?:KPI\s*#?\d+\s*Assessment Guide|دليل\s+تقييم\s+المؤشر\s+رقم\s*\d+)',
    re.IGNORECASE,
)
_GUIDE_SECTION_RE = re.compile(
    r'###\s*(?:KPI Assessment Guidelines|أدلة\s+تقييم\s+مؤشرات\s+الأداء)',
    re.IGNORECASE,
)
_ASSESSMENT_TABLE_HDR_RE = re.compile(
    r'\|\s*(?:المؤشر|KPI|Indicator)\s*\|[^\n]*(?:طريقة\s+التقييم|Assessment\s+Method)',
    re.IGNORECASE,
)

_KPI_ASSESSMENT_DEFAULTS: Dict[str, Dict[str, str]] = {
    'governance_maturity': {
        'method_ar': 'مراجعة اعتماد السياسات وسجلات الحوكمة',
        'evidence_ar': 'سجل السياسات المعتمدة ومحاضر اللجان',
        'interpret_ar': '≥ 90% يدل على نضج حوكمة مستدام',
    },
    'ecc_dcc_compliance': {
        'method_ar': 'تدقيق بنود ECC/DCC مقابل الأدلة',
        'evidence_ar': 'مصفوفة الامتثال ونتائج التقييم',
        'interpret_ar': '≥ 90% يحقق الحد الأدنى التنظيمي',
    },
    'iam_pam_mfa': {
        'method_ar': 'فحص تغطية MFA/PAM على الأنظمة الحرجة',
        'evidence_ar': 'تقارير IAM وقوائم الحسابات المميزة',
        'interpret_ar': '≥ 95% يقلل مخاطر الوصول غير المصرح',
    },
    'soc_mttd': {
        'method_ar': 'استخراج أوقات الكشف من SIEM/SOC',
        'evidence_ar': 'سجلات التنبيهات وتذاكر الحوادث',
        'interpret_ar': '≤ 15 دقيقة يدل على كشف فعّال',
    },
    'mttd_detection': {
        'method_ar': 'استخراج أوقات الكشف من SIEM/SOC',
        'evidence_ar': 'سجلات التنبيهات وتذاكر الحوادث',
        'interpret_ar': '≤ 15 دقيقة يدل على كشف فعّال',
    },
    'incident_response_mttr': {
        'method_ar': 'قياس زمن الاحتواء من ITSM/SOAR',
        'evidence_ar': 'سجل الحوادث وخط زمن الاستجابة',
        'interpret_ar': '≤ 4 ساعات يحقق SLA الاستجابة',
    },
    'mttr_incident': {
        'method_ar': 'قياس زمن الاحتواء من ITSM/SOAR',
        'evidence_ar': 'سجل الحوادث وخط زمن الاستجابة',
        'interpret_ar': '≤ 4 ساعات يحقق SLA الاستجابة',
    },
    'vulnerability_sla': {
        'method_ar': 'مطابقة تواريخ المعالجة مع SLA الثغرات',
        'evidence_ar': 'تقارير إدارة الثغرات وسجل التصحيح',
        'interpret_ar': '≥ 95% يدل على التزام SLA',
    },
    'awareness_phishing': {
        'method_ar': 'تحليل نتائج التوعية ومحاكاة التصيد',
        'evidence_ar': 'تقارير LMS ونتائج Phishing Simulation',
        'interpret_ar': '≥ 85% يدل على وعي فعّال',
    },
    'backup_dr': {
        'method_ar': 'مراجعة سجلات النسخ والاستعادة',
        'evidence_ar': 'سجلات النسخ الاحتياطي واختبارات DR',
        'interpret_ar': '≥ 99% يضمن جاهزية التعافي',
    },
    'backup_restore': {
        'method_ar': 'مراجعة سجلات النسخ والاستعادة',
        'evidence_ar': 'سجلات النسخ الاحتياطي واختبارات DR',
        'interpret_ar': '≥ 99% يضمن جاهزية التعافي',
    },
    'data_classification': {
        'method_ar': 'حصر البيانات الحساسة وحالة التصنيف',
        'evidence_ar': 'سجل التصنيف وجرد البيانات',
        'interpret_ar': '≥ 90% يقلل مخاطر التسرب',
    },
    'encryption': {
        'method_ar': 'التحقق من تشفير الأصول الحساسة',
        'evidence_ar': 'تقارير التشفير وإدارة المفاتيح',
        'interpret_ar': '≥ 95% يحقق حماية البيانات',
    },
    'encryption_coverage': {
        'method_ar': 'التحقق من تشفير الأصول الحساسة',
        'evidence_ar': 'تقارير التشفير وإدارة المفاتيح',
        'interpret_ar': '≥ 95% يحقق حماية البيانات',
    },
    'dlp': {
        'method_ar': 'مراجعة قواعد DLP وتغطية البيانات',
        'evidence_ar': 'تقارير DLP وسجل الحوادث',
        'interpret_ar': '≥ 90% يمنع تسرب البيانات',
    },
    'dlp_coverage': {
        'method_ar': 'مراجعة قواعد DLP وتغطية البيانات',
        'evidence_ar': 'تقارير DLP وسجل الحوادث',
        'interpret_ar': '≥ 90% يمنع تسرب البيانات',
    },
    'governance': {
        'method_ar': 'مراجعة مؤشرات الحوكمة والسياسات',
        'evidence_ar': 'سجلات الحوكمة والامتثال',
        'interpret_ar': 'تحقيق الهدف يدل على نضج الحوكمة',
    },
    'compliance': {
        'method_ar': 'تقييم الامتثال للأطر المرجعية',
        'evidence_ar': 'مصفوفة الامتثال والمراجعات',
        'interpret_ar': 'تحقيق الهدف يحقق الحد التنظيمي',
    },
    'third_party_risk': {
        'method_ar': 'تقييم أمن موردي الأطراف الثالثة',
        'evidence_ar': 'استبيانات الموردين وسجل المخاطر',
        'interpret_ar': 'تحقيق الهدف يقلل مخاطر سلسلة التوريد',
    },
}

_GENERIC_DEFAULTS = {
    'method_ar': 'جمع البيانات من المصدر المحدد وتطبيق صيغة الاحتساب',
    'evidence_ar': 'سجلات النظام المصدر وتقرير القياس المعتمد',
    'interpret_ar': 'تحقيق الحد المستهدف يدل على أداء مقبول',
    'method_en': 'Collect data from the defined source and apply the formula',
    'evidence_en': 'Source system logs and signed measurement report',
    'interpret_en': 'Meeting the target indicates acceptable performance',
}


def kpi_assessment_guides_present(kpis_text: str) -> bool:
    blob = kpis_text or ''
    if _PER_KPI_GUIDE_RE.search(blob):
        return True
    if _GUIDE_SECTION_RE.search(blob) and _ASSESSMENT_TABLE_HDR_RE.search(blob):
        return True
    return False


def _defaults_for_family(fam: str, lang: str) -> Dict[str, str]:
    spec = dict(_KPI_ASSESSMENT_DEFAULTS.get(fam) or _GENERIC_DEFAULTS)
    if lang != 'ar':
        return {
            'method': spec.get('method_en', spec.get('method_ar', '')),
            'evidence': spec.get('evidence_en', spec.get('evidence_ar', '')),
            'interpret': spec.get(
                'interpret_en', spec.get('interpret_ar', '')),
        }
    return {
        'method': spec.get('method_ar', ''),
        'evidence': spec.get('evidence_ar', ''),
        'interpret': spec.get('interpret_ar', ''),
    }


def _kpi_rows_from_section(kpis_text: str) -> List[Dict[str, str]]:
    main_blob = (kpis_text or '').split('###')[0]
    _lines, rows = _parse_kpi_rows(main_blob)
    out: List[Dict[str, str]] = []
    for idx, cells in enumerate(rows, 1):
        if len(cells) < 2:
            continue
        num = (cells[0] or str(idx)).strip()
        name = cells[1].strip()
        if not name or name.lower() in ('kpi', 'المؤشر', '#', 'وصف المؤشر'):
            continue
        fam = resolve_kpi_canonical_family(name) or ''
        if len(cells) >= 6 and (cells[2] or '').upper() in ('KPI', 'KRI'):
            target = cells[3] if len(cells) > 3 else ''
            formula = cells[4] if len(cells) > 4 else ''
            source = cells[5] if len(cells) > 5 else ''
            frequency = cells[6] if len(cells) > 6 else 'شهري'
            owner = cells[7] if len(cells) > 7 else 'CISO'
        else:
            target = cells[2] if len(cells) > 2 else ''
            formula = cells[3] if len(cells) > 3 else ''
            source = cells[4] if len(cells) > 4 else ''
            frequency = cells[5] if len(cells) > 5 else 'شهري'
            owner = 'CISO'
        if not fam:
            for kf, reg in KPI_CANONICAL_REGISTRY_FULL.items():
                if reg.get('label_ar', '') == name:
                    fam = kf
                    break
        out.append({
            'num': num,
            'name': name,
            'family': fam,
            'target': target,
            'formula': formula,
            'source': source,
            'frequency': frequency,
            'owner': owner,
        })
    if out:
        return out
    order = list(KPI_CANONICAL_REGISTRY_FULL.keys())
    for i, fam in enumerate(order, 1):
        reg = KPI_CANONICAL_REGISTRY_FULL[fam]
        out.append({
            'num': str(i),
            'name': reg['label_ar'],
            'family': fam,
            'target': reg.get('target', ''),
            'formula': reg.get('formula', ''),
            'source': reg.get('source', ''),
            'frequency': reg.get('frequency', 'شهري'),
            'owner': reg.get('owner', 'CISO'),
        })
    return out


def _strip_existing_guides_section(kpis_text: str) -> str:
    blob = kpis_text or ''
    m = _GUIDE_SECTION_RE.search(blob)
    if not m:
        return blob.rstrip()
    return blob[:m.start()].rstrip()


def _build_consolidated_guides_table(
        rows: List[Dict[str, str]], *, lang: str) -> str:
    parts: List[str] = []
    heading = _GUIDE_HEADING_AR if lang == 'ar' else _GUIDE_HEADING_EN
    parts.append('')
    parts.append(heading)
    parts.append('')
    if lang == 'ar':
        parts.append(
            '| المؤشر | طريقة التقييم | صيغة الاحتساب | مصدر البيانات | '
            'دورية القياس | المالك | الحد المستهدف | دليل القبول | '
            'تفسير النتيجة |')
    else:
        parts.append(
            '| KPI | Assessment Method | Formula | Data Source | '
            'Frequency | Owner | Target | Evidence Required | '
            'Result Interpretation |')
    parts.append('|---|---|---|---|---|---|---|---|---|')
    seen_fams: Set[str] = set()
    for row in rows:
        fam = row.get('family') or ''
        if fam and fam in seen_fams:
            continue
        if fam:
            seen_fams.add(fam)
        defs = _defaults_for_family(fam, lang)
        parts.append(
            f'| {row["name"]} | {defs["method"]} | {row["formula"]} | '
            f'{row["source"]} | {row["frequency"]} | {row["owner"]} | '
            f'{row["target"]} | {defs["evidence"]} | {defs["interpret"]} |')
    return '\n'.join(parts) + '\n'


def _build_per_kpi_guide_blocks(
        rows: List[Dict[str, str]], *, lang: str) -> str:
    parts: List[str] = []
    for row in rows:
        num = row['num']
        name = row['name']
        if lang == 'ar':
            parts.append(f'#### دليل تقييم المؤشر رقم {num}: {name}')
            parts.append(
                '| الخطوة | الإجراء | الأداة/النظام | المسؤول | المخرج |')
            parts.append('|---|---|---|---|---|')
            defs = _defaults_for_family(row.get('family') or '', lang)
            parts.append(
                f'| 1 | {defs["method"]} | {row["source"]} | '
                f'{row["owner"]} | {defs["evidence"]} |')
            parts.append(
                f'| 2 | تطبيق صيغة الاحتساب: {row["formula"]} | '
                f'{row["source"]} | {row["owner"]} | قيمة المؤشر |')
            parts.append(
                f'| 3 | {defs["interpret"]} | — | {row["owner"]} | '
                f'تقرير التقييم |')
        else:
            parts.append(f'#### KPI #{num} Assessment Guide: {name}')
            parts.append(
                '| Step | Action | Tool/System | Owner | Output |')
            parts.append('|---|---|---|---|---|')
            defs = _defaults_for_family(row.get('family') or '', lang)
            parts.append(
                f'| 1 | {defs["method"]} | {row["source"]} | '
                f'{row["owner"]} | {defs["evidence"]} |')
            parts.append(
                f'| 2 | Apply formula: {row["formula"]} | '
                f'{row["source"]} | {row["owner"]} | KPI value |')
            parts.append(
                f'| 3 | {defs["interpret"]} | — | {row["owner"]} | '
                f'Assessment report |')
        parts.append('')
    return '\n'.join(parts)


def build_kpi_assessment_guides_block(
        kpi_rows: List[Dict[str, str]], *, lang: str = 'ar') -> str:
    if not kpi_rows:
        kpi_rows = _kpi_rows_from_section('')
    return (
        _build_consolidated_guides_table(kpi_rows, lang=lang)
        + _build_per_kpi_guide_blocks(kpi_rows, lang=lang)
    )


def repair_kpi_assessment_guides_in_kpis(
        kpis_text: str,
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Ensure KPI Assessment Guidelines exist; build from canonical KPI rows."""
    _ = backend
    lang_n = 'ar' if str(lang or '').lower() == 'ar' else 'en'
    blob = kpis_text or ''
    present_before = kpi_assessment_guides_present(blob)
    kpi_rows = _kpi_rows_from_section(blob)
    guide_rows_before = len(_PER_KPI_GUIDE_RE.findall(blob))
    required_fams = {
        r['family'] for r in kpi_rows if r.get('family')}
    missing_before = [
        f for f in required_fams
        if f and f not in _families_covered_in_guides(blob, kpi_rows)]
    inserted = False
    out = blob
    consolidated_rows = _count_assessment_table_rows(blob)
    needs_repair = (
        not present_before
        or missing_before
        or (guide_rows_before < len(kpi_rows)
            and consolidated_rows < len(kpi_rows)))
    if needs_repair:
        base = _strip_existing_guides_section(blob)
        block = build_kpi_assessment_guides_block(kpi_rows, lang=lang_n)
        out = base.rstrip() + '\n' + block
        inserted = True
    guide_rows_after = len(_PER_KPI_GUIDE_RE.findall(out))
    missing_after = [
        f for f in required_fams
        if f and f not in _families_covered_in_guides(out, kpi_rows)]
    stale_cleared = (
        present_before is False or inserted) and not missing_after
    blocking = ''
    if not kpi_assessment_guides_present(out):
        blocking = 'kpi_assessment_guides_missing'
    diag = {
        'section_present_before': present_before,
        'section_present_after': kpi_assessment_guides_present(out),
        'kpi_rows_detected': len(kpi_rows),
        'guide_rows_before': guide_rows_before,
        'guide_rows_after': guide_rows_after,
        'missing_kpi_families_before': list(missing_before),
        'missing_kpi_families_after': list(missing_after),
        'inserted': inserted,
        'stale_issue_cleared': stale_cleared,
        'blocking_error_if_any': blocking,
    }
    return out, diag


def _count_assessment_table_rows(blob: str) -> int:
    m = _GUIDE_SECTION_RE.search(blob or '')
    if not m:
        return 0
    tail = (blob or '')[m.end():]
    count = 0
    in_table = False
    for ln in tail.splitlines():
        s = ln.strip()
        if not s:
            if in_table:
                break
            continue
        if s.startswith('|') and '---' not in s:
            if in_table and not any(
                    h in s for h in (
                        'المؤشر', 'KPI', 'Indicator', 'طريقة', 'Assessment')):
                count += 1
            elif not in_table and _ASSESSMENT_TABLE_HDR_RE.search(s):
                in_table = True
            continue
        if s.startswith('####') or s.startswith('###'):
            break
    return count


def _families_covered_in_guides(
        blob: str, kpi_rows: List[Dict[str, str]]) -> Set[str]:
    covered: Set[str] = set()
    for row in kpi_rows:
        name = row.get('name') or ''
        fam = row.get('family') or ''
        if name and name in blob:
            if fam:
                covered.add(fam)
        if fam and fam in (blob or ''):
            covered.add(fam)
    if _GUIDE_SECTION_RE.search(blob or ''):
        for row in kpi_rows:
            if row.get('name') and row['name'] in blob:
                if row.get('family'):
                    covered.add(row['family'])
    return covered


def repair_kpi_assessment_guides_for_sections(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = dict(sections or {})
    kpis, diag = repair_kpi_assessment_guides_in_kpis(
        out.get('kpis', '') or '', lang=lang, backend=backend)
    out['kpis'] = kpis
    emit_kpi_assessment_guides_repair_diag(diag)
    return out, diag


def refine_kpi_assessment_quality_issues(
        issues: List[str],
        repair_diag: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Drop stale ``kpi_assessment_guides_missing`` after deterministic repair."""
    repair_diag = repair_diag or {}
    refined = list(issues or [])
    if 'kpi_assessment_guides_missing' not in refined:
        return refined
    if repair_diag.get('section_present_after'):
        refined = [i for i in refined if i != 'kpi_assessment_guides_missing']
    elif repair_diag.get('stale_issue_cleared'):
        refined = [i for i in refined if i != 'kpi_assessment_guides_missing']
    return refined


def emit_kpi_assessment_guides_repair_diag(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[KPI-ASSESSMENT-GUIDES-REPAIR] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


_MANDATORY_REL32_SECTIONS: Tuple[Tuple[str, str, str], ...] = (
    ('vision', REL32_CANONICAL_HEADINGS['vision'], 'table'),
    ('pillars', REL32_CANONICAL_HEADINGS['pillars'], 'body'),
    ('environment', REL32_CANONICAL_HEADINGS['environment'], 'body'),
    ('gaps', REL32_CANONICAL_HEADINGS['gaps'], 'gap_table'),
    ('gaps', 'دليل تطبيق', 'gap_guides'),
    ('roadmap', REL32_CANONICAL_HEADINGS['roadmap'], 'table'),
    ('kpis', REL32_CANONICAL_HEADINGS['kpis'], 'kpi_table'),
    ('kpis', 'أدلة تقييم', 'kpi_guides'),
    ('confidence', REL32_CANONICAL_HEADINGS['confidence'], 'confidence'),
    ('confidence', 'المخاطر', 'risk_register'),
    ('governance', REL32_CANONICAL_HEADINGS['governance'], 'table'),
    ('traceability', REL32_CANONICAL_HEADINGS['traceability'], 'table'),
)


def evaluate_rel32_final_strategy_completeness(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Check all mandatory REL3.2 strategy sections/subsections are present."""
    secs = dict(sections or {})
    mandatory = [m[1] for m in _MANDATORY_REL32_SECTIONS]
    present_before: List[str] = []
    missing: List[str] = []
    for key, label, kind in _MANDATORY_REL32_SECTIONS:
        body = secs.get(key, '') or ''
        ok = False
        if kind == 'table':
            ok = label in body and '|' in body
        elif kind == 'body':
            ok = label in body and len(body.strip()) > 40
        elif kind == 'gap_table':
            ok = 'الفجوة' in body and '|' in body
        elif kind == 'gap_guides':
            ok = bool(re.search(
                r'دليل\s+تطبيق|Implementation Guide', body, re.I))
        elif kind == 'kpi_table':
            ok = label in body and '|' in body
        elif kind == 'kpi_guides':
            ok = kpi_assessment_guides_present(body)
        elif kind == 'confidence':
            ok = label in body and re.search(r'\d+\s*%', body)
        elif kind == 'risk_register':
            ok = 'المخاطر' in body and 'خطة المعالجة' in body
        token = f'{key}:{kind}'
        if ok:
            present_before.append(token)
        else:
            missing.append(token)
    complete = not missing
    return {
        'mandatory_sections': mandatory,
        'sections_present_before': present_before,
        'sections_inserted_or_repaired': [],
        'sections_present_after': present_before,
        'missing_sections_after': missing,
        'saved_content_complete': complete,
        'preview_complete': complete,
        'docx_complete': complete,
        'pdf_complete': complete,
        'blocking_errors': [] if complete else [
            f'rel32_mandatory_section_missing:{m}' for m in missing],
    }


def emit_rel32_final_strategy_completeness_diag(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL32-FINAL-STRATEGY-COMPLETENESS] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
