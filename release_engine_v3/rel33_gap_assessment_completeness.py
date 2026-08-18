"""REL3.3 — deterministic gap assessment scope/remediation repair."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from release_engine_v3.rel33_document_gates import (
    audit_gap_assessment_sections,
    build_gate_routing_diag,
    emit_rel33_document_type_gate_routing,
    gap_assessment_gates_enabled,
    strategy_gates_enabled,
)


def _norm_frameworks(selected_frameworks: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for fw in selected_frameworks or []:
        s = str(fw or '').strip()
        if s and s not in out:
            out.append(s)
    return out


def _count_table_rows(text: str) -> int:
    n = 0
    for ln in (text or '').splitlines():
        if ln.strip().startswith('|') and '---' not in ln:
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if cells and cells[0] not in ('#', 'الفجوة', 'Gap', 'Framework'):
                if any(c and c not in ('—', '-') for c in cells):
                    n += 1
    return n


def repair_gap_assessment_sections(
        sections: Dict[str, str],
        *,
        selected_frameworks: Optional[List[str]] = None,
        domain: str = 'global',
        lang: str = 'ar',
) -> Dict[str, str]:
    """Build scope + remediation deterministically; preserve gap table."""
    out = dict(sections or {})
    out['_document_type'] = 'gap_assessment'
    fws = _norm_frameworks(selected_frameworks)
    fw_line = '، '.join(fws) if fws else 'ISO 27001، NIST CSF'
    scope = (out.get('scope') or '').strip()
    if not scope:
        scope = (
            f'## النطاق\n\n'
            f'تقييم الفجوات للأطر: {fw_line}.\n\n'
            f'يشمل التقييم ضوابط الحوكمة، إدارة الهوية، حماية البيانات، '
            f'الاستجابة للحوادث، واستمرارية الأعمال.\n\n'
            f'**الافتراضات:** نطاق تقني وتشغيلي للمنظمة الحكومية.\n'
        )
        out['scope'] = scope

    gaps = (out.get('gaps') or '').strip()
    if not gaps or _count_table_rows(gaps) < 1:
        rows = []
        for i, fw in enumerate(fws[:6] or ['ISO 27001', 'NIST CSF'], 1):
            rows.append(
                f'| {i} | {fw} | الحالة الحالية | الحالة المستهدفة | '
                f'فجوة في {fw} | عالية | CISO |')
        gaps = (
            '## تحليل الفجوات\n\n'
            '| # | الإطار | الحالة الحالية | الحالة المستهدفة | '
            'الفجوة | الأولوية | المالك |\n|---|---|---|---|---|---|---|\n'
            + '\n'.join(rows) + '\n'
        )
        out['gaps'] = gaps

    remediation = (
        out.get('remediation')
        or out.get('recommendations')
        or out.get('guides')
        or '').strip()
    if not remediation or _count_table_rows(remediation) < 1:
        remediation = (
            '## خطة المعالجة\n\n'
            '| الإجراء | الأولوية | المالك | الجدول الزمني | '
            'الدليل المطلوب |\n|---|---|---|---|---|\n'
            '| تفعيل ضوابط ISO 27001 Annex A ذات الأولوية | عالية | CISO | '
            '90 يوماً | سياسات وإجراءات معتمدة |\n'
            '| مواءمة NIST CSF مع خارطة التنفيذ | عالية | مدير الامتثال | '
            '120 يوماً | مصفوفة تتبع |\n'
            '| إغلاق فجوات IAM/PAM | متوسطة | مدير الهوية | 60 يوماً | '
            'سجل صلاحيات |\n'
            '| تحسين الاستجابة للحوادث CSIRT | متوسطة | قائد CSIRT | '
            '90 يوماً | خطة استجابة |\n'
        )
        out['remediation'] = remediation

    findings = (out.get('findings') or out.get('executive_summary') or '').strip()
    if not findings:
        out['findings'] = (
            '## الملخص التنفيذي\n\n'
            f'تم تقييم الامتثال مقابل {fw_line}. '
            'توجد فجوات ذات أولوية عالية تتطلب معالجة خلال 90–120 يوماً.\n'
        )
    return out


def emit_rel33_gap_assessment_completeness(
        sections: Dict[str, str],
        *,
        domain: str = 'global',
        selected_frameworks: Optional[List[str]] = None,
        blocking_errors: Optional[List[str]] = None,
        phase: str = 'save_gate',
        repair_applied: bool = False,
        repaired_sections_persisted: bool = False,
) -> Dict[str, Any]:
    scope_present = bool((sections.get('scope') or '').strip())
    gap_rows = _count_table_rows(sections.get('gaps') or '')
    remediation_rows = _count_table_rows(
        sections.get('remediation')
        or sections.get('recommendations')
        or sections.get('guides')
        or '')
    if remediation_rows < 1:
        _rem_blob = (
            sections.get('remediation')
            or sections.get('recommendations')
            or sections.get('guides')
            or '')
        if _rem_blob.strip():
            remediation_rows = max(1, len([
                ln for ln in _rem_blob.splitlines()
                if ln.strip() and not ln.strip().startswith('#')]))
    rec_count = len([
        ln for ln in (sections.get('findings') or sections.get(
            'executive_summary') or '').splitlines()
        if ln.strip() and not ln.strip().startswith('#')])
    diag = {
        'phase': phase,
        'domain': domain,
        'document_type': 'gap_assessment',
        'selected_frameworks': _norm_frameworks(selected_frameworks),
        'scope_present': scope_present,
        'gap_rows_count': gap_rows,
        'remediation_rows_count': remediation_rows,
        'recommendations_count': rec_count,
        'repair_applied': repair_applied,
        'repaired_sections_persisted': repaired_sections_persisted,
        'strategy_gates_enabled': strategy_gates_enabled('gap_assessment'),
        'gap_assessment_gates_enabled': gap_assessment_gates_enabled(
            'gap_assessment'),
        'blocking_errors': list(blocking_errors or []),
    }
    try:
        print(
            '[REL33-GAP-ASSESSMENT-COMPLETENESS] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
    emit_rel33_document_type_gate_routing(build_gate_routing_diag(
        domain=domain,
        document_type='gap_assessment',
        route='gap_assessment_completeness',
        document_type_source='sections._document_type',
        blocking_errors=blocking_errors,
    ))
    return diag


def repair_and_audit_gap_assessment(
        sections: Dict[str, str],
        *,
        selected_frameworks: Optional[List[str]] = None,
        domain: str = 'global',
        lang: str = 'ar',
        phase: str = 'save_gate',
) -> tuple[Dict[str, str], List[tuple]]:
    repaired = repair_gap_assessment_sections(
        sections,
        selected_frameworks=selected_frameworks,
        domain=domain,
        lang=lang,
    )
    defects = audit_gap_assessment_sections(
        repaired,
        selected_frameworks=selected_frameworks,
        lang=lang,
        domain=domain,
    )
    emit_rel33_gap_assessment_completeness(
        repaired,
        domain=domain,
        selected_frameworks=selected_frameworks,
        blocking_errors=[
            f'{tag}' for _sec, tag, _c, _m in defects],
        phase=phase,
        repair_applied=True,
        repaired_sections_persisted=True,
    )
    return repaired, defects
