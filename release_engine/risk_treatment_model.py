"""PR-REL2.4 — risk register treatment substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

_EMPTY_TREATMENT = frozenset({
    '', '—', '-', 'tbd', 'TBD', 'سيتم لاحقاً', 'خطة', 'plan', 'n/a', 'N/A',
})

_REQUIRED_RISK_THEMES = (
    'compliance',
    'capabilities',
    'data_protection',
    'incident_response',
    'resource_capacity',
    'operational_continuity',
)

_RISK_TREATMENTS_AR = {
    'compliance': (
        'تنفيذ برنامج امتثال NCA ECC/DCC مع مراجعات ربع سنوية — '
        'المالك: مدير الامتثال'),
    'capabilities': (
        'تعزيز القدرات السيبرانية عبر SOC/SIEM وCSIRT — المالك: CISO'),
    'data_protection': (
        'تطبيق ضوابط DCC للتصنيف والتشفير وDLP — المالك: مدير حماية البيانات'),
    'incident_response': (
        'تفعيل خطط الاستجابة للحوادث وتمارين CSIRT — المالك: قائد CSIRT'),
    'resource_capacity': (
        'تخصيص موارد وطاقات تشغيلية للأمن السيبراني — المالك: CISO'),
    'operational_continuity': (
        'اختبار النسخ الاحتياطي وخطط استمرارية الأعمال — '
        'المالك: مدير استمرارية الأعمال'),
}

_THEME_KEYWORDS = {
    'compliance': ('امتثال', 'ecc', 'dcc', 'تنظيمي'),
    'capabilities': ('قدرات', 'soc', 'siem', 'مهارات'),
    'data_protection': ('بيانات', 'dlp', 'تصنيف', 'تشفير'),
    'incident_response': ('حوادث', 'csirt', 'استجابة', 'حادث'),
    'resource_capacity': ('موارد', 'طاقة', 'ميزانية', 'كفاءات'),
    'operational_continuity': ('استمرارية', 'تشغيل', 'تعطل', 'bcp'),
}


def _parse_risk_rows(text: str) -> Tuple[List[str], int, List[List[str]]]:
    lines = (text or '').splitlines()
    hdr = -1
    for i, ln in enumerate(lines):
        if ln.strip().startswith('|') and (
                'خطة المعالجة' in ln or 'treatment' in ln.lower()
                or 'المعالجة' in ln):
            hdr = i
            break
    if hdr < 0:
        return lines, -1, []
    rows = []
    for ln in lines[hdr + 1:]:
        if not ln.strip().startswith('|') or '---' in ln:
            if rows:
                break
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells and (cells[0].isdigit() or len(cells) >= 4):
            if cells[0].isdigit():
                rows.append(cells)
            elif len(cells) >= 4:
                rows.append(cells)
    return lines, hdr, rows


def _treatment_col_idx(header_line: str) -> int:
    cells = [c.strip() for c in header_line.strip('|').split('|')]
    for i, c in enumerate(cells):
        if 'خطة المعالجة' in c or 'treatment' in c.lower():
            return i
    return max(0, len(cells) - 2)


def _is_empty_treatment(val: str) -> bool:
    return (val or '').strip().lower() in {
        x.lower() for x in _EMPTY_TREATMENT}


def _themes_covered(rows: List[List[str]], treat_idx: int) -> Dict[str, bool]:
    covered = {t: False for t in _REQUIRED_RISK_THEMES}
    for cells in rows:
        blob = ' '.join(cells).lower()
        for theme, kws in _THEME_KEYWORDS.items():
            if any(k in blob for k in kws):
                covered[theme] = True
    return covered


def finalize_risk_treatment(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    keys = ('confidence', 'risk', 'risk_register', 'gaps')
    target_key = None
    text = ''
    for k in keys:
        if sections.get(k) and 'خطة المعالجة' in (sections.get(k) or ''):
            target_key = k
            text = sections[k]
            break
        if sections.get(k) and 'treatment' in (sections.get(k) or '').lower():
            target_key = k
            text = sections[k]
            break

    if not target_key:
        text = sections.get('confidence', '') or ''
        target_key = 'confidence'

    lines, hdr, rows = _parse_risk_rows(text)
    empty_before: List[str] = []
    treat_idx = 4
    if hdr >= 0:
        treat_idx = _treatment_col_idx(lines[hdr])

    new_rows: List[List[str]] = []
    for cells in rows:
        c = list(cells)
        if len(c) > treat_idx:
            plan = c[treat_idx]
            if _is_empty_treatment(plan):
                empty_before.append(plan or 'empty')
                blob = ' '.join(c).lower()
                repaired = None
                for theme, kws in _THEME_KEYWORDS.items():
                    if any(k in blob for k in kws):
                        repaired = _RISK_TREATMENTS_AR[theme]
                        break
                c[treat_idx] = repaired or _RISK_TREATMENTS_AR['capabilities']
        new_rows.append(c)

    themes = _themes_covered(new_rows, treat_idx)
    missing_themes = [t for t in _REQUIRED_RISK_THEMES if not themes.get(t)]
    if missing_themes and hdr >= 0:
        for theme in missing_themes:
            tpl = _RISK_TREATMENTS_AR[theme]
            name = {
                'compliance': 'مخاطر الامتثال التنظيمي',
                'capabilities': 'نقص القدرات السيبرانية',
                'data_protection': 'مخاطر حماية البيانات',
                'incident_response': 'مخاطر الاستجابة للحوادث',
                'resource_capacity': 'مخاطر الموارد والطاقات',
                'operational_continuity': 'مخاطر استمرارية التشغيل',
            }[theme]
            new_rows.append([
                str(len(new_rows) + 1), name, 'متوسط', 'عالٍ', tpl,
            ])

    empty_after: List[str] = []
    for c in new_rows:
        if len(c) > treat_idx and _is_empty_treatment(c[treat_idx]):
            empty_after.append(c[treat_idx])

    if hdr >= 0 and new_rows:
        out_lines = lines[:hdr + 1]
        seen = set()
        for i, c in enumerate(new_rows, 1):
            c = list(c)
            if c:
                c[0] = str(i)
            key = '|'.join(c[1:3]) if len(c) > 2 else str(c)
            if key in seen:
                continue
            seen.add(key)
            out_lines.append('| ' + ' | '.join(c) + ' |')
        text = '\n'.join(out_lines)

    passed = not empty_after
    blocking = ''
    if not passed:
        blocking = 'rel2_substantive_quality_failed:risk:empty_treatment'

    out = dict(sections)
    out[target_key] = text
    diag = {
        'empty_treatment_plans_before': empty_before,
        'empty_treatment_plans_after': empty_after,
        'risk_treatment_passed': passed,
        'action_taken': (
            'risk_treatment_repaired' if empty_before else 'validated'),
        'blocking_error_if_any': blocking,
    }
    return out, diag


def emit_risk_treatment_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-RISK-TREATMENT-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
