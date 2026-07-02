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
        'تخصيص موارد وطاقات تشغيلية مخصصة للأمن السيبراني مع خطة '
        'تنفيذ ربع سنوية — المالك: CISO'),
    'operational_continuity': (
        'اختبار النسخ الاحتياطي وخطط استمرارية الأعمال — '
        'المالك: مدير استمرارية الأعمال'),
}

_GENERIC_TREATMENT = 'ضوابط تقنية وإجراءات تشغيلية ومراقبة مستمرة'

_RISK_SPECIFIC_RULES = (
    (('حوكمة', 'سياسة', 'governance', 'امتثال تنظيمي'), (
        'تأسيس إطار سياسات حوكمة معتمد ومراجعات امتثال ربع سنوية — '
        'المالك: CISO')),
    (('iam', 'mfa', 'pam', 'هوية', 'صلاحية', 'وصول'), (
        'نشر MFA/PAM وإعادة تصديق صلاحيات ربع سنوية — المالك: مدير الهوية')),
    (('soc', 'siem', 'كشف', 'رصد', 'مراقبة'), (
        'تفعيل SOC/SIEM وضبط حالات الاستخدام للكشف — المالك: مدير SOC')),
    (('تصيد', 'phishing', 'ransomware', 'فدية', 'برمجيات'), (
        'محاكاة تصيد وخطط استجابة لبرمجيات الفدية — المالك: CSIRT')),
    (('مورد', 'طرف ثالث', 'supplier', 'third', 'أطراف', 'من الأطر'), (
        'تقييم مخاطر الأطراف الثالثة وضوابط تعاقدية — '
        'المالك: إدارة المشتريات')),
    (('ثغر', 'vulnerab', 'patch', 'ترقيع'), (
        'فحص شهري للثغرات ومعالجة وفق SLA — المالك: مدير الثغرات')),
)


def specific_risk_treatment_for_blob(risk_blob: str, *, lang: str = 'ar') -> str:
    """Return a risk-specific treatment plan for a register row blob."""
    blob = (risk_blob or '').lower()
    for keywords, treatment in _RISK_SPECIFIC_RULES:
        if any(k in blob for k in keywords):
            return treatment
    if lang == 'ar':
        return (
            'تنفيذ ضوابط تقنية وإجراءات تشغيلية مخصصة للمخاطر المحددة '
            'ومراقبة مستمرة — المالك: CISO')
    return (
        'Implement risk-specific technical controls, procedures, '
        'and continuous monitoring — Owner: CISO')


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


def _is_generic_treatment(val: str) -> bool:
    return (val or '').strip() == _GENERIC_TREATMENT


def _repair_flat_risk_register(text: str, *, lang: str = 'ar') -> str:
    """Replace generic/empty treatments in flat DOCX/PDF risk register text."""
    if _GENERIC_TREATMENT not in (text or ''):
        return text or ''
    lines = (text or '').splitlines()
    out: List[str] = []
    for i, ln in enumerate(lines):
        stripped = (ln or '').strip()
        if stripped == _GENERIC_TREATMENT or _is_empty_treatment(stripped):
            context = ' '.join(lines[max(0, i - 4):i])
            out.append(specific_risk_treatment_for_blob(context, lang=lang))
            continue
        out.append(ln)
    return '\n'.join(out)


def _themes_covered(rows: List[List[str]], treat_idx: int) -> Dict[str, bool]:
    covered = {t: False for t in _REQUIRED_RISK_THEMES}
    for cells in rows:
        blob = ' '.join(cells).lower()
        for theme, kws in _THEME_KEYWORDS.items():
            if any(k in blob for k in kws):
                covered[theme] = True
    return covered


def _repair_flat_confidence_register(
        text: str, *, lang: str = 'ar') -> str:
    """Repair flat (non-markdown) confidence risk register rows."""
    lines = (text or '').splitlines()
    out: List[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        stripped = (ln or '').strip()
        if stripped.isdigit() and i + 5 < len(lines):
            block = [lines[i + j].strip() for j in range(6)]
            risk_blob = ' '.join(block).lower()
            treatment = block[4]
            if (
                    _is_generic_treatment(treatment)
                    or _is_empty_treatment(treatment)
                    or len(re.findall(r'[\u0600-\u06FF]+', treatment)) < 8
            ):
                repaired = specific_risk_treatment_for_blob(risk_blob, lang=lang)
                for theme, kws in _THEME_KEYWORDS.items():
                    if any(k in risk_blob for k in kws):
                        repaired = _RISK_TREATMENTS_AR[theme]
                        break
                block[4] = repaired
            out.append(stripped)
            out.extend(block[1:])
            i += 6
            continue
        out.append(ln)
        i += 1
    return '\n'.join(out)


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

    if _GENERIC_TREATMENT in text and 'خطة المعالجة' in text:
        text = _repair_flat_risk_register(text, lang=lang)

    lines, hdr, rows = _parse_risk_rows(text)
    empty_before: List[str] = []
    treat_idx = 4
    if hdr >= 0:
        treat_idx = _treatment_col_idx(lines[hdr])

    if hdr < 0 and _GENERIC_TREATMENT in text:
        text = _repair_flat_risk_register(text, lang=lang)
        lines, hdr, rows = _parse_risk_rows(text)
        if hdr >= 0:
            treat_idx = _treatment_col_idx(lines[hdr])

    new_rows: List[List[str]] = []
    for cells in rows:
        c = list(cells)
        if len(c) > treat_idx:
            plan = c[treat_idx]
            blob = ' '.join(c).lower()
            if _is_empty_treatment(plan) or _is_generic_treatment(plan):
                if _is_empty_treatment(plan):
                    empty_before.append(plan or 'empty')
                repaired = specific_risk_treatment_for_blob(blob, lang=lang)
                for theme, kws in _THEME_KEYWORDS.items():
                    if any(k in blob for k in kws):
                        repaired = _RISK_TREATMENTS_AR[theme]
                        break
                c[treat_idx] = repaired
        new_rows.append(c)

    themes = _themes_covered(new_rows, treat_idx)
    missing_themes = [t for t in _REQUIRED_RISK_THEMES if not themes.get(t)]
    if missing_themes and hdr >= 0:
        for theme in missing_themes:
            if len(new_rows) >= MAX_RISK_REGISTER_ROWS:
                break
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

    if hdr < 0 and 'خطة المعالجة' in text and 'المالك' in text:
        text = _repair_flat_confidence_register(text, lang=lang)

    if hdr < 0 and _GENERIC_TREATMENT not in text:
        passed = True
    elif hdr < 0:
        passed = _GENERIC_TREATMENT not in text
    else:
        passed = not empty_after
    blocking = ''
    if not passed:
        blocking = 'rel2_substantive_quality_failed:risk:empty_treatment'

    out = dict(sections)
    out[target_key] = text
    orig_had_generic = _GENERIC_TREATMENT in (sections.get(target_key) or '')
    out, _ = trim_risk_register_rows(out, max_rows=MAX_RISK_REGISTER_ROWS)
    diag = {
        'empty_treatment_plans_before': empty_before,
        'empty_treatment_plans_after': empty_after,
        'risk_treatment_passed': passed,
        'action_taken': (
            'risk_treatment_repaired'
            if empty_before or orig_had_generic else 'validated'),
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


MAX_RISK_REGISTER_ROWS = 8


def _trim_flat_risk_register(
        text: str, *, max_rows: int = MAX_RISK_REGISTER_ROWS) -> Tuple[str, bool]:
    """Cap flat (non-markdown) confidence risk register rows."""
    lines = (text or '').splitlines()
    start = -1
    for i, ln in enumerate(lines):
        if ln.strip() == 'المالك' and i >= 1 and lines[i - 1].strip() == 'خطة المعالجة':
            start = i + 1
            break
    if start < 0:
        return text, False
    blocks: List[Tuple[int, int]] = []
    i = start
    while i < len(lines):
        if lines[i].strip().isdigit() and i + 5 < len(lines):
            blocks.append((i, i + 6))
            i += 6
            continue
        i += 1
    if len(blocks) <= max_rows:
        return text, False
    keep_end = blocks[max_rows - 1][1]
    tail_start = blocks[-1][1]
    out_lines = lines[:keep_end] + lines[tail_start:]
    for bi, (row_start, _) in enumerate(blocks[:max_rows]):
        out_lines[row_start] = str(bi + 1)
    return '\n'.join(out_lines), True


def trim_risk_register_rows(
        sections: Dict[str, str],
        *,
        max_rows: int = 8,
) -> Tuple[Dict[str, str], bool]:
    """Cap markdown risk register rows for DQS (6–8 required)."""
    keys = ('confidence', 'risk', 'risk_register')
    target_key = None
    text = ''
    for k in keys:
        if sections.get(k) and 'خطة المعالجة' in (sections.get(k) or ''):
            target_key = k
            text = sections[k]
            break
    if not target_key:
        for k in keys:
            val = sections.get(k) or ''
            if 'خطة المعالجة' in val and 'المالك' in val:
                trimmed, did = _trim_flat_risk_register(val, max_rows=max_rows)
                if did:
                    out = dict(sections)
                    out[k] = trimmed
                    return out, True
        return sections, False
    lines, hdr, rows = _parse_risk_rows(text)
    if hdr < 0:
        trimmed, did = _trim_flat_risk_register(text, max_rows=max_rows)
        if did:
            out = dict(sections)
            out[target_key] = trimmed
            return out, True
        return sections, False
    if len(rows) <= max_rows:
        return sections, False
    trimmed = rows[:max_rows]
    out_lines = lines[:hdr + 1]
    for i, c in enumerate(trimmed, 1):
        cells = list(c)
        if cells:
            cells[0] = str(i)
        out_lines.append('| ' + ' | '.join(cells) + ' |')
    out = dict(sections)
    out[target_key] = '\n'.join(out_lines)
    return out, True
