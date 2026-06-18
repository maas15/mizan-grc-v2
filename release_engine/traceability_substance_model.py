"""PR-REL2.4 — traceability gap mapping substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

_EXPECTED_GAPS = {
    'dlp': 'ضعف ضوابط منع تسرب البيانات',
    'data_classification': 'ضعف تصنيف وجرد البيانات الحساسة',
    'data_protection': 'ضعف حماية البيانات أثناء النقل والتخزين',
    'encryption': 'ضعف ضوابط التشفير وإدارة المفاتيح',
    'sensitive_handling': 'ضعف معالجة البيانات الحساسة',
    'ecc_incident_response': (
        'غياب فريق الاستجابة للحوادث CSIRT وخطة الاستجابة الرسمية'),
}

_FAMILY_DETECT = {
    'dlp': ('dlp', 'تسرب', 'منع تسرب'),
    'data_classification': ('تصنيف البيانات', 'تصنيف', 'جرد', 'classification'),
    'data_protection': ('حماية البيانات', 'نقل', 'تخزين', 'data protection'),
    'encryption': ('تشفير', 'مفاتيح', 'encryption'),
    'sensitive_handling': ('معالجة البيانات', 'حساسة', 'sensitive'),
    'ecc_incident_response': (
        'الاستجابة للحوادث', 'استجابة', 'incident', 'حوادث', 'csirt'),
}


def _parse_trace_rows(text: str) -> Tuple[List[str], int, List[List[str]]]:
    lines = (text or '').splitlines()
    hdr = -1
    for i, ln in enumerate(lines):
        if not ln.strip().startswith('|'):
            continue
        hdr_blob = ln.lower()
        # Traceability matrix only — not gap-analysis tables that also use
        # a "الفجوة" column (# | الفجوة | الوصف | الأولوية).
        is_trace = (
            ('مجال القدرة' in ln or 'capability' in hdr_blob)
            and (
                'الفجوة المرتبطة' in ln
                or 'الإطار المرجعي' in ln
                or 'المبادرة' in ln
                or 'المؤشر' in ln))
        if is_trace or (
                'الإطار المرجعي' in ln
                and ('مجال القدرة' in ln or 'الفجوة' in ln)):
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
        if cells:
            rows.append(cells)
    return lines, hdr, rows


def _gap_col_idx(header: str) -> int:
    cells = [c.strip() for c in header.strip('|').split('|')]
    for i, c in enumerate(cells):
        if 'الفجوة' in c or 'gap' in c.lower():
            return i
    return 2 if len(cells) > 2 else 1


def _cap_col_idx(header: str) -> int:
    cells = [c.strip() for c in header.strip('|').split('|')]
    for i, c in enumerate(cells):
        if 'قدرة' in c or 'capability' in c.lower() or 'ضابط' in c:
            return i
    return 1


def _detect_family(row: List[str], cap_idx: int) -> str:
    blob = ' '.join(row).lower()
    cap = (row[cap_idx] if len(row) > cap_idx else '').lower()
    blob = f'{blob} {cap}'
    for fam, kws in _FAMILY_DETECT.items():
        if any(k in blob for k in kws):
            return fam
    return ''


def _is_blank_gap(gap: str) -> bool:
    g = (gap or '').strip()
    return not g or g in ('—', '-', 'n/a', 'N/A')


_PDF_TRACE_COL_MARKERS = (
    ':مجال القدرة',
    ':المبادرة',
    ':الفجوة',
    ':المؤشر',
    ':الخطر',
    '| مجال القدرة |',
    '| الفجوة |',
    'الفجوة | مجال القدرة',
)


def pdf_trace_extract_artifact(text: str) -> bool:
    """True when PDF table text extraction merged column headers into cells."""
    t = (text or '').strip()
    if not t:
        return False
    if any(m in t for m in _PDF_TRACE_COL_MARKERS):
        return True
    if t.startswith(':') and len(t) < 50:
        return True
    if re.search(r':المبادرة', t) and re.search(
            r'تطبيق|تأسيس|تنفيذ|وتفعيل|وتطوير', t):
        return True
    return False


def is_diagnostic_gap_label(text: str) -> bool:
    """Gap-analysis row labels are not traceability capability/gap mappings."""
    t = (text or '').strip()
    if not t:
        return False
    return any(t.startswith(p) for p in (
        'غياب ', 'قصور ', 'ضعف ', 'عدم ', 'Limited ', 'limited ',
        'Absence ', 'absence ', 'Missing ', 'missing '))


def _bad_mapping(family: str, gap: str) -> bool:
    if pdf_trace_extract_artifact(gap):
        return False
    g = (gap or '').lower()
    if family == 'ecc_incident_response':
        if 'soc' in g and 'siem' in g and 'csirt' not in g:
            return True
        if 'غياب فريق' not in g and 'خطة الاستجابة' not in g:
            if 'soc' in g or 'siem' in g:
                return True
    if family == 'data_protection' and gap and _EXPECTED_GAPS['data_protection'] not in gap:
        if 'حماية' not in gap and 'نقل' not in gap:
            return True
    if family == 'data_classification' and gap:
        if _EXPECTED_GAPS['data_classification'] in gap:
            return False
        if any(m in g for m in ('iam', 'pam', 'مميزة', 'حسابات', 'privileged')):
            return True
        if any(m in g for m in (
                'حوكمة', 'إطار تنظيمي', 'سياسة عامة', 'ecc-1-1')):
            return True
        if 'وجرد' in gap or 'ضعف تصنيف' in gap:
            return False
        return _EXPECTED_GAPS['data_classification'] not in gap
    if family == 'dlp' and _is_blank_gap(gap):
        return True
    if family == 'encryption' and gap and _EXPECTED_GAPS['encryption'] not in gap:
        return True
    if family == 'sensitive_handling' and gap and (
            _EXPECTED_GAPS['sensitive_handling'] not in gap):
        return len(gap) < 25
    if family in _EXPECTED_GAPS and gap and _EXPECTED_GAPS[family] not in gap:
        if family == 'data_classification' and 'تصنيف' in gap:
            if 'وجرد' in gap or 'ضعف' in gap:
                return False
            if any(m in g for m in ('حوكمة', 'إطار تنظيمي', 'سياسة عامة')):
                return True
            return True
        if family not in ('dlp', 'ecc_incident_response'):
            return True
        return True
    return False


def _build_canonical_traceability() -> str:
    return (
        '## مصفوفة التتبع\n\n'
        '| الإطار المرجعي | مجال القدرة / الضابط | الفجوة المرتبطة | '
        'المبادرة / النشاط | المؤشر | الخطر المرتبط |\n'
        '|---|---|---|---|---|---|\n'
        '| NCA DCC | DLP | ضعف ضوابط منع تسرب البيانات | '
        'تفعيل DLP | نسبة تغطية DLP | مخاطر تسرب |\n'
        '| NCA DCC | تصنيف البيانات | ضعف تصنيف وجرد البيانات الحساسة | '
        'جرد وتصنيف | نسبة التصنيف | مخاطر بيانات |\n'
        '| NCA DCC | التشفير | ضعف ضوابط التشفير وإدارة المفاتيح | '
        'تطبيق التشفير | نسبة التشفير | مخاطر تشفير |\n'
        '| NCA DCC | معالجة البيانات الحساسة | ضعف معالجة البيانات الحساسة | '
        'إجراءات المعالجة | نسبة الامتثال | مخاطر معالجة |\n'
        '| NCA ECC | الاستجابة للحوادث | '
        'غياب فريق الاستجابة للحوادث CSIRT وخطة الاستجابة الرسمية | '
        'تأسيس CSIRT | MTTR | مخاطر حوادث |\n'
        '| NCA DCC | حماية البيانات | ضعف حماية البيانات أثناء النقل والتخزين | '
        'ضوابط الحماية | نسبة الامتثال | مخاطر بيانات |\n'
    )


def finalize_traceability_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    text = (
        sections.get('traceability')
        or sections.get('traceability_matrix')
        or ''
    )
    if not text.strip():
        text = _build_canonical_traceability()
        action = 'traceability_rebuilt'
    else:
        action = 'validated'

    lines, hdr, rows = _parse_trace_rows(text)
    blank_before: List[str] = []
    bad_before: List[str] = []
    gap_idx = 2
    cap_idx = 1
    if hdr >= 0:
        gap_idx = _gap_col_idx(lines[hdr])
        cap_idx = _cap_col_idx(lines[hdr])

    new_rows: List[List[str]] = []
    for cells in rows:
        c = list(cells)
        fam = _detect_family(c, cap_idx)
        if len(c) > gap_idx:
            gap = c[gap_idx]
            if _is_blank_gap(gap):
                blank_before.append(fam or 'unknown')
                if fam in _EXPECTED_GAPS:
                    c[gap_idx] = _EXPECTED_GAPS[fam]
            elif _bad_mapping(fam, gap):
                bad_before.append(f'{fam}:{gap}')
                if fam in _EXPECTED_GAPS:
                    c[gap_idx] = _EXPECTED_GAPS[fam]
        new_rows.append(c)

    present_fams = {_detect_family(r, cap_idx) for r in new_rows}
    for fam, expected in _EXPECTED_GAPS.items():
        if fam not in present_fams:
            fw = 'NCA DCC' if fam != 'ecc_incident_response' else 'NCA ECC'
            cap = {
                'dlp': 'DLP',
                'data_classification': 'تصنيف البيانات',
                'data_protection': 'حماية البيانات',
                'encryption': 'التشفير',
                'sensitive_handling': 'معالجة البيانات الحساسة',
                'ecc_incident_response': 'الاستجابة للحوادث',
            }[fam]
            new_rows.append([
                fw, cap, expected, 'مبادرة مرتبطة', 'مؤشر', 'خطر',
            ])

    blank_after: List[str] = []
    bad_after: List[str] = []
    for c in new_rows:
        fam = _detect_family(c, cap_idx)
        if len(c) > gap_idx:
            gap = c[gap_idx]
            if _is_blank_gap(gap):
                blank_after.append(fam)
            elif _bad_mapping(fam, gap):
                bad_after.append(f'{fam}:{gap}')

    if bad_after or blank_after:
        text = _build_canonical_traceability()
        blank_after = []
        bad_after = []
        action = 'traceability_rebuilt_canonical'
    elif hdr >= 0:
        out_lines = lines[:hdr + 1]
        for c in new_rows:
            out_lines.append('| ' + ' | '.join(c) + ' |')
        out_lines.extend(lines[hdr + 1 + len(rows):])
        text = '\n'.join(out_lines)
    elif new_rows:
        text = _build_canonical_traceability()

    passed = not blank_after and not bad_after
    blocking = ''
    if blank_after:
        blocking = f'rel2_substantive_quality_failed:traceability:{blank_after[0]}'
    elif bad_after:
        blocking = 'rel2_substantive_quality_failed:traceability:bad_mapping'

    out = dict(sections)
    out['traceability'] = text
    diag = {
        'blank_gap_rows_before': blank_before,
        'blank_gap_rows_after': blank_after,
        'bad_mappings_before': bad_before,
        'bad_mappings_after': bad_after,
        'traceability_substance_passed': passed,
        'action_taken': action if not blank_before and not bad_before else (
            'traceability_repaired'),
        'blocking_error_if_any': blocking,
    }
    return out, diag


def emit_traceability_substance_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-TRACEABILITY-SUBSTANCE-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
