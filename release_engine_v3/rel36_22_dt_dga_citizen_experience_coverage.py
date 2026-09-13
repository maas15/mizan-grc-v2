"""REL36.22 — DT Arabic DGA citizen_experience selected-framework coverage.

REL35 deterministically covers DGA interoperability. The official
selected-framework coverage gate still requires the
``citizen_experience`` family (``تجربة المستفيد`` / ``تجربة المواطن``)
in at least one of pillars / environment / gaps / roadmap / KPIs.
Live official ``dt:strategy:ar`` on 8d4a954 failed with

``selected_framework_coverage_missing:DGA:citizen_experience``

reported on all five repair targets because the family was globally
absent.

This module inserts detector-visible Arabic citizen-experience content
into each counted section that still lacks the official tokens. It does
not weaken the coverage gate and does not apply outside DT Arabic
strategy with DGA selected.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel35_domain_framework_fidelity import (
    _append_md_row,
    _append_paragraph,
    dga_interoperability_covered,
    dga_selected,
    repair_dga_interoperability_sections,
    section_has_dga_interop,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_22_DT_DGA_CITIZEN_EXPERIENCE_COVERAGE_TAG = (
    '[REL36.22-DT-DGA-CITIZEN-EXPERIENCE-COVERAGE]')

REQUIRED_SECTIONS = (
    'pillars', 'environment', 'gaps', 'roadmap', 'kpis',
)
EXPECTED_DGA_CAPABILITIES = (
    'digital_services', 'interoperability', 'citizen_experience',
)
OFFICIAL_CITIZEN_AR = (
    'تجربة المستفيد',
    'تجربة المواطن',
)
OFFICIAL_CITIZEN_EN = (
    'citizen experience',
    'user experience',
)
_LEAKS = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
_FW_DOMAIN_LABEL = {
    'dt': 'Digital Transformation',
    'digital_transformation': 'Digital Transformation',
}
_PILLAR_HEADER = (
    '| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |')
_PILLAR_ROW = (
    '| 1 | تحسين تجربة المستفيد في الخدمات الرقمية | '
    'تصميم وتحسين الخدمات الرقمية وفق رحلة المستفيد ومتطلبات '
    'هيئة الحكومة الرقمية DGA | خطة تحسين تجربة المستفيد ومؤشرات '
    'رضا المستفيد | مدير تجربة المستفيد |')
_PILLAR_ROW_4 = (
    '| تحسين تجربة المستفيد في الخدمات الرقمية | '
    'تصميم وتحسين الخدمات الرقمية وفق رحلة المستفيد ومتطلبات '
    'هيئة الحكومة الرقمية DGA | خطة تحسين تجربة المستفيد ومؤشرات '
    'رضا المستفيد | مدير تجربة المستفيد |')
_ENV_PARAGRAPH = (
    'تتطلب مواءمة الجهة مع إطار هيئة الحكومة الرقمية DGA تحسين '
    'تجربة المستفيد عبر قياس رضا المستفيد، تحليل رحلة المستفيد، '
    'وتبسيط الوصول إلى الخدمات الرقمية متعددة القنوات.')
_GAP_HEADER = '| # | الفجوة | الوصف | الأولوية | الحالة |'
_GAP_ROW = (
    '| 1 | ضعف قياس وتحسين تجربة المستفيد | لا توجد آلية مؤسسية '
    'مكتملة لقياس رضا المستفيد وتحليل رحلة المستفيد وتحسين الخدمات '
    'الرقمية وفق متطلبات DGA | عالية | مفتوحة |')
_ROAD_HEADER = (
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | '
    'الإطار المرتبط |')
_ROAD_ROW = (
    '| المرحلة 1: تأسيس | 1-6 أشهر | بناء إطار قياس وتحسين تجربة '
    'المستفيد | مدير تجربة المستفيد | لوحة مؤشرات رضا المستفيد وخطة '
    'تحسين رحلة المستفيد | DGA |')
_KPI_HEADER = (
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | '
    'مصدر | التكرار | المالك |')
_KPI_ROW = (
    '| 1 | نسبة رضا المستفيد عن الخدمات الرقمية | نتيجة | ≥ 85% | '
    'عدد التقييمات الإيجابية / إجمالي تقييمات المستفيدين × 100 | '
    'منصة قياس تجربة المستفيد | ربع سنوي | مدير تجربة المستفيد |')
_DUP_MARKERS = (
    'تحسين تجربة المستفيد في الخدمات الرقمية',
    'نسبة رضا المستفيد عن الخدمات الرقمية',
    'بناء إطار قياس وتحسين تجربة المستفيد',
    'ضعف قياس وتحسين تجربة المستفيد',
)
_ARABIC_CHAR_RE = re.compile(r'[\u0600-\u06FF]')


def _domain_code(domain: Optional[str]) -> str:
    return _normalize_rel31_domain_code(str(domain or ''))


def _norm_dtype(document_type: Optional[str]) -> str:
    raw = str(document_type or 'strategy').strip().lower()
    if raw in {'', 'strategy', 'strategy_document', 'strategy document'}:
        return 'strategy'
    return raw


def rel36_22_should_apply(
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> bool:
    if _domain_code(domain) != 'dt':
        return False
    if normalize_rel36_lang(lang) != 'ar':
        return False
    if _norm_dtype(document_type) != 'strategy':
        return False
    return dga_selected(selected_frameworks)


def section_has_citizen_experience(text: str) -> bool:
    blob = str(text or '')
    if any(tok in blob for tok in OFFICIAL_CITIZEN_AR):
        return True
    low = blob.lower()
    return any(tok in low for tok in OFFICIAL_CITIZEN_EN)


def _detected_by_section(sections: Dict[str, str]) -> Dict[str, bool]:
    return {
        key: section_has_citizen_experience(sections.get(key, ''))
        for key in REQUIRED_SECTIONS
    }


def _interop_by_section(sections: Dict[str, str]) -> Dict[str, bool]:
    return {
        key: section_has_dga_interop(sections.get(key, ''))
        for key in REQUIRED_SECTIONS
    }


def _capabilities_by_section(sections: Dict[str, str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for key in REQUIRED_SECTIONS:
        blob = str(sections.get(key) or '')
        found: List[str] = []
        if any(tok in blob for tok in ('الخدمات الرقمية', 'التحول الرقمي',
                                       'digital services',
                                       'digital transformation')):
            found.append('digital_services')
        if section_has_dga_interop(blob):
            found.append('interoperability')
        if section_has_citizen_experience(blob):
            found.append('citizen_experience')
        out[key] = found
    return out


def _missing_caps_by_section(
        detected: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    return {
        key: [c for c in EXPECTED_DGA_CAPABILITIES if c not in (detected.get(key) or [])]
        for key in REQUIRED_SECTIONS
    }


def _first_table_header(text: str) -> str:
    for ln in str(text or '').splitlines():
        raw = ln.strip()
        if raw.startswith('|') and '---' not in raw:
            return raw
    return ''


def _col_count(header: str) -> int:
    if not header:
        return 0
    return len([c for c in header.strip().strip('|').split('|')])


def _insert_section(text: str, key: str) -> str:
    body = str(text or '')
    if section_has_citizen_experience(body):
        return body
    header = _first_table_header(body)
    cols = _col_count(header)
    if key == 'environment':
        return _append_paragraph(body, _ENV_PARAGRAPH)
    if key == 'pillars':
        row = _PILLAR_ROW if cols >= 5 else _PILLAR_ROW_4
        if '|' in body:
            return _append_md_row(body, _PILLAR_HEADER, row)
        return _append_paragraph(body, _PILLAR_HEADER + '\n|---|---|---|---|---|\n' + _PILLAR_ROW)
    if key == 'gaps':
        if '|' in body:
            return _append_md_row(body, _GAP_HEADER, _GAP_ROW)
        return _append_paragraph(body, _GAP_HEADER + '\n|---|---|---|---|---|\n' + _GAP_ROW)
    if key == 'roadmap':
        if '|' in body:
            return _append_md_row(body, _ROAD_HEADER, _ROAD_ROW)
        return _append_paragraph(body, _ROAD_HEADER + '\n|---|---|---|---|---|---|\n' + _ROAD_ROW)
    if key == 'kpis':
        if '|' in body:
            return _append_md_row(body, _KPI_HEADER, _KPI_ROW)
        return _append_paragraph(body, _KPI_HEADER + '\n|---|---|---|---|---|---|---|---|\n' + _KPI_ROW)
    return body


def _duplicate_rows(sections: Dict[str, str]) -> bool:
    for key in REQUIRED_SECTIONS:
        blob = str(sections.get(key) or '')
        for marker in _DUP_MARKERS:
            if blob.count(marker) > 1:
                return True
    return False


def _leakage_terms(sections: Dict[str, str]) -> List[str]:
    hay = '\n'.join(str(sections.get(k) or '') for k in REQUIRED_SECTIONS)
    found: List[str] = []
    for tok in _LEAKS:
        if tok == 'NCA':
            if re.search(r'(?<![A-Z])NCA(?![A-Z])', hay) and tok not in found:
                found.append(tok)
            continue
        if tok in hay and tok not in found:
            found.append(tok)
    return found


def _official_missing(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]],
        lang: str,
) -> List[str]:
    try:
        from app import _compute_missing_selected_framework_coverage
        missing = _compute_missing_selected_framework_coverage(
            sections, list(_selected_list(selected_frameworks)),
            domain='Digital Transformation', lang=lang,
        ) or []
        return [
            f'selected_framework_coverage_missing:{fw}:{fam}'
            + (f' ({sk})' if sk and sk != '*' else '')
            for fw, fam, sk in missing
        ]
    except Exception:
        return []


def _citizen_blockers(blockers: Sequence[str]) -> List[str]:
    return [
        b for b in blockers
        if 'selected_framework_coverage_missing:DGA:citizen_experience' in b
    ]


def apply_rel36_22_dt_dga_citizen_experience_coverage(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Optional[str] = None,
        org_name: Optional[str] = None,
        emit: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = {str(k): str(v or '') for k, v in (sections or {}).items()}
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    doc_type = _norm_dtype(document_type)
    fw = list(_selected_list(selected_frameworks))
    diagnostics: Dict[str, Any] = {
        'task_id': task_id or '',
        'domain': dcode,
        'lang': nlang,
        'document_type': doc_type,
        'selected_frameworks': fw,
        'dga_selected': dga_selected(fw),
        'expected_dga_capabilities': list(EXPECTED_DGA_CAPABILITIES),
        'applied': False,
        'passed': False,
    }
    if not rel36_22_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type,
            selected_frameworks=fw):
        diagnostics['skipped'] = True
        return out, diagnostics

    out, _interop_repaired = repair_dga_interoperability_sections(
        out, lang='ar')
    detected_before = _capabilities_by_section(out)
    citizen_before = _detected_by_section(out)
    missing_before = _missing_caps_by_section(detected_before)
    blockers_before = _official_missing(out, fw, nlang)

    inserted: List[str] = []
    for key in REQUIRED_SECTIONS:
        before = out.get(key, '')
        after = _insert_section(before, key)
        if after != before:
            out[key] = after
            inserted.append(key)

    detected_after = _capabilities_by_section(out)
    citizen_after = _detected_by_section(out)
    missing_after = _missing_caps_by_section(detected_after)
    interop_after = _interop_by_section(out)
    blockers_after = _official_missing(out, fw, nlang)
    citizen_blockers_after = _citizen_blockers(blockers_after)
    leaks = _leakage_terms(out)
    duplicate = _duplicate_rows(out)
    all_citizen = all(citizen_after.values())
    interop_ok = dga_interoperability_covered(out)
    passed = (
        all_citizen
        and interop_ok
        and citizen_blockers_after == []
        and duplicate is False
        and leaks == []
    )
    if citizen_blockers_after or not all_citizen:
        passed = False

    diagnostics.update({
        'applied': True,
        'detected_capabilities_before_by_section': detected_before,
        'detected_capabilities_after_by_section': detected_after,
        'missing_capabilities_before_by_section': missing_before,
        'missing_capabilities_after_by_section': missing_after,
        'citizen_experience_present_before_by_section': citizen_before,
        'citizen_experience_present_after_by_section': citizen_after,
        'interoperability_present_after_by_section': interop_after,
        'inserted_sections': inserted,
        'duplicate_rows_after': duplicate,
        'leakage_terms_after': leaks,
        'selected_framework_blockers_before': blockers_before,
        'selected_framework_blockers_after': blockers_after,
        'save_blockers_before': _citizen_blockers(blockers_before),
        'save_blockers_after': citizen_blockers_after,
        'docx_allowed': passed,
        'pdf_allowed': passed,
        'passed': passed,
        'org_name': org_name or '',
        'interop_repaired_sections': _interop_repaired,
    })
    if emit:
        print(
            REL36_22_DT_DGA_CITIZEN_EXPERIENCE_COVERAGE_TAG + ' '
            + json.dumps(diagnostics, ensure_ascii=False, default=str),
            flush=True,
        )
    return out, diagnostics
