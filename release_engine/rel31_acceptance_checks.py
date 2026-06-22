"""PR-REL3.1 — acceptance failure checks on actual returned DOCX/PDF bytes.

Works on flat DOCX/PDF extracted text (no markdown pipes required) as well as
markdown preview blobs.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from release_engine.rel27_export_checks import (
    REL27_GENERIC_FORMULAS,
    REQUIRED_PILLAR_NAME_VARIANTS,
)
from release_engine.rel28_route_evidence import (
    PILLAR_HEADING_MARKERS,
    check_pillars_after_strategic_heading,
)

PLACEHOLDER_PILLAR_TEXT = (
    'ركيزة استراتيجية تدعم تنفيذ القدرات السيبرانية المطلوبة '
    'وفق إطار NCA ECC/DCC'
)

REL31_ARABIC_RESIDUES = (
    'الحوادث السيبرانيةمع',
    'حوادثلا يقلعن',
    'ال معتمد',
    'المسؤول أمن السيبرانيe',
    'المسؤول أمن السيبرانيLead',
    'Lead e',
    'حلمنع',
    'المحددةفي',
    'ال معالجة',
    'بال منصات',
    'الحاليةفي',
    'الموظفينفي',
    'حلولمنع',
    'لل معالجة',
    'ل معالجة',
    'ال منقولة',
    'النقرفي',
    'الناجمةعن',
    'ال مناسبة',
    'ال مناسب',
    'ال معنية',
    'المراقبة المست',
    'segmentation-Micro',
    'CSISO',
)

_DCC_CLASSIFICATION_GAP = 'ضعف تصنيف وجرد البيانات الحساسة'
_IAM_PRIVILEGE_MARKERS = (
    'حسابات مميزة', 'حسابات متميزة', 'IAM', 'PAM', 'صلاحيات الوصول',
    'أدنى صلاحية', 'الوصول المميز',
)
_DCC_CLASSIFICATION_WRONG_MARKERS = _IAM_PRIVILEGE_MARKERS + (
    'إطار تنظيمي', 'حوكمة الأمن', 'سياسة عامة', 'ECC-1-1',
    'السياسة العامة',
)

_NEXT_SECTION_AFTER_PILLARS = (
    'البيئة التنظيمية',
    'تحليل الفجوات',
    'خارطة الطريق',
    'مؤشرات الأداء',
    'تقييم الثقة',
    'نموذج الحوكمة',
    'مصفوفة تتبع',
)

_KPI_SECTION_MARKERS = (
    'مؤشرات الأداء',
    'مؤشرات الأداء الرئيسية',
    '## 6.',
    'KPI',
)

_RISK_SECTION_MARKERS = (
    'تقييم الثقة',
    'سجل المخاطر',
    'المخاطر الرئيسية',
)

_TRACE_SECTION_MARKERS = (
    'مصفوفة تتبع',
    'مصفوفة التتبع',
    'مجال القدرة',
)

_TOC_LINE_RE = re.compile(r'^\d+\s+\S')

_GLUE_RESIDUE_PATTERNS = {
    'المراقبة المست': r'المراقبة المست(?!مر)',
}


def arabic_glue_residue_present(text: str, pat: str) -> bool:
    """Match glue residues without false positives (e.g. المستمرة)."""
    special = _GLUE_RESIDUE_PATTERNS.get(pat)
    if special:
        return bool(re.search(special, text or ''))
    return pat in (text or '')


def _line_at(text: str, pos: int) -> str:
    if pos < 0:
        return ''
    start = text.rfind('\n', 0, pos) + 1
    end = text.find('\n', pos)
    if end < 0:
        end = len(text)
    return text[start:end]


def _is_toc_line(line: str) -> bool:
    return bool(_TOC_LINE_RE.match((line or '').strip()))


def _body_section_between(
        blob: str,
        start_markers: Tuple[str, ...],
        end_markers: Tuple[str, ...],
        *,
        prefer_last: bool = False,
) -> str:
    """Slice flat export text between body section headings (skip TOC lines)."""
    text = blob or ''
    start = -1
    for marker in sorted(start_markers, key=len, reverse=True):
        pos = len(text) if prefer_last else 0
        while True:
            idx = text.rfind(marker, 0, pos) if prefer_last else text.find(marker, pos)
            if idx < 0:
                break
            if not _is_toc_line(_line_at(text, idx)):
                start = idx
                if not prefer_last:
                    break
            pos = idx - 1 if prefer_last else idx + 1
        if start >= 0:
            break
    if start < 0:
        return ''
    end = len(text)
    for marker in end_markers:
        pos = start + 20
        idx = text.find(marker, pos)
        if idx > start:
            if not _is_toc_line(_line_at(text, idx)):
                end = min(end, idx)
    return text[start:end]


def _last_non_toc_find(text: str, marker: str) -> int:
    """Last occurrence of marker that is not on a TOC line."""
    best = -1
    pos = 0
    while True:
        idx = text.find(marker, pos)
        if idx < 0:
            break
        if not _is_toc_line(_line_at(text, idx)):
            best = idx
        pos = idx + 1
    return best


def flat_pillar_initiative_blob(blob: str) -> str:
    """Pillar initiative table body from flat professional DOCX/PDF text."""
    text = blob or ''
    start = -1
    for marker in (
            'المبادرة\nالوصف\nالمخرج المتوقع\nالمسؤول',
            'المبادرة\nالوصف\nالمخرج المتوقع',
            'المخرج المتوقع\nالمسؤول\nسياسات الحوكمة',
    ):
        idx = _last_non_toc_find(text, marker)
        if idx >= 0:
            start = max(0, idx - 20)
            break
    if start < 0:
        idx = _last_non_toc_find(text, '2. الركائز الاستراتيجية')
        if idx >= 0:
            start = idx
    if start < 0:
        for needle in (
                'منصة حوكمة سيبرانية معتمدة',
                'منصة حوكمة معتمدة',
                'لجنة حوكمة فعّالة',
        ):
            idx = _last_non_toc_find(text, needle)
            if idx >= 0:
                start = max(0, idx - 200)
                break
    if start < 0:
        return ''
    end = len(text)
    for end_m in (
            'خارطة الطريق التنفيذية',
            'Implementation Roadmap',
            'المرحلة\nالفترة\nالمبادرة',
            'مؤشرات الأداء الرئيسية',
            'Key Performance Indicators',
            'التهديد / الفجوة',
    ):
        pos = start + 80
        while True:
            eidx = text.find(end_m, pos)
            if eidx < 0:
                break
            if not _is_toc_line(_line_at(text, eidx)):
                end = min(end, eidx)
                break
            pos = eidx + 1
    return text[start:end]


def flat_roadmap_initiative_blob(blob: str) -> str:
    """Roadmap initiative rows from flat export text."""
    text = blob or ''
    idx = text.rfind('المرحلة\nالفترة\nالمبادرة')
    if idx < 0:
        idx = text.rfind('المرحلة\nالفترة')
    if idx < 0:
        return ''
    end = len(text)
    for end_m in ('#\nالمؤشر', 'المؤشر\nالنوع', 'صيغة الاحتساب'):
        e = text.find(end_m, idx + 40)
        if e > idx:
            end = min(end, e)
    return text[idx:end]


def count_flat_roadmap_initiatives(blob: str) -> int:
    """Count distinct flat-export roadmap initiative rows."""
    section = flat_roadmap_initiative_blob(blob) or (blob or '')
    return len(re.findall(r'المرحلة\s*[123][:：]', section))


def flat_kpi_kri_section_blob(blob: str) -> str:
    """KPI/KRI tables from flat professional export text."""
    text = blob or ''
    start = -1
    for needle in (
            '#\nالمؤشر\nالنوع',
            'المؤشر\nالنوع\nالقيمة المستهدفة',
            'نسبة محاولات الدخول الفاشلة الشاذة',
            'متوسط زمن الكشف MTTD',
            'متوسط زمن اكتشاف الحوادث',
            'درجة مخاطر الأطراف الثالثة',
            'نضج حوكمة الأمن السيبراني وسياسات معتمدة',
            'وصف المؤشر\nالقيمة المستهدفة',
    ):
        idx = _last_non_toc_find(text, needle)
        if idx >= 0:
            start = max(0, idx - 60)
            break
    if start < 0:
        for marker in (
                'مؤشرات الأداء الرئيسية',
                'Key Performance Indicators',
        ):
            idx = _last_non_toc_find(text, marker)
            if idx >= 0:
                start = idx
                break
    if start < 0:
        return ''
    end = len(text)
    for end_m in (
            'تقييم الثقة والمخاطر',
            'Confidence Score',
            'الملاحق',
            'Appendices',
    ):
        pos = start + 120
        while True:
            eidx = text.find(end_m, pos)
            if eidx < 0:
                break
            if not _is_toc_line(_line_at(text, eidx)):
                end = min(end, eidx)
                break
            pos = eidx + 1
    return text[start:end]


def _risk_register_blob(blob: str) -> str:
    text = blob or ''
    # Flat DOCX order often places the register table after governance stubs.
    table_start = -1
    for marker in ('خطة المعالجة', 'خطة معالجة'):
        pos = 0
        while True:
            idx = text.find(marker, pos)
            if idx < 0:
                break
            if _is_toc_line(_line_at(text, idx)):
                pos = idx + 1
                continue
            ctx = text[max(0, idx - 160):idx + 60]
            if 'المخاطر' in ctx and (
                    'الاحتمالية' in ctx or 'التأثير' in ctx):
                table_start = max(0, idx - 160) + ctx.find('المخاطر')
                break
            pos = idx + 1
        if table_start >= 0:
            break
    if table_start >= 0:
        end = len(text)
        for end_m in (
                'الدور\nنطاق المسؤولية', 'نطاق المسؤولية',
                'نموذج الحوكمة والمسؤوليات', 'الملاحق'):
            idx = text.find(end_m, table_start + 80)
            if idx > table_start:
                end = min(end, idx)
        return text[table_start:end]
    return _body_section_between(
        blob,
        ('تقييم الثقة والمخاطر', 'تقييم الثقة'),
        ('مؤشرات الأداء الرئيسية', 'الملاحق'),
    )


def _trace_matrix_blob(blob: str) -> str:
    """Traceability matrix body — excludes governance roles and appendices."""
    text = blob or ''
    blocks: List[str] = []
    search = 0
    while True:
        idx = text.find('مجال القدرة', search)
        if idx < 0:
            break
        search = idx + 1
        if _is_toc_line(_line_at(text, idx)):
            continue
        header = text[idx:idx + 120]
        header_lines = header.split('\n')[:4]
        if not any('الفجوة' in ln for ln in header_lines):
            continue
        ref = text.rfind('الإطار المرجعي', max(0, idx - 200), idx)
        start = ref if ref >= 0 else idx
        end = len(text)
        nxt_ref = text.find('الإطار المرجعي', idx + 40)
        if nxt_ref > idx:
            end = min(end, nxt_ref)
        for end_m in (
                'الإطار\nالمبادرة', 'المبادرة\nالمؤشر',
                'الدور\nنطاق المسؤولية', 'الملاحق'):
            eidx = text.find(end_m, idx + 40)
            if eidx > idx:
                end = min(end, eidx)
        blocks.append(text[start:end])
    if blocks:
        section = '\n'.join(blocks)
    else:
        section = _body_section_between(
            blob,
            ('مصفوفة تتبع الأطر المرجعية', 'مصفوفة تتبع', 'مصفوفة التتبع'),
            ('الملاحق', 'Appendices'),
            prefer_last=True,
        )
    if not section.strip():
        return ''
    # Drop glossary / RACI bleed that shares capability labels.
    kept: List[str] = []
    for ln in section.splitlines():
        stripped = ln.strip()
        if stripped.startswith('•'):
            continue
        if 'Data Classification:' in ln or 'Data Governance:' in ln:
            continue
        if 'مساءَل عن' in ln or 'مساءَلة عن' in ln:
            continue
        if stripped.startswith('مدير ') and 'نطاق المسؤولية' not in ln:
            if any(r in ln for r in (
                    'مدير إدارة الهوية', 'مدير حماية البيانات',
                    'مدير حوكمة', 'مدير مركز العمليات')):
                continue
        kept.append(ln)
    return '\n'.join(kept)


def _slice_after_pillar_heading(blob: str) -> str:
    from release_engine.rel28_route_evidence import pillar_body_after_heading
    return pillar_body_after_heading(blob)


def check_missing_pillars_after_heading_flat(blob: str) -> List[str]:
    """Pillars heading present but four canonical pillar names missing after it."""
    if not any(m in (blob or '') for m in PILLAR_HEADING_MARKERS):
        return []
    section = _slice_after_pillar_heading(blob or '')
    scan = section if section.strip() else ''
    if not scan.strip():
        return ['missing_pillars_after_heading']
    missing = []
    for variants in REQUIRED_PILLAR_NAME_VARIANTS:
        if not any(v in scan for v in variants):
            missing.append(variants[0])
    if missing:
        return ['missing_pillars_after_heading']
    return []


def check_placeholder_pillar_text_in_objectives(blob: str) -> List[str]:
    text = blob or ''
    if PLACEHOLDER_PILLAR_TEXT not in text:
        return []
    if text.count(PLACEHOLDER_PILLAR_TEXT) >= 2:
        return ['placeholder_pillar_text_in_objectives']
    before = text.rsplit('الركائز الاستراتيجية', 1)[0]
    if PLACEHOLDER_PILLAR_TEXT in before:
        return ['placeholder_pillar_text_in_objectives']
    return []


def check_kpi_dlp_incident_as_percentage(blob: str) -> List[str]:
    text = blob or ''
    if 'عدد حوادث تسرب البيانات الحرجة' not in text:
        return []
    idx = text.find('عدد حوادث تسرب البيانات الحرجة')
    lines = text[idx:idx + 400].splitlines()
    if len(lines) >= 3:
        type_line = lines[1].strip().upper()
        target_line = lines[2]
        if type_line == 'KPI' and re.search(
                r'(?:100%|≥\s*\d+\s*%|≥\d+)', target_line):
            return ['kpi_dlp_incident_as_percentage']
    window = text[idx:idx + 280]
    if re.search(r'KPI', window, re.I):
        if re.search(r'(?:100%|≥\s*\d+\s*%|≥\d+)', window):
            if 'KRI' not in window.upper():
                return ['kpi_dlp_incident_as_percentage']
    if re.search(
            r'عدد حوادث تسرب البيانات الحرجة[^\n]*(?:100%|≥\s*\d+\s*%)',
            text):
        return ['kpi_dlp_incident_as_percentage']
    return []


def check_generic_kpi_formula(blob: str) -> List[str]:
    found = []
    for gf in REL27_GENERIC_FORMULAS:
        if gf in (blob or ''):
            found.append('generic_kpi_formula')
            break
    if 'المنجز المقيس' in (blob or '') and 'الهدف التشغيلي' in (blob or ''):
        found.append('generic_kpi_formula')
    return list(dict.fromkeys(found))


def _third_party_kpi_block(text: str) -> str:
    """Isolate the third-party KPI card/row without bleeding into adjacent metrics."""
    needle = 'درجة مخاطر الأطراف الثالثة'
    idx = (text or '').find(needle)
    if idx < 0:
        return ''
    lines = text[idx:].splitlines()
    block_lines = [lines[0]]
    for ln in lines[1:]:
        stripped = (ln or '').strip()
        if re.match(r'^\d+\s*$', stripped):
            break
        if re.match(r'^\|\s*\d+\s*\|', stripped):
            break
        if stripped.startswith('#'):
            break
        block_lines.append(ln)
        if len('\n'.join(block_lines)) > 160:
            break
    return '\n'.join(block_lines)


def check_third_party_risk_kpi_100(blob: str) -> List[str]:
    text = blob or ''
    block = _third_party_kpi_block(text)
    if not block:
        return []
    if re.search(r'(?:KPI|KRI)\s*\n\s*100%', block):
        return ['kpi_third_party_risk_100_percent']
    for ln in block.splitlines():
        if 'درجة مخاطر الأطراف الثالثة' not in ln:
            continue
        if re.search(r'100%', ln) and re.search(
                r'المنجز|المخطط|×\s*100', ln, re.I):
            return ['third_party_risk_completion_formula']
    window = block[:240]
    if re.search(r'KPI', window, re.I) and not re.search(r'KRI', window, re.I):
        return ['third_party_risk_as_kpi']
    return []


def check_login_anomaly_kpi_100(blob: str) -> List[str]:
    text = blob or ''
    needle = 'نسبة محاولات الدخول الفاشلة الشاذة'
    if needle not in text:
        return []
    idx = text.find(needle)
    window = text[idx:idx + 120]
    if re.search(r'KPI', window, re.I) and re.search(r'100%', window):
        return ['kpi_login_anomaly_as_100_percent']
    return []


def check_dlp_incident_nonzero_tolerance(blob: str) -> List[str]:
    text = blob or ''
    needle = 'عدد حوادث تسرب البيانات الحرجة'
    if needle not in text:
        return []
    idx = text.find(needle)
    window = text[idx:idx + 160]
    if '0 حوادث' in window:
        return []
    if re.search(r'≤\s*[1-9]|≥\s*[1-9]', window):
        return ['dlp_incident_nonzero_tolerance']
    return []


def check_empty_risk_treatment_flat(blob: str) -> List[str]:
    risk_blob = _risk_register_blob(blob)
    if not risk_blob.strip():
        return []
    in_register = False
    standalone_dash = 0
    for ln in risk_blob.splitlines():
        if any(m in ln for m in (
                'سجل المخاطر', 'المخاطر الرئيسية', 'خطة المعالجة',
                'التخفيف', 'المعالجة')):
            if not _is_toc_line(ln):
                in_register = True
        if ln.strip().startswith('##') and 'المخاطر' not in ln:
            in_register = False
        if not in_register:
            continue
        if ln.strip() in ('—', '-'):
            standalone_dash += 1
        if ln.strip().startswith('|') and '---' not in ln:
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if cells and cells[-1] in ('—', '-', ''):
                return ['empty_risk_treatment']
    if standalone_dash >= 3:
        return ['empty_risk_treatment']
    return []


def check_traceability_dcc_classification_invalid(blob: str) -> List[str]:
    trace_blob = _trace_matrix_blob(blob)
    if not trace_blob.strip() or 'تصنيف البيانات' not in trace_blob:
        return []
    for ln in trace_blob.splitlines():
        if 'تصنيف البيانات' not in ln:
            continue
        ctx_start = max(0, trace_blob.find(ln) - 20)
        ctx_end = min(len(trace_blob), trace_blob.find(ln) + len(ln) + 200)
        ctx = trace_blob[ctx_start:ctx_end]
        if _DCC_CLASSIFICATION_GAP in ctx:
            continue
        if any(m in ctx for m in _DCC_CLASSIFICATION_WRONG_MARKERS):
            return ['traceability_dcc_classification_invalid']
    for m in re.finditer(
            r'تصنيف البيانات\s*\n\s*([^\n]+)', trace_blob):
        gap_line = (m.group(1) or '').strip()
        if _DCC_CLASSIFICATION_GAP in gap_line:
            continue
        if any(i in gap_line for i in _DCC_CLASSIFICATION_WRONG_MARKERS):
            return ['traceability_dcc_classification_invalid']
    return []


def flat_traceability_bad_mappings(blob: str) -> List[str]:
    """Detect semantically wrong flat DOCX/PDF traceability gap mappings."""
    trace = _trace_matrix_blob(blob)
    if not trace.strip():
        return []
    try:
        from release_engine.traceability_substance_model import (
            _bad_mapping,
            _detect_family,
            is_diagnostic_gap_label,
            pdf_trace_extract_artifact,
        )
    except Exception:  # noqa: BLE001
        return []
    defects: List[str] = []
    lines = [ln.strip() for ln in trace.splitlines() if ln.strip()]
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith('NCA ') and i + 2 < len(lines):
            cap, gap = lines[i + 1], lines[i + 2]
            if not cap.startswith('NCA ') and not gap.startswith('NCA '):
                if not pdf_trace_extract_artifact(cap) and not pdf_trace_extract_artifact(gap):
                    if not is_diagnostic_gap_label(cap):
                        fam = _detect_family([cap, gap], 0)
                        if fam and _bad_mapping(fam, gap):
                            defects.append(f'trace_gap_mismatch:{cap}')
                i += 3
                continue
        if ln in (
                'تصنيف البيانات', 'حماية البيانات', 'الاستجابة للحوادث',
                'منع تسرب البيانات / DLP', 'DLP', 'التشفير'):
            if i + 1 < len(lines):
                nxt = lines[i + 1]
                if not pdf_trace_extract_artifact(ln) and not pdf_trace_extract_artifact(nxt):
                    if not is_diagnostic_gap_label(ln):
                        fam = _detect_family([ln, nxt], 0)
                        if fam and _bad_mapping(fam, nxt):
                            defects.append(f'trace_gap_mismatch:{ln}')
        i += 1
    return list(dict.fromkeys(defects))


def check_arabic_residue_rel31(blob: str) -> List[str]:
    text = blob or ''
    for pat in REL31_ARABIC_RESIDUES:
        if pat == 'ال معتمد':
            scrubbed = text.replace('الهدف التشغيلي المعتمد', '')
            for phrase in (
                    'أعمال معتمدة', 'خطة معتمدة', 'خطة زمنية معتمدة',
                    'معتمدة للعمليات', 'سجل بيانات مصنفة ومعتمد',
                    'بيانات حساسة معتمدة', 'ال معتمدة'):
                scrubbed = scrubbed.replace(phrase, '')
            if re.search(r'(?:^|\n)\s*ال معتمد\s*(?:\n|$)', scrubbed):
                return ['arabic_residue']
            if re.search(r'ال معتمد\s*\n\s*KPI', scrubbed):
                return ['arabic_residue']
            continue
        elif arabic_glue_residue_present(text, pat):
            return ['arabic_residue']
    if re.search(r'الحوادث السيبرانية\s*مع', text):
        return ['arabic_residue']
    if re.search(r'المسؤول أمن السيبراني\s*Lead', text, re.I):
        return ['arabic_residue']
    return []


def check_pdf_missing_pillars_structural(
        pdf_text: str,
        *,
        pdf_bytes: bytes = b'') -> List[str]:
    """Fail PDF when canonical pillar markers absent (incl. garbled extraction)."""
    from release_engine.rel28_route_evidence import pillar_body_after_heading
    if not pdf_bytes and not pdf_text:
        return []
    blob = pdf_text or ''
    found = sum(
        1 for variants in REQUIRED_PILLAR_NAME_VARIANTS
        if any(v in blob for v in variants))
    if found >= 4:
        return []
    # Prefer pillar-body slice when heading exists (card layouts may scatter names).
    body = pillar_body_after_heading(blob)
    if body.strip():
        body_found = sum(
            1 for variants in REQUIRED_PILLAR_NAME_VARIANTS
            if any(v in body for v in variants))
        if body_found >= 4:
            return []
    if pdf_bytes and len(pdf_bytes) > 10000:
        return ['missing_pillars_after_heading']
    if pdf_text and len(pdf_text.strip()) > 500:
        return ['missing_pillars_after_heading']
    return []


def run_rel31_acceptance_checks(
        blob: str,
        *,
        route: str = 'docx',
        pdf_bytes: bytes = b'') -> List[str]:
    """Return standardized REL3.1 defect codes for one export channel."""
    if not (blob or '').strip() and not pdf_bytes:
        return []
    defects: List[str] = []
    route_n = (route or 'docx').lower()

    common_fns = (
        check_missing_pillars_after_heading_flat,
        check_pillars_after_strategic_heading,
        check_placeholder_pillar_text_in_objectives,
        check_arabic_residue_rel31,
    )
    export_kpi_fns = (
        check_kpi_dlp_incident_as_percentage,
        check_generic_kpi_formula,
        check_third_party_risk_kpi_100,
    )
    export_other_fns = (
        check_empty_risk_treatment_flat,
        check_traceability_dcc_classification_invalid,
    )

    for fn in common_fns:
        defects.extend(fn(blob or ''))

    if route_n in ('docx', 'pdf'):
        kpi_blob = flat_kpi_kri_section_blob(blob or '')
        kpi_target = kpi_blob if kpi_blob.strip() else (blob or '')
        for fn in export_kpi_fns:
            defects.extend(fn(kpi_target))
        for fn in export_other_fns:
            defects.extend(fn(blob or ''))

    if route_n == 'pdf':
        defects.extend(
            check_pdf_missing_pillars_structural(
                blob or '', pdf_bytes=pdf_bytes))

    return list(dict.fromkeys(defects))


def rel31_blockers(route: str, defects: List[str]) -> List[str]:
    route_n = (route or 'docx').lower()
    return [
        f'rel3_export_evidence_failed:{route_n}:{d}'
        for d in defects
    ]


def repair_rel31_canonical_sections(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        backend: Dict[str, Any] | None = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Canonical repairs before RenderTree — not exported-byte patches."""
    from release_engine.pillar_model import _build_canonical_pillars, finalize_pillars
    from release_engine.rendered_evidence_validator import (
        repair_sections_for_rendered_evidence,
    )

    backend = dict(backend or {})
    repairs: List[str] = []
    out = dict(sections or {})

    vision = out.get('vision', '') or ''
    if PLACEHOLDER_PILLAR_TEXT in vision:
        lines = [
            ln for ln in vision.splitlines()
            if PLACEHOLDER_PILLAR_TEXT not in ln]
        out['vision'] = '\n'.join(lines).strip()
        repairs.append('rel31:removed_placeholder_pillar_from_objectives')

    out['pillars'] = _build_canonical_pillars(lang)
    out, pil_diag = finalize_pillars(
        out, lang=lang, domain=domain, backend=backend)
    if pil_diag.get('action_taken'):
        repairs.append(f'rel31:{pil_diag.get("action_taken")}')

    out = repair_sections_for_rendered_evidence(
        out, lang=lang, domain=domain, backend=backend)
    repairs.append('rel31:rendered_evidence_repair_pipeline')

    try:
        from release_engine.rel31_content_substance_checks import (
            repair_rel31_content_substance,
        )
        out, sub_rep = repair_rel31_content_substance(
            out, lang=lang, domain=domain, backend=backend)
        repairs.extend(sub_rep)
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine_v3.rel31_authority import validate_rel3_objectives
        backend.setdefault('app_module', backend.get('app_module'))
        obj = validate_rel3_objectives(out, backend=backend)
        out = obj.get('sections') or out
        if obj.get('valid'):
            repairs.append('rel31:objectives_validated')
        elif backend.get('baseline_strategic_objectives'):
            try:
                fws = backend.get('selected_frameworks') or []
                out, _so_diag = backend['baseline_strategic_objectives'](
                    out, lang, fws)
                repairs.append('rel31:baseline_strategic_objectives')
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass

    rows = len(re.findall(r'^\|\s*\d+\s*\|', out.get('vision', '') or '', re.M))
    if rows < 6 and backend.get('baseline_strategic_objectives'):
        try:
            fws = backend.get('selected_frameworks') or []
            out, _so_diag = backend['baseline_strategic_objectives'](
                out, lang, fws)
            repairs.append('rel31:baseline_strategic_objectives_forced')
        except Exception:  # noqa: BLE001
            pass

    try:
        from release_engine_v3.rel31_authority import _rel31_inject_missing_so_families
        out = _rel31_inject_missing_so_families(out, backend=backend)
        repairs.append('rel31:so_family_injection')
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine_v3.document_quality_spec import (
            repair_document_quality_sections,
        )
        out, dqs_rep = repair_document_quality_sections(
            out, lang=lang, domain=domain, backend=backend)
        repairs.extend(dqs_rep)
    except Exception:  # noqa: BLE001
        pass

    return out, list(dict.fromkeys(repairs))
