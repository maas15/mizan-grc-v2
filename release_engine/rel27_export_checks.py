"""PR-REL2.7 — fail-closed checks on actual exported DOCX/PDF/preview text."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from release_engine.roadmap_model import (
    FORBIDDEN_OWNERS,
    ROADMAP_FAMILIES,
    _FAMILY_TOKENS,
    _detect_families,
    _parse_roadmap_rows,
    _row_blob,
)
from release_engine.rendered_evidence_validator import (
    _CSIRT_GAP,
    _DCC_DATA_PROT_GAP,
    _DCC_DLP_GAP,
    _GENERIC_FORMULA_VARIANTS,
)

# Four Cyber pillars — accept canonical heading variants in exported text.
REQUIRED_PILLAR_NAME_VARIANTS: Tuple[Tuple[str, ...], ...] = (
    ('الحوكمة ونموذج التشغيل', 'حوكمة ونموذج التشغيل'),
    ('الحماية والكشف والاستجابة',),
    ('الهوية وحماية البيانات',),
    ('المرونة واستمرارية الأعمال',),
)

REL27_GENERIC_FORMULAS = (
    '(القيمة المحققة / القيمة المستهدفة) × 100',
    '(القيمة المحققة/القيمة المستهدفة) × 100',
    '(المنجز / المخطط) × 100',
    '(المنجز المقيس ÷ الهدف التشغيلي المعتمد) × 100',
    '(عدد العناصر المطابقة / إجمالي العناصر) × 100',
    '(عدد العناصر المطابقة/إجمالي العناصر) × 100',
) + _GENERIC_FORMULA_VARIANTS

_ARABIC_RESIDUE_ALLOWLIST = (
    'أعمال معتمدة',
    'خطة معتمدة',
    'خطة زمنية معتمدة',
    'معتمدة للعمليات',
    'سجل بيانات مصنفة ومعتمد',
    'بيانات حساسة معتمدة',
    'إجراءات معالجة بيانات حساسة معتمدة',
)

REL27_ARABIC_RESIDUES = (
    'الحاليةفي',
    'الموظفينفي',
    'رئيسيةفي',
    'ال منظمة',
    'ال معلومات',
    'ال معمول',
    'ال معتمدة',
    'ال معيارية',
    'ل منع',
    'لل معالجة',
    'حلولمنع',
)

REL27_WEAK_ROADMAP_OUTPUTS = (
    'مخرج تشغيلي معتمد ومقاس',
    'مخرج تشغيلي',
)

REL27_EMPTY_TREATMENT = frozenset({
    '—', '-', '', 'TBD', 'tbd', 'سيتم لاحقاً', 'سيتم لاحقا',
})

_KPI_SECTION_RE = re.compile(
    r'##\s*(?:6\.?\s*)?(?:مؤشرات|KPI|KRI)',
    re.IGNORECASE,
)
_FORMULA_SECTION_RE = re.compile(
    r'صيغ(?:ة|ات)\s+الاحتساب|formula',
    re.IGNORECASE,
)


def _pillar_heading_present(blob: str) -> bool:
    return 'الركائز الاستراتيجية' in blob or (
        'الركائز' in blob and 'استراتيج' in blob)


def check_missing_pillars(blob: str) -> List[str]:
    """Block when pillars heading exists but pillar names are absent."""
    if not _pillar_heading_present(blob or ''):
        return []
    missing: List[str] = []
    for variants in REQUIRED_PILLAR_NAME_VARIANTS:
        if not any(v in (blob or '') for v in variants):
            missing.append(variants[0])
    if missing:
        return ['missing_pillars']
    return []


def _kpi_section_blob(blob: str) -> str:
    """Extract the primary KPI section — prefer the richest table block."""
    lines = (blob or '').splitlines()
    candidates: List[List[str]] = []
    current: List[str] = []
    in_kpi = False
    for ln in lines:
        if _KPI_SECTION_RE.search(ln):
            if current:
                candidates.append(current)
            in_kpi = True
            current = [ln]
            continue
        if in_kpi and ln.strip().startswith('##') and not ln.strip().startswith('###'):
            if 'صيغ' not in ln and 'formula' not in ln.lower():
                if 'مؤشر' in ln or 'kpi' in ln.lower():
                    current.append(ln)
                    continue
                candidates.append(current)
                current = []
                in_kpi = False
                continue
        if in_kpi:
            current.append(ln)
    if current:
        candidates.append(current)

    def _data_rows(sec_lines: List[str]) -> int:
        count = 0
        for ln in sec_lines:
            if not ln.strip().startswith('|') or '---' in ln:
                continue
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if cells and (cells[0].isdigit() or re.match(r'^NCA\s', cells[0], re.I)):
                count += 1
        return count

    if not candidates:
        return ''
    best = max(candidates, key=_data_rows)
    return '\n'.join(best)


def _extract_kpi_main_rows(blob: str) -> List[List[str]]:
    rows: List[List[str]] = []
    section = _kpi_section_blob(blob)
    if not section:
        return rows
    in_formula = False
    main_data_started = False
    for ln in section.splitlines():
        if ln.strip().startswith('##'):
            if re.search(r'صيغ|formula|\bkri\b', ln, re.I):
                if ln.strip().startswith('###') and not main_data_started:
                    continue
                if main_data_started:
                    in_formula = True
            continue
        if in_formula:
            continue
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if not cells:
            continue
        if cells[0] in ('#', 'رقم', 'وصف المؤشر'):
            if main_data_started:
                break
            continue
        if cells[0].isdigit() or re.match(r'NCA\s', cells[0], re.I):
            rows.append(cells)
            main_data_started = True
    if rows:
        return rows
    # Plain DOCX/PDF text — lines without markdown pipes.
    buf: List[str] = []
    for ln in section.splitlines():
        t = ln.strip()
        if not t or t.startswith('##'):
            continue
        if re.match(r'^(?:NCA\s*(?:DCC|ECC)|\d+)\b', t, re.I):
            if buf:
                rows.append(buf)
            buf = [t]
        elif buf:
            buf.append(t)
            if len(buf) >= 3:
                rows.append(buf)
                buf = []
    if buf and len(buf) >= 2:
        rows.append(buf)
    return rows


def parse_flat_professional_kpi_cards(section: str) -> List[Dict[str, str]]:
    """Card-style KPI rows from professional flat export (number/name/type/target)."""
    rows: List[Dict[str, str]] = []
    lines = [ln.strip() for ln in (section or '').splitlines()]
    i = 0
    while i < len(lines):
        if re.match(r'^\d+$', lines[i]):
            if i + 2 >= len(lines):
                break
            name, typ = lines[i + 1], lines[i + 2]
            target = lines[i + 3] if i + 3 < len(lines) else ''
            if name and name not in ('#', 'المؤشر', 'النوع', 'القيمة المستهدفة'):
                rows.append({
                    'num': lines[i],
                    'name': name,
                    'type': typ,
                    'target': target,
                })
                i += 4
                continue
        i += 1
    return rows


def _count_kpi_tables(blob: str) -> Tuple[int, int]:
    """Return (main_kpi_table_count, formula_table_count)."""
    section = _kpi_section_blob(blob or '')
    if not section:
        return 0, 0
    has_pipes = '|' in section
    main = 0
    formula = 0
    if has_pipes:
        in_formula = False
        saw_main_header = False
        saw_formula_header = False
        saw_main_data = False
        for ln in section.splitlines():
            if ln.strip().startswith('##') and re.search(
                    r'صيغ|formula|\bkri\b', ln, re.I):
                if ln.strip().startswith('###') and not saw_main_data:
                    continue
                if saw_main_header or saw_main_data:
                    in_formula = True
                    saw_formula_header = False
                continue
            if not ln.strip().startswith('|') or '---' in ln:
                continue
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if in_formula:
                if not saw_formula_header and cells[0] in ('#', 'رقم'):
                    saw_formula_header = True
                    formula = 1
            else:
                if not saw_main_header and (
                        cells[0] in ('#', 'رقم') or 'وصف المؤشر' in ln):
                    saw_main_header = True
                    main = 1
                elif cells[0].isdigit() or re.match(r'^NCA\s', cells[0], re.I):
                    saw_main_data = True
    if main == 0 and _extract_kpi_main_rows(blob):
        main = 1
    if formula == 0 and (
            'صيغة الاحتساب' in section
            or 'formula' in section.lower()):
        formula = 1
    return main, formula


def check_kpi_canonical(blob: str) -> Dict[str, Any]:
    """Validate exported KPI main + formula tables from one canonical model."""
    kpi_section = _kpi_section_blob(blob or '')
    section_has_kpi = bool(kpi_section.strip())
    rows = _extract_kpi_main_rows(blob or '')
    main_count, formula_count = _count_kpi_tables(blob or '')
    duplicate_metrics: List[str] = []
    generic_formulas: List[str] = []
    semantic_defects: List[str] = []

    mttr_count = 0
    numbers: List[int] = []
    for cells in rows:
        num = cells[0] if cells else ''
        if num.isdigit():
            numbers.append(int(num))
        name = cells[1] if len(cells) > 1 else (cells[0] if len(cells) == 1 else '')
        target = cells[2] if len(cells) > 2 else ''
        formula = cells[3] if len(cells) > 3 else ''
        row_blob = ' '.join(cells)
        if re.match(r'^NCA\s*(DCC|ECC)\b', str(num).strip(), re.I):
            semantic_defects.append('framework_code_in_kpi_number_column')
        if re.search(r'\bMTTR\b', name, re.I):
            mttr_count += 1
        if 'عدد حوادث تسرب البيانات الحرجة' in name:
            if '%' in target and 'حوادث' not in target:
                semantic_defects.append('dlp_incident_kpi_percent_target')
        blob_line = '|'.join(cells)
        for gf in REL27_GENERIC_FORMULAS:
            if gf in blob_line or gf in formula:
                generic_formulas.append('generic_formula')
    if mttr_count > 1:
        duplicate_metrics.append('duplicate_MTTR')
    if main_count > 1:
        semantic_defects.append('duplicated_kpi_sections')
    if formula_count > 1:
        semantic_defects.append('duplicated_formula_sections')
    if rows and formula_count and main_count and formula_count != main_count:
        semantic_defects.append('formula_table_count_mismatch')
    numbering_valid = True
    if numbers:
        numbering_valid = (
            len(numbers) == len(set(numbers))
            and min(numbers) >= 1
            and max(numbers) <= len(numbers) + 3)

    payload = {
        'exported_kpi_table_count': main_count,
        'exported_formula_table_count': formula_count,
        'numbering_valid': numbering_valid,
        'duplicate_metrics': list(dict.fromkeys(duplicate_metrics)),
        'generic_formulas': list(dict.fromkeys(generic_formulas)),
        'semantic_defects': list(dict.fromkeys(semantic_defects)),
    }
    defects: List[str] = []
    defects.extend(payload['duplicate_metrics'])
    defects.extend(payload['generic_formulas'])
    defects.extend(payload['semantic_defects'])
    if not numbering_valid:
        defects.append('kpi_numbering_invalid')
    if main_count > 1:
        defects.append(f'exported_kpi_table_count:{main_count}')
    elif main_count == 0 and section_has_kpi:
        defects.append('exported_kpi_table_count:0')
    if formula_count > 1:
        defects.append(f'exported_formula_table_count:{formula_count}')
    payload['defects'] = list(dict.fromkeys(defects))
    payload['exported_kpi_canonical_valid'] = not defects
    return payload


def _roadmap_section_blob(blob: str) -> str:
    lines: List[str] = []
    in_roadmap = False
    for ln in (blob or '').splitlines():
        if 'خارطة الطريق' in ln or 'Implementation Roadmap' in ln:
            in_roadmap = True
            lines = [ln]
            continue
        if in_roadmap and ln.strip().startswith('##'):
            break
        if in_roadmap:
            lines.append(ln)
    return '\n'.join(lines)


def _roadmap_rows_from_blob(blob: str) -> List[Dict[str, str]]:
    section = _roadmap_section_blob(blob or '')
    return _parse_roadmap_rows(section)


def _dedupe_row_key(row: Dict[str, str]) -> str:
    return _row_blob(row).strip()


def check_roadmap_coverage(blob: str) -> Dict[str, Any]:
    """Count visible roadmap rows and required families from exported text."""
    rows = _roadmap_rows_from_blob(blob or '')
    seen: Dict[str, int] = {}
    unique_rows: List[Dict[str, str]] = []
    duplicates: List[str] = []
    for row in rows:
        key = _dedupe_row_key(row)
        if key in seen:
            duplicates.append(key[:80])
            continue
        seen[key] = 1
        unique_rows.append(row)

    present = _detect_families(unique_rows)
    section = _roadmap_section_blob(blob or '')
    scan_blob = (blob or '') if 'خارطة الطريق' in (blob or '') else (section or '')
    if scan_blob:
        low = scan_blob.lower()
        for fam, tokens in _FAMILY_TOKENS.items():
            if present.get(fam):
                continue
            if any(
                    (t.lower() in low if t.isascii() else t in scan_blob)
                    for t in tokens):
                present[fam] = True
    missing_families = [f for f in ROADMAP_FAMILIES if not present.get(f)]
    weak_outputs: List[str] = []
    weak_owners: List[str] = []
    for row in unique_rows:
        out = (row.get('output') or row.get('المخرج') or '').strip()
        owner = (row.get('owner') or row.get('المسؤول') or '').strip()
        if any(w in out for w in REL27_WEAK_ROADMAP_OUTPUTS):
            weak_outputs.append(out[:60])
        if owner in FORBIDDEN_OWNERS or len(owner) < 3:
            weak_owners.append(owner or 'empty_owner')

    visible_count = max(len(unique_rows), sum(1 for f in ROADMAP_FAMILIES if present.get(f)))
    defects: List[str] = []
    if visible_count < 10:
        defects.append(f'roadmap_row_count:{visible_count}')
    if duplicates:
        defects.append('roadmap_duplicate_rows')
    for fam in missing_families:
        defects.append(f'missing_family:{fam}')
    if weak_outputs:
        defects.append('roadmap_weak_output')
    if weak_owners:
        defects.append('roadmap_weak_owner')

    payload = {
        'visible_row_count': visible_count,
        'distinct_row_count': visible_count,
        'duplicate_rows': list(dict.fromkeys(duplicates))[:8],
        'missing_families': missing_families,
        'weak_outputs': list(dict.fromkeys(weak_outputs))[:8],
        'weak_owners': list(dict.fromkeys(weak_owners))[:8],
        'defects': defects,
        'exported_roadmap_coverage_valid': not defects,
    }
    return payload


def check_risk_treatment_exported(blob: str) -> List[str]:
    defects: List[str] = []
    in_risk = False
    for ln in (blob or '').splitlines():
        low = ln.lower()
        if any(k in ln for k in (
                'تقييم الثقة', 'سجل المخاطر', 'confidence risk')):
            in_risk = True
        if in_risk and ln.strip().startswith('##') and not any(
                k in ln for k in ('ثقة', 'مخاطر', 'confidence')):
            in_risk = False
        if not in_risk:
            continue
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        if 'خطة المعالجة' in ln or 'treatment' in low:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if len(cells) < 4:
            continue
        treatment = cells[-1]
        if treatment in REL27_EMPTY_TREATMENT:
            defects.append('empty_risk_treatment')
    return list(dict.fromkeys(defects))


def check_traceability_semantics(blob: str) -> List[str]:
    bad: List[str] = []
    in_trace = False
    for ln in (blob or '').splitlines():
        if 'مصفوفة التتبع' in ln or 'traceability' in ln.lower():
            in_trace = True
        if in_trace and ln.strip().startswith('##') and 'مصفوفة' not in ln:
            in_trace = False
        if not in_trace:
            continue
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        cap = cells[1] if len(cells) > 1 else ''
        gap = cells[2] if len(cells) > 2 else ''
        if 'حماية البيانات' in cap:
            if _DCC_DATA_PROT_GAP not in gap and (
                    'DLP' in gap.upper()
                    or gap.strip().upper() == 'DLP'
                    or ('منع تسرب' in gap and _DCC_DATA_PROT_GAP not in gap)):
                bad.append('dcc_data_protection_dlp_only')
        if cap.strip().upper() == 'DLP' or (
                'منع تسرب' in cap and 'DCC' in ln.upper()):
            if gap in REL27_EMPTY_TREATMENT or _DCC_DLP_GAP not in gap:
                if gap in REL27_EMPTY_TREATMENT:
                    bad.append('dcc_dlp_gap_blank')
                elif _DCC_DLP_GAP not in gap:
                    bad.append('dcc_dlp_gap_weak')
        if 'الاستجابة للحوادث' in cap or 'الاستجابة للحوادث' in ln:
            if _CSIRT_GAP not in gap:
                if any(p in gap for p in (
                        'عدم وجود مركز عمليات أمنية', 'نقص مركز SOC')):
                    bad.append('ecc_incident_soc_only_gap')
                if re.search(r'SOC\s*CSIRT|CSIRT\s*SOC', ln, re.I):
                    bad.append('ecc_incident_mixed_soc_csirt')
        if gap in REL27_EMPTY_TREATMENT:
            bad.append('traceability_gap_blank')
    if 'CSIRT SOC' in (blob or '') or 'SOC CSIRT' in (blob or ''):
        bad.append('traceability_mixed_soc_csirt')
    if re.search(
            r'SOC\s*\(\s*CSIRT\s*\)|CSIRT\s*\(\s*SOC\s*\)', blob or '', re.I):
        bad.append('traceability_mixed_soc_csirt')
    return list(dict.fromkeys(bad))


def _contains_arabic_residue(blob: str, pattern: str) -> bool:
    if not pattern or not blob:
        return False
    scrubbed = blob
    if pattern == 'ال معتمدة':
        for phrase in _ARABIC_RESIDUE_ALLOWLIST:
            scrubbed = scrubbed.replace(phrase, '')
    return pattern in scrubbed


def check_arabic_residues_exported(blob: str) -> Dict[str, Any]:
    found = [
        p for p in REL27_ARABIC_RESIDUES
        if _contains_arabic_residue(blob or '', p)]
    glue_re = re.compile(
        r'(?:الحالية|الموظفين|رئيسية|حلول)(?=في)'
        r'|(?:^|[\s\u200f\u200e\u200b\u200c\u200d\u00a0\u202f])'
        r'ال[\s\u200f\u200e\u200b\u200c\u200d\u00a0\u202f]+'
        r'(?:منظمة|معلومات|معمول|معتمدة|معتمد|معيارية|مناسبة|مناسب)'
        r'|لل[\s\u200f\u200e\u200b\u200c\u200d\u00a0\u202f]+معالجة'
        r'|حلولمنع',
        re.UNICODE,
    )
    if glue_re.search(blob or ''):
        found.append('arabic_glued_particle')
    payload = {
        'residues_found': list(dict.fromkeys(found)),
        'exported_arabic_quality_valid': not found,
    }
    return payload


def _section_key_from_heading(ln: str) -> Optional[str]:
    low = (ln or '').lower()
    if 'رؤية' in ln or 'أهداف' in ln or 'vision' in low:
        return 'vision'
    if 'ركائز' in ln or 'pillar' in low:
        return 'pillars'
    if 'خارطة' in ln or 'roadmap' in low:
        return 'roadmap'
    if 'مؤشر' in ln or 'kpi' in low:
        return 'kpis'
    if 'تتبع' in ln or 'traceability' in low:
        return 'traceability'
    return None


def _split_sections_from_export_text(text: str) -> Dict[str, str]:
    """Extract legacy section blobs from combined export/preview markdown."""
    sections: Dict[str, str] = {}
    current: Optional[str] = None
    buf: List[str] = []
    for ln in (text or '').splitlines():
        if ln.strip().startswith('##'):
            new_key = _section_key_from_heading(ln)
            if new_key and new_key == current:
                buf.append(ln)
                continue
            if current and buf:
                sections[current] = '\n'.join(buf).strip()
            current = new_key
            buf = [ln] if current else []
        elif current:
            buf.append(ln)
    if current and buf:
        sections[current] = '\n'.join(buf).strip()
    return sections


def check_export_model_drift(
        canonical_sections: Optional[Dict[str, str]],
        preview_text: str,
        docx_text: str,
        pdf_text: str = '',
        *,
        hash_fn=None,
) -> List[str]:
    """Block when canonical section hashes diverge from actual exported text."""
    from release_engine.section_parity import (
        PARITY_SECTION_KEYS,
        _LEGACY_MAP,
        _section_hash,
    )

    if not canonical_sections:
        return []
    blockers: List[str] = []
    canon_hashes = {
        k: _section_hash(
            (canonical_sections.get(_LEGACY_MAP[k]) or '').strip(), hash_fn)
        for k in PARITY_SECTION_KEYS
    }
    for label, text in (
            ('preview', preview_text),
            ('docx', docx_text),
            ('pdf', pdf_text),
    ):
        if not text:
            continue
        split = _split_sections_from_export_text(text)
        for key in PARITY_SECTION_KEYS:
            legacy = _LEGACY_MAP[key]
            exported = (split.get(legacy) or '').strip()
            eh = _section_hash(exported, hash_fn)
            ch = canon_hashes.get(key, '')
            if ch and eh and ch != eh:
                blockers.append(f'rel2_export_model_drift:{key}:{label}')
    return blockers


def emit_exported_kpi_canonical_check(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-EXPORTED-KPI-CANONICAL-CHECK] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def emit_exported_roadmap_coverage_check(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-EXPORTED-ROADMAP-COVERAGE-CHECK] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def emit_exported_arabic_residue_check(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-EXPORTED-ARABIC-RESIDUE-CHECK] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def rel27_channel_checks(blob: str) -> Dict[str, Any]:
    """Run all REL2.7 exported-text checks for one channel."""
    if not blob:
        return {
            'missing_sections': [],
            'kpi_defects': [],
            'roadmap_defects': [],
            'risk_defects': [],
            'traceability_defects': [],
            'arabic_residues': [],
            'kpi_canonical': {},
            'roadmap_coverage': {},
            'arabic_check': {},
        }
    missing = check_missing_pillars(blob)
    has_kpi = bool(_kpi_section_blob(blob).strip()) or 'مؤشرات' in blob
    has_roadmap = 'خارطة الطريق' in blob or 'Implementation Roadmap' in blob
    has_risk = any(k in blob for k in ('تقييم الثقة', 'سجل المخاطر'))
    has_trace = 'مصفوفة التتبع' in blob or 'traceability' in blob.lower()

    kpi_canonical = check_kpi_canonical(blob) if has_kpi else {}
    roadmap = check_roadmap_coverage(blob) if has_roadmap else {}
    risk = check_risk_treatment_exported(blob) if has_risk else []
    trace = check_traceability_semantics(blob) if has_trace else []
    arabic = check_arabic_residues_exported(blob)

    missing_sections: List[str] = []
    if missing:
        missing_sections.append('pillars')

    kpi_defects = list(kpi_canonical.get('defects') or [])
    roadmap_defects = list(roadmap.get('defects') or [])
    risk_defects = risk
    traceability_defects = trace
    arabic_residues = list(arabic.get('residues_found') or [])

    return {
        'missing_sections': missing_sections,
        'kpi_defects': kpi_defects,
        'roadmap_defects': roadmap_defects,
        'risk_defects': risk_defects,
        'traceability_defects': traceability_defects,
        'arabic_residues': arabic_residues,
        'kpi_canonical': kpi_canonical,
        'roadmap_coverage': roadmap,
        'arabic_check': arabic,
    }
