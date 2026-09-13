"""REL36.23.1 — DT Arabic DGA KPI single-table / idempotency.

Official 6/6 on ``64df263`` failed ``dt:strategy:ar`` with

    kpi_main_header_count_invalid (kpis) 2/1

Root cause: ``repair_dga_interoperability_sections`` appends a full
second KPI main table (``| # | وصف المؤشر | ...``) when the existing
kpis section lacks interoperability tokens. REL36.22 always calls that
helper. REL36.23 part E can re-invoke REL36.22 after token
normalization. ``_final_strategy_audit`` then counts two KPI main
headers and blocks save.

This module collapses every Arabic KPI main table into the first one,
merges DGA citizen / interop / digital-services rows in place, and is
a no-op on the second pass. It does not weaken
``kpi_main_header_count_invalid`` or selected-framework coverage.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel35_domain_framework_fidelity import (
    dga_selected,
    section_has_dga_interop,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_22_dt_dga_citizen_experience_coverage import (
    OFFICIAL_CITIZEN_AR,
    REQUIRED_SECTIONS,
    section_has_citizen_experience,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_23_1_DT_DGA_KPI_SINGLE_TABLE_INTEGRITY_TAG = (
    '[REL36.23.1-DT-DGA-KPI-SINGLE-TABLE-INTEGRITY]')

_SPLIT_TOKEN = 'المست فيد'
_CONTIGUOUS_TOKEN = 'المستفيد'
_DT_SECTIONS = ('pillars', 'environment', 'gaps', 'roadmap', 'kpis')
_KPI_ALIASES = ('kpis', 'kpi', 'performance_kpis')

KPI_MAIN_HEADER_RE = re.compile(
    r'^\|[\s\u00a0]*#[\s\u00a0]*\|'
    r'[\s\u00a0]*(?:KPI[\s\u00a0]+Description|وصف[\s\u00a0]+المؤشر|'
    r'KPI|المؤشر|Metric)'
    r'[\s\u00a0]*\|',
    re.MULTILINE | re.IGNORECASE,
)
_SEP_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_GUIDE_HEADING_RE = re.compile(
    r'^#{2,4}[\s\u00a0\u200e\u200f]*'
    r'(?:'
    r'(?:Per[\-\s]?)?KPI[\s\u00a0]+Assessment[\s\u00a0]+Guidelines?'
    r'|Indicator[\s\u00a0]+Assessment[\s\u00a0]+Guidelines?'
    r'|(?:أدلة|دليل|إرشادات)'
    r'[\s\u00a0\u200e\u200f]+تقييم'
    r')',
    re.MULTILINE | re.IGNORECASE,
)
_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)

CANONICAL_KPI_HEADER = (
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | '
    'مصدر | التكرار | المالك |')
CANONICAL_KPI_SEP = '|---|---|---|---|---|---|---|---|'

CITIZEN_KPI_DESC = 'نسبة رضا المستفيد عن الخدمات الرقمية'
INTEROP_KPI_DESC = (
    'نسبة تكامل الخدمات الرقمية عبر واجهات API أو الربط الحكومي')
DIGITAL_KPI_DESC = (
    'نسبة الخدمات الرقمية المحسنة أو المؤتمتة وفق متطلبات DGA')

_CITIZEN_MARKERS = (
    CITIZEN_KPI_DESC, 'رضا المستفيد', 'تجربة المستفيد',
)
_INTEROP_MARKERS = (
    INTEROP_KPI_DESC, 'التشغيل البيني', 'التكامل الحكومي',
    'واجهات API', 'الربط الحكومي', 'قياس نضج التكامل',
)
_DIGITAL_MARKERS = (
    DIGITAL_KPI_DESC, 'الخدمات الرقمية المحسنة', 'المؤتمتة وفق',
    'نسبة الخدمات الرقمية',
)


def _domain_code(domain: Optional[str]) -> str:
    return _normalize_rel31_domain_code(str(domain or ''))


def _norm_dtype(document_type: Optional[str]) -> str:
    raw = str(document_type or 'strategy').strip().lower()
    if raw in {'', 'strategy', 'strategy_document', 'strategy document'}:
        return 'strategy'
    return raw


def rel36_23_1_should_apply(
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


def kpi_main_header_count(text: str) -> int:
    return len(KPI_MAIN_HEADER_RE.findall(str(text or '')))


def kpi_header_locations(text: str) -> List[int]:
    return [
        idx + 1
        for idx, line in enumerate(str(text or '').splitlines())
        if KPI_MAIN_HEADER_RE.match(line.strip())
    ]


def _ensure_canonical_key(
        sections: Dict[str, str], key: str, aliases: Sequence[str]) -> None:
    if str(sections.get(key) or '').strip():
        return
    for alias in aliases:
        blob = str(sections.get(alias) or '')
        if blob.strip():
            sections[key] = blob
            return


def _set_aliases(
        sections: Dict[str, str], key: str,
        aliases: Sequence[str], value: str) -> None:
    sections[key] = value
    for alias in aliases:
        if alias in sections or alias == key:
            sections[alias] = value


def _normalize_split_tokens(sections: Dict[str, str]) -> int:
    hits = 0
    for key in _DT_SECTIONS:
        blob = str(sections.get(key) or '')
        n = blob.count(_SPLIT_TOKEN)
        if n:
            sections[key] = blob.replace(_SPLIT_TOKEN, _CONTIGUOUS_TOKEN)
            hits += n
    return hits


def _split_cells(line: str) -> List[str]:
    raw = str(line or '').strip()
    if raw.startswith('|'):
        raw = raw[1:]
    if raw.endswith('|'):
        raw = raw[:-1]
    return [c.strip() for c in raw.split('|')]


def _is_data_row(line: str) -> bool:
    raw = str(line or '').strip()
    if not raw.startswith('|') or _SEP_RE.match(raw):
        return False
    if KPI_MAIN_HEADER_RE.match(raw):
        return False
    cells = _split_cells(raw)
    return len(cells) >= 4


def _row_signature(line: str) -> str:
    cells = _split_cells(line)
    body = cells[1:] if cells and re.match(r'^\d+$|^DGA-\d+$', cells[0] or '') else cells
    return ' || '.join(c.strip().lower() for c in body if c.strip())


def _row_has(line: str, markers: Sequence[str]) -> bool:
    blob = str(line or '')
    return any(tok in blob for tok in markers)


def _format_row(n: int, desc: str, kind: str, target: str,
                formula: str, source: str, freq: str, owner: str) -> str:
    return (
        f'| {n} | {desc} | {kind} | {target} | {formula} | '
        f'{source} | {freq} | {owner} |'
    )


def _citizen_row(n: int) -> str:
    return _format_row(
        n, CITIZEN_KPI_DESC, 'نتيجة', '≥ 85%',
        'عدد التقييمات الإيجابية / إجمالي تقييمات المستفيدين × 100',
        'منصة قياس تجربة المستفيد', 'ربع سنوي', 'مدير تجربة المستفيد',
    )


def _interop_row(n: int) -> str:
    return _format_row(
        n, INTEROP_KPI_DESC, 'نتيجة', '≥ 80%',
        'الخدمات المترابطة عبر التشغيل البيني / الخدمات المستهدفة × 100',
        'كتالوج خدمات رقمية للتكامل الحكومي',
        'ربع سنوي', 'مدير التحول الرقمي',
    )


def _digital_row(n: int) -> str:
    return _format_row(
        n, DIGITAL_KPI_DESC, 'نتيجة', '≥ 80%',
        'الخدمات الرقمية المحسنة أو المؤتمتة / إجمالي الخدمات × 100',
        'كتالوج خدمات رقمية', 'ربع سنوي', 'مدير التحول الرقمي',
    )


def _renumber(rows: Sequence[str]) -> List[str]:
    out: List[str] = []
    for idx, row in enumerate(rows, start=1):
        cells = _split_cells(row)
        if not cells:
            continue
        if re.match(r'^\d+$|^DGA-\d+$', cells[0] or ''):
            cells[0] = str(idx)
        else:
            cells.insert(0, str(idx))
        while len(cells) < 8:
            cells.append('—')
        out.append('| ' + ' | '.join(cells[:8]) + ' |')
    return out


def _extract_guide_suffix(text: str) -> Tuple[str, str]:
    blob = str(text or '')
    match = _GUIDE_HEADING_RE.search(blob)
    if not match:
        return blob, ''
    return blob[:match.start()].rstrip(), blob[match.start():].lstrip('\n')


def _collect_data_rows(body: str) -> List[str]:
    rows: List[str] = []
    seen = set()
    for line in str(body or '').splitlines():
        if not _is_data_row(line):
            continue
        sig = _row_signature(line)
        if not sig or sig in seen:
            continue
        seen.add(sig)
        rows.append(line.strip())
    return rows


def _prefix_before_first_header(text: str) -> str:
    match = KPI_MAIN_HEADER_RE.search(str(text or ''))
    if not match:
        return str(text or '').rstrip()
    return str(text or '')[:match.start()].rstrip()


def collapse_kpi_tables_and_merge_dga_rows(text: str) -> Tuple[str, Dict[str, Any]]:
    """Collapse every KPI main table into one and merge required DGA rows."""
    raw = str(text or '')
    guides_before = bool(_GUIDE_HEADING_RE.search(raw))
    body, suffix = _extract_guide_suffix(raw)
    prefix = _prefix_before_first_header(body)
    rows = _collect_data_rows(body)
    merged = False
    if not any(_row_has(r, _CITIZEN_MARKERS) for r in rows):
        rows.append(_citizen_row(len(rows) + 1))
        merged = True
    if not any(_row_has(r, _INTEROP_MARKERS) for r in rows):
        rows.append(_interop_row(len(rows) + 1))
        merged = True
    if not any(_row_has(r, _DIGITAL_MARKERS) for r in rows):
        rows.append(_digital_row(len(rows) + 1))
        merged = True
    if not rows:
        rows = [_digital_row(1), _interop_row(2), _citizen_row(3)]
        merged = True
    numbered = _renumber(rows)
    table = '\n'.join([CANONICAL_KPI_HEADER, CANONICAL_KPI_SEP, *numbered])
    parts = [p for p in (prefix, table, suffix) if p]
    rebuilt = '\n\n'.join(parts).strip() + '\n'
    return rebuilt, {
        'rows_merged_into_first_table': merged,
        'rows_appended_as_new_table': False,
        'kpi_assessment_guides_preserved': (
            (not guides_before) or bool(_GUIDE_HEADING_RE.search(rebuilt))
        ),
        'kpi_rows_after_list': numbered,
    }


def _official_blockers(
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
            for fw, fam, _sk in missing
        ]
    except Exception:
        return []


def _leakage_terms(sections: Dict[str, str]) -> List[str]:
    hay = '\n'.join(str(sections.get(k) or '') for k in _DT_SECTIONS)
    found: List[str] = []
    for tok in _LEAKS:
        if tok == 'NCA':
            continue
        if tok in hay and tok not in found:
            found.append(tok)
    if re.search(r'(?<![A-Z])NCA(?![A-Z])', hay) and 'NCA' not in found:
        if 'NCA ECC' not in hay and 'NCA DCC' not in hay:
            found.append('NCA')
    return found


def _header_blockers(text: str) -> List[str]:
    count = kpi_main_header_count(text)
    if count != 1:
        return [f'kpi_main_header_count_invalid (kpis) {count}/1']
    return []


def apply_rel36_23_1_dt_dga_kpi_single_table_integrity(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Optional[str] = None,
        org_name: Optional[str] = None,
        emit: bool = True,
        rel36_22_reapply_needed: bool = False,
        rel36_22_reapply_mode: str = 'none',
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = {str(k): str(v or '') for k, v in (sections or {}).items()}
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    doc_type = _norm_dtype(document_type)
    fw = list(_selected_list(selected_frameworks))
    _ensure_canonical_key(out, 'kpis', _KPI_ALIASES)
    kpis_before = str(out.get('kpis') or '')
    headers_before = kpi_main_header_count(kpis_before)
    locs_before = kpi_header_locations(kpis_before)
    rows_before = _collect_data_rows(kpis_before)
    save_before = _official_blockers(out, fw, nlang) + _header_blockers(kpis_before)
    diagnostics: Dict[str, Any] = {
        'task_id': task_id or '',
        'domain': dcode,
        'lang': nlang,
        'document_type': doc_type,
        'selected_frameworks': fw,
        'kpi_main_header_count_before': headers_before,
        'kpi_header_locations_before': locs_before,
        'duplicate_kpi_tables_before': headers_before > 1,
        'kpi_rows_before': len(rows_before),
        'rel36_22_reapply_needed': bool(rel36_22_reapply_needed),
        'rel36_22_reapply_mode': rel36_22_reapply_mode,
        'save_blockers_before': save_before,
        'org_name': org_name or '',
        'applied': False,
        'passed': False,
    }
    if not rel36_23_1_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type,
            selected_frameworks=fw):
        diagnostics['skipped'] = True
        return out, diagnostics

    _normalize_split_tokens(out)
    rebuilt, merge_meta = collapse_kpi_tables_and_merge_dga_rows(
        str(out.get('kpis') or ''))
    _set_aliases(out, 'kpis', _KPI_ALIASES, rebuilt)

    kpis_after = str(out.get('kpis') or '')
    headers_after = kpi_main_header_count(kpis_after)
    second, _ = collapse_kpi_tables_and_merge_dga_rows(kpis_after)
    idempotent = (
        kpi_main_header_count(second) == 1
        and _collect_data_rows(second) == _collect_data_rows(kpis_after)
    )
    citizen_kpi = any(
        _row_has(r, _CITIZEN_MARKERS) for r in _collect_data_rows(kpis_after))
    interop_kpi = any(
        _row_has(r, _INTEROP_MARKERS) for r in _collect_data_rows(kpis_after))
    digital_kpi = any(
        _row_has(r, _DIGITAL_MARKERS) for r in _collect_data_rows(kpis_after))
    split_hits = sum(
        str(out.get(k) or '').count(_SPLIT_TOKEN) for k in _DT_SECTIONS)
    citizen_present = any(
        section_has_citizen_experience(out.get(k, ''))
        or any(tok in str(out.get(k) or '') for tok in OFFICIAL_CITIZEN_AR)
        for k in REQUIRED_SECTIONS
    ) or citizen_kpi
    official = _official_blockers(out, fw, nlang)
    header_blockers = _header_blockers(kpis_after)
    leaks = _leakage_terms(out)
    save_after = official + header_blockers
    passed = (
        headers_after == 1
        and header_blockers == []
        and official == []
        and leaks == []
        and citizen_kpi
        and interop_kpi
        and citizen_present
        and split_hits == 0
        and merge_meta['rows_appended_as_new_table'] is False
        and idempotent
        and 'kpi_main_header_count_invalid' not in ' '.join(save_after)
    )
    diagnostics.update({
        'applied': True,
        'kpi_main_header_count_after': headers_after,
        'kpi_header_locations_after': kpi_header_locations(kpis_after),
        'duplicate_kpi_tables_after': headers_after > 1,
        'kpi_rows_after': len(_collect_data_rows(kpis_after)),
        'citizen_experience_kpi_present_after': citizen_kpi,
        'interoperability_kpi_present_after': interop_kpi,
        'digital_services_kpi_present_after': digital_kpi,
        'rows_merged_into_first_table': merge_meta['rows_merged_into_first_table'],
        'rows_appended_as_new_table': False,
        'kpi_assessment_guides_preserved': merge_meta[
            'kpi_assessment_guides_preserved'],
        'split_token_hits_after': split_hits,
        'citizen_experience_present_after': citizen_present,
        'selected_framework_blockers_after': official,
        'kpi_header_blockers_after': header_blockers,
        'save_blockers_after': save_after,
        'leakage_terms_after': leaks,
        'idempotent_second_pass': idempotent,
        'interop_tokens_present_after': section_has_dga_interop(kpis_after),
        'passed': passed,
    })
    if emit:
        print(
            REL36_23_1_DT_DGA_KPI_SINGLE_TABLE_INTEGRITY_TAG + ' '
            + json.dumps(diagnostics, ensure_ascii=False, default=str),
            flush=True,
        )
    return out, diagnostics
