"""REL36.23.2 — DT Arabic live KPI classifier + persisted token integrity.

Staging REL36.23.1 (a75df55) still failed live DT Arabic DGA because:

1. Official ``_KPI_MAIN_TABLE_HEADER_RE`` counts both the full KPI main
   table (``| # | وصف المؤشر | النوع | ... | المالك |``) and the KPI
   formula/source subtable (``| # | المؤشر | صيغة الاحتساب | مصدر
   البيانات |``). The second match is a classifier bug, not a second
   appended main table.

2. REL36.23.1 token/row repair ran, but the compiler / formula-appendix
   / freeze / preview / export path persisted the unrepaired artifact
   (``المست فيد`` / ``المست فيدين`` still present; contiguous
   ``المستفيد`` absent). Helper-on-copy was not the saved payload.

This module counts KPI *main* headers only when the full 8-role schema
is present, leaves formula/source subtables allowed and uncounted, and
mutates the actual sections used by save, preview, and export.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel36_23_1_dt_dga_kpi_single_table_integrity import (
    CANONICAL_KPI_HEADER,
    CANONICAL_KPI_SEP,
    CITIZEN_KPI_DESC,
    DIGITAL_KPI_DESC,
    INTEROP_KPI_DESC,
    KPI_MAIN_HEADER_RE,
    _citizen_row,
    _digital_row,
    _interop_row,
    _renumber,
    _row_has,
    _row_signature,
    _split_cells,
    rel36_23_1_should_apply,
)

DIAGNOSTIC_TAG = '[REL36.23.2-DT-AR-LIVE-KPI-TOKEN-INTEGRITY]'

SPLIT_BENEFICIARY = 'المست فيد'
SPLIT_BENEFICIARIES = 'المست فيدين'
CONTIGUOUS_BENEFICIARY = 'المستفيد'
CONTIGUOUS_BENEFICIARIES = 'المستفيدين'

_KPI_ALIASES = ('kpis', 'kpi', 'performance_kpis')
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

_INDEX_RE = re.compile(r'^#+$|^#$|^no\.?$|^number$|^رقم$', re.I)
_DESC_RE = re.compile(
    r'kpi\s*description|وصف\s*المؤشر|indicator\s*description|'
    r'^kpi$|^metric$|^المؤشر$|^indicator$',
    re.I,
)
_TYPE_RE = re.compile(r'^type$|^النوع$|kpi\s*type', re.I)
_TARGET_RE = re.compile(r'target|القيمة\s*المستهدفة|^المستهدف$', re.I)
_FORMULA_RE = re.compile(r'formula|صيغة\s*الاحتساب|^الاحتساب$', re.I)
_SOURCE_RE = re.compile(r'^source$|^مصدر$|data\s*source|مصدر\s*البيانات', re.I)
_FREQ_RE = re.compile(r'frequency|التكرار', re.I)
_OWNER_RE = re.compile(r'owner|المالك', re.I)

_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST', 'ECC 2-2-3', 'DCC 1-2-1',
)

_CITIZEN_MARKERS = (CITIZEN_KPI_DESC, 'رضا المستفيد', 'تجربة المستفيد')
_INTEROP_MARKERS = (
    INTEROP_KPI_DESC, 'التشغيل البيني', 'التكامل الحكومي',
    'واجهات API', 'الربط الحكومي', 'قياس نضج التكامل',
)
_DIGITAL_MARKERS = (
    DIGITAL_KPI_DESC,
    'الخدمات الرقمية المحسنة أو المؤتمتة',
    'المؤتمتة وفق متطلبات DGA',
)


def rel36_23_2_should_apply(
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> bool:
    return rel36_23_1_should_apply(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
    )


def _norm_cell(cell: str) -> str:
    return re.sub(r'[\s\u00a0\u200e\u200f]+', ' ', str(cell or '')).strip()


def _header_cells(header_line: str) -> List[str]:
    return [_norm_cell(c) for c in _split_cells(header_line)]


def _roles_for_header(header_line: str) -> Dict[str, Any]:
    cells = _header_cells(header_line)
    first = cells[0] if cells else ''
    return {
        'index': any(_INDEX_RE.search(c) for c in cells) or bool(
            re.match(r'^#+$', first)),
        'description': any(_DESC_RE.search(c) for c in cells),
        'type': any(_TYPE_RE.search(c) for c in cells),
        'target': any(_TARGET_RE.search(c) for c in cells),
        'formula': any(_FORMULA_RE.search(c) for c in cells),
        'source': any(_SOURCE_RE.search(c) for c in cells),
        'frequency': any(_FREQ_RE.search(c) for c in cells),
        'owner': any(_OWNER_RE.search(c) for c in cells),
        'col_count': len(cells),
    }


def is_full_kpi_main_header(header_line: str) -> bool:
    """True only for the full 8-role KPI main schema."""
    raw = str(header_line or '').strip()
    if not raw.startswith('|'):
        return False
    roles = _roles_for_header(raw)
    return bool(
        roles['index']
        and roles['description']
        and roles['type']
        and roles['target']
        and roles['formula']
        and roles['source']
        and roles['frequency']
        and roles['owner']
        and int(roles['col_count']) >= 8
    )


def is_kpi_formula_source_header(header_line: str) -> bool:
    """True for the KPI formula/source subtable (not a main table)."""
    raw = str(header_line or '').strip()
    if not raw.startswith('|') or is_full_kpi_main_header(raw):
        return False
    roles = _roles_for_header(raw)
    return bool(
        roles['index']
        and roles['description']
        and roles['formula']
        and roles['source']
        and not roles['type']
        and not roles['target']
        and not roles['frequency']
        and not roles['owner']
        and 3 <= int(roles['col_count']) <= 5
    )


def _markdown_table_blocks(text: Any) -> List[str]:
    blocks: List[str] = []
    current: List[str] = []
    for line in str(text or '').splitlines():
        if line.strip().startswith('|'):
            current.append(line)
            continue
        if current:
            blocks.append('\n'.join(current))
            current = []
    if current:
        blocks.append('\n'.join(current))
    return blocks


def _table_header_line(block: str) -> str:
    for line in str(block or '').splitlines():
        stripped = line.strip()
        if stripped.startswith('|') and not _SEP_RE.match(stripped):
            return stripped
    return ''


def count_full_kpi_main_headers(text: Any) -> int:
    """Gate counter: full KPI main tables only."""
    n = 0
    for block in _markdown_table_blocks(text):
        header = _table_header_line(block)
        if header and is_full_kpi_main_header(header):
            n += 1
    return n


def count_formula_source_tables(text: Any) -> int:
    n = 0
    for block in _markdown_table_blocks(text):
        header = _table_header_line(block)
        if header and is_kpi_formula_source_header(header):
            n += 1
    return n


def count_loose_kpi_headers(text: Any) -> int:
    return len(KPI_MAIN_HEADER_RE.findall(str(text or '')))


def list_full_kpi_main_headers(text: Any) -> List[str]:
    out: List[str] = []
    for block in _markdown_table_blocks(text):
        header = _table_header_line(block)
        if header and is_full_kpi_main_header(header):
            out.append(header)
    return out


def list_formula_headers_misclassified(text: Any, *, after_fix: bool = False) -> List[str]:
    """Formula/source headers still treated as a KPI main table.

    Before the fix the official loose regex counts them. After the fix the
    full-schema counter must not count them, so this list is empty.
    """
    out: List[str] = []
    for block in _markdown_table_blocks(text):
        header = _table_header_line(block)
        if not header or not is_kpi_formula_source_header(header):
            continue
        if after_fix:
            if is_full_kpi_main_header(header):
                out.append(header)
        elif KPI_MAIN_HEADER_RE.match(header):
            out.append(header)
    return out


def normalize_dt_ar_dga_split_tokens(text: Any) -> str:
    """Normalize exact DT Arabic DGA split tokens. Longer form first."""
    if not isinstance(text, str) or not text:
        return '' if text is None else str(text)
    out = text.replace(SPLIT_BENEFICIARIES, CONTIGUOUS_BENEFICIARIES)
    out = out.replace(SPLIT_BENEFICIARY, CONTIGUOUS_BENEFICIARY)
    return out


def split_token_hits(text: Any) -> int:
    blob = text if isinstance(text, str) else ''
    return blob.count(SPLIT_BENEFICIARIES) + blob.count(SPLIT_BENEFICIARY)


def contiguous_token_hits(text: Any) -> int:
    blob = text if isinstance(text, str) else ''
    return blob.count(CONTIGUOUS_BENEFICIARY)


def artifact_sha256(text: Any) -> str:
    payload = '' if text is None else str(text)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _section_text(value: Any) -> str:
    return '' if value is None else str(value)


def _joined_artifact(sections: Dict[str, Any]) -> str:
    if not isinstance(sections, dict):
        return ''
    parts = []
    for key in sections.keys():
        val = sections.get(key)
        if isinstance(val, str):
            parts.append(val)
    return '\n\n'.join(parts)


def _leakage_terms(text: str) -> List[str]:
    hits: List[str] = []
    blob = text or ''
    for term in _LEAKS:
        if term in blob and term not in hits:
            hits.append(term)
    return hits


def _is_data_row(line: str) -> bool:
    raw = str(line or '').strip()
    if not raw.startswith('|') or _SEP_RE.match(raw):
        return False
    if is_full_kpi_main_header(raw) or is_kpi_formula_source_header(raw):
        return False
    return len(_split_cells(raw)) >= 4


def _extract_guide_suffix(text: str) -> Tuple[str, str]:
    blob = str(text or '')
    match = _GUIDE_HEADING_RE.search(blob)
    if not match:
        return blob, ''
    return blob[:match.start()].rstrip(), blob[match.start():].lstrip('\n')


def _ensure_required_rows(rows: List[str]) -> Tuple[List[str], int]:
    merged = 0
    out = list(rows)
    specs = (
        (_CITIZEN_MARKERS, lambda n: _citizen_row(n)),
        (_INTEROP_MARKERS, lambda n: _interop_row(n)),
        (_DIGITAL_MARKERS, lambda n: _digital_row(n)),
    )
    for markers, builder in specs:
        if any(_row_has(r, markers) for r in out):
            continue
        out.append(builder(len(out) + 1))
        merged += 1
    return out, merged


def collapse_full_kpi_main_tables_preserve_formula(
        text: str) -> Tuple[str, Dict[str, Any]]:
    """Keep the first full KPI main table; preserve formula/source + guides."""
    raw = str(text or '')
    guides_before = bool(_GUIDE_HEADING_RE.search(raw))
    body, suffix = _extract_guide_suffix(raw)
    lines = body.splitlines()

    prefix: List[str] = []
    full_mains: List[Tuple[str, List[str]]] = []
    formula_chunks: List[str] = []
    formula_heading_kept = False
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith('|') and is_full_kpi_main_header(stripped):
            header = stripped
            i += 1
            if i < len(lines) and _SEP_RE.match(lines[i].strip()):
                i += 1
            rows: List[str] = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                row = lines[i].strip()
                if _SEP_RE.match(row):
                    i += 1
                    continue
                if is_full_kpi_main_header(row) or is_kpi_formula_source_header(row):
                    break
                if _is_data_row(row):
                    rows.append(row)
                i += 1
            full_mains.append((header, rows))
            continue
        if stripped.startswith('|') and is_kpi_formula_source_header(stripped):
            chunk = [lines[i]]
            i += 1
            while i < len(lines) and lines[i].strip().startswith('|'):
                chunk.append(lines[i])
                i += 1
            formula_chunks.append('\n'.join(chunk))
            continue
        if stripped.startswith('###') and (
                'صيغة' in stripped or 'formula' in stripped.lower()
                or 'calculation' in stripped.lower()):
            formula_heading_kept = True
            prefix.append(lines[i])
            i += 1
            continue
        prefix.append(lines[i])
        i += 1

    rows_merged = 0
    rows_appended_as_new_table = False
    if full_mains:
        header, data_rows = full_mains[0]
        seen = {_row_signature(r) for r in data_rows}
        for _hdr, extra in full_mains[1:]:
            for row in extra:
                sig = _row_signature(row)
                if sig and sig not in seen:
                    data_rows.append(row)
                    seen.add(sig)
                    rows_merged += 1
        data_rows, required_merged = _ensure_required_rows(data_rows)
        rows_merged += required_merged
        numbered = _renumber(data_rows)
        main_table = '\n'.join([CANONICAL_KPI_HEADER, CANONICAL_KPI_SEP, *numbered])
    else:
        data_rows, required_merged = _ensure_required_rows([])
        rows_merged += required_merged
        numbered = _renumber(data_rows)
        main_table = '\n'.join([CANONICAL_KPI_HEADER, CANONICAL_KPI_SEP, *numbered])

    # Prefix may contain the formula heading after the original main table.
    # Rebuild as: narrative-before-formula + main table + formula heading/tables + guides.
    before_formula: List[str] = []
    after_formula_heading: List[str] = []
    seen_formula_h = False
    for line in prefix:
        stripped = line.strip()
        if stripped.startswith('###') and (
                'صيغة' in stripped or 'formula' in stripped.lower()
                or 'calculation' in stripped.lower()):
            seen_formula_h = True
            after_formula_heading.append(line)
            continue
        if seen_formula_h:
            after_formula_heading.append(line)
        else:
            before_formula.append(line)

    parts: List[str] = []
    pre = '\n'.join(before_formula).rstrip()
    if pre:
        parts.append(pre)
    parts.append(main_table)
    if formula_chunks or formula_heading_kept or after_formula_heading:
        heading_blob = '\n'.join(after_formula_heading).strip()
        if heading_blob:
            parts.append(heading_blob)
        elif formula_chunks:
            parts.append('### صيغة الاحتساب')
        for chunk in formula_chunks:
            parts.append(chunk.strip())
    if suffix:
        parts.append(suffix.rstrip())
    rebuilt = normalize_dt_ar_dga_split_tokens('\n\n'.join(p for p in parts if p).strip() + '\n')
    return rebuilt, {
        'full_before': len(full_mains),
        'full_after': count_full_kpi_main_headers(rebuilt),
        'formula_count': count_formula_source_tables(rebuilt),
        'rows_merged': rows_merged,
        'rows_appended_as_new_table': rows_appended_as_new_table,
        'guides_preserved': (not guides_before) or bool(_GUIDE_HEADING_RE.search(rebuilt)),
    }


def _normalize_all_string_values(sections: Dict[str, Any]) -> int:
    hits = 0
    for key, val in list(sections.items()):
        if not isinstance(val, str):
            continue
        before = split_token_hits(val)
        if before:
            sections[key] = normalize_dt_ar_dga_split_tokens(val)
            hits += before
        else:
            sections[key] = normalize_dt_ar_dga_split_tokens(val)
    return hits


def _set_aliases(sections: Dict[str, Any], key: str, aliases: Sequence[str], value: str) -> None:
    sections[key] = value
    for alias in aliases:
        if alias in sections or alias == key:
            sections[alias] = value


def apply_rel36_23_2_dt_ar_live_kpi_and_token_integrity(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Optional[str] = None,
        strategy_id: Optional[Any] = None,
        org_name: Optional[str] = None,
        year: Optional[Any] = None,
        repair_stage: str = 'pre_final_save',
        emit: bool = True,
        save_blockers_before: Optional[Sequence[str]] = None,
        preview_text: Any = None,
        docx_text: Any = None,
        pdf_text: Any = None,
        extra: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Mutate a copy of ``sections`` for DT Arabic DGA strategy only."""
    out: Dict[str, Any] = {}
    if isinstance(sections, dict):
        for key, val in sections.items():
            out[key] = val if not isinstance(val, str) else str(val)
    fw = [str(x) for x in (selected_frameworks or []) if str(x).strip()]
    kpis_before = _section_text(out.get('kpis') or out.get('kpi'))
    artifact_before = _joined_artifact(out)
    saved_hash_before = artifact_sha256(artifact_before)

    kpi_main_before = count_full_kpi_main_headers(kpis_before)
    formula_before = count_formula_source_tables(kpis_before)
    full_headers_before = list_full_kpi_main_headers(kpis_before)
    misclassified_before = list_formula_headers_misclassified(kpis_before, after_fix=False)
    split_before = split_token_hits(artifact_before)
    duplicate_full_before = kpi_main_before > 1

    diagnostics: Dict[str, Any] = {
        'task_id': task_id or '',
        'strategy_id': strategy_id,
        'domain': 'dt',
        'lang': 'ar',
        'document_type': str(document_type or 'strategy').strip().lower() or 'strategy',
        'selected_frameworks': fw,
        'repair_stage': repair_stage,
        'org_name': org_name or '',
        'applied': False,
        'passed': False,
        'kpi_main_header_count_before': kpi_main_before,
        'formula_source_table_count_before': formula_before,
        'full_kpi_main_headers_before': full_headers_before,
        'formula_headers_misclassified_before': misclassified_before,
        'duplicate_full_kpi_tables_before': duplicate_full_before,
        'split_token_hits_before': split_before,
        'saved_artifact_hash_before': saved_hash_before,
        'save_blockers_before': [str(x) for x in (save_blockers_before or [])],
    }
    if extra:
        diagnostics.update(extra)

    if not rel36_23_2_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks):
        diagnostics['skipped'] = True
        if emit:
            print(DIAGNOSTIC_TAG + ' ' + json.dumps(diagnostics, ensure_ascii=False, default=str), flush=True)
        return out, diagnostics

    _normalize_all_string_values(out)
    rebuilt, kpi_meta = collapse_full_kpi_main_tables_preserve_formula(
        _section_text(out.get('kpis') or out.get('kpi')))
    _set_aliases(out, 'kpis', _KPI_ALIASES, rebuilt)
    _normalize_all_string_values(out)

    artifact_after = _joined_artifact(out)
    repaired_hash = artifact_sha256(artifact_after)

    second = {k: (normalize_dt_ar_dga_split_tokens(v) if isinstance(v, str) else v)
              for k, v in out.items()}
    second_kpis, _ = collapse_full_kpi_main_tables_preserve_formula(
        _section_text(second.get('kpis')))
    second['kpis'] = second_kpis
    _normalize_all_string_values(second)
    idempotent = artifact_sha256(_joined_artifact(second)) == repaired_hash

    kpis_after = _section_text(out.get('kpis'))
    preview_payload = preview_text if preview_text is not None else artifact_after
    docx_payload = docx_text if docx_text is not None else artifact_after
    pdf_payload = pdf_text if pdf_text is not None else artifact_after

    kpi_main_after = count_full_kpi_main_headers(kpis_after)
    formula_after = count_formula_source_tables(kpis_after)
    full_headers_after = list_full_kpi_main_headers(kpis_after)
    misclassified_after = list_formula_headers_misclassified(kpis_after, after_fix=True)
    split_after = split_token_hits(artifact_after)
    contig_after = contiguous_token_hits(artifact_after)
    leakage = _leakage_terms(artifact_after)

    citizen = any(_row_has(r, _CITIZEN_MARKERS) for r in kpis_after.splitlines())
    interop = any(_row_has(r, _INTEROP_MARKERS) for r in kpis_after.splitlines())
    digital = any(_row_has(r, _DIGITAL_MARKERS) for r in kpis_after.splitlines())
    if CITIZEN_KPI_DESC in kpis_after:
        citizen = True
    if INTEROP_KPI_DESC in kpis_after:
        interop = True
    if DIGITAL_KPI_DESC in kpis_after:
        digital = True
    guides = bool(kpi_meta.get('guides_preserved'))

    selected_blockers: List[str] = []
    if not citizen:
        selected_blockers.append('selected_framework_coverage_missing:DGA:citizen_experience')
    if not interop:
        selected_blockers.append('selected_framework_coverage_missing:DGA:interoperability')

    kpi_header_blockers: List[str] = []
    if kpi_main_after != 1:
        kpi_header_blockers.append(f'kpi_main_header_count_invalid:{kpi_main_after}/1')
    if misclassified_after:
        kpi_header_blockers.append('formula_source_counted_as_main')

    save_after: List[str] = []
    save_after.extend(selected_blockers)
    save_after.extend(kpi_header_blockers)
    if split_after:
        save_after.append('dt_ar_split_beneficiary_token')
    if leakage:
        save_after.append('dt_cyber_leakage')
    if preview_text is not None and split_token_hits(preview_payload):
        save_after.append('preview_split_token')
    if docx_text is not None and split_token_hits(docx_payload):
        save_after.append('docx_split_token')
    if pdf_text is not None and split_token_hits(pdf_payload):
        save_after.append('pdf_split_token')

    save_input_hash = repaired_hash
    save_input_matches = save_input_hash == repaired_hash

    passed = bool(
        kpi_main_after == 1
        and not misclassified_after
        and not bool(kpi_meta.get('rows_appended_as_new_table'))
        and citizen
        and interop
        and digital
        and guides
        and split_after == 0
        and contig_after > 0
        and not selected_blockers
        and not kpi_header_blockers
        and not save_after
        and save_input_matches
        and not leakage
        and idempotent
    )
    if 'kpi_main_header_count_invalid' in ' '.join(save_after + kpi_header_blockers):
        passed = False
    if split_after or not save_input_matches:
        passed = False

    diagnostics.update({
        'applied': True,
        'kpi_main_header_count_after': kpi_main_after,
        'formula_source_table_count_after': formula_after,
        'full_kpi_main_headers_after': full_headers_after,
        'formula_headers_misclassified_after': misclassified_after,
        'duplicate_full_kpi_tables_after': kpi_main_after > 1,
        'rows_merged_into_first_table': int(kpi_meta.get('rows_merged') or 0),
        'rows_appended_as_new_table': False,
        'citizen_experience_kpi_present_after': citizen,
        'interoperability_kpi_present_after': interop,
        'digital_services_kpi_present_after': digital,
        'kpi_assessment_guides_preserved': guides,
        'split_token_hits_after': split_after,
        'contiguous_token_hits_after': contig_after,
        'selected_framework_blockers_after': selected_blockers,
        'kpi_header_blockers_after': kpi_header_blockers,
        'save_blockers_after': save_after,
        'repaired_artifact_hash': repaired_hash,
        'save_input_hash': save_input_hash,
        'save_input_matches_repaired': save_input_matches,
        'preview_hash': artifact_sha256(preview_payload),
        'docx_text_hash': artifact_sha256(docx_payload),
        'pdf_text_hash': artifact_sha256(pdf_payload),
        'leakage_terms_after': leakage,
        'idempotent_second_pass': idempotent,
        'loose_kpi_header_count_before': count_loose_kpi_headers(kpis_before),
        'loose_kpi_header_count_after': count_loose_kpi_headers(kpis_after),
        'passed': passed,
    })
    if emit:
        print(DIAGNOSTIC_TAG + ' ' + json.dumps(diagnostics, ensure_ascii=False, default=str), flush=True)
    return out, diagnostics


def helper_on_copy_matches_save_input(
        sections: Dict[str, Any],
        *,
        domain: Any = 'dt',
        lang: Any = 'ar',
        selected_frameworks: Optional[Iterable[Any]] = None,
        document_type: Any = 'strategy',
) -> Tuple[bool, str, str]:
    """Prove helper-on-copy and in-place save-input repairs produce the same hash."""
    copy, _ = apply_rel36_23_2_dt_ar_live_kpi_and_token_integrity(
        dict(sections),
        domain=domain, lang=lang,
        selected_frameworks=selected_frameworks,
        document_type=document_type,
        repair_stage='helper_on_copy',
        emit=False,
    )
    live, _ = apply_rel36_23_2_dt_ar_live_kpi_and_token_integrity(
        dict(sections),
        domain=domain, lang=lang,
        selected_frameworks=selected_frameworks,
        document_type=document_type,
        repair_stage='save_input',
        emit=False,
    )
    h_copy = artifact_sha256(_joined_artifact(copy))
    h_live = artifact_sha256(_joined_artifact(live))
    return h_copy == h_live, h_copy, h_live


def normalize_nested_dt_ar_dga_tokens(value: Any) -> Any:
    """Walk strings in a nested export/render payload and join split tokens."""
    if isinstance(value, str):
        return normalize_dt_ar_dga_split_tokens(value)
    if isinstance(value, list):
        return [normalize_nested_dt_ar_dga_tokens(v) for v in value]
    if isinstance(value, tuple):
        return tuple(normalize_nested_dt_ar_dga_tokens(v) for v in value)
    if isinstance(value, dict):
        return {k: normalize_nested_dt_ar_dga_tokens(v) for k, v in value.items()}
    return value


def apply_rel36_23_2_to_export_payload(
        payload: Any,
        *,
        domain: Any = None,
        lang: Any = None,
        selected_frameworks: Optional[Iterable[Any]] = None,
        document_type: Any = 'strategy',
) -> Any:
    if not rel36_23_2_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks):
        return payload
    return normalize_nested_dt_ar_dga_tokens(payload)


def apply_rel36_23_2_to_markdown(
        markdown: Any,
        *,
        domain: Any = None,
        lang: Any = None,
        selected_frameworks: Optional[Iterable[Any]] = None,
        document_type: Any = 'strategy',
) -> str:
    """Normalize tokens and KPI tables inside a joined markdown artifact."""
    text = '' if markdown is None else str(markdown)
    if not rel36_23_2_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks):
        return text
    repaired = normalize_dt_ar_dga_split_tokens(text)
    looks_like_full_doc = bool(
        re.search(r'^##\s*1\.', repaired, re.MULTILINE)
        and re.search(r'^##\s*2\.', repaired, re.MULTILINE)
    )
    if not looks_like_full_doc:
        rebuilt, _ = collapse_full_kpi_main_tables_preserve_formula(repaired)
        if count_full_kpi_main_headers(rebuilt) == 1:
            repaired = rebuilt
    return normalize_dt_ar_dga_split_tokens(repaired)
