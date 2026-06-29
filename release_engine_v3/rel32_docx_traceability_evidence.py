"""PR-REL3.2.4 — DOCX returned-file traceability evidence from frozen rows."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY,
    _bad_mapping,
    _cap_col_idx,
    _gap_col_idx,
    _parse_trace_rows,
    is_diagnostic_gap_label,
    pdf_trace_extract_artifact,
    resolve_traceability_canonical_family,
)

_GAP_GAP_PREFIXES = ('ضعف ', 'غياب ', 'قصور ', 'عدم ')
_INIT_TABLE_MARKERS = frozenset({'المبادرة', 'المؤشر', 'المخاطر'})
_CANON_BY_CAPABILITY = {
    spec['capability']: fam
    for fam, spec in TRACE_CANONICAL_REGISTRY.items()
}
_CANON_BY_GAP = {
    spec['expected_gap']: fam
    for fam, spec in TRACE_CANONICAL_REGISTRY.items()
}


def _is_framework_line(ln: str) -> bool:
    t = (ln or '').strip()
    return t.startswith('NCA ') or t in ('الأمن السيبراني',)


def _looks_like_gap_label(text: str) -> bool:
    t = (text or '').strip()
    if not t or t in ('—', '-', 'n/a', 'N/A'):
        return False
    if is_diagnostic_gap_label(t):
        return True
    if any(t.startswith(p) for p in _GAP_GAP_PREFIXES):
        return True
    if t in _CANON_BY_GAP:
        return True
    return False


def _looks_like_initiative_label(text: str) -> bool:
    t = (text or '').strip()
    if not t or _looks_like_gap_label(t):
        return False
    if t in {spec['initiative'] for spec in TRACE_CANONICAL_REGISTRY.values()}:
        return True
    if len(t) < 48 and not any(c.isdigit() for c in t[:3]):
        if not _is_framework_line(t) and t not in _CANON_BY_CAPABILITY:
            if 'نسبة' not in t and 'MTT' not in t.upper():
                return True
    return False


def expected_traceability_rows_from_registry() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for fam, spec in TRACE_CANONICAL_REGISTRY.items():
        rows.append({
            'family': fam,
            'framework': spec['framework'],
            'capability': spec['capability'],
            'gap': spec['expected_gap'],
            'initiative': spec['initiative'],
        })
    return rows


def extract_docx_flat_traceability_rows(blob: str) -> List[Dict[str, str]]:
    """Parse flat DOCX cell text from professional trace_fw_gap tables only."""
    from release_engine.rel31_acceptance_checks import _trace_matrix_blob

    trace = _trace_matrix_blob(blob or '')
    if not trace.strip():
        return []
    lines = [ln.strip() for ln in trace.splitlines() if ln.strip()]
    rows: List[Dict[str, str]] = []
    mode = ''
    i = 0
    while i < len(lines):
        ln = lines[i]
        if (
                ln == 'الإطار المرجعي'
                and i + 2 < len(lines)
                and lines[i + 1] == 'مجال القدرة'
                and 'الفجوة' in lines[i + 2]):
            mode = 'gap_table'
            i += 3
            continue
        if ln == 'الإطار' and i + 1 < len(lines) and lines[i + 1] == 'المبادرة':
            mode = 'init_table'
            i += 2
            while i < len(lines) and lines[i] in _INIT_TABLE_MARKERS:
                i += 1
            continue
        if mode == 'gap_table' and _is_framework_line(ln) and i + 2 < len(lines):
            fw, cap, gap = ln, lines[i + 1], lines[i + 2]
            if _is_framework_line(cap) or _is_framework_line(gap):
                i += 1
                continue
            rows.append({
                'framework': fw,
                'capability': cap,
                'gap': gap,
                'initiative': '',
            })
            i += 3
            continue
        if mode == 'init_table' and _is_framework_line(ln):
            i += 1
            while i < len(lines) and not _is_framework_line(lines[i]):
                i += 1
            continue
        i += 1

    if rows:
        return rows

    # Fallback: markdown pipe table inside trace blob.
    _lines, hdr, table_rows = _parse_trace_rows(trace)
    if hdr < 0 or not table_rows:
        return rows
    cap_idx = _cap_col_idx(_lines[hdr])
    gap_idx = _gap_col_idx(_lines[hdr])
    fw_idx = 0
    for cells in table_rows:
        cap = cells[cap_idx] if len(cells) > cap_idx else ''
        gap = cells[gap_idx] if len(cells) > gap_idx else ''
        fw = cells[fw_idx] if cells else ''
        if cap and gap:
            rows.append({
                'framework': fw,
                'capability': cap,
                'gap': gap,
                'initiative': '',
            })
    return rows


def _pair_capability_gap_in_trace(
        trace_blob: str,
        capability: str,
        expected_gap: str,
) -> Tuple[str, bool]:
    """Find best gap label for a canonical capability inside trace text."""
    lines = [ln.strip() for ln in (trace_blob or '').splitlines() if ln.strip()]
    for i, ln in enumerate(lines):
        if ln != capability:
            continue
        for j in (i + 1, i + 2, i - 1):
            if 0 <= j < len(lines):
                cand = lines[j]
                if expected_gap in cand or cand == expected_gap:
                    return cand, True
        if expected_gap in trace_blob:
            return expected_gap, True
    return '', False


def traceability_defects_from_extracted_rows(
        rows: List[Dict[str, str]],
        *,
        trace_blob: str = '',
) -> Tuple[List[str], Dict[str, Any]]:
    """Compare extracted DOCX trace rows to canonical registry (no narrative inference)."""
    defects: List[str] = []
    diag: Dict[str, Any] = {
        'docx_traceability_extracted_rows': list(rows or []),
        'expected_traceability_rows': expected_traceability_rows_from_registry(),
        'evidence_traceability_parser_source': 'docx_flat_gap_table',
        'traceability_evidence_false_positive': False,
        'post_renderer_traceability_mutated': False,
    }
    spec_sh = TRACE_CANONICAL_REGISTRY['sensitive_handling']
    diag['expected_gap_for_sensitive_handling'] = spec_sh['expected_gap']
    actual_sh = ''
    for row in rows or []:
        if row.get('capability') == spec_sh['capability']:
            actual_sh = str(row.get('gap') or '')
            break
    if not actual_sh:
        actual_sh, _ = _pair_capability_gap_in_trace(
            trace_blob, spec_sh['capability'], spec_sh['expected_gap'])
    diag['actual_gap_for_sensitive_handling'] = actual_sh

    seen_caps: set = set()
    for row in rows or []:
        cap = str(row.get('capability') or '').strip()
        gap = str(row.get('gap') or '').strip()
        if not cap or cap in seen_caps:
            continue
        seen_caps.add(cap)
        fam = _CANON_BY_CAPABILITY.get(cap)
        if not fam:
            continue
        expected = TRACE_CANONICAL_REGISTRY[fam]['expected_gap']
        if expected in gap or gap == expected:
            continue
        if pdf_trace_extract_artifact(cap) or pdf_trace_extract_artifact(gap):
            continue
        if _looks_like_initiative_label(gap) and not _looks_like_gap_label(gap):
            paired, ok = _pair_capability_gap_in_trace(trace_blob, cap, expected)
            if ok:
                diag['traceability_evidence_false_positive'] = True
                continue
            if expected in (trace_blob or ''):
                diag['traceability_evidence_false_positive'] = True
                continue
        if _bad_mapping(fam, gap):
            defects.append(f'trace_gap_mismatch:{cap}')
    diag['traceability_bad_mappings'] = list(dict.fromkeys(defects))
    return list(dict.fromkeys(defects)), diag


def validate_frozen_traceability_not_mutated(
        frozen_traceability: str,
        extracted_rows: List[Dict[str, str]],
) -> Tuple[bool, List[str]]:
    """Fail closed when post-renderer DOCX rows diverge from frozen artifact."""
    if not (frozen_traceability or '').strip():
        return True, []
    expected_caps = {
        spec['capability']: spec['expected_gap']
        for spec in TRACE_CANONICAL_REGISTRY.values()
    }
    by_cap = {
        str(r.get('capability') or '').strip(): str(r.get('gap') or '').strip()
        for r in (extracted_rows or [])
        if str(r.get('capability') or '').strip() in expected_caps
    }
    blockers: List[str] = []
    for cap, exp_gap in expected_caps.items():
        if cap not in frozen_traceability:
            continue
        if cap not in by_cap:
            continue
        actual = by_cap[cap]
        if exp_gap in actual or actual == exp_gap:
            continue
        if exp_gap in frozen_traceability and exp_gap in (actual or ''):
            continue
        blockers.append(f'rel32_post_renderer_traceability_mutated:{cap}')
    return (not blockers, blockers)


def evaluate_docx_traceability_evidence(
        blob: str,
        *,
        frozen_traceability: str = '',
        artifact_complete: bool = False,
) -> Tuple[List[str], Dict[str, Any]]:
    from release_engine.rel31_acceptance_checks import _trace_matrix_blob

    trace_blob = _trace_matrix_blob(blob or '')
    rows = extract_docx_flat_traceability_rows(blob or '')
    if rows:
        parser_source = 'docx_flat_gap_table'
    elif '|' in trace_blob and 'مجال القدرة' in trace_blob:
        parser_source = 'markdown_pipe_table'
        rows = extract_docx_flat_traceability_rows(trace_blob)
    else:
        parser_source = 'legacy_line_scan'
        rows = []

    defects, diag = traceability_defects_from_extracted_rows(
        rows, trace_blob=trace_blob)
    diag['evidence_traceability_parser_source'] = parser_source

    if artifact_complete and frozen_traceability.strip() and rows:
        ok, mut = validate_frozen_traceability_not_mutated(
            frozen_traceability, rows)
        diag['post_renderer_traceability_mutated'] = not ok
        if mut:
            defects = list(dict.fromkeys(defects + mut))

    if (
            not defects
            and diag.get('traceability_evidence_false_positive')
            and TRACE_CANONICAL_REGISTRY['sensitive_handling']['expected_gap']
            in (blob or '')):
        diag['traceability_evidence_false_positive'] = True
    return defects, diag


def emit_rel32_docx_traceability_evidence_diag(meta: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(meta or {})
    try:
        print(
            '[REL32-DOCX-TRACEABILITY-EVIDENCE] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
    return payload
