"""REL36.8 — pre-save English Cyber pillars section parity repair.

English Cyber ECC+DCC generation can fail the REL2 save gate with:

    rel2_pillars_failed:empty_or_invalid
    rel2_section_parity_failed:pillars

Root cause: ``finalize_pillars`` counts any 3+ column pipe row as a valid
initiative, so glued / 3-column / Program|Outcome tables look complete.
The professional-model extractor used for DOCX/PDF parity only binds a
table when the header contains ``initiative`` / ``مبادرة``, and
``normalize_pillar_blocks`` treats three family-named ``###`` headings as
substantive even when those tables are missing. Preview therefore sees
pillars while docx/pdf parity views do not. REL36.5 cannot help because
the failure is pre-save.

This module rewrites the English Cyber pillars section to a canonical
4-column Initiative table before REL2 gates. It does not mark parity
passed, skip ``rel2_section_parity``, or skip ``rel2_pillars_failed``.
"""

from __future__ import annotations

import json
import re
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine.pillar_model import (
    CYBER_PILLAR_FAMILIES,
    _PILLAR_CATALOG_EN,
    _count_pillar_blocks,
    _pillar_families_present,
)
from release_engine.section_parity import (
    _pillars_artifact_present,
    _pillars_model_export_present,
)
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    REL36_2_ALLOWED_OWNERS,
    _is_empty_owner,
    _is_sep_row,
    infer_english_cyber_owner,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_8_EN_CYBER_PILLARS_PARITY_TAG = (
    '[REL36.8-EN-CYBER-PILLARS-PARITY-REPAIR]')

REL36_8_PILLAR_HEADER = (
    'Initiative', 'Description', 'Expected Deliverable', 'Owner',
)
REL36_8_SECTION_HEADING = '## 2. Strategic Pillars'
REL36_8_FAMILY_HEADINGS = tuple(heading for heading, _rows in _PILLAR_CATALOG_EN)

_FAMILY_RE = re.compile(r'family:[A-Za-z0-9_]+')
_GLUED_HEADING_RE = re.compile(
    r'^(#{3,4}\s+[^|\n]+?)\s*(\|.+)$',
    re.MULTILINE,
)

_TLS = threading.local()
REENTRANCY_GUARD_TYPE = 'thread_local'

_HEADER_LABELS = frozenset((
    'initiative', 'description', 'expected deliverable', 'owner',
    'program', 'outcome', 'lead',
    'responsible owner', 'accountable owner',
    'المبادرة', 'الوصف', 'المخرج المتوقع', 'المخرج', 'المسؤول', 'المالك',
    '#',
))
_SCHEMA_POL = 'program_outcome_lead'
_SCHEMA_PO = 'program_outcome'
_SCHEMA_CANONICAL = 'initiative_4col'

_FAMILY_TITLE_MARKERS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ('governance_operating_model', (
        'governance', 'operating model', 'policy', 'raci', 'committee',
        'حوكمة',
    )),
    ('protection_detection_response', (
        'protection', 'detection', 'response', 'soc', 'siem', 'csirt',
        'الحماية',
    )),
    ('identity_data_protection', (
        'identity', 'data protection', 'iam', 'pam', 'mfa', 'dlp',
        'classification', 'الهوية',
    )),
    ('resilience_continuity', (
        'resilience', 'continuity', 'backup', 'disaster', 'bcp', 'dr',
        'المرونة',
    )),
)


def _selected_list(selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    return [str(x) for x in (selected_frameworks or []) if x]


def _frameworks_include_nca(selected: Sequence[str], blob: str = '') -> bool:
    joined = ' '.join(selected) + ' ' + str(blob or '')
    upper = joined.upper()
    return 'ECC' in upper or 'DCC' in upper or 'NCA' in upper


def rel36_8_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        pillars_text: str = '',
) -> bool:
    dcode = _normalize_rel31_domain_code(domain)
    if dcode != 'cyber':
        return False
    if normalize_rel36_lang(lang) != 'en':
        return False
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype not in ('strategy', 'strategy document', 'strategy_document'):
        return False
    selected = _selected_list(selected_frameworks)
    if selected:
        return _frameworks_include_nca(selected, pillars_text)
    return True


def _unglue_heading_table_lines(text: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        heading = match.group(1).rstrip()
        rest = match.group(2).strip()
        if rest.startswith('|'):
            return f'{heading}\n{rest}'
        return match.group(0)

    return _GLUED_HEADING_RE.sub(_repl, text or '')


def _strip_family_markers(text: str) -> str:
    return _FAMILY_RE.sub('', text or '')


def _family_for_blob(blob: str) -> str:
    low = (blob or '').lower()
    for fam, tokens in _FAMILY_TITLE_MARKERS:
        if any(tok in low for tok in tokens):
            return fam
    return ''


def _iter_pipe_rows(text: str) -> List[List[str]]:
    rows: List[List[str]] = []
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if not s.startswith('|'):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if _is_sep_row(cells):
            continue
        if any(cells):
            rows.append(cells)
    return rows


def _tls_depth() -> int:
    return int(getattr(_TLS, 'depth', 0) or 0)


def rel36_8_thread_local_depth() -> int:
    """Public helper for tests: current thread's repair nesting depth."""
    return _tls_depth()


def _cell_is_header_label(cell: str) -> bool:
    return str(cell or '').strip().lower() in _HEADER_LABELS


def _cell_is_long_content(cell: str) -> bool:
    text = str(cell or '').strip()
    if not text or _cell_is_header_label(text):
        return False
    words = [w for w in re.split(r'\s+', text) if w]
    return len(words) > 5 or len(text) > 48


def _is_source_header_row(cells: Sequence[str]) -> bool:
    """Require a pipe-shaped short header: at least two exact header labels.

    Content rows that merely mention initiative / description / owner must
    be preserved. Example that must NOT be treated as a header:

        Control ownership initiative | Define accountable owners | Approved RACI | CISO
    """
    vals = [str(c).strip() for c in cells if str(c).strip() != '']
    if len(vals) < 2:
        return False
    if any(_cell_is_long_content(v) for v in vals):
        return False
    label_hits = sum(1 for v in vals if _cell_is_header_label(v))
    return label_hits >= 2


def _header_schema(cells: Sequence[str]) -> str:
    labels = [str(c).strip().lower() for c in cells if str(c).strip()]
    if 'program' in labels and 'outcome' in labels and 'lead' in labels:
        return _SCHEMA_POL
    if 'program' in labels and 'outcome' in labels:
        return _SCHEMA_PO
    return _SCHEMA_CANONICAL


def _preserve_lead_owner(lead: str, initiative: str, description: str) -> str:
    """Keep a valid Lead owner; infer only when Lead is empty or unknown."""
    owner = str(lead or '').strip()
    if owner in REL36_2_ALLOWED_OWNERS:
        return owner
    inferred = infer_english_cyber_owner(initiative, description)
    return inferred if inferred in REL36_2_ALLOWED_OWNERS else 'CISO'


def _row_from_cells(
        cells: Sequence[str],
        schema: str = _SCHEMA_CANONICAL,
        stats: Optional[Dict[str, Any]] = None,
) -> Optional[Tuple[str, str, str, str]]:
    vals = [str(c).strip() for c in cells if str(c).strip() != '']
    if not vals:
        return None
    if _is_source_header_row(vals):
        if stats is not None:
            stats['header_rows_dropped'] = int(
                stats.get('header_rows_dropped') or 0) + 1
        return None
    if stats is not None:
        blob = ' '.join(vals).lower()
        if any(tok in blob for tok in ('initiative', 'description', 'owner')):
            stats['content_rows_preserved'] = int(
                stats.get('content_rows_preserved') or 0) + 1
    if re.fullmatch(r'\d+', vals[0] or ''):
        vals = vals[1:]
    if len(vals) < 2:
        return None
    pol_like = schema in (_SCHEMA_POL, _SCHEMA_PO) or (
        len(vals) == 3 and vals[2] in REL36_2_ALLOWED_OWNERS
    )
    if pol_like and len(vals) == 3:
        if stats is not None:
            stats['lead_mapping_rows_detected'] = int(
                stats.get('lead_mapping_rows_detected') or 0) + 1
        initiative = vals[0]
        description = vals[1]
        deliverable = vals[1]
        owner = _preserve_lead_owner(vals[2], initiative, description)
        if stats is not None:
            stats['lead_mapping_rows_converted'] = int(
                stats.get('lead_mapping_rows_converted') or 0) + 1
        if not initiative:
            return None
        return initiative, description, deliverable, owner
    initiative = vals[0]
    description = vals[1] if len(vals) > 1 else initiative
    deliverable = vals[2] if len(vals) > 2 else description
    owner = vals[3] if len(vals) > 3 else ''
    if _is_empty_owner(owner):
        owner = infer_english_cyber_owner(initiative, description)
    if owner not in REL36_2_ALLOWED_OWNERS:
        inferred = infer_english_cyber_owner(initiative, description)
        owner = inferred if inferred in REL36_2_ALLOWED_OWNERS else 'CISO'
    if not initiative:
        return None
    return initiative, description, deliverable, owner


def _empty_extract_stats() -> Dict[str, Any]:
    return {
        'lead_mapping_rows_detected': 0,
        'lead_mapping_rows_converted': 0,
        'header_rows_dropped': 0,
        'content_rows_preserved': 0,
    }


def _extract_family_rows(
        text: str,
) -> Tuple[Dict[str, List[Tuple[str, str, str, str]]], Dict[str, Any]]:
    grouped: Dict[str, List[Tuple[str, str, str, str]]] = {
        fam: [] for fam in CYBER_PILLAR_FAMILIES
    }
    stats = _empty_extract_stats()
    unglued = _unglue_heading_table_lines(_strip_family_markers(text or ''))
    chunks = re.split(r'(?=^#{3,4}\s+)', unglued, flags=re.MULTILINE)
    leftover: List[Tuple[str, str, str, str]] = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.splitlines()
        title = lines[0].lstrip('#').strip() if lines else ''
        fam = _family_for_blob(title + '\n' + chunk)
        schema = _SCHEMA_CANONICAL
        for cells in _iter_pipe_rows(chunk):
            if _is_source_header_row(cells):
                schema = _header_schema(cells)
                stats['header_rows_dropped'] = int(
                    stats.get('header_rows_dropped') or 0) + 1
                continue
            parsed = _row_from_cells(cells, schema=schema, stats=stats)
            if not parsed:
                continue
            target = fam or _family_for_blob(' '.join(parsed))
            if target:
                grouped[target].append(parsed)
            else:
                leftover.append(parsed)
    for parsed in leftover:
        fam = _family_for_blob(' '.join(parsed)) or 'governance_operating_model'
        grouped[fam].append(parsed)
    return grouped, stats


def _canonical_rows_for_family(fam: str) -> List[Tuple[str, str, str, str]]:
    idx = {
        'governance_operating_model': 0,
        'protection_detection_response': 1,
        'identity_data_protection': 2,
        'resilience_continuity': 3,
    }.get(fam, 0)
    return [tuple(row) for row in _PILLAR_CATALOG_EN[idx][1]]


def _ensure_three_rows(
        fam: str,
        rows: List[Tuple[str, str, str, str]],
) -> List[Tuple[str, str, str, str]]:
    out = list(rows)
    seen = {r[0].strip().lower() for r in out}
    for catalog in _canonical_rows_for_family(fam):
        if len(out) >= 3:
            break
        if catalog[0].strip().lower() in seen:
            continue
        out.append(catalog)
        seen.add(catalog[0].strip().lower())
    while len(out) < 3:
        out.extend(_canonical_rows_for_family(fam)[: 3 - len(out)])
    return out[: max(3, len(out))]


def render_canonical_english_cyber_pillars(
        text: str = '',
        stats: Optional[Dict[str, Any]] = None,
) -> str:
    grouped, extracted = _extract_family_rows(text)
    if stats is not None:
        stats.update(extracted)
    parts = [REL36_8_SECTION_HEADING, '']
    header = '| ' + ' | '.join(REL36_8_PILLAR_HEADER) + ' |'
    sep = '|---|---|---|---|'
    for fam, heading in zip(CYBER_PILLAR_FAMILIES, REL36_8_FAMILY_HEADINGS):
        rows = _ensure_three_rows(fam, grouped.get(fam) or [])
        parts.append(heading)
        parts.append('')
        parts.append(header)
        parts.append(sep)
        for init, desc, deliverable, owner in rows:
            parts.append(f'| {init} | {desc} | {deliverable} | {owner} |')
        parts.append('')
    return '\n'.join(parts).rstrip() + '\n'


def _heading_list(text: str) -> List[str]:
    return [
        ln.lstrip('#').strip()
        for ln in str(text or '').splitlines()
        if re.match(r'^#{2,4}\s+', ln)
    ]


def _table_count(text: str) -> int:
    blocks = re.split(r'(?=^#{3,4}\s+)', text or '', flags=re.MULTILINE)
    n = 0
    for chunk in blocks:
        rows = _iter_pipe_rows(chunk)
        if any(_row_from_cells(r) for r in rows):
            n += 1
    return n


def _initiative_row_count(text: str) -> int:
    return sum(1 for cells in _iter_pipe_rows(text) if _row_from_cells(cells))


def _english_pillars_need_repair(text: str) -> bool:
    blob = text or ''
    if _FAMILY_RE.search(blob):
        return True
    if _GLUED_HEADING_RE.search(blob):
        return True
    if '|' not in blob:
        return True
    if not re.search(r'^#{3,4}\s+', blob, re.MULTILINE):
        return True
    count, counts, empty = _count_pillar_blocks(blob)
    if count < 3 or empty or any(c < 3 for c in counts):
        return True
    missing = [
        f for f in CYBER_PILLAR_FAMILIES
        if not _pillar_families_present(blob).get(f)]
    if missing:
        return True
    header_blob = ' '.join(
        ' '.join(cells).lower()
        for cells in _iter_pipe_rows(blob)
        if _is_source_header_row(cells)
    )
    if 'initiative' not in header_blob and 'مبادرة' not in header_blob:
        return True
    if 'owner' not in header_blob and 'المسؤول' not in header_blob:
        return True
    if REL36_8_SECTION_HEADING not in blob:
        return True
    if any(h not in blob for h in REL36_8_FAMILY_HEADINGS):
        return True
    return False


def _rendered_table_valid(text: str) -> bool:
    count, counts, empty = _count_pillar_blocks(text)
    missing = [
        f for f in CYBER_PILLAR_FAMILIES
        if not _pillar_families_present(text).get(f)]
    return (
        count >= 3
        and all(c >= 3 for c in counts)
        and not empty
        and not missing
    )


def _rel2_pillars_blockers(text: str) -> List[str]:
    if _rendered_table_valid(text):
        return []
    return ['rel2_pillars_failed:empty_or_invalid']


def _parity_snapshot(
        sections: Dict[str, str],
        *,
        backend: Optional[Dict[str, Any]],
        lang: str,
        domain: str,
) -> Dict[str, Any]:
    secs = {
        k: v for k, v in (sections or {}).items()
        if isinstance(v, str) and not str(k).startswith('_')
    }
    present_final = _pillars_artifact_present(secs)
    present_preview = present_final
    present_docx = False
    present_pdf = False
    missing_docx: List[str] = []
    missing_pdf: List[str] = []
    parity_blockers: List[str] = []
    try:
        from professional_strategy_render import normalize_pillar_blocks
        _pblocks = normalize_pillar_blocks(secs.get('pillars') or '', 'en')
        present_docx = any(
            (pb.get('table') or {}).get('rows') for pb in _pblocks)
        present_pdf = present_docx
    except Exception:  # noqa: BLE001
        present_docx = False
        present_pdf = False
    build_model = (backend or {}).get('build_professional_model')
    model = None
    if build_model:
        try:
            model = build_model(
                secs.get('pillars') or '',
                metadata={'domain': domain, 'lang': lang},
                sections=secs,
                selected_frameworks=[],
                lang=lang,
                domain=domain,
            )
            present_docx = _pillars_model_export_present(model)
            present_pdf = present_docx
        except Exception:  # noqa: BLE001
            model = None
    if present_preview and not present_docx:
        missing_docx = ['pillars']
    if present_preview and not present_pdf:
        missing_pdf = ['pillars']
    # Pillar-only blockers. Do not reuse evaluate_section_parity's first
    # missing key (vision/roadmap/kpis) as a pillars failure, and do not
    # pass pillars-only markdown into the full parity evaluator.
    if (not present_docx) or (not present_pdf) or missing_docx or missing_pdf:
        parity_blockers = ['rel2_section_parity_failed:pillars']
    return {
        'pillars_present_final': present_final,
        'pillars_present_preview': present_preview,
        'pillars_present_docx': present_docx,
        'pillars_present_pdf': present_pdf,
        'missing_sections_docx': missing_docx,
        'missing_sections_pdf': missing_pdf,
        'rel2_section_parity_blockers': parity_blockers,
    }


def evaluate_rel36_8_en_cyber_pillars_parity(
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Any = None,
        repair_stage: str = 'pre_rel2_gates',
        before_text: str = '',
        after_text: str = '',
        before_parity: Optional[Dict[str, Any]] = None,
        after_parity: Optional[Dict[str, Any]] = None,
        repair_applied: bool = False,
        reentrancy_guard_type: str = REENTRANCY_GUARD_TYPE,
        thread_id: Any = None,
        thread_local_depth_before: int = 0,
        thread_local_depth_after: int = 0,
        reentrant_skipped: bool = False,
        repair_executed: bool = False,
        lead_mapping_rows_detected: int = 0,
        lead_mapping_rows_converted: int = 0,
        header_rows_dropped: int = 0,
        content_rows_preserved: int = 0,
) -> Dict[str, Any]:
    before_parity = before_parity or {}
    after_parity = after_parity or {}
    pillars_blockers_before = _rel2_pillars_blockers(before_text)
    pillars_blockers_after = _rel2_pillars_blockers(after_text)
    parity_blockers_after = list(
        after_parity.get('rel2_section_parity_blockers') or [])
    passed = (
        bool(after_parity.get('pillars_present_docx'))
        and bool(after_parity.get('pillars_present_pdf'))
        and not list(after_parity.get('missing_sections_docx') or [])
        and not list(after_parity.get('missing_sections_pdf') or [])
        and not pillars_blockers_after
        and not parity_blockers_after
    )
    return {
        'domain': _normalize_rel31_domain_code(domain) or 'cyber',
        'lang': normalize_rel36_lang(lang) or 'en',
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': _selected_list(selected_frameworks),
        'task_id': str(task_id or ''),
        'repair_stage': repair_stage,
        'pillar_heading_before': _heading_list(before_text),
        'pillar_heading_after': _heading_list(after_text),
        'pillar_tables_before': _table_count(before_text),
        'pillar_tables_after': _table_count(after_text),
        'pillar_rows_before': _initiative_row_count(before_text),
        'pillar_rows_after': _initiative_row_count(after_text),
        'rendered_table_valid_before': _rendered_table_valid(before_text),
        'rendered_table_valid_after': _rendered_table_valid(after_text),
        'pillars_present_final_before': bool(
            before_parity.get('pillars_present_final')),
        'pillars_present_final_after': bool(
            after_parity.get('pillars_present_final')),
        'pillars_present_preview_before': bool(
            before_parity.get('pillars_present_preview')),
        'pillars_present_preview_after': bool(
            after_parity.get('pillars_present_preview')),
        'pillars_present_docx_before': bool(
            before_parity.get('pillars_present_docx')),
        'pillars_present_docx_after': bool(
            after_parity.get('pillars_present_docx')),
        'pillars_present_pdf_before': bool(
            before_parity.get('pillars_present_pdf')),
        'pillars_present_pdf_after': bool(
            after_parity.get('pillars_present_pdf')),
        'missing_sections_docx_before': list(
            before_parity.get('missing_sections_docx') or []),
        'missing_sections_docx_after': list(
            after_parity.get('missing_sections_docx') or []),
        'missing_sections_pdf_before': list(
            before_parity.get('missing_sections_pdf') or []),
        'missing_sections_pdf_after': list(
            after_parity.get('missing_sections_pdf') or []),
        'rel2_pillars_blockers_before': pillars_blockers_before,
        'rel2_pillars_blockers_after': pillars_blockers_after,
        'rel2_section_parity_blockers_before': list(
            before_parity.get('rel2_section_parity_blockers') or []),
        'rel2_section_parity_blockers_after': parity_blockers_after,
        'repair_applied': bool(repair_applied),
        'reentrancy_guard_type': reentrancy_guard_type or REENTRANCY_GUARD_TYPE,
        'thread_id': int(thread_id if thread_id is not None else threading.get_ident()),
        'thread_local_depth_before': int(thread_local_depth_before or 0),
        'thread_local_depth_after': int(thread_local_depth_after or 0),
        'reentrant_skipped': bool(reentrant_skipped),
        'repair_executed': bool(repair_executed),
        'lead_mapping_rows_detected': int(lead_mapping_rows_detected or 0),
        'lead_mapping_rows_converted': int(lead_mapping_rows_converted or 0),
        'header_rows_dropped': int(header_rows_dropped or 0),
        'content_rows_preserved': int(content_rows_preserved or 0),
        'passed': passed,
    }


def emit_rel36_8_en_cyber_pillars_parity(payload: Dict[str, Any]) -> None:
    try:
        print(
            REL36_8_EN_CYBER_PILLARS_PARITY_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _skip_payload(
        *,
        action_taken: str,
        depth_before: int,
        reentrant_skipped: bool = False,
) -> Dict[str, Any]:
    return {
        'passed': False,
        'repair_applied': False,
        'repair_executed': False,
        'reentrant_skipped': bool(reentrant_skipped),
        'reentrancy_guard_type': REENTRANCY_GUARD_TYPE,
        'thread_id': threading.get_ident(),
        'thread_local_depth_before': int(depth_before),
        'thread_local_depth_after': int(depth_before),
        'lead_mapping_rows_detected': 0,
        'lead_mapping_rows_converted': 0,
        'header_rows_dropped': 0,
        'content_rows_preserved': 0,
        'action_taken': action_taken,
    }


def apply_rel36_8_en_cyber_pillars_parity(
        sections: Dict[str, str],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        backend: Optional[Dict[str, Any]] = None,
        task_id: Any = None,
        repair_stage: str = 'pre_rel2_gates',
        emit: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = dict(sections or {})
    before_text = str(out.get('pillars') or '')
    depth_before = _tls_depth()
    if not rel36_8_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks,
            pillars_text=before_text):
        return sections, _skip_payload(
            action_taken='skipped', depth_before=depth_before)
    if depth_before > 0:
        return sections, _skip_payload(
            action_taken='reentrant',
            depth_before=depth_before,
            reentrant_skipped=True,
        )
    _TLS.depth = depth_before + 1
    try:
        # Nested professional-model builds from finalize_pillars must not
        # re-enter this repair. Snapshot uses extractor presence only.
        snap_backend = backend if repair_stage != 'finalize_pillars' else None
        before_parity = _parity_snapshot(
            out, backend=snap_backend, lang='en', domain='cyber')
        repair_applied = _english_pillars_need_repair(before_text)
        extract_stats = _empty_extract_stats()
        after_text = (
            render_canonical_english_cyber_pillars(
                before_text, stats=extract_stats)
            if repair_applied else before_text
        )
        if repair_applied:
            out['pillars'] = after_text
        after_parity = _parity_snapshot(
            out, backend=snap_backend, lang='en', domain='cyber')
        diag = evaluate_rel36_8_en_cyber_pillars_parity(
            domain=domain,
            lang=lang,
            document_type=document_type,
            selected_frameworks=selected_frameworks,
            task_id=task_id,
            repair_stage=repair_stage,
            before_text=before_text,
            after_text=after_text,
            before_parity=before_parity,
            after_parity=after_parity,
            repair_applied=repair_applied,
            reentrancy_guard_type=REENTRANCY_GUARD_TYPE,
            thread_id=threading.get_ident(),
            thread_local_depth_before=depth_before,
            thread_local_depth_after=_tls_depth(),
            reentrant_skipped=False,
            repair_executed=bool(repair_applied),
            lead_mapping_rows_detected=extract_stats.get(
                'lead_mapping_rows_detected') or 0,
            lead_mapping_rows_converted=extract_stats.get(
                'lead_mapping_rows_converted') or 0,
            header_rows_dropped=extract_stats.get('header_rows_dropped') or 0,
            content_rows_preserved=extract_stats.get(
                'content_rows_preserved') or 0,
        )
        if emit:
            emit_rel36_8_en_cyber_pillars_parity(diag)
        return out, diag
    finally:
        _TLS.depth = depth_before
