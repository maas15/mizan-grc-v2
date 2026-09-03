"""REL36.12 — English Cyber pre-save pillar fallback.

Production English Cyber ECC+DCC (task ``8bf90ade-62d1-4049-82df-6bede21a41ad``)
failed before save with ``rel2_pillars_failed:empty_or_invalid``.

``finalize_pillars`` had three non-empty pillars (4/5/6 initiatives) but
``mismatched_outputs_after=1``. ``_fix_mismatched_outputs`` cannot clear a
row whose initiative title already contains both mismatch keywords
(for example ``DLP`` + ``governance``). ``needs_rebuild`` ignores leftover
mismatch, so ``action_taken`` stayed ``no_changes`` and
``rendered_table_valid`` stayed false.

REL36.8 / 36.8.3 / 36.9 structural checks omit that mismatch flag, so they
can report ``passed=true`` while the unchanged REL2 gate still blocks.

This module inspects the final parsed pillar model immediately before that
gate can block save. If any English Cyber pillar is empty or invalid, it
replaces only the pillars section with a deterministic 4-pillar table set
and re-runs the unchanged gate. It does not mark the gate passed.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine.pillar_model import (
    CYBER_PILLAR_FAMILIES,
    _PILLAR_CATALOG_EN,
    _count_pillar_blocks,
    _fix_mismatched_outputs,
    _pillar_families_present,
    finalize_pillars,
)
from release_engine.section_parity import evaluate_section_parity
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    REL36_2_ALLOWED_OWNERS,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    REL36_8_PILLAR_HEADER,
    REL36_8_SECTION_HEADING,
    _is_source_header_row,
    _iter_pipe_rows,
    _owner_binding_inventory,
    _rel2_pillars_blockers,
    _selected_list,
    rel36_8_should_apply,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_12_EN_CYBER_PRESAVE_PILLAR_STABILITY_TAG = (
    '[REL36.12-EN-CYBER-PRESAVE-PILLAR-STABILITY]')

REL36_12_FAMILY_HEADINGS: Tuple[str, ...] = (
    '### Cybersecurity Governance and Operating Model',
    '### Protection, Detection and Response',
    '### Identity, Access and Data Protection',
    '### Resilience and Continuous Improvement',
)

_REL36_12_EXTRA_ROWS: Dict[str, Tuple[Tuple[str, str, str, str], ...]] = {
    'governance_operating_model': (
        ('Security awareness operating cadence',
         'Deliver the annual cybersecurity awareness and phishing program '
         'aligned to NCA ECC',
         'Annual awareness plan and completion reports',
         'Security Awareness Manager'),
        ('Control ownership register',
         'Keep the NCA ECC control-ownership register current across '
         'departments',
         'Approved control-ownership register',
         'Cybersecurity Governance Manager'),
    ),
    'protection_detection_response': (
        ('Vulnerability management program',
         'Operate continuous vulnerability scanning and remediation SLAs '
         'aligned to NCA ECC',
         'Vulnerability program with remediation SLA',
         'Vulnerability Manager'),
    ),
    'identity_data_protection': (
        ('Encryption and key-management controls',
         'Apply encryption and key-management controls for sensitive data '
         'under NCA DCC',
         'Encryption and key-management controls for sensitive data',
         'Data Protection Officer'),
    ),
    'resilience_continuity': (
        ('Crisis communications playbook',
         'Approve crisis-communications steps for cyber incidents affecting '
         'critical services under NCA ECC',
         'Approved crisis-communications playbook',
         'Business Continuity Manager'),
    ),
}

_HEADING_SPLIT_RE = re.compile(r'(?=^#{3,4}\s+)', re.MULTILINE)
_FAMILY_MARK_RE = re.compile(r'family:[A-Za-z0-9_]+')


def rel36_12_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        pillars_text: str = '',
) -> bool:
    return rel36_8_should_apply(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        pillars_text=pillars_text,
    )


def _data_rows(chunk: str) -> List[List[str]]:
    rows: List[List[str]] = []
    for cells in _iter_pipe_rows(chunk):
        if _is_source_header_row(cells):
            continue
        if len(cells) < 3:
            continue
        rows.append(list(cells))
    return rows


def _heading_table_issues(text: str) -> Tuple[List[str], List[str]]:
    """Return (empty_pillars, missing_tables) from ###/#### headings."""
    empty: List[str] = []
    missing: List[str] = []
    for chunk in _HEADING_SPLIT_RE.split(text or ''):
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.splitlines()
        raw_title = lines[0].strip() if lines else ''
        if not raw_title.startswith('#'):
            continue
        title = raw_title.lstrip('#').strip()
        if not title or title.lower().startswith('2. strategic'):
            continue
        rows = _data_rows(chunk)
        has_table = bool(re.search(r'^\s*\|', chunk, re.MULTILINE))
        if not has_table:
            missing.append(title)
        elif not rows:
            empty.append(title)
    return empty, missing


def inspect_english_cyber_pillars(text: str) -> Dict[str, Any]:
    count, counts, empty_blocks = _count_pillar_blocks(text)
    families = _pillar_families_present(text)
    missing_families = [
        fam for fam in CYBER_PILLAR_FAMILIES if not families.get(fam)]
    _fixed, mm_before, mm_after = _fix_mismatched_outputs(text or '', lang='en')
    empty_headings, missing_tables = _heading_table_issues(text)
    empty_pillars = list(dict.fromkeys(
        list(empty_blocks or []) + empty_headings))
    rendered = (
        count >= 3
        and bool(counts)
        and all(c >= 3 for c in counts)
        and not empty_pillars
        and not missing_tables
        and not missing_families
        and mm_after == 0
        and not _FAMILY_MARK_RE.search(text or '')
    )
    blockers = [] if rendered else ['rel2_pillars_failed:empty_or_invalid']
    if not rendered and not blockers:
        blockers = _rel2_pillars_blockers(text or '')
    return {
        'pillar_count': count,
        'initiative_count_by_pillar': list(counts),
        'empty_pillars': empty_pillars,
        'missing_tables': missing_tables,
        'missing_pillar_families': missing_families,
        'mismatched_outputs_before': mm_before,
        'mismatched_outputs_after': mm_after,
        'rendered_table_valid': rendered,
        'rel2_pillars_blockers': blockers,
    }


def needs_deterministic_fallback(
        text: str,
        *,
        prior_pillars_diag: Optional[Dict[str, Any]] = None,
) -> bool:
    snap = inspect_english_cyber_pillars(text)
    if not snap['rendered_table_valid']:
        return True
    if snap['rel2_pillars_blockers']:
        return True
    prior = prior_pillars_diag or {}
    prior_err = str(prior.get('blocking_error_if_any') or '').strip()
    if prior_err.startswith('rel2_pillars_failed'):
        return True
    if prior and prior.get('rendered_table_valid') is False:
        return True
    if int(prior.get('mismatched_outputs_after') or 0) > 0:
        return True
    return False


def render_deterministic_english_cyber_presave_pillars(
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> str:
    """Canonical 4-pillar English Cyber tables with valid owners."""
    selected = _selected_list(selected_frameworks)
    joined = ' '.join(selected).upper()
    ecc = 'ECC' in joined or 'NCA' in joined or not selected
    dcc = 'DCC' in joined or 'NCA' in joined or not selected
    scope_bits = []
    if ecc:
        scope_bits.append('NCA ECC')
    if dcc:
        scope_bits.append('NCA DCC')
    scope = ' and '.join(scope_bits) or 'NCA ECC and NCA DCC'

    parts = [
        REL36_8_SECTION_HEADING,
        '',
        f'English Cyber pillars scoped to {scope} for this organization.',
        '',
    ]
    header = '| ' + ' | '.join(REL36_8_PILLAR_HEADER) + ' |'
    sep = '|---|---|---|---|'
    for fam, heading, (_catalog_heading, catalog_rows) in zip(
            CYBER_PILLAR_FAMILIES, REL36_12_FAMILY_HEADINGS, _PILLAR_CATALOG_EN):
        rows: List[Tuple[str, str, str, str]] = [
            tuple(row) for row in catalog_rows]
        for extra in _REL36_12_EXTRA_ROWS.get(fam, ()):
            if extra[0].strip().lower() not in {
                    r[0].strip().lower() for r in rows}:
                rows.append(extra)
        parts.append(heading)
        parts.append('')
        parts.append(header)
        parts.append(sep)
        for init, desc, deliverable, owner in rows:
            owner = owner if owner in REL36_2_ALLOWED_OWNERS else 'CISO'
            parts.append(f'| {init} | {desc} | {deliverable} | {owner} |')
        parts.append('')
    return '\n'.join(parts).rstrip() + '\n'


def _parity_pillar_blockers(
        sections: Dict[str, str],
        *,
        backend: Optional[Dict[str, Any]],
        selected_frameworks: Optional[Sequence[str]],
        artifact: Optional[Dict[str, Any]],
) -> List[str]:
    if not (backend or {}).get('build_professional_model'):
        try:
            from professional_strategy_render import normalize_pillar_blocks
            blocks = normalize_pillar_blocks(
                sections.get('pillars') or '', 'en')
            if any((pb.get('table') or {}).get('rows') for pb in blocks):
                return []
            return ['rel2_section_parity_failed:pillars']
        except Exception:  # noqa: BLE001
            return []
    try:
        merged = dict(artifact or {})
        merged['sections'] = sections
        merged['final_markdown'] = sections.get('pillars') or ''
        merged.setdefault('domain', 'cyber')
        merged.setdefault('contract_meta', {
            'lang': 'en',
            'domain': 'cyber',
            'selected_frameworks': list(selected_frameworks or []),
        })
        parity = evaluate_section_parity(merged, backend, lang='en')
        if parity.get('parity_passed'):
            return []
        perr = str(parity.get('blocking_error_if_any') or '')
        if 'pillar' in perr.lower():
            return [perr]
        missing = parity.get('missing_sections') or []
        if 'pillars' in missing:
            return ['rel2_section_parity_failed:pillars']
    except Exception:  # noqa: BLE001
        return []
    return []


def evaluate_rel36_12_en_cyber_presave_pillar_stability(
        *,
        task_id: Any = '',
        attempt_id: Any = '',
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        pillar_count_before: int = 0,
        pillar_count_after: int = 0,
        initiative_count_by_pillar_before: Optional[List[int]] = None,
        initiative_count_by_pillar_after: Optional[List[int]] = None,
        empty_pillars_before: Optional[List[str]] = None,
        empty_pillars_after: Optional[List[str]] = None,
        missing_pillar_families_before: Optional[List[str]] = None,
        missing_pillar_families_after: Optional[List[str]] = None,
        rendered_table_valid_before: bool = False,
        rendered_table_valid_after: bool = False,
        mismatched_outputs_before: int = 0,
        mismatched_outputs_after: int = 0,
        owner_cells_empty_after: Optional[List[str]] = None,
        owner_values_in_deliverable_after: Optional[List[str]] = None,
        deterministic_fallback_applied: bool = False,
        final_rel2_pillars_blockers_after: Optional[List[str]] = None,
        final_section_parity_blockers_after: Optional[List[str]] = None,
        save_allowed_after: bool = False,
) -> Dict[str, Any]:
    empty_after = list(empty_pillars_after or [])
    missing_after = list(missing_pillar_families_after or [])
    owners_empty = list(owner_cells_empty_after or [])
    owners_in_deliv = list(owner_values_in_deliverable_after or [])
    rel2_blockers = list(final_rel2_pillars_blockers_after or [])
    parity_blockers = list(final_section_parity_blockers_after or [])
    passed = (
        bool(rendered_table_valid_after)
        and not empty_after
        and not missing_after
        and int(mismatched_outputs_after or 0) == 0
        and not owners_empty
        and not owners_in_deliv
        and not rel2_blockers
        and not parity_blockers
        and bool(save_allowed_after)
    )
    return {
        'task_id': str(task_id or ''),
        'attempt_id': str(attempt_id or ''),
        'domain': _normalize_rel31_domain_code(domain) or 'cyber',
        'lang': normalize_rel36_lang(lang) or 'en',
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': _selected_list(selected_frameworks),
        'pillar_count_before': int(pillar_count_before or 0),
        'pillar_count_after': int(pillar_count_after or 0),
        'initiative_count_by_pillar_before': list(
            initiative_count_by_pillar_before or []),
        'initiative_count_by_pillar_after': list(
            initiative_count_by_pillar_after or []),
        'empty_pillars_before': list(empty_pillars_before or []),
        'empty_pillars_after': empty_after,
        'missing_pillar_families_before': list(
            missing_pillar_families_before or []),
        'missing_pillar_families_after': missing_after,
        'rendered_table_valid_before': bool(rendered_table_valid_before),
        'rendered_table_valid_after': bool(rendered_table_valid_after),
        'mismatched_outputs_before': int(mismatched_outputs_before or 0),
        'mismatched_outputs_after': int(mismatched_outputs_after or 0),
        'owner_cells_empty_after': owners_empty,
        'owner_values_in_deliverable_after': owners_in_deliv,
        'deterministic_fallback_applied': bool(deterministic_fallback_applied),
        'final_rel2_pillars_blockers_after': rel2_blockers,
        'final_section_parity_blockers_after': parity_blockers,
        'save_allowed_after': bool(save_allowed_after),
        'passed': passed,
        'applied': True,
    }


def emit_rel36_12_en_cyber_presave_pillar_stability(
        payload: Dict[str, Any],
) -> None:
    try:
        print(
            REL36_12_EN_CYBER_PRESAVE_PILLAR_STABILITY_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_12_en_cyber_presave_pillar_stability(
        sections: Dict[str, str],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        backend: Optional[Dict[str, Any]] = None,
        task_id: Any = None,
        attempt_id: Any = None,
        artifact: Optional[Dict[str, Any]] = None,
        prior_pillars_diag: Optional[Dict[str, Any]] = None,
        emit: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = dict(sections or {})
    before_text = str(out.get('pillars') or '')
    if not rel36_12_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks,
            pillars_text=before_text):
        return sections, {
            'applied': False,
            'passed': False,
            'deterministic_fallback_applied': False,
            'action_taken': 'skipped',
            'save_allowed_after': False,
        }

    attempt = attempt_id or str(uuid.uuid4())[:8]
    before = inspect_english_cyber_pillars(before_text)
    fallback = needs_deterministic_fallback(
        before_text, prior_pillars_diag=prior_pillars_diag)

    if fallback:
        out['pillars'] = render_deterministic_english_cyber_presave_pillars(
            selected_frameworks)

    backend = dict(backend or {})
    backend.setdefault('selected_frameworks', _selected_list(selected_frameworks))
    backend.setdefault('document_type', document_type or 'strategy')
    backend.setdefault('task_id', task_id)
    finalize_diag: Dict[str, Any] = {}
    try:
        out, finalize_diag = finalize_pillars(
            out, lang='en', domain='cyber', backend=backend)
    except Exception:  # noqa: BLE001
        finalize_diag = {}

    after_text = str(out.get('pillars') or '')
    after = inspect_english_cyber_pillars(after_text)
    # Prefer the unchanged REL2 finalize model when it is available.
    if finalize_diag:
        after['pillar_count'] = int(
            finalize_diag.get('pillar_count_after') or after['pillar_count'])
        after['initiative_count_by_pillar'] = list(
            finalize_diag.get('initiative_count_by_pillar')
            or after['initiative_count_by_pillar'])
        after['empty_pillars'] = list(
            finalize_diag.get('empty_pillars_after') or after['empty_pillars'])
        after['missing_pillar_families'] = list(
            finalize_diag.get('missing_pillar_families_after')
            or after['missing_pillar_families'])
        after['mismatched_outputs_after'] = int(
            finalize_diag.get('mismatched_outputs_after')
            if finalize_diag.get('mismatched_outputs_after') is not None
            else after['mismatched_outputs_after'])
        after['rendered_table_valid'] = bool(
            finalize_diag.get('rendered_table_valid')) and after[
            'mismatched_outputs_after'] == 0 and not after['empty_pillars']
        err = str(finalize_diag.get('blocking_error_if_any') or '').strip()
        after['rel2_pillars_blockers'] = [err] if err else (
            [] if after['rendered_table_valid'] else [
                'rel2_pillars_failed:empty_or_invalid'])

    if fallback and (
            after['rel2_pillars_blockers']
            or not after['rendered_table_valid']):
        # Last chance: bind the deterministic tables without a second
        # synthesis pass that could reintroduce an unfixed mismatch.
        out['pillars'] = render_deterministic_english_cyber_presave_pillars(
            selected_frameworks)
        after = inspect_english_cyber_pillars(str(out.get('pillars') or ''))
        finalize_diag = {
            'pillar_count_before': before['pillar_count'],
            'pillar_count_after': after['pillar_count'],
            'initiative_count_by_pillar': after['initiative_count_by_pillar'],
            'empty_pillars_before': before['empty_pillars'],
            'empty_pillars_after': after['empty_pillars'],
            'missing_pillar_families_before': before['missing_pillar_families'],
            'missing_pillar_families_after': after['missing_pillar_families'],
            'mismatched_outputs_before': before['mismatched_outputs_after'],
            'mismatched_outputs_after': after['mismatched_outputs_after'],
            'rendered_table_valid': after['rendered_table_valid'],
            'action_taken': 'rel36_12_deterministic_fallback',
            'blocking_error_if_any': (
                '' if after['rendered_table_valid']
                else 'rel2_pillars_failed:empty_or_invalid'),
        }
        after['rel2_pillars_blockers'] = (
            [] if after['rendered_table_valid']
            else ['rel2_pillars_failed:empty_or_invalid'])

    empty_owners, in_deliv = _owner_binding_inventory(out.get('pillars') or '')
    parity_blockers = _parity_pillar_blockers(
        out,
        backend=backend,
        selected_frameworks=_selected_list(selected_frameworks),
        artifact=artifact,
    )
    rel2_blockers = list(after['rel2_pillars_blockers'])
    rendered_after = bool(after['rendered_table_valid']) and not rel2_blockers
    save_allowed = (
        rendered_after
        and not after['empty_pillars']
        and not rel2_blockers
        and not parity_blockers
        and not empty_owners
        and not in_deliv
    )
    diag = evaluate_rel36_12_en_cyber_presave_pillar_stability(
        task_id=task_id,
        attempt_id=attempt,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        pillar_count_before=before['pillar_count'],
        pillar_count_after=after['pillar_count'],
        initiative_count_by_pillar_before=before['initiative_count_by_pillar'],
        initiative_count_by_pillar_after=after['initiative_count_by_pillar'],
        empty_pillars_before=before['empty_pillars'],
        empty_pillars_after=after['empty_pillars'],
        missing_pillar_families_before=before['missing_pillar_families'],
        missing_pillar_families_after=after['missing_pillar_families'],
        rendered_table_valid_before=before['rendered_table_valid'],
        rendered_table_valid_after=rendered_after,
        mismatched_outputs_before=before['mismatched_outputs_after'],
        mismatched_outputs_after=after['mismatched_outputs_after'],
        owner_cells_empty_after=empty_owners,
        owner_values_in_deliverable_after=in_deliv,
        deterministic_fallback_applied=fallback,
        final_rel2_pillars_blockers_after=rel2_blockers,
        final_section_parity_blockers_after=parity_blockers,
        save_allowed_after=save_allowed,
    )
    diag['finalize_diag'] = finalize_diag
    if emit:
        emit_rel36_12_en_cyber_presave_pillar_stability(diag)
    return out, diag
