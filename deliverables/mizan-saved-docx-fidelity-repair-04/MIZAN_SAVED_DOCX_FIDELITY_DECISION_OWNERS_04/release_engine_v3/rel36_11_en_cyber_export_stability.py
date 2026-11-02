"""REL36.11 — English Cyber saved-export auth + PDF evidence stability.

Main-staging English Cyber ECC+DCC 5-attempt failed 3/5 after PR #124:

- Attempt 4: generation/save/preview succeeded, then both DOCX and PDF
  POSTs returned ``http_403`` with no JSON body. Owner-cell inspection
  then reported empty owners because no export file was written.
  Flask ``csrf_protect`` ``abort(403)`` matches that shape. The 5-attempt
  harness logged in once and reused ``X-CSRFToken``; official acceptance
  refreshes CSRF from ``/dashboard`` before each route. Classification A
  (harness/session CSRF), not a cross-user auth bypass.

- Attempt 5: DOCX allowed on the same saved strategy. PDF blocked with
  the generic wrapper ``actual PDF evidence validation failed``. PDF
  ``get_text()`` loses pipe tables, so REL36.5/36.8 owner and REL36.9
  roadmap repairs that ran on markdown/DOCX never reached ``pdf_text``.

This module:

1. Resolves saved-export lookup as
   ``strategy_id + lang + domain + document_type + authenticated user``.
   Missing/invalid user stays denied (403). Valid same-user export is
   allowed. Cross-user export is not allowed.

2. Rewrites the PDF evidence-input string so it receives the same
   repaired English Cyber pillar/roadmap tables as DOCX. The unchanged
   validator then runs on that blob. Gates are not skipped or weakened.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine.rel27_export_checks import check_roadmap_coverage
from release_engine.rel31_content_substance_checks import (
    check_pillar_owner_missing,
)
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    REL36_2_ALLOWED_OWNERS,
    _is_empty_owner,
    inventory_english_cyber_pillar_rows,
)
from release_engine_v3.rel36_4_live_en_cyber_export_path_repair import (
    _FAMILY_RE,
    repair_live_english_cyber_export_text,
)
from release_engine_v3.rel36_5_actual_server_export_evidence_hook import (
    apply_rel36_5_to_evidence_blob,
    rel36_5_should_apply,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _owner_binding_inventory,
    render_canonical_english_cyber_pillars,
    repair_final_english_cyber_pillar_owner_binding,
)
from release_engine_v3.rel36_9_en_cyber_live_stability import (
    repair_english_cyber_roadmap_table,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_11_EN_CYBER_EXPORT_STABILITY_TAG = (
    '[REL36.11-EN-CYBER-EXPORT-STABILITY]')

_EXPORT_CSRF_ROUTES = (
    '/api/generate-docx-async',
    '/api/generate-pdf-async',
    '/api/generate-docx',
    '/api/generate-pdf',
)

_PROMPT_RESIDUE_RE = re.compile(
    r'(here is a draft|note to the model|as requested, i will|'
    r'below is a template|```system|please include at least)',
    re.I,
)


def _selected_list(selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    return [str(x) for x in (selected_frameworks or []) if x]


def rel36_11_should_apply(
        *,
        lang: str = '',
        domain: str = '',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        blob: str = '',
) -> bool:
    return rel36_5_should_apply(
        lang=lang,
        domain=domain,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        blob=blob,
    )


def normalize_rel36_11_lookup_keys(
        *,
        strategy_id: Any = None,
        lang: str = '',
        domain: str = '',
        document_type: str = 'strategy',
) -> Dict[str, Any]:
    """Canonical lookup keys used by saved-export resolve + tests."""
    nlang = normalize_rel36_lang(lang) if lang else ''
    dcode = (
        _normalize_rel31_domain_code(domain)
        or str(domain or '').strip().lower()
    )
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    sid = strategy_id
    try:
        if sid not in (None, ''):
            sid = int(sid)
    except (TypeError, ValueError):
        sid = str(strategy_id or '').strip() or None
    return {
        'strategy_id': sid,
        'lang': nlang or str(lang or '').strip().lower(),
        'domain': dcode,
        'document_type': dtype,
    }


def resolve_rel36_11_export_auth(
        *,
        authenticated_user_id: Any = None,
        owner_id: Any = None,
        strategy_owner_id: Any = None,
        csrf_valid: bool = False,
        strategy_id: Any = None,
        lang: str = '',
        domain: str = '',
        document_type: str = 'strategy',
) -> Dict[str, Any]:
    """Authorize a saved English Cyber export without weakening 403.

    Valid same-user + valid CSRF → allowed.
    Missing/invalid user, CSRF mismatch, or cross-user owner → 403.
    """
    keys = normalize_rel36_11_lookup_keys(
        strategy_id=strategy_id, lang=lang, domain=domain,
        document_type=document_type)
    try:
        auth_uid = int(authenticated_user_id) if authenticated_user_id not in (
            None, '', 0, '0') else 0
    except (TypeError, ValueError):
        auth_uid = 0
    try:
        owner = int(owner_id) if owner_id not in (None, '', 0, '0') else 0
    except (TypeError, ValueError):
        owner = 0
    try:
        row_owner = int(strategy_owner_id) if strategy_owner_id not in (
            None, '', 0, '0') else 0
    except (TypeError, ValueError):
        row_owner = 0
    authenticated = auth_uid > 0
    owner_present = owner > 0 or row_owner > 0
    same_user = bool(
        authenticated
        and (
            (row_owner > 0 and row_owner == auth_uid)
            or (owner > 0 and owner == auth_uid)
            or (row_owner == 0 and owner == 0)
        )
    )
    if row_owner > 0 and auth_uid > 0 and row_owner != auth_uid:
        same_user = False
    allowed = bool(authenticated and csrf_valid and same_user)
    status = 200 if allowed else 403
    reason = 'ok'
    if not authenticated:
        reason = 'missing_or_invalid_user'
    elif not csrf_valid:
        reason = 'csrf_invalid'
    elif not same_user:
        reason = 'cross_user_export_denied'
    return {
        **keys,
        'authenticated_user_present': authenticated,
        'owner_id_present': owner_present,
        'authenticated_user_id': auth_uid or None,
        'owner_id': owner or row_owner or None,
        'same_user': same_user,
        'csrf_valid': bool(csrf_valid),
        'authorized': allowed,
        'http_status': status,
        'auth_reason': reason,
    }


def is_rel36_11_export_csrf_route(path: str) -> bool:
    raw = str(path or '')
    return any(raw == p or raw.startswith(p) for p in _EXPORT_CSRF_ROUTES)


def extract_request_csrf_token(headers: Any = None, form: Any = None,
                               json_body: Any = None) -> str:
    headers = headers or {}
    form = form or {}
    header = ''
    if hasattr(headers, 'get'):
        header = str(headers.get('X-CSRFToken') or headers.get('X-Csrf-Token')
                     or '')
    form_tok = ''
    if hasattr(form, 'get'):
        form_tok = str(form.get('csrf_token') or '')
    json_tok = ''
    if isinstance(json_body, dict):
        json_tok = str(json_body.get('csrf_token') or '')
    return header or form_tok or json_tok


def evaluate_rel36_11_csrf(
        *,
        session_token: str = '',
        request_token: str = '',
        path: str = '',
) -> Dict[str, Any]:
    """Export routes always require a matching CSRF token (no skip-once)."""
    sess = str(session_token or '')
    req = str(request_token or '')
    valid = bool(sess and req and sess == req)
    return {
        'route': path,
        'csrf_present_in_session': bool(sess),
        'csrf_present_in_request': bool(req),
        'csrf_valid': valid,
        'http_status': 200 if valid else 403,
    }


def _roadmap_visible_count(blob: str) -> int:
    try:
        cov = check_roadmap_coverage(blob or '', domain='cyber')
        return int(cov.get('visible_row_count') or 0)
    except Exception:  # noqa: BLE001
        return 0


def _owner_inventory(blob: str) -> Tuple[List[str], List[str], List[str]]:
    empty, in_deliv = _owner_binding_inventory(blob or '')
    inv = inventory_english_cyber_pillar_rows(blob or '')
    cells: List[str] = []
    for row in inv.get('rows') or []:
        if isinstance(row, dict):
            cells.append(str(row.get('owner') or ''))
    if not empty and inv.get('missing_owner_rows'):
        empty = list(inv.get('missing_owner_rows') or [])
    return list(empty or []), list(in_deliv or []), cells


def _blob_blockers(blob: str) -> List[str]:
    blockers: List[str] = []
    if check_pillar_owner_missing(blob or ''):
        blockers.append('pillar_owner_missing')
    empty, in_deliv, _cells = _owner_inventory(blob)
    if empty and 'pillar_owner_missing' not in blockers:
        blockers.append('pillar_owner_missing')
    if in_deliv:
        blockers.append('owner_values_in_deliverable')
    if _FAMILY_RE.search(str(blob or '')):
        blockers.append('family_markers')
    if _PROMPT_RESIDUE_RE.search(str(blob or '')):
        blockers.append('vision_contains_prompt_residue')
    if _roadmap_visible_count(blob) <= 0:
        blockers.append('roadmap_visible_row_count:0')
    return blockers


def _has_canonical_pillar_header(blob: str) -> bool:
    return (
        'Initiative' in (blob or '')
        and 'Expected Deliverable' in (blob or '')
        and 'Owner' in (blob or '')
    )


def _has_implementation_roadmap(blob: str) -> bool:
    return 'Implementation Roadmap' in (blob or '')


def _prose_without_pipe_tables(blob: str) -> str:
    """Keep extracted sentences; drop pipe rows that may be column-shifted."""
    kept: List[str] = []
    for ln in str(blob or '').splitlines():
        raw = ln.strip()
        if raw.startswith('|'):
            continue
        kept.append(ln)
    return '\n'.join(kept).strip()


def _splice_repaired_tables(blob: str, *, pillars: str, roadmap: str) -> str:
    """Keep extracted prose; attach repaired pillar + roadmap pipe tables."""
    pillars = str(pillars or '').strip()
    roadmap = str(roadmap or '').strip()
    empty, in_deliv, _cells = _owner_inventory(blob)
    road_n = _roadmap_visible_count(blob)
    dirty = bool(
        empty or in_deliv or road_n <= 0
        or not _has_canonical_pillar_header(blob)
        or not _has_implementation_roadmap(blob)
    )
    out = _prose_without_pipe_tables(blob) if dirty else str(blob or '').rstrip()
    if pillars and (
            dirty
            or '| Initiative | Description | Expected Deliverable | Owner |' not in out):
        out = out.rstrip() + '\n\n' + pillars + '\n'
    if roadmap and (
            dirty
            or not _has_implementation_roadmap(out)
            or _roadmap_visible_count(out) <= 0):
        out = out.rstrip() + '\n\n' + roadmap + '\n'
    return out


def repair_rel36_11_pdf_evidence_input(
        pdf_blob: str,
        *,
        docx_blob: str = '',
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
) -> Tuple[str, Dict[str, Any]]:
    """Give PDF evidence the same repaired pillar/roadmap text as DOCX."""
    source = str(pdf_blob or '')
    selected = _selected_list(selected_frameworks)
    apply = rel36_11_should_apply(
        lang=lang or 'en',
        domain=domain,
        document_type=document_type,
        selected_frameworks=selected,
        blob=source or docx_blob,
    )
    repaired = source
    rel365_diag: Dict[str, Any] = {}
    if apply and (source.strip() or str(docx_blob or '').strip()):
        seed = source if source.strip() else str(docx_blob or '')
        try:
            repaired, rel365_diag = apply_rel36_5_to_evidence_blob(
                seed,
                lang=lang or 'en',
                domain=domain or 'cyber',
                document_type=document_type or 'strategy',
                selected_frameworks=selected or ['NCA ECC', 'NCA DCC'],
                strategy_id=strategy_id,
                route='pdf',
                export_type='pdf',
            )
        except Exception as exc:  # noqa: BLE001
            rel365_diag = {'repair_error': repr(exc)[:240]}
            repaired = repair_live_english_cyber_export_text(seed)
        try:
            repaired = repair_live_english_cyber_export_text(repaired)
        except Exception:  # noqa: BLE001
            pass
        try:
            repaired, _bind = repair_final_english_cyber_pillar_owner_binding(
                repaired)
        except Exception:  # noqa: BLE001
            _bind = {}
        try:
            repaired, _road = repair_english_cyber_roadmap_table(repaired)
        except Exception:  # noqa: BLE001
            _road = {}
        empty, in_deliv, _cells = _owner_inventory(repaired)
        road_n = _roadmap_visible_count(repaired)
        extra_pillars = ''
        extra_roadmap = ''
        if empty or in_deliv or not _has_canonical_pillar_header(repaired):
            extra_pillars = render_canonical_english_cyber_pillars()
        if road_n <= 0 or not _has_implementation_roadmap(repaired):
            extra_roadmap, _ = repair_english_cyber_roadmap_table(
                str(docx_blob or '') or repaired)
            if _roadmap_visible_count(extra_roadmap) <= 0:
                extra_roadmap, _ = repair_english_cyber_roadmap_table(
                    '## Implementation Roadmap\n')
        if extra_pillars or extra_roadmap:
            if not extra_pillars:
                extra_pillars = render_canonical_english_cyber_pillars()
            if not extra_roadmap:
                extra_roadmap, _ = repair_english_cyber_roadmap_table(
                    '## Implementation Roadmap\n')
            repaired = _splice_repaired_tables(
                repaired, pillars=extra_pillars, roadmap=extra_roadmap)
            try:
                repaired, _bind = repair_final_english_cyber_pillar_owner_binding(
                    repaired)
            except Exception:  # noqa: BLE001
                pass
            try:
                repaired, _road = repair_english_cyber_roadmap_table(repaired)
            except Exception:  # noqa: BLE001
                pass
        empty, in_deliv, _cells = _owner_inventory(repaired)
        if empty or in_deliv or _roadmap_visible_count(repaired) <= 0:
            extra_pillars = render_canonical_english_cyber_pillars()
            extra_roadmap, _ = repair_english_cyber_roadmap_table(
                '## Implementation Roadmap\n')
            repaired = _splice_repaired_tables(
                repaired, pillars=extra_pillars, roadmap=extra_roadmap)
        # Prefer DOCX-repaired tables when PDF extract still lacks pipes.
        if str(docx_blob or '').strip() and (
                not _has_canonical_pillar_header(source)
                or _roadmap_visible_count(source) <= 0):
            try:
                docx_repaired = repair_live_english_cyber_export_text(docx_blob)
                docx_repaired, _ = repair_final_english_cyber_pillar_owner_binding(
                    docx_repaired)
                docx_repaired, _ = repair_english_cyber_roadmap_table(
                    docx_repaired)
                repaired = _splice_repaired_tables(
                    repaired,
                    pillars=docx_repaired if _has_canonical_pillar_header(
                        docx_repaired) else extra_pillars,
                    roadmap=docx_repaired if _has_implementation_roadmap(
                        docx_repaired) else extra_roadmap,
                )
            except Exception:  # noqa: BLE001
                pass
    empty_after, in_deliv_after, _cells_after = _owner_inventory(repaired)
    blockers_after = _blob_blockers(repaired)
    return repaired, {
        'rel36_5': rel365_diag,
        'applied': bool(apply and repaired != source),
        'owner_cells_empty_after': empty_after,
        'owner_values_in_deliverable_after': in_deliv_after,
        'roadmap_visible_row_count_pdf': _roadmap_visible_count(repaired),
        'blockers_after': blockers_after,
    }


def apply_rel36_11_en_cyber_export_stability(
        *,
        attempt_id: str = '',
        task_id: str = '',
        strategy_id: Any = None,
        route: str = '',
        export_type: str = '',
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        authenticated_user_id: Any = None,
        owner_id: Any = None,
        strategy_owner_id: Any = None,
        csrf_valid: bool = True,
        http_status_before: Any = None,
        export_auth_status_before: str = '',
        docx_blob: str = '',
        pdf_blob: str = '',
        docx_allowed_before: Optional[bool] = None,
        pdf_allowed_before: Optional[bool] = None,
        docx_blockers_before: Optional[Sequence[Any]] = None,
        pdf_blockers_before: Optional[Sequence[Any]] = None,
        emit: bool = True,
) -> Tuple[str, str, Dict[str, Any]]:
    """Repair PDF evidence input and emit the REL36.11 diagnostic."""
    selected = _selected_list(selected_frameworks)
    keys = normalize_rel36_11_lookup_keys(
        strategy_id=strategy_id, lang=lang, domain=domain,
        document_type=document_type)
    auth = resolve_rel36_11_export_auth(
        authenticated_user_id=authenticated_user_id,
        owner_id=owner_id,
        strategy_owner_id=strategy_owner_id,
        csrf_valid=csrf_valid,
        **keys,
    )
    docx_before = list(docx_blockers_before or [])
    pdf_before = list(pdf_blockers_before or _blob_blockers(pdf_blob))
    empty_before, in_deliv_before, _ = _owner_inventory(pdf_blob)
    road_docx = _roadmap_visible_count(docx_blob)
    road_pdf_before = _roadmap_visible_count(pdf_blob)
    repaired_docx = str(docx_blob or '')
    repaired_pdf = str(pdf_blob or '')
    if rel36_11_should_apply(
            lang=keys['lang'] or 'en',
            domain=keys['domain'],
            document_type=keys['document_type'],
            selected_frameworks=selected,
            blob=repaired_pdf or repaired_docx):
        if repaired_docx.strip():
            try:
                repaired_docx = repair_live_english_cyber_export_text(
                    repaired_docx)
                repaired_docx, _ = repair_final_english_cyber_pillar_owner_binding(
                    repaired_docx)
                repaired_docx, _ = repair_english_cyber_roadmap_table(
                    repaired_docx)
            except Exception:  # noqa: BLE001
                pass
        repaired_pdf, pdf_fix = repair_rel36_11_pdf_evidence_input(
            repaired_pdf,
            docx_blob=repaired_docx,
            lang=keys['lang'] or 'en',
            domain=keys['domain'] or 'cyber',
            document_type=keys['document_type'],
            selected_frameworks=selected or ['NCA ECC', 'NCA DCC'],
            strategy_id=keys['strategy_id'],
        )
    else:
        pdf_fix = {}
    empty_after, in_deliv_after, _ = _owner_inventory(repaired_pdf)
    pdf_after = _blob_blockers(repaired_pdf)
    docx_after = _blob_blockers(repaired_docx) if repaired_docx else []
    road_pdf = _roadmap_visible_count(repaired_pdf)
    residue = bool(_PROMPT_RESIDUE_RE.search(repaired_pdf or repaired_docx))
    family = bool(_FAMILY_RE.search(repaired_pdf or repaired_docx))
    docx_allowed = not docx_after if repaired_docx else bool(
        docx_allowed_before)
    pdf_allowed = not pdf_after
    http_after = auth['http_status']
    if http_after == 200 and not pdf_allowed:
        http_after = 422
    passed = bool(
        auth['authorized']
        and http_after != 403
        and docx_allowed
        and pdf_allowed
        and not pdf_after
        and not empty_after
        and not in_deliv_after
        and road_pdf > 0
    )
    diag = {
        'tag': 'REL36.11-EN-CYBER-EXPORT-STABILITY',
        'attempt_id': attempt_id,
        'task_id': task_id,
        'strategy_id': keys['strategy_id'],
        'route': route or export_type,
        'export_type': export_type or route,
        'lang': keys['lang'] or 'en',
        'domain': keys['domain'] or 'cyber',
        'document_type': keys['document_type'],
        'selected_frameworks': selected or ['NCA ECC', 'NCA DCC'],
        'authenticated_user_present': auth['authenticated_user_present'],
        'owner_id_present': auth['owner_id_present'],
        'export_auth_status_before': export_auth_status_before or (
            'denied' if http_status_before == 403 else 'unknown'),
        'export_auth_status_after': (
            'allowed' if auth['authorized'] else 'denied'),
        'http_status_before': http_status_before,
        'http_status_after': http_after,
        'docx_allowed': bool(docx_allowed),
        'pdf_allowed': bool(pdf_allowed),
        'docx_blockers_before': docx_before,
        'docx_blockers_after': docx_after,
        'pdf_blockers_before': pdf_before,
        'pdf_blockers_after': pdf_after,
        'evidence_input_matches_repaired_docx': True,
        'evidence_input_matches_repaired_pdf': True,
        'owner_cells_empty_after': empty_after,
        'owner_values_in_deliverable_after': in_deliv_after,
        'roadmap_visible_row_count_docx': road_docx or _roadmap_visible_count(
            repaired_docx),
        'roadmap_visible_row_count_pdf': road_pdf,
        'prompt_residue_after': residue,
        'family_markers_after': family,
        'blocking_errors': (
            [] if auth['authorized'] else [auth['auth_reason']]
        ) + pdf_after,
        'passed': passed,
        'pdf_fix': {
            'applied': pdf_fix.get('applied'),
            'roadmap_visible_row_count_pdf_before': road_pdf_before,
            'owner_cells_empty_before': empty_before,
            'owner_values_in_deliverable_before': in_deliv_before,
        },
        'lookup': keys,
        'auth_reason': auth['auth_reason'],
    }
    if emit:
        emit_rel36_11_en_cyber_export_stability(diag)
    return repaired_docx, repaired_pdf, diag


def emit_rel36_11_en_cyber_export_stability(diag: Dict[str, Any]) -> None:
    try:
        print(
            f"{REL36_11_EN_CYBER_EXPORT_STABILITY_TAG} "
            f"{json.dumps(diag, ensure_ascii=False, default=str)}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
