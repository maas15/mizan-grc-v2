"""REL32 — post-render traceability immutability check across export routes."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY,
    _parse_trace_rows,
)
from release_engine_v3.rel32_docx_traceability_evidence import (
    evaluate_docx_traceability_evidence,
    expected_traceability_rows_from_registry,
    extract_docx_flat_traceability_rows,
)

_SENSITIVE = TRACE_CANONICAL_REGISTRY['sensitive_handling']
_CLASSIFICATION_GAP = TRACE_CANONICAL_REGISTRY['data_classification']['expected_gap']


def _rows_from_route_text(text: str) -> List[Dict[str, str]]:
    rows = extract_docx_flat_traceability_rows(text or '')
    if rows:
        return rows
    lines, hdr, table_rows = _parse_trace_rows(text or '')
    if hdr < 0 or not table_rows:
        return rows
    from release_engine.traceability_substance_model import (
        _cap_col_idx,
        _gap_col_idx,
    )
    cap_idx = _cap_col_idx(lines[hdr])
    gap_idx = _gap_col_idx(lines[hdr])
    for cells in table_rows:
        cap = cells[cap_idx] if len(cells) > cap_idx else ''
        gap = cells[gap_idx] if len(cells) > gap_idx else ''
        fw = cells[0] if cells else ''
        if cap and gap:
            rows.append({
                'framework': fw,
                'capability': cap,
                'gap': gap,
                'initiative': '',
            })
    return rows


def _route_mutations(
        route: str,
        rows: List[Dict[str, str]],
) -> Tuple[List[Dict[str, str]], List[str]]:
    mutated: List[Dict[str, str]] = []
    blockers: List[str] = []
    by_cap = {
        str(r.get('capability') or '').strip(): str(r.get('gap') or '').strip()
        for r in (rows or [])
        if str(r.get('capability') or '').strip()
    }
    for canon in expected_traceability_rows_from_registry():
        cap = canon['capability']
        expected_gap = canon['gap']
        actual_gap = by_cap.get(cap, '')
        if not actual_gap:
            continue
        if expected_gap in actual_gap or actual_gap == expected_gap:
            continue
        if (
                cap == _SENSITIVE['capability']
                and _CLASSIFICATION_GAP in actual_gap
        ):
            blockers.append(
                f'rel32_traceability_post_render_mutation:{cap}')
            mutated.append({
                'route': route,
                'capability': cap,
                'expected_gap': expected_gap,
                'actual_gap': actual_gap,
                'canonical_family': 'sensitive_handling',
            })
            continue
        blockers.append(f'{route}:trace_gap_mismatch:{cap}')
        mutated.append({
            'route': route,
            'capability': cap,
            'expected_gap': expected_gap,
            'actual_gap': actual_gap,
            'canonical_family': canon.get('family', ''),
        })
    return mutated, blockers


def evaluate_traceability_immutability(
        *,
        preview_text: str = '',
        docx_text: str = '',
        pdf_text: str = '',
        frozen_traceability: str = '',
        artifact_complete: bool = False,
) -> Dict[str, Any]:
    """Compare rendered route text against TRACE_CANONICAL_REGISTRY rows."""
    canonical_rows = expected_traceability_rows_from_registry()
    route_payloads = {
        'preview': preview_text or '',
        'docx': docx_text or '',
        'pdf': pdf_text or '',
    }
    rendered_by_route: Dict[str, List[Dict[str, str]]] = {}
    mutated_rows: List[Dict[str, str]] = []
    blocking_errors: List[str] = []
    mutating_layer: Optional[str] = None

    for route, text in route_payloads.items():
        if not text.strip():
            rendered_by_route[route] = []
            continue
        rows = _rows_from_route_text(text)
        rendered_by_route[route] = rows
        route_mutated, route_blockers = _route_mutations(route, rows)
        mutated_rows.extend(route_mutated)
        blocking_errors.extend(route_blockers)
        defects, _diag = evaluate_docx_traceability_evidence(
            text,
            frozen_traceability=(
                frozen_traceability if route == 'docx' else ''),
            artifact_complete=artifact_complete and route == 'docx',
        )
        for defect in defects:
            if defect.startswith('rel32_traceability_post_render_mutation:'):
                cap = defect.split(':', 1)[-1]
                blocking_errors.append(defect)
                if not any(
                        m.get('capability') == cap for m in mutated_rows):
                    mutated_rows.append({
                        'route': route,
                        'capability': cap,
                        'expected_gap': _SENSITIVE['expected_gap'],
                        'actual_gap': by_cap_gap(rows, cap),
                        'canonical_family': 'sensitive_handling',
                    })
            elif defect.startswith('trace_gap_mismatch:'):
                cap = defect.split(':', 1)[-1]
                blocking_errors.append(f'{route}:{defect}')
            else:
                blocking_errors.append(f'{route}:{defect}')

    blocking_errors = list(dict.fromkeys(blocking_errors))
    post_render_mutation_detected = bool(mutated_rows)
    if post_render_mutation_detected and not mutating_layer:
        mutating_layer = 'unknown_post_render_layer'

    return {
        'canonical_traceability_rows': canonical_rows,
        'rendered_preview_traceability_rows': rendered_by_route.get('preview', []),
        'rendered_docx_traceability_rows': rendered_by_route.get('docx', []),
        'rendered_pdf_traceability_rows': rendered_by_route.get('pdf', []),
        'mutated_rows': mutated_rows,
        'post_render_mutation_detected': post_render_mutation_detected,
        'mutating_layer_if_known': mutating_layer,
        'traceability_immutability_passed': not blocking_errors,
        'blocking_errors': blocking_errors,
    }


def by_cap_gap(rows: List[Dict[str, str]], cap: str) -> str:
    for row in rows or []:
        if str(row.get('capability') or '').strip() == cap:
            return str(row.get('gap') or '').strip()
    return ''


def emit_rel32_traceability_immutability_check(
        payload: Dict[str, Any],
) -> Dict[str, Any]:
    body = dict(payload or {})
    try:
        print(
            '[REL32-TRACEABILITY-IMMUTABILITY-CHECK] '
            + json.dumps(body, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
    return body
