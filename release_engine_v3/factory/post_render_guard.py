"""Post-render canonical mutation guards."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.registries.platform_registries import (
    immutable_traceability_row,
    normalize_canonical_family,
)


def _trace_defects_for_route(route: str, text: str) -> Tuple[List[str], Dict[str, Any]]:
    if not (text or '').strip():
        return [], {}
    try:
        from release_engine_v3.rel32_docx_traceability_evidence import (
            evaluate_docx_traceability_evidence,
        )
        defects, diag = evaluate_docx_traceability_evidence(text)
        diag = dict(diag or {})
        diag['route'] = route
        return list(defects or []), diag
    except Exception as exc:  # noqa: BLE001
        return [f'{route}_traceability_eval_error:{exc}'], {'route': route}


def verify_immutable_traceability_routes(
        *,
        preview_text: str = '',
        docx_text: str = '',
        pdf_text: str = '',
) -> Dict[str, Any]:
    """Enforce canonical registry traceability across preview/docx/pdf."""
    sh = immutable_traceability_row('sensitive_handling')
    required_cap = sh['capability'] if sh else ''
    required_gap = sh['gap'] if sh else ''

    route_results: Dict[str, Any] = {}
    blocking: List[str] = []
    for route, text in (
            ('preview', preview_text),
            ('docx', docx_text),
            ('pdf', pdf_text)):
        if not (text or '').strip():
            continue
        defects, diag = _trace_defects_for_route(route, text)
        route_results[route] = {
            'traceability_bad_mappings': defects,
            'diagnostics': diag,
            'passed': not defects,
        }
        if required_cap and required_cap not in text:
            blocking.append(f'{route}:missing_capability:{required_cap}')
        if required_gap and required_gap not in text:
            blocking.append(f'{route}:missing_expected_gap:{required_gap}')
        for defect in defects:
            blocking.append(f'{route}:{defect}')

    docx_failed = bool(
        route_results.get('docx', {}).get('traceability_bad_mappings'))
    pdf_passed = route_results.get('pdf', {}).get('passed')
    if docx_failed and pdf_passed:
        blocking.append(
            'pdf_traceability_semantic_bypass_docx_failure')
        route_results.setdefault('pdf', {})['passed'] = False

    return {
        'passed': not blocking,
        'blocking_errors': list(dict.fromkeys(blocking)),
        'route_results': route_results,
        'required_sensitive_handling': sh,
    }


def verify_no_post_render_mutation(
        frozen_rows: Optional[List[Dict[str, str]]],
        *,
        route_text: str,
        section: str = 'traceability',
        field: str = 'gap',
) -> List[str]:
    """Block when exported text diverges from frozen canonical rows."""
    blockers: List[str] = []
    if not frozen_rows or not (route_text or '').strip():
        return blockers
    for row in frozen_rows:
        fam = normalize_canonical_family(str(row.get('family') or ''))
        expected_gap = (row.get('gap') or '').strip()
        capability = (row.get('capability') or '').strip()
        if not expected_gap or not capability:
            continue
        if capability in route_text and expected_gap not in route_text:
            wrong = immutable_traceability_row(fam)
            if wrong and wrong['gap'] in route_text:
                continue
            blockers.append(
                f'post_render_canonical_mutation:{section}:{field}:'
                f'{fam}:{capability}')
    return blockers


def emit_post_render_guard_diag(payload: Dict[str, Any]) -> None:
    try:
        print(
            f'[FINAL-DOC-POST-RENDER-GUARD] '
            f'{json.dumps(payload, ensure_ascii=False)}',
            flush=True)
    except Exception:  # noqa: BLE001
        pass
