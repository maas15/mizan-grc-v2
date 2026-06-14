"""PR-REL2.7 — fail-closed actual export evidence with repair cap."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from release_engine.export_evidence_validator import (
    repair_before_export_if_possible,
    repair_for_actual_export_defects,
    validate_artifact_actual_exports,
)
from release_engine.rel25_finalize import apply_rel25_cyber_evidence_finalize

REL27_MAX_REPAIR_ATTEMPTS = 2


def apply_rel27_cyber_export_evidence_finalize(
        artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    """Validate actual exports; repair canonical source up to 2 times."""
    dcode = (domain or artifact.get('domain') or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security') or lang != 'ar':
        return artifact, [], {}

    if not backend.get('validate_export_evidence'):
        return artifact, [], {}

    repair_actions: List[str] = []
    merged = dict(artifact)
    backend = dict(backend)
    meta = merged.get('contract_meta') or {}
    fws = meta.get('selected_frameworks') or merged.get('selected_frameworks') or []
    backend['selected_frameworks'] = fws
    backend['validate_export_evidence'] = True
    rel2_cache = backend.get('_rel2_cache') or {}
    rel2_cache.pop('exports', None)

    export_diag: Dict[str, Any] = {}
    for attempt in range(REL27_MAX_REPAIR_ATTEMPTS + 1):
        export_diag = validate_artifact_actual_exports(
            merged, backend, domain=dcode, lang=lang,
            require_docx=True, require_pdf=True,
            route_name='finalize')
        if export_diag.get('actual_export_evidence_passed'):
            break
        if attempt >= REL27_MAX_REPAIR_ATTEMPTS:
            reason = ';'.join(
                (export_diag.get('blocking_errors') or [])[:4]) or 'defects_remain'
            err = f'rel2_actual_export_evidence_failed:repair_exhausted:{reason}'
            if err not in export_diag.get('blocking_errors', []):
                export_diag.setdefault('blocking_errors', []).append(err)
            export_diag['export_evidence_passed'] = False
            export_diag['actual_export_evidence_passed'] = False
            export_diag['action_taken'] = 'repair_exhausted_blocked'
            break
        repair_actions.append('rel27:actual_export_evidence_repaired')
        merged, rep = repair_before_export_if_possible(
            merged, domain=dcode, lang=lang, backend=backend)
        repair_actions.extend(rep)
        merged, rel271_rep = repair_for_actual_export_defects(
            merged, export_diag, domain=dcode, lang=lang, backend=backend)
        repair_actions.extend(rel271_rep)
        merged, rel25_rep, _ = apply_rel25_cyber_evidence_finalize(
            merged, domain=dcode, lang=lang, backend=backend)
        repair_actions.extend(rel25_rep or [])
        order = (
            'vision', 'pillars', 'environment', 'gaps',
            'roadmap', 'kpis', 'confidence', 'traceability',
        )
        sections = merged.get('sections') or {}
        merged['final_markdown'] = '\n\n'.join(
            (sections.get(k) or '').strip()
            for k in order if (sections.get(k) or '').strip())
        hash_fn = backend.get('content_hash')
        if hash_fn and merged.get('final_markdown'):
            merged['final_hash'] = hash_fn(merged['final_markdown'])
        rel2_cache = backend.get('_rel2_cache') or {}
        rel2_cache.pop('exports', None)

    return merged, repair_actions, {'export': export_diag}


def rel27_blocking_errors(diags: Dict[str, Any]) -> List[str]:
    ev = diags.get('export') or {}
    return list(ev.get('blocking_errors') or [])
