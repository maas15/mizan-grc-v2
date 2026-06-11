"""PR-REL2.6 — actual exported DOCX/PDF evidence finalize before seal."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

def apply_rel26_cyber_export_evidence_finalize(
        artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
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
    from release_engine.rel27_finalize import (
        REL27_MAX_REPAIR_ATTEMPTS,
        apply_rel27_cyber_export_evidence_finalize,
    )
    merged, repair_actions, diags = apply_rel27_cyber_export_evidence_finalize(
        merged, domain=dcode, lang=lang, backend=backend)
    export_diag = diags.get('export') or {}
    _ = REL27_MAX_REPAIR_ATTEMPTS  # re-export name for tests

    return merged, repair_actions, {'export': export_diag}


def rel26_blocking_errors(diags: Dict[str, Any]) -> List[str]:
    ev = diags.get('export') or {}
    return list(ev.get('blocking_errors') or [])
