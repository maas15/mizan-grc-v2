"""PR-REL2.6 — actual exported DOCX/PDF evidence finalize before seal."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from release_engine.export_evidence_validator import (
    repair_before_export_if_possible,
    validate_artifact_actual_exports,
)
from release_engine.rel25_finalize import apply_rel25_cyber_evidence_finalize


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
    for _pass in range(3):
        export_diag = validate_artifact_actual_exports(
            merged, backend, domain=dcode, lang=lang,
            require_docx=True, require_pdf=True)
        if export_diag.get('export_evidence_passed'):
            break
        repair_actions.append('rel26:actual_export_evidence_repaired')
        merged, rep = repair_before_export_if_possible(
            merged, domain=dcode, lang=lang, backend=backend)
        repair_actions.extend(rep)
        merged, _, _ = apply_rel25_cyber_evidence_finalize(
            merged, domain=dcode, lang=lang, backend=backend)
        export_diag = validate_artifact_actual_exports(
            merged, backend, domain=dcode, lang=lang,
            require_docx=True, require_pdf=True)
        if export_diag.get('export_evidence_passed'):
            break

    return merged, repair_actions, {'export': export_diag}


def rel26_blocking_errors(diags: Dict[str, Any]) -> List[str]:
    ev = diags.get('export') or {}
    return list(ev.get('blocking_errors') or [])
