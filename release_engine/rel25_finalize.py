"""PR-REL2.5 — rendered evidence finalize before seal.

Release scope (PR-REL2.5): fully enforced on Cyber Arabic Technical strategy.
National launch requires equivalent rendered-evidence gates for Data/AI Arabic
Technical, English Technical strategy, policy, risk register, and audit report
before final launch approval.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from release_engine.rendered_evidence_validator import (
    _scrub_global_forbidden,
    repair_sections_for_rendered_evidence,
    validate_rendered_evidence,
)
from release_engine.rel24_finalize import apply_rel24_cyber_substance_finalize


def _rebuild_markdown(sections: Dict[str, str]) -> str:
    order = (
        'vision', 'pillars', 'environment', 'gaps',
        'roadmap', 'kpis', 'traceability', 'confidence',
    )
    return '\n\n'.join(
        (sections.get(k) or '').strip()
        for k in order if (sections.get(k) or '').strip())


def apply_rel25_cyber_evidence_finalize(
        artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    dcode = (domain or artifact.get('domain') or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security') or lang != 'ar':
        return artifact, [], {}

    repair_actions: List[str] = []
    merged = dict(artifact)
    meta = merged.get('contract_meta') or {}
    fws = meta.get('selected_frameworks') or merged.get(
        'selected_frameworks') or []
    backend = dict(backend)
    backend['selected_frameworks'] = fws

    evidence_diag: Dict[str, Any] = {}
    for _pass in range(3):
        sections = {
            k: v for k, v in (merged.get('sections') or {}).items()
            if isinstance(v, str)}
        sections = repair_sections_for_rendered_evidence(
            sections, lang=lang, domain=dcode, backend=backend)
        merged['sections'] = sections
        merged['final_markdown'] = _scrub_global_forbidden(
            _rebuild_markdown(sections))
        hash_fn = backend.get('content_hash')
        if hash_fn:
            merged['final_hash'] = hash_fn(merged['final_markdown'])

        evidence_diag = validate_rendered_evidence(
            merged, backend, domain=dcode, lang=lang)
        if evidence_diag.get('rendered_evidence_passed'):
            break

        repair_actions.append('rel25:rendered_evidence_repaired')
        merged, rel24_repairs, _ = apply_rel24_cyber_substance_finalize(
            merged, domain=dcode, lang=lang, backend=backend)
        repair_actions.extend(rel24_repairs)
        sections = repair_sections_for_rendered_evidence(
            dict(merged.get('sections') or {}),
            lang=lang, domain=dcode, backend=backend)
        merged['sections'] = sections
        merged['final_markdown'] = _rebuild_markdown(sections)
        if hash_fn:
            merged['final_hash'] = hash_fn(merged['final_markdown'])
        evidence_diag = validate_rendered_evidence(
            merged, backend, domain=dcode, lang=lang)
        if evidence_diag.get('rendered_evidence_passed'):
            break

    return merged, repair_actions, {'evidence': evidence_diag}


def rel25_blocking_errors(diags: Dict[str, Any]) -> List[str]:
    ev = diags.get('evidence') or {}
    return list(ev.get('blocking_errors') or [])
