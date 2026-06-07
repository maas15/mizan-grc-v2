"""PR-REL2.3 — cyber strategy finalize pipeline before seal."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from release_engine.arabic_language_gate import (
    apply_arabic_final_gate,
    emit_arabic_final_language_gate,
)
from release_engine.kpi_model import (
    emit_kpi_final_semantic_model,
    finalize_kpi_semantics,
)
from release_engine.pillar_model import (
    emit_pillar_final_model,
    finalize_pillars,
)
from release_engine.roadmap_model import (
    emit_roadmap_final_model,
    finalize_roadmap,
)
from release_engine.section_parity import (
    emit_section_parity_check,
    evaluate_section_parity,
)


def _rebuild_markdown(sections: Dict[str, str]) -> str:
    order = (
        'vision', 'pillars', 'environment', 'gaps',
        'roadmap', 'kpis', 'confidence',
    )
    return '\n\n'.join(
        (sections.get(k) or '').strip()
        for k in order if (sections.get(k) or '').strip())


def apply_rel23_cyber_finalize(
        artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    """
    Run REL2.3 models on cyber strategy artifacts before final seal.
    Returns (artifact, repair_actions, diagnostics).
    """
    dcode = (domain or artifact.get('domain') or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security'):
        return artifact, [], {}

    sections = {
        k: v for k, v in (artifact.get('sections') or {}).items()
        if isinstance(v, str)}
    repair_actions: List[str] = []
    diags: Dict[str, Any] = {}
    meta = artifact.get('contract_meta') or {}
    fws = meta.get('selected_frameworks') or artifact.get(
        'selected_frameworks') or []

    sections, ar_diag = apply_arabic_final_gate(sections, lang=lang)
    emit_arabic_final_language_gate(ar_diag)
    diags['arabic'] = ar_diag
    if ar_diag.get('residues_before'):
        repair_actions.append('rel23:arabic_repaired')

    sections, pil_diag = finalize_pillars(
        sections, lang=lang, domain=dcode, backend=backend)
    emit_pillar_final_model(pil_diag)
    diags['pillars'] = pil_diag
    if pil_diag.get('action_taken') != 'no_changes':
        repair_actions.append(f'rel23:{pil_diag.get("action_taken")}')

    sections, road_diag = finalize_roadmap(
        sections, lang=lang, domain=dcode,
        selected_frameworks=fws, backend=backend)
    emit_roadmap_final_model(road_diag)
    diags['roadmap'] = road_diag
    if road_diag.get('action_taken'):
        repair_actions.append(f'rel23:{road_diag.get("action_taken")}')

    sections, kpi_diag = finalize_kpi_semantics(
        sections, lang=lang, backend=backend)
    emit_kpi_final_semantic_model(kpi_diag)
    diags['kpis'] = kpi_diag
    if kpi_diag.get('action_taken'):
        repair_actions.append(f'rel23:{kpi_diag.get("action_taken")}')

    merged = dict(artifact)
    merged['sections'] = sections
    merged['final_markdown'] = _rebuild_markdown(sections)
    hash_fn = backend.get('content_hash')
    if hash_fn:
        merged['final_hash'] = hash_fn(merged['final_markdown'])

    parity = evaluate_section_parity(merged, backend, lang=lang)
    emit_section_parity_check(parity)
    diags['section_parity'] = parity

    return merged, repair_actions, diags


def rel23_blocking_errors(diags: Dict[str, Any]) -> List[str]:
    blockers: List[str] = []
    for key in ('arabic', 'pillars', 'roadmap', 'kpis', 'section_parity'):
        diag = diags.get(key) or {}
        err = (diag.get('blocking_error_if_any') or '').strip()
        if err and err not in blockers:
            blockers.append(err)
    parity = diags.get('section_parity') or {}
    if not parity.get('parity_passed'):
        err = parity.get('blocking_error_if_any') or 'rel2_section_parity_failed'
        if err not in blockers:
            blockers.append(err)
    return blockers
