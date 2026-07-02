"""PR-REL2.4 — cyber strategy substantive quality finalize pipeline."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from release_engine.arabic_language_gate import apply_arabic_substance_gate
from release_engine.kpi_substance_model import (
    emit_kpi_substance_model,
    finalize_kpi_substance,
)
from release_engine.pillar_substance_model import (
    emit_pillar_substance_model,
    finalize_pillar_substance,
)
from release_engine.roadmap_substance_model import (
    emit_roadmap_substance_model,
    finalize_roadmap_substance,
)
from release_engine.risk_treatment_model import (
    emit_risk_treatment_model,
    finalize_risk_treatment,
)
from release_engine.so_substance_model import (
    emit_so_substance_model,
    finalize_so_substance,
)
from release_engine.substantive_quality_gate import (
    emit_substantive_content_quality_gate,
    evaluate_substantive_quality,
)
from release_engine.traceability_substance_model import (
    emit_traceability_substance_model,
    finalize_traceability_substance,
)


def _rebuild_markdown(sections: Dict[str, str]) -> str:
    order = (
        'vision', 'pillars', 'environment', 'gaps',
        'roadmap', 'kpis', 'traceability', 'confidence',
    )
    return '\n\n'.join(
        (sections.get(k) or '').strip()
        for k in order if (sections.get(k) or '').strip())


def apply_rel24_cyber_substance_finalize(
        artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    dcode = (domain or artifact.get('domain') or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security') or lang != 'ar':
        return artifact, [], {}

    sections = {
        k: v for k, v in (artifact.get('sections') or {}).items()
        if isinstance(v, str)}
    repair_actions: List[str] = []
    diags: Dict[str, Any] = {}
    meta = artifact.get('contract_meta') or {}
    fws = meta.get('selected_frameworks') or artifact.get(
        'selected_frameworks') or []

    sections, so_diag = finalize_so_substance(sections, lang=lang)
    emit_so_substance_model(so_diag)
    diags['so'] = so_diag
    if so_diag.get('weak_targets_before'):
        repair_actions.append('rel24:so_substance_repaired')

    sections, pil_diag = finalize_pillar_substance(
        sections, lang=lang, domain=dcode)
    emit_pillar_substance_model(pil_diag)
    diags['pillars'] = pil_diag
    if pil_diag.get('generic_outputs_before'):
        repair_actions.append('rel24:pillar_substance_enriched')

    sections, road_diag = finalize_roadmap_substance(
        sections, lang=lang, domain=dcode,
        selected_frameworks=fws, backend=backend)
    emit_roadmap_substance_model(road_diag)
    diags['roadmap'] = road_diag
    if road_diag.get('weak_outputs_before'):
        repair_actions.append('rel24:roadmap_substance_repaired')

    sections, kpi_diag = finalize_kpi_substance(
        sections, lang=lang, backend=backend)
    emit_kpi_substance_model(kpi_diag)
    diags['kpis'] = kpi_diag
    if kpi_diag.get('action_taken') == 'kpi_substance_repaired':
        repair_actions.append('rel24:kpi_substance_repaired')

    sections, risk_diag = finalize_risk_treatment(sections, lang=lang)
    emit_risk_treatment_model(risk_diag)
    diags['risk'] = risk_diag
    if risk_diag.get('empty_treatment_plans_before'):
        repair_actions.append('rel24:risk_treatment_repaired')

    sections, trace_diag = finalize_traceability_substance(
        sections, lang=lang)
    emit_traceability_substance_model(trace_diag)
    diags['traceability'] = trace_diag
    if trace_diag.get('blank_gap_rows_before') or trace_diag.get(
            'bad_mappings_before'):
        repair_actions.append('rel24:traceability_repaired')

    sections, ar_diag = apply_arabic_substance_gate(sections, lang=lang)
    diags['arabic'] = ar_diag
    if ar_diag.get('residues_before'):
        repair_actions.append('rel24:arabic_substance_repaired')

    for _pass in range(3):
        if not diags.get('so', {}).get('objectives_quality_passed', True):
            sections, so_diag = finalize_so_substance(sections, lang=lang)
            diags['so'] = so_diag
        if not diags.get('kpis', {}).get('kpi_substance_passed', True):
            sections, kpi_diag = finalize_kpi_substance(
                sections, lang=lang, backend=backend)
            diags['kpis'] = kpi_diag
        sections, ar_diag = apply_arabic_substance_gate(sections, lang=lang)
        diags['arabic'] = ar_diag
        gate = evaluate_substantive_quality(
            domain=dcode,
            lang=lang,
            document_type='strategy',
            diags=diags,
        )
        if gate.get('board_ready_substance_passed'):
            break
    emit_substantive_content_quality_gate(gate)
    diags['substantive_gate'] = gate

    merged = dict(artifact)
    merged['sections'] = sections
    merged['final_markdown'] = _rebuild_markdown(sections)
    hash_fn = backend.get('content_hash')
    if hash_fn:
        merged['final_hash'] = hash_fn(merged['final_markdown'])

    return merged, repair_actions, diags


def rel24_blocking_errors(diags: Dict[str, Any]) -> List[str]:
    gate = diags.get('substantive_gate') or {}
    blockers = list(gate.get('blocking_errors') or [])
    if not gate.get('board_ready_substance_passed'):
        for key in ('so', 'pillars', 'roadmap', 'kpis', 'risk',
                    'traceability', 'arabic'):
            diag = diags.get(key) or {}
            err = (diag.get('blocking_error_if_any') or '').strip()
            if err and err not in blockers:
                blockers.append(err)
    return blockers
