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
    backend = dict(backend or {})
    backend.setdefault('selected_frameworks', fws)
    backend.setdefault('document_type', 'strategy')
    backend.setdefault('task_id', artifact.get('task_id'))

    try:
        from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
            apply_rel36_8_en_cyber_pillars_parity,
        )
        sections, rel368 = apply_rel36_8_en_cyber_pillars_parity(
            sections,
            domain=dcode,
            lang=lang,
            document_type='strategy',
            selected_frameworks=fws,
            backend=backend,
            task_id=artifact.get('task_id'),
            repair_stage='pre_rel2_gates',
        )
        diags['rel36_8'] = rel368
        if rel368.get('repair_applied'):
            repair_actions.append('rel36_8:en_cyber_pillars_parity')
    except Exception:  # noqa: BLE001
        pass

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

    try:
        from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
            apply_rel36_8_3_final_pillar_binding,
        )
        sections, rel3683 = apply_rel36_8_3_final_pillar_binding(
            sections,
            domain=dcode,
            lang=lang,
            document_type='strategy',
            selected_frameworks=fws,
            backend=backend,
            task_id=artifact.get('task_id'),
            artifact=artifact,
        )
        diags['rel36_8_3'] = rel3683
        if rel3683.get('repair_applied'):
            repair_actions.append('rel36_8_3:final_pillar_binding')
        if rel3683.get('final_rel2_pillars_blockers_after'):
            pil_diag = dict(pil_diag)
            pil_diag['rendered_table_valid'] = False
            pil_diag['blocking_error_if_any'] = (
                rel3683['final_rel2_pillars_blockers_after'][0])
            diags['pillars'] = pil_diag
        elif rel3683.get('passed'):
            pil_diag = dict(pil_diag)
            pil_diag['rendered_table_valid'] = True
            pil_diag['blocking_error_if_any'] = ''
            diags['pillars'] = pil_diag
    except Exception:  # noqa: BLE001
        pass

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

    # Re-run after pillar/roadmap/kpi — models may reintroduce glued residues.
    sections, ar_diag = apply_arabic_final_gate(sections, lang=lang)
    emit_arabic_final_language_gate(ar_diag)
    diags['arabic'] = ar_diag
    if ar_diag.get('residues_before'):
        repair_actions.append('rel23:arabic_repaired')

    try:
        from release_engine_v3.rel36_9_en_cyber_live_stability import (
            apply_rel36_9_en_cyber_live_stability,
        )
        sections, rel369 = apply_rel36_9_en_cyber_live_stability(
            sections,
            domain=dcode,
            lang=lang,
            document_type='strategy',
            selected_frameworks=fws,
            backend=backend,
            task_id=artifact.get('task_id'),
            artifact=artifact,
        )
        diags['rel36_9'] = rel369
        if rel369.get('roadmap_visible_row_count_after', 0) > 0:
            repair_actions.append('rel36_9:en_cyber_live_stability')
        try:
            from release_engine_v3.rel36_9_1_en_cyber_vision_prompt_residue import (
                apply_rel36_9_1_en_cyber_vision_prompt_residue,
            )
            sections, rel3691 = apply_rel36_9_1_en_cyber_vision_prompt_residue(
                sections,
                domain=dcode,
                lang=lang,
                document_type='strategy',
                selected_frameworks=fws,
                task_id=artifact.get('task_id'),
            )
            diags['rel36_9_1'] = rel3691
            if rel3691.get('cleanup_applied') or rel3691.get('vision_rebuilt'):
                repair_actions.append(
                    'rel36_9_1:en_cyber_vision_prompt_residue')
        except Exception:  # noqa: BLE001
            pass
        if rel369.get('rel2_pillars_after'):
            pil_diag = dict(diags.get('pillars') or {})
            pil_diag['rendered_table_valid'] = False
            pil_diag['blocking_error_if_any'] = rel369['rel2_pillars_after'][0]
            diags['pillars'] = pil_diag
        elif rel369.get('passed'):
            pil_diag = dict(diags.get('pillars') or {})
            pil_diag['rendered_table_valid'] = True
            pil_diag['blocking_error_if_any'] = ''
            diags['pillars'] = pil_diag
    except Exception:  # noqa: BLE001
        pass

    try:
        from release_engine_v3.rel36_12_en_cyber_presave_pillar_stability import (
            apply_rel36_12_en_cyber_presave_pillar_stability,
        )
        sections, rel3612 = apply_rel36_12_en_cyber_presave_pillar_stability(
            sections,
            domain=dcode,
            lang=lang,
            document_type='strategy',
            selected_frameworks=fws,
            backend=backend,
            task_id=artifact.get('task_id'),
            artifact=artifact,
            prior_pillars_diag=diags.get('pillars'),
        )
        diags['rel36_12'] = rel3612
        if rel3612.get('deterministic_fallback_applied'):
            repair_actions.append('rel36_12:en_cyber_presave_pillar_stability')
        try:
            from release_engine_v3.rel36_13_en_cyber_core_completeness import (
                apply_rel36_13_en_cyber_core_completeness,
            )
            sections, rel3613 = apply_rel36_13_en_cyber_core_completeness(
                sections,
                domain=dcode,
                lang=lang,
                document_type='strategy',
                selected_frameworks=fws,
                backend=backend,
                task_id=artifact.get('task_id'),
                artifact=artifact,
            )
            diags['rel36_13'] = rel3613
            if rel3613.get('repaired_sections'):
                repair_actions.append(
                    'rel36_13:en_cyber_core_completeness')
        except Exception:  # noqa: BLE001
            pass
        if rel3612.get('applied'):
            pil_diag = dict(rel3612.get('finalize_diag') or diags.get('pillars') or {})
            pil_diag['rendered_table_valid'] = bool(
                rel3612.get('rendered_table_valid_after'))
            blockers_after = list(
                rel3612.get('final_rel2_pillars_blockers_after') or [])
            pil_diag['blocking_error_if_any'] = (
                blockers_after[0] if blockers_after else '')
            if rel3612.get('pillar_count_after') is not None:
                pil_diag['pillar_count_after'] = rel3612['pillar_count_after']
            if rel3612.get('initiative_count_by_pillar_after') is not None:
                pil_diag['initiative_count_by_pillar'] = rel3612[
                    'initiative_count_by_pillar_after']
            if rel3612.get('empty_pillars_after') is not None:
                pil_diag['empty_pillars_after'] = rel3612['empty_pillars_after']
            if rel3612.get('missing_pillar_families_after') is not None:
                pil_diag['missing_pillar_families_after'] = rel3612[
                    'missing_pillar_families_after']
            if rel3612.get('mismatched_outputs_after') is not None:
                pil_diag['mismatched_outputs_after'] = rel3612[
                    'mismatched_outputs_after']
            diags['pillars'] = pil_diag
    except Exception:  # noqa: BLE001
        pass

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
