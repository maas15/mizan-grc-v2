"""PR-REL2 final quality contract — single content gate after seal."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from release_engine.canonical_artifact import structural_quality_issues
from release_engine.export_contract import assert_export_hash_parity
from release_engine.scoring import MIN_DIMENSION, score_artifact
from release_engine.section_model import legacy_sections_to_canonical
from release_engine.traceability import traceability_issues

CRITICAL_BLOCKER_PREFIXES = (
    'rel2_missing_mandatory_section:',
    'rel2_raw_section_marker_present',
    'kpi_metric_semantics_invalid',
    'strategic_objectives_table_missing_after_repair',
    'post_seal_mutation',
    'rel2_section_parity_failed',
    'rel2_pillars_failed',
    'rel2_roadmap_failed',
    'rel2_kpi_failed',
    'rel2_arabic_quality_failed',
    'rel2_export_visual_failed',
    'rel2_substantive_quality_failed',
    'rel2_rendered_evidence_failed',
    'rel2_actual_export_evidence_failed',
)


def _is_critical(code: str) -> bool:
    c = (code or '').strip()
    if not c:
        return False
    if c in (
        'kpi_metric_semantics_invalid',
        'strategic_objectives_section_missing',
        'rel2_export_hash_mismatch:preview',
        'rel2_post_seal_mutation:preview',
    ):
        return True
    return any(c.startswith(p) for p in CRITICAL_BLOCKER_PREFIXES)


def _rel24_contract_checks(artifact: Dict[str, Any]) -> Dict[str, Any]:
    rel24 = ((artifact.get('diagnostics') or {}).get('rel2') or {}).get(
        'rel24') or {}
    if not rel24:
        return {
            'pillar_substance_passed': True,
            'roadmap_substance_passed': True,
            'kpi_substance_passed': True,
            'risk_treatment_passed': True,
            'traceability_substance_passed': True,
            'objectives_quality_passed': True,
            'board_ready_substance_passed': True,
            'rel24_blocking_errors': [],
        }
    gate = rel24.get('substantive_gate') or {}
    so = rel24.get('so') or {}
    pillars = rel24.get('pillars') or {}
    roadmap = rel24.get('roadmap') or {}
    kpis = rel24.get('kpis') or {}
    risk = rel24.get('risk') or {}
    trace = rel24.get('traceability') or {}

    rel24_blockers: List[str] = list(gate.get('blocking_errors') or [])
    for diag in (so, pillars, roadmap, kpis, risk, trace):
        err = (diag.get('blocking_error_if_any') or '').strip()
        if err and err not in rel24_blockers:
            rel24_blockers.append(err)

    return {
        'objectives_quality_passed': bool(
            so.get('objectives_quality_passed', True)),
        'pillar_substance_passed': bool(
            pillars.get('pillar_depth_passed', True)),
        'roadmap_substance_passed': bool(
            roadmap.get('roadmap_depth_passed', True)),
        'kpi_substance_passed': bool(
            kpis.get('kpi_substance_passed', True)),
        'risk_treatment_passed': bool(
            risk.get('risk_treatment_passed', True)),
        'traceability_substance_passed': bool(
            trace.get('traceability_substance_passed', True)),
        'board_ready_substance_passed': bool(
            gate.get('board_ready_substance_passed', True)),
        'rel24_blocking_errors': rel24_blockers,
    }


def _rel25_contract_checks(artifact: Dict[str, Any]) -> Dict[str, Any]:
    rel25 = ((artifact.get('diagnostics') or {}).get('rel2') or {}).get(
        'rel25') or {}
    if not rel25:
        return {
            'rendered_evidence_passed': True,
            'no_forbidden_patterns': True,
            'risk_treatments_complete': True,
            'final_kpi_semantics_visible': True,
            'final_traceability_visible_valid': True,
            'final_arabic_rendered_quality_passed': True,
            'rel25_blocking_errors': [],
        }
    ev = rel25.get('evidence') or {}
    forbidden = ev.get('forbidden_patterns_found') or []
    kpi_defects = ev.get('kpi_semantic_defects_found') or []
    risk_empty = ev.get('risk_empty_treatments_found') or []
    trace_bad = ev.get('traceability_bad_mappings_found') or []
    arabic = ev.get('arabic_residues_found') or []
    passed = bool(ev.get('rendered_evidence_passed'))
    blockers = list(ev.get('blocking_errors') or [])
    return {
        'rendered_evidence_passed': passed,
        'no_forbidden_patterns': not forbidden,
        'risk_treatments_complete': not risk_empty,
        'final_kpi_semantics_visible': not kpi_defects,
        'final_traceability_visible_valid': not trace_bad,
        'final_arabic_rendered_quality_passed': not arabic,
        'rel25_blocking_errors': blockers,
    }


def _rel26_contract_checks(artifact: Dict[str, Any]) -> Dict[str, Any]:
    rel26 = ((artifact.get('diagnostics') or {}).get('rel2') or {}).get(
        'rel26') or {}
    if not rel26:
        return {
            'actual_export_evidence_passed': True,
            'preview_export_evidence_passed': True,
            'docx_export_evidence_passed': True,
            'pdf_export_evidence_passed': True,
            'rel26_blocking_errors': [],
        }
    ev = rel26.get('export') or {}
    passed = bool(ev.get('export_evidence_passed'))
    blockers = list(ev.get('blocking_errors') or [])
    return {
        'actual_export_evidence_passed': passed,
        'preview_export_evidence_passed': bool(
            ev.get('preview_export_evidence_passed', passed)),
        'docx_export_evidence_passed': bool(
            ev.get('docx_export_evidence_passed', passed)),
        'pdf_export_evidence_passed': bool(
            ev.get('pdf_export_evidence_passed', passed)),
        'pdf_text_extraction_unreliable': bool(
            ev.get('pdf_text_extraction_unreliable')),
        'rel26_blocking_errors': blockers,
    }


def _rel23_contract_checks(artifact: Dict[str, Any]) -> Dict[str, Any]:
    rel23 = ((artifact.get('diagnostics') or {}).get('rel2') or {}).get(
        'rel23') or {}
    if not rel23:
        return {
            'section_parity_passed': True,
            'pillars_valid': True,
            'roadmap_valid': True,
            'kpi_semantics_valid': True,
            'arabic_quality_passed': True,
            'export_visual_ready': True,
            'rel23_blocking_errors': [],
        }
    parity = rel23.get('section_parity') or {}
    pillars = rel23.get('pillars') or {}
    roadmap = rel23.get('roadmap') or {}
    kpis = rel23.get('kpis') or {}
    arabic = rel23.get('arabic') or {}
    export_visual = rel23.get('export_visual') or {}
    rel24 = ((artifact.get('diagnostics') or {}).get('rel2') or {}).get(
        'rel24') or {}
    arabic_rel24 = rel24.get('arabic') or {}
    roadmap_rel24 = rel24.get('roadmap') or {}

    section_parity_passed = bool(parity.get('parity_passed'))
    pillars_valid = not (pillars.get('blocking_error_if_any') or '')
    roadmap_valid = not (roadmap.get('blocking_error_if_any') or '')
    if rel24 and roadmap_rel24.get('roadmap_depth_passed'):
        roadmap_valid = True
    kpi_semantics_valid = bool(kpis.get('kpi_semantics_valid'))
    arabic_quality_passed = bool(
        arabic_rel24.get('arabic_quality_passed')
        if rel24 else arabic.get('arabic_quality_passed'))
    export_visual_ready = export_visual.get(
        'export_visual_ready', section_parity_passed)

    rel23_blockers: List[str] = []
    if not section_parity_passed:
        err = parity.get('blocking_error_if_any') or 'rel2_section_parity_failed'
        rel23_blockers.append(err)
    if not pillars_valid:
        rel23_blockers.append(
            pillars.get('blocking_error_if_any') or 'rel2_pillars_failed')
    if not roadmap_valid:
        rel23_blockers.append(
            roadmap.get('blocking_error_if_any') or 'rel2_roadmap_failed')
    if not kpi_semantics_valid:
        rel23_blockers.append(
            kpis.get('blocking_error_if_any') or 'rel2_kpi_failed')
    if not arabic_quality_passed:
        rel23_blockers.append(
            (arabic_rel24.get('blocking_error_if_any')
             or arabic.get('blocking_error_if_any')
             or 'rel2_arabic_quality_failed'))

    return {
        'section_parity_passed': section_parity_passed,
        'pillars_valid': pillars_valid,
        'roadmap_valid': roadmap_valid,
        'kpi_semantics_valid': kpi_semantics_valid,
        'arabic_quality_passed': arabic_quality_passed,
        'export_visual_ready': export_visual_ready,
        'rel23_blocking_errors': rel23_blockers,
    }


def evaluate_final_quality(
        artifact: Dict[str, Any],
        *,
        domain_pack: Optional[Dict[str, Any]] = None,
        document_type: str = 'strategy',
        lang: str = 'ar',
        export_route: str = 'preview',
        skip_structural: bool = False,
) -> Dict[str, Any]:
    """
    Final gate: release_ready_final_passed=True only when all contract checks pass.
    """
    domain_pack = domain_pack or {}
    blocking = list(artifact.get('blocking_errors') or [])
    canon = legacy_sections_to_canonical(artifact.get('sections'))
    mandatory = domain_pack.get('mandatory_canonical_sections') or []
    struct: List[str] = []
    if not skip_structural:
        struct = structural_quality_issues(canon, mandatory=mandatory or None)
        for si in struct:
            if si not in blocking:
                blocking.append(si)
    for ti in traceability_issues(artifact, domain_pack=domain_pack):
        if ti not in blocking:
            blocking.append(ti)

    rel23_checks = _rel23_contract_checks(artifact)
    rel24_checks = _rel24_contract_checks(artifact)
    rel25_checks = _rel25_contract_checks(artifact)
    rel26_checks = _rel26_contract_checks(artifact)
    for rb in rel23_checks.get('rel23_blocking_errors') or []:
        if rb not in blocking:
            blocking.append(rb)
    for rb in rel24_checks.get('rel24_blocking_errors') or []:
        if rb not in blocking:
            blocking.append(rb)
    for rb in rel25_checks.get('rel25_blocking_errors') or []:
        if rb not in blocking:
            blocking.append(rb)
    for rb in rel26_checks.get('rel26_blocking_errors') or []:
        if rb not in blocking:
            blocking.append(rb)

    scoring = score_artifact(
        {**artifact, 'blocking_errors': blocking},
        domain_pack=domain_pack,
        document_type=document_type,
        lang=lang,
    )
    fh = artifact.get('final_hash') or ''
    export_issues = assert_export_hash_parity(
        artifact, route=export_route, content_hash=fh)
    parity_ok = not export_issues

    critical = [b for b in blocking if _is_critical(b)]
    dim_failed = scoring.get('failed_dimensions') or []
    total = scoring.get('total_score') or 0
    threshold = scoring.get('threshold') or 90
    sealed = bool(artifact.get('sealed')) and not blocking

    rel23_ready = (
        rel23_checks.get('section_parity_passed', True)
        and rel23_checks.get('pillars_valid', True)
        and rel23_checks.get('roadmap_valid', True)
        and rel23_checks.get('kpi_semantics_valid', True)
        and rel23_checks.get('arabic_quality_passed', True)
        and rel23_checks.get('export_visual_ready', True)
    )
    rel24_ready = rel24_checks.get('board_ready_substance_passed', True)
    rel25_ready = rel25_checks.get('rendered_evidence_passed', True)
    rel26_ready = rel26_checks.get('actual_export_evidence_passed', True)

    release_ready = (
        sealed
        and not critical
        and total >= threshold
        and not dim_failed
        and all(
            scoring.get('dimension_scores', {}).get(d, 0) >= MIN_DIMENSION
            for d in scoring.get('dimension_scores', {}))
        and parity_ok
        and bool(fh)
        and rel23_ready
        and rel24_ready
        and rel25_ready
        and rel26_ready
    )

    contract_payload = {
        **rel23_checks,
        **rel24_checks,
        **rel25_checks,
        **rel26_checks,
        'release_ready_final_passed': release_ready,
        'blocking_errors': blocking,
    }
    try:
        print(
            '[RELEASE-FINAL-QUALITY-CONTRACT] '
            + json.dumps(contract_payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass

    return {
        'release_ready_final_passed': release_ready,
        'blocking_errors': blocking,
        'critical_blockers': critical,
        'scoring': scoring,
        'export_parity_ok': parity_ok,
        'export_issues': export_issues,
        'structural_issues': struct,
        'section_parity_passed': rel23_checks.get('section_parity_passed'),
        'pillars_valid': rel23_checks.get('pillars_valid'),
        'roadmap_valid': rel23_checks.get('roadmap_valid'),
        'kpi_semantics_valid': rel23_checks.get('kpi_semantics_valid'),
        'arabic_quality_passed': rel23_checks.get('arabic_quality_passed'),
        'export_visual_ready': rel23_checks.get('export_visual_ready'),
        'objectives_quality_passed': rel24_checks.get('objectives_quality_passed'),
        'pillar_substance_passed': rel24_checks.get('pillar_substance_passed'),
        'roadmap_substance_passed': rel24_checks.get('roadmap_substance_passed'),
        'kpi_substance_passed': rel24_checks.get('kpi_substance_passed'),
        'risk_treatment_passed': rel24_checks.get('risk_treatment_passed'),
        'traceability_substance_passed': rel24_checks.get(
            'traceability_substance_passed'),
        'board_ready_substance_passed': rel24_checks.get(
            'board_ready_substance_passed'),
        'rendered_evidence_passed': rel25_checks.get(
            'rendered_evidence_passed'),
        'no_forbidden_patterns': rel25_checks.get('no_forbidden_patterns'),
        'risk_treatments_complete': rel25_checks.get(
            'risk_treatments_complete'),
        'final_kpi_semantics_visible': rel25_checks.get(
            'final_kpi_semantics_visible'),
        'final_traceability_visible_valid': rel25_checks.get(
            'final_traceability_visible_valid'),
        'final_arabic_rendered_quality_passed': rel25_checks.get(
            'final_arabic_rendered_quality_passed'),
        'actual_export_evidence_passed': rel26_checks.get(
            'actual_export_evidence_passed'),
        'preview_export_evidence_passed': rel26_checks.get(
            'preview_export_evidence_passed'),
        'docx_export_evidence_passed': rel26_checks.get(
            'docx_export_evidence_passed'),
        'pdf_export_evidence_passed': rel26_checks.get(
            'pdf_export_evidence_passed'),
        'checks': {
            'content_completeness': not struct,
            'domain_relevance': scoring.get('dimension_scores', {}).get(
                'domain_coverage', 0) >= MIN_DIMENSION,
            'framework_coverage': scoring.get('dimension_scores', {}).get(
                'framework_control_coverage', 0) >= MIN_DIMENSION,
            'traceability': scoring.get('dimension_scores', {}).get(
                'traceability', 0) >= MIN_DIMENSION,
            'executive_coherence': scoring.get('dimension_scores', {}).get(
                'strategic_coherence', 0) >= MIN_DIMENSION,
            'export_hash_parity': parity_ok,
            'section_parity': rel23_checks.get('section_parity_passed'),
            'pillars_valid': rel23_checks.get('pillars_valid'),
            'roadmap_valid': rel23_checks.get('roadmap_valid'),
            'kpi_semantics_valid': rel23_checks.get('kpi_semantics_valid'),
            'arabic_quality_passed': rel23_checks.get('arabic_quality_passed'),
        },
    }
