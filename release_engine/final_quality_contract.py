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

    section_parity_passed = bool(parity.get('parity_passed'))
    pillars_valid = not (pillars.get('blocking_error_if_any') or '')
    roadmap_valid = not (roadmap.get('blocking_error_if_any') or '')
    kpi_semantics_valid = bool(kpis.get('kpi_semantics_valid'))
    arabic_quality_passed = bool(arabic.get('arabic_quality_passed'))
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
            arabic.get('blocking_error_if_any') or 'rel2_arabic_quality_failed')

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
    for rb in rel23_checks.get('rel23_blocking_errors') or []:
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
    )

    contract_payload = {
        **rel23_checks,
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
