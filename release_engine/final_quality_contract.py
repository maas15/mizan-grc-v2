"""PR-REL2 final quality contract — single content gate after seal."""

from __future__ import annotations

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
    )

    return {
        'release_ready_final_passed': release_ready,
        'blocking_errors': blocking,
        'critical_blockers': critical,
        'scoring': scoring,
        'export_parity_ok': parity_ok,
        'export_issues': export_issues,
        'structural_issues': struct,
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
        },
    }
