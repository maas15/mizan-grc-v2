"""PR-REL2 board-ready scoring — ten dimensions per artifact."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from release_engine.section_model import legacy_sections_to_canonical
from release_engine.table_model import count_markdown_table_rows, has_table

DIMENSIONS = (
    'strategic_coherence',
    'domain_coverage',
    'framework_control_coverage',
    'roadmap_quality',
    'kpi_kri_quality',
    'governance_accountability',
    'traceability',
    'risk_quality',
    'language_quality',
    'export_layout_quality',
)

DOC_TYPE_THRESHOLDS = {
    'strategy': 90,
    'board_strategy': 90,
    'technical_strategy': 90,
    'policy': 90,
    'procedure': 88,
    'risk_register': 90,
    'audit': 90,
    'assessment': 90,
    'roadmap': 90,
    'executive_summary': 88,
    'kpi_kri': 88,
    'gap_assessment': 88,
    'traceability_matrix': 88,
}

MIN_DIMENSION = 80


def _score_section_presence(canon: Dict[str, str], keys: List[str]) -> int:
    present = sum(1 for k in keys if (canon.get(k) or '').strip())
    if not keys:
        return 85
    return min(100, 70 + int(30 * present / len(keys)))


def score_artifact(
        artifact: Dict[str, Any],
        *,
        domain_pack: Optional[Dict[str, Any]] = None,
        document_type: str = 'strategy',
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Compute dimension scores and acceptance metadata."""
    domain_pack = domain_pack or {}
    weights = domain_pack.get('scoring_weights') or {}
    legacy = artifact.get('sections') or {}
    canon = legacy_sections_to_canonical(legacy)
    mandatory = domain_pack.get('mandatory_canonical_sections') or [
        'vision_objectives', 'pillars', 'environment',
        'gap_analysis', 'roadmap', 'kpi_kri', 'confidence_risk',
    ]
    qf = artifact.get('quality_flags') or {}
    blockers = list(artifact.get('blocking_errors') or [])

    doc_key = (document_type or 'strategy').strip().lower()
    vo = canon.get('vision_objectives') or ''
    so_rows = count_markdown_table_rows(vo)
    if doc_key not in ('strategy', 'board_strategy', 'technical_strategy'):
        strategic_coherence = (
            92 if so_rows >= 2
            else 90 if vo.strip() and has_table(vo)
            else 88 if vo.strip()
            else 60)
    else:
        strategic_coherence = (
            95 if so_rows >= 3 and qf.get('strategic_objectives_valid')
            else 92 if so_rows >= 2
            else 75 if so_rows >= 1
            else 60)

    domain_coverage = _score_section_presence(canon, mandatory)

    fw = artifact.get('selected_frameworks') or domain_pack.get('frameworks_default') or []
    framework_control_coverage = (
        92 if fw else 85 if domain_pack.get('framework_catalog_ids') else 78)

    roadmap = canon.get('roadmap') or ''
    _rm_rows = count_markdown_table_rows(roadmap)
    roadmap_quality = (
        94 if qf.get('roadmap_phase_timeline_valid')
        else 92 if has_table(roadmap) and _rm_rows >= 3
        else 88 if has_table(roadmap) and _rm_rows >= 1
        else 55)

    kpi = canon.get('kpi_kri') or ''
    _kpi_rows = count_markdown_table_rows(kpi)
    kpi_kri_quality = (
        94 if qf.get('kpi_schema_valid')
        else 92 if has_table(kpi) and _kpi_rows >= 2
        else 88 if has_table(kpi) and _kpi_rows >= 1
        else 55)

    conf = canon.get('confidence_risk') or ''
    gov_blob = (roadmap + vo + (canon.get('pillars') or ''))
    governance_accountability = (
        90 if 'CISO' in gov_blob or 'مجلس' in vo or 'CDO' in gov_blob
        else 88 if has_table(roadmap) or 'Owner' in gov_blob
        else 75)

    traceability = (
        88 if canon.get('traceability') or '<!-- trace:' in (artifact.get('final_markdown') or '')
        else 82)

    risk_quality = (
        90 if qf.get('confidence_valid') or 'confidence' in conf.lower() or 'ثقة' in conf
        else 72)

    language_quality = (
        92 if lang == 'ar' and any('\u0600' <= c <= '\u06FF' for c in vo)
        else 92 if lang == 'en' and not any('\u0600' <= c <= '\u06FF' for c in vo[:200])
        else 78)

    export_layout_quality = (
        95 if artifact.get('sealed') and not blockers
        else 70 if artifact.get('sealed')
        else 50)

    dimension_scores = {
        'strategic_coherence': strategic_coherence,
        'domain_coverage': domain_coverage,
        'framework_control_coverage': framework_control_coverage,
        'roadmap_quality': roadmap_quality,
        'kpi_kri_quality': kpi_kri_quality,
        'governance_accountability': governance_accountability,
        'traceability': traceability,
        'risk_quality': risk_quality,
        'language_quality': language_quality,
        'export_layout_quality': export_layout_quality,
    }
    for dim, w in (weights or {}).items():
        if dim in dimension_scores and isinstance(w, (int, float)):
            dimension_scores[dim] = min(100, int(
                dimension_scores[dim] * float(w)))

    total = int(sum(dimension_scores.values()) / len(dimension_scores))
    failed = [d for d, s in dimension_scores.items() if s < MIN_DIMENSION]
    threshold = DOC_TYPE_THRESHOLDS.get(doc_key, 90)
    final_acceptance = (
        not blockers
        and total >= threshold
        and not failed
        and bool(artifact.get('sealed')))

    return {
        'total_score': total,
        'dimension_scores': dimension_scores,
        'failed_dimensions': failed,
        'blocking_errors': blockers,
        'repair_actions': list(artifact.get('repair_actions') or []),
        'final_acceptance_flag': final_acceptance,
        'threshold': threshold,
        'min_dimension': MIN_DIMENSION,
    }
