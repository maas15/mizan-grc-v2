"""PR-REL3 — canonical quality validators (advisory + export blockers)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from release_engine.export_evidence_validator import validate_actual_export_evidence
from release_engine.rel28_route_evidence import (
    check_pillars_after_strategic_heading,
    check_roadmap_visible_drift,
)
from release_engine.rel27_export_checks import (
    check_kpi_canonical,
    check_roadmap_coverage,
    rel27_channel_checks,
)
from release_engine_v3.contracts import CanonicalSection


def validate_canonical_quality(
        sections: Dict[str, CanonicalSection],
        *,
        legacy_sections: Optional[Dict[str, str]] = None,
        domain: str = 'cyber',
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Validate canonical model; delegates visible checks to REL2 validators."""
    blockers: List[str] = []
    legacy = legacy_sections or {}
    blob = '\n\n'.join(
        (legacy.get(k) or '')
        for k in ('vision', 'pillars', 'environment', 'gaps',
                  'roadmap', 'kpis', 'confidence', 'traceability')
    )
    if not blob.strip():
        from release_engine_v3.section_models import strategy_document_to_markdown
        from release_engine_v3.section_models import build_strategy_document
        blob = strategy_document_to_markdown(
            build_strategy_document(legacy))
    blockers.extend(check_pillars_after_strategic_heading(blob))
    kpi_chk = check_kpi_canonical(blob)
    if not kpi_chk.get('exported_kpi_canonical_valid'):
        blockers.extend(kpi_chk.get('defects') or [])
    road = check_roadmap_coverage(blob)
    if int(road.get('visible_row_count') or 0) < 10:
        blockers.append(
            f'rel3_export_model_drift:roadmap_visible_row_count:'
            f'{road.get("visible_row_count")}')
    ch = rel27_channel_checks(blob)
    for key in ('risk_defects', 'traceability_defects', 'arabic_residues'):
        blockers.extend(ch.get(key) or [])
    return {
        'blocking_errors': list(dict.fromkeys(blockers)),
        'kpi_valid': kpi_chk.get('exported_kpi_canonical_valid'),
        'roadmap_row_count': road.get('visible_row_count'),
        'pillar_check': not check_pillars_after_strategic_heading(blob),
    }


def validate_export_text(
        route: str,
        *,
        preview_text: str = '',
        docx_text: str = '',
        pdf_text: str = '',
        domain: str = 'cyber',
        lang: str = 'ar',
        pdf_text_extraction_unreliable: bool = False,
        pdf_bytes_had: bool = False,
        canonical_sections: Optional[Dict[str, str]] = None,
        final_hash: str = '',
) -> Dict[str, Any]:
    """Route-bound evidence on actual extracted text."""
    gate = validate_actual_export_evidence(
        preview_text,
        docx_text,
        pdf_text,
        domain=domain,
        lang=lang,
        document_type='strategy',
        pdf_text_extraction_unreliable=pdf_text_extraction_unreliable,
        pdf_bytes_had=pdf_bytes_had,
        route_name=route,
        final_hash=final_hash,
        canonical_sections=None,
    )
    # Prefix blockers with rel3 namespace for export routes
    rel3_blockers: List[str] = []
    for err in gate.get('blocking_errors') or []:
        if err.startswith('rel2_') or err.startswith('rel3_'):
            rel3_blockers.append(
                err.replace('rel2_actual_export_evidence_failed',
                            'rel3_export_evidence_failed', 1)
                if 'rel2_actual_export_evidence_failed' in err
                else err)
        else:
            rel3_blockers.append(
                f'rel3_export_evidence_failed:{route}:{err}')
    gate['blocking_errors'] = rel3_blockers
    gate['rel3_evidence'] = True
    return gate
