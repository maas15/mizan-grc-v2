"""Platform-wide Document Excellence Gate (DQS facade)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from release_engine_v3.document_quality_spec import evaluate_document_quality
from release_engine_v3.factory.post_render_guard import (
    verify_immutable_traceability_routes,
)
from release_engine_v3.registries.platform_registries import (
    DOCUMENT_TYPE_SCHEMA_REGISTRY,
)

_DOCUMENT_TYPE_THRESHOLDS: Dict[str, Dict[str, int]] = {
    'strategy': {'consulting_grade_score': 90},
    'policy': {'compliance_structure_score': 90},
    'procedure': {'operational_actionability_score': 90},
    'risk': {'risk_completeness_score': 90},
    'audit': {'evidence_traceability_score': 90},
    'roadmap': {'initiative_coverage_score': 90},
    'executive_summary': {'executive_readiness_score': 90},
    'gap_assessment': {'consulting_grade_score': 90},
    'kpi_framework': {'consulting_grade_score': 90},
    'governance_model': {'compliance_structure_score': 90},
}


def _score_from_eval(base: Dict[str, Any], document_type: str) -> Dict[str, int]:
    """Derive platform scores from canonical + route evidence."""
    canonical = (base.get('evidence') or {}).get('canonical') or {}
    routes = base.get('route_evidence') or {}
    section_ok = sum(
        1 for s in (canonical.get('section_results') or {}).values()
        if isinstance(s, dict) and s.get('passed'))
    section_total = max(len(canonical.get('section_results') or {}), 1)
    substance = int(100 * section_ok / section_total)

    route_ok = sum(1 for r in routes.values() if r.get('content_substance_passed'))
    route_total = max(len(routes), 1)
    route_score = int(100 * route_ok / route_total) if routes else substance

    consulting = int((substance * 0.6) + (route_score * 0.4))
    executive = int((substance * 0.5) + (route_score * 0.5))
    content_substance = substance

    scores = {
        'content_substance_score': content_substance,
        'executive_readiness_score': executive,
        'consulting_grade_score': consulting,
        'compliance_structure_score': consulting,
        'operational_actionability_score': consulting,
        'risk_completeness_score': consulting,
        'evidence_traceability_score': route_score,
        'initiative_coverage_score': route_score,
        'quality_score': consulting,
    }
    thresholds = _DOCUMENT_TYPE_THRESHOLDS.get(document_type, {})
    for key, minimum in thresholds.items():
        if scores.get(key, 0) < minimum:
            base.setdefault('blocking_errors', []).append(
                f'{key}_below_threshold:{scores.get(key, 0)}<{minimum}')
    return scores


class DocumentExcellenceGate:
    """Universal DQS entry — canonical document in, quality verdict out."""

    @staticmethod
    def evaluate(
            *,
            canonical_document: Any = None,
            render_tree: Any = None,
            preview_text: str = '',
            docx_text: str = '',
            pdf_text: str = '',
            domain: str = 'cyber',
            document_type: str = 'strategy',
            lang: str = 'ar',
            pdf_bytes: bytes = b'',
            legacy_sections: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        sections = legacy_sections
        if canonical_document is not None:
            if hasattr(canonical_document, 'legacy_sections'):
                sections = canonical_document.legacy_sections
            elif isinstance(canonical_document, dict):
                sections = canonical_document.get('sections') or sections

        base = evaluate_document_quality(
            canonical_artifact=canonical_document,
            legacy_sections=sections,
            render_tree=render_tree,
            extracted_preview_text=preview_text,
            extracted_docx_text=docx_text,
            extracted_pdf_text=pdf_text,
            pdf_bytes=pdf_bytes,
        )

        trace_guard = verify_immutable_traceability_routes(
            preview_text=preview_text,
            docx_text=docx_text,
            pdf_text=pdf_text,
        )
        blocking: List[str] = list(base.get('blocking_errors') or [])
        warnings: List[str] = []
        if not trace_guard.get('passed'):
            blocking.extend(trace_guard.get('blocking_errors') or [])

        dt = (document_type or 'strategy').strip().lower()
        scores = _score_from_eval(base, dt)
        schema = DOCUMENT_TYPE_SCHEMA_REGISTRY.get(dt, {})
        if dt not in DOCUMENT_TYPE_SCHEMA_REGISTRY:
            warnings.append(f'unknown_document_type:{dt}')

        passed = not blocking and bool(base.get('passed', False))
        if scores.get('consulting_grade_score', 0) < schema.get(
                'min_consulting_grade', 0):
            if schema.get('min_consulting_grade'):
                passed = False

        export_route_results = {
            route: {
                'export_return_allowed': ev.get('content_substance_passed', False),
                'blocking_errors': ev.get('blocking_errors') or [],
            }
            for route, ev in (base.get('route_evidence') or {}).items()
        }

        return {
            'passed': passed,
            'document_quality_passed': passed,
            'quality_score': scores['quality_score'],
            'blocking_errors': list(dict.fromkeys(blocking)),
            'warning_errors': warnings,
            'section_results': base.get('section_results') or {},
            'export_route_results': export_route_results,
            'content_substance_score': scores['content_substance_score'],
            'executive_readiness_score': scores['executive_readiness_score'],
            'consulting_grade_score': scores['consulting_grade_score'],
            'compliance_structure_score': scores['compliance_structure_score'],
            'operational_actionability_score': scores[
                'operational_actionability_score'],
            'risk_completeness_score': scores['risk_completeness_score'],
            'evidence_traceability_score': scores['evidence_traceability_score'],
            'initiative_coverage_score': scores['initiative_coverage_score'],
            'traceability_guard': trace_guard,
            'evidence': base.get('evidence') or {},
            'export_return_allowed': passed,
        }


# Module-level alias requested in sprint spec.
DocumentQualitySpec = DocumentExcellenceGate
