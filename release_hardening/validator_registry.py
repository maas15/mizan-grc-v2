"""PR-REL1 scoped validator registry — no validator without a declared source."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

# Each entry declares source scope; orchestrator supplies callables via backend.
VALIDATOR_REGISTRY: Dict[str, Dict[str, Any]] = {
    'strategic_objectives': {
        'source': 'sections.vision_objectives.canonical_table',
        'legacy_section_key': 'vision',
        'blockers': [
            'strategic_objectives_incomplete_row',
            'strategic_objectives_row_schema_violation',
            'strategic_objectives_rows_insufficient',
            'strategic_objectives_section_missing',
            'strategic_objectives_table_missing_after_repair',
        ],
        'backend_keys': {
            'validator': 'so_incomplete_rows',
            'extractor': 'extract_canonical_so_rows',
            'ignored_cross_section': 'collect_ignored_cross_section',
        },
        'global_scan_disabled': True,
    },
    'roadmap': {
        'source': 'sections.roadmap.canonical_table',
        'legacy_section_key': 'roadmap',
        'blockers': [
            'roadmap_phase_missing_timeline',
            'roadmap_phase_coverage_invalid',
            'missing_phase_timeline',
            'roadmap_phase_timeline_invalid_period',
            'cyber_roadmap_balance_missing',
            'prcy74_missing_required_dcc_family',
            'prcy71_final_artifact_missing_required_dcc_roadmap_rows',
        ],
        'backend_keys': {
            'validator': 'roadmap_timeline_valid',
            'repairer': 'roadmap_timeline_normalize',
        },
        'global_scan_disabled': True,
    },
    'kpi_kri': {
        'source': 'sections.kpi_kri.canonical_table',
        'legacy_section_key': 'kpis',
        'blockers': ['kpi_metric_semantics_invalid'],
        'backend_keys': {'validator': 'kpi_semantics_valid'},
        'global_scan_disabled': True,
    },
    'confidence_risk': {
        'source': 'sections.confidence_risk',
        'legacy_section_key': 'confidence',
        'blockers': [
            'confidence_score_missing',
            'score_justification_missing',
        ],
        'backend_keys': {
            'validator': 'confidence_present',
            'repairer': 'confidence_repair',
        },
        'global_scan_disabled': True,
    },
    'traceability': {
        'source': 'sections.traceability',
        'legacy_section_key': 'traceability',
        'blockers': [],
        'backend_keys': {},
        'global_scan_disabled': True,
    },
    'pdf_render': {
        'source': 'artifact.sealed.read_only',
        'blockers': [
            'pdf_table_vertical_stack_warnings',
            'pdf_table_vertical_stack_unresolved',
        ],
        'backend_keys': {
            'validator': 'pdf_vertical_stack_gate',
        },
        'mutates_sealed_content': False,
        'global_scan_disabled': True,
    },
    'docmodel': {
        'source': 'artifact.sealed.read_only',
        'blockers': ['docmodel_professional_quality'],
        'backend_keys': {'validator': 'docmodel_quality'},
        'mutates_sealed_content': False,
        'global_scan_disabled': True,
    },
}

# Legacy gate retirement metadata (unsafe → scoped/diagnostic/removed).
LEGACY_GATE_CLASSIFICATION: Dict[str, Dict[str, str]] = {
    'strategic_objectives_incomplete_row': {
        'legacy_emitter': '_prcy80_strategic_objectives_incomplete_rows',
        'status': 'scoped',
        'scoped_validator': 'strategic_objectives',
        'notes': 'PR-CY85 canonical vision table only when prcy85+rel1',
    },
    'strategic_objectives_row_schema_violation': {
        'legacy_emitter': '_audit_doc_quality',
        'status': 'scoped',
        'scoped_validator': 'strategic_objectives',
    },
    'strategic_objectives_rows_insufficient': {
        'legacy_emitter': '_prcy67_count_valid_so_rows',
        'status': 'scoped',
        'scoped_validator': 'strategic_objectives',
    },
    'strategic_objectives_section_missing': {
        'legacy_emitter': '_prcy80_strategic_objectives_incomplete_rows',
        'status': 'scoped',
        'scoped_validator': 'strategic_objectives',
    },
    'roadmap_phase_missing_timeline': {
        'legacy_emitter': '_prcy23_final_assertions / _prcy81',
        'status': 'scoped',
        'scoped_validator': 'roadmap',
    },
    'roadmap_phase_coverage_invalid': {
        'legacy_emitter': '_prcy78_repair_roadmap_phase_coverage',
        'status': 'scoped',
        'scoped_validator': 'roadmap',
    },
    'cyber_roadmap_balance_missing': {
        'legacy_emitter': '_compute_missing_cyber_roadmap_balance_topics',
        'status': 'scoped',
        'scoped_validator': 'roadmap',
    },
    'prcy74_missing_required_dcc_family': {
        'legacy_emitter': '_validate_required_dcc_roadmap_families',
        'status': 'scoped',
        'scoped_validator': 'roadmap',
    },
    'prcy71_final_artifact_missing_required_dcc_roadmap_rows': {
        'legacy_emitter': '_prcy71_missing_required_dcc_roadmap_families',
        'status': 'scoped',
        'scoped_validator': 'roadmap',
    },
    'confidence_score_missing': {
        'legacy_emitter': '_prcy65_detect_confidence_presence',
        'status': 'scoped',
        'scoped_validator': 'confidence_risk',
    },
    'score_justification_missing': {
        'legacy_emitter': '_prcy65_detect_confidence_presence',
        'status': 'scoped',
        'scoped_validator': 'confidence_risk',
    },
    'kpi_metric_semantics_invalid': {
        'legacy_emitter': '_audit_doc_quality / KPI branch',
        'status': 'scoped',
        'scoped_validator': 'kpi_kri',
    },
    'pdf_table_vertical_stack_warnings': {
        'legacy_emitter': 'evaluate_vertical_stack_gate',
        'status': 'diagnostic',
        'scoped_validator': 'pdf_render',
        'notes': 'Actionable warnings; unresolved layout blocks at export',
    },
    'docmodel_professional_quality': {
        'legacy_emitter': 'build_professional_strategy_document_model',
        'status': 'diagnostic',
        'scoped_validator': 'docmodel',
    },
    'strategic_objectives_cross_section_row_ignored': {
        'legacy_emitter': '_prcy85_collect_ignored_cross_section_rows',
        'status': 'diagnostic',
        'scoped_validator': 'strategic_objectives',
    },
}


def classify_legacy_gate(blocker: str) -> Dict[str, str]:
    """Return retirement metadata for a blocker code (prefix match)."""
    code = (blocker or '').strip()
    if code.startswith('final_quality_gate_failed:'):
        code = code.split(':', 1)[1]
    base = code.split(':')[0]
    if base in LEGACY_GATE_CLASSIFICATION:
        return dict(LEGACY_GATE_CLASSIFICATION[base])
    for key, meta in LEGACY_GATE_CLASSIFICATION.items():
        if code.startswith(key):
            return dict(meta)
    return {
        'legacy_emitter': 'unknown',
        'status': 'unclassified',
        'scoped_validator': '',
    }


def run_scoped_validators(
        *,
        domain: str,
        lang: str,
        legacy_sections: Dict[str, str],
        backend: Dict[str, Callable[..., Any]],
        cyber_only: bool = True,
        audit_only: bool = False,
) -> Dict[str, Any]:
    """
    Run validators declared in VALIDATOR_REGISTRY using backend callables.

    Returns blockers, diagnostics, and per-validator results.
    """
    blockers: List[str] = []
    diag: Dict[str, Any] = {
        'domain': domain,
        'lang': lang,
        'validators_run': [],
        'global_scan_disabled': True,
        'audit_only': audit_only,
    }
    dcode = (domain or '').strip().lower()
    is_cyber = dcode in ('', 'cyber', 'cyber_security')

    if not is_cyber and cyber_only:
        return {
            'blockers': [],
            'diag': {**diag, 'skipped': 'non_cyber_structural_only'},
        }

    sections = legacy_sections if isinstance(legacy_sections, dict) else {}

    # Strategic objectives — canonical vision only.
    so_fn = backend.get('so_incomplete_rows')
    if so_fn and VALIDATOR_REGISTRY['strategic_objectives']['source']:
        issues = so_fn(sections, lang) or []
        diag['validators_run'].append('strategic_objectives')
        diag['strategic_objectives_issues'] = list(issues)
        if not audit_only:
            for i in issues:
                if i and i not in blockers:
                    blockers.append(i)

    ignored_fn = backend.get('collect_ignored_cross_section')
    if ignored_fn:
        ignored, traces = ignored_fn(sections)
        diag['ignored_cross_section_rows_count'] = len(ignored or [])
        diag['ignored_trace_sections'] = list(traces or [])

    # Roadmap timeline (cyber).
    rm_fn = backend.get('roadmap_timeline_valid')
    if rm_fn and is_cyber:
        valid = rm_fn(sections, lang)
        diag['validators_run'].append('roadmap')
        diag['roadmap_phase_timeline_valid'] = bool(valid)
        if not valid and not audit_only:
            blockers.append('roadmap_phase_missing_timeline')

    conf_fn = backend.get('confidence_present')
    if conf_fn and is_cyber:
        conf_issues = conf_fn(sections, lang) or []
        diag['validators_run'].append('confidence_risk')
        if not audit_only:
            for c in conf_issues:
                if c and c not in blockers:
                    blockers.append(c)

    return {'blockers': blockers, 'diag': diag}


def assert_no_post_sealed_blockers(
        artifact: Dict[str, Any],
        *,
        backend: Dict[str, Callable[..., Any]],
        lang: str = 'ar',
) -> List[str]:
    """Re-run scoped validators in audit-only mode; must not add new blockers."""
    if not artifact.get('sealed'):
        return ['rel1_audit_skipped_not_sealed']
    sections = artifact.get('sections') or artifact.get('sections_json') or {}
    domain = artifact.get('domain') or (
        (artifact.get('metadata') or {}).get('domain')) or 'cyber'
    result = run_scoped_validators(
        domain=domain,
        lang=lang,
        legacy_sections=sections,
        backend=backend,
        audit_only=True,
    )
    new_blockers = []
    for b in result.get('blockers') or []:
        if b not in (artifact.get('blocking_errors') or []):
            new_blockers.append(b)
    return new_blockers
