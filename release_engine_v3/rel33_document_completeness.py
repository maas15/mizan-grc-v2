"""PR-REL3.3 — deterministic completeness gates per domain / document type."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from release_engine_v3.registries.platform_registries import (
    DOCUMENT_TYPE_SCHEMA_REGISTRY,
    resolve_registries,
)


def _section_nonempty(sections: Dict[str, str], key: str) -> bool:
    return bool((sections.get(key) or '').strip())


def _table_row_count(body: str, min_cols: int = 2) -> int:
    rows = 0
    for ln in (body or '').splitlines():
        s = ln.strip()
        if not s.startswith('|') or '---' in s:
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if len(cells) >= min_cols and cells[0] and not cells[0].startswith('#'):
            rows += 1
    return rows


def _evaluate_registry_evidence(
        sections: Dict[str, str],
        *,
        domain: str,
        document_type: str,
        lang: str = 'ar',
) -> tuple[bool, List[str]]:
    """Registry-driven evidence (not AI prose inference)."""
    dtype = str(document_type or '').strip().lower()
    blockers: List[str] = []
    registries = resolve_registries(
        domain=domain, document_type=dtype, lang=lang)
    if dtype == 'strategy':
        trace = registries.get('traceability') or {}
        body = sections.get('traceability') or ''
        if trace and not _table_row_count(body, 3):
            blockers.append('rel33_traceability_registry_rows_missing')
        return not blockers, blockers
    if dtype == 'policy':
        controls = sections.get('controls') or ''
        if _table_row_count(controls, 2) < 1:
            blockers.append('rel33_policy_control_coverage_missing')
        return not blockers, blockers
    if dtype == 'procedure':
        steps = sections.get('steps') or ''
        if _table_row_count(steps, 2) < 2:
            blockers.append('rel33_procedure_step_completeness_missing')
        return not blockers, blockers
    if dtype == 'risk':
        treatments = sections.get('treatments') or ''
        if _table_row_count(treatments, 2) < 1:
            blockers.append('rel33_risk_treatment_mapping_missing')
        return not blockers, blockers
    if dtype == 'audit':
        evidence = sections.get('evidence') or ''
        if _table_row_count(evidence, 2) < 1:
            blockers.append('rel33_audit_evidence_mapping_missing')
        return not blockers, blockers
    if dtype == 'roadmap':
        owners = sections.get('owners') or sections.get('phases') or ''
        if not re.search(r'مالك|owner', owners, re.I):
            blockers.append('rel33_roadmap_milestone_ownership_missing')
        return not blockers, blockers
    if dtype == 'gap_assessment':
        guides = sections.get('guides') or ''
        if not re.search(r'دليل|guide', guides, re.I):
            blockers.append('rel33_gap_assessment_guides_missing')
        return not blockers, blockers
    if dtype == 'executive_summary':
        if not _section_nonempty(sections, 'decision'):
            blockers.append('rel33_executive_decision_missing')
        return not blockers, blockers
    return True, blockers


def evaluate_rel33_completeness_gate(
        sections: Dict[str, str],
        *,
        domain: str,
        document_type: str,
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Fail closed when required sections are missing after deterministic repair."""
    dtype = str(document_type or 'strategy').strip().lower()
    secs = dict(sections or {})
    if dtype == 'strategy':
        from release_engine_v3.rel32_complete_strategy_compiler import (
            evaluate_rel32_final_strategy_completeness,
        )
        comp = evaluate_rel32_final_strategy_completeness(
            secs,
            lang=lang,
            domain=domain,
            document_type=dtype,
        )
        ref_ok, ref_blockers = _evaluate_registry_evidence(
            secs, domain=domain, document_type=dtype, lang=lang)
        blockers = list(comp.get('blocking_errors') or [])
        if not ref_ok:
            blockers.extend(ref_blockers)
        passed = bool(comp.get('saved_content_complete')) and ref_ok
        return {
            'passed': passed,
            'completeness_gate_passed': passed,
            'blocking_errors': blockers,
            'details': comp,
        }

    schema = DOCUMENT_TYPE_SCHEMA_REGISTRY.get(dtype) or {}
    required = tuple(schema.get('sections') or ())
    missing = [s for s in required if not _section_nonempty(secs, s)]
    blockers = [f'rel33_section_missing:{m}' for m in missing]
    ref_ok, ref_blockers = _evaluate_registry_evidence(
        secs, domain=domain, document_type=dtype, lang=lang)
    if not ref_ok:
        blockers.extend(ref_blockers)
    passed = not missing and ref_ok
    return {
        'passed': passed,
        'completeness_gate_passed': passed,
        'blocking_errors': blockers,
        'missing_sections': missing,
    }
