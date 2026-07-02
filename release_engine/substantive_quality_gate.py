"""PR-REL2.4 — aggregate substantive content quality gate."""

from __future__ import annotations

import json
from typing import Any, Dict, List


def evaluate_substantive_quality(
        *,
        domain: str,
        lang: str,
        document_type: str,
        diags: Dict[str, Any],
) -> Dict[str, Any]:
    so = diags.get('so') or {}
    pillars = diags.get('pillars') or {}
    roadmap = diags.get('roadmap') or {}
    kpis = diags.get('kpis') or {}
    risk = diags.get('risk') or {}
    trace = diags.get('traceability') or {}
    arabic = diags.get('arabic') or {}

    objectives_quality_passed = bool(so.get('objectives_quality_passed', True))
    pillar_depth_passed = bool(pillars.get('pillar_depth_passed', True))
    roadmap_depth_passed = bool(roadmap.get('roadmap_depth_passed', True))
    kpi_semantics_passed = bool(
        kpis.get('kpi_substance_passed', kpis.get('kpi_semantics_valid', True)))
    risk_treatment_passed = bool(risk.get('risk_treatment_passed', True))
    traceability_semantics_passed = bool(
        trace.get('traceability_substance_passed', True))
    arabic_language_passed = bool(arabic.get('arabic_quality_passed', True))

    failed_sections: List[str] = []
    blocking_errors: List[str] = []

    checks = (
        ('objectives', objectives_quality_passed, so),
        ('pillars', pillar_depth_passed, pillars),
        ('roadmap', roadmap_depth_passed, roadmap),
        ('kpi', kpi_semantics_passed, kpis),
        ('risk', risk_treatment_passed, risk),
        ('traceability', traceability_semantics_passed, trace),
        ('arabic', arabic_language_passed, arabic),
    )
    for section, passed, diag in checks:
        if not passed:
            failed_sections.append(section)
            err = (diag.get('blocking_error_if_any') or '').strip()
            if err:
                blocking_errors.append(err)
            else:
                blocking_errors.append(
                    f'rel2_substantive_quality_failed:{section}:substance')

    board_ready_substance_passed = not failed_sections
    actions = [
        d.get('action_taken', '')
        for _, _, d in checks
        if d.get('action_taken') and d.get('action_taken') != 'validated'
    ]
    action_taken = actions[0] if actions else 'validated'

    return {
        'domain': domain,
        'lang': lang,
        'document_type': document_type,
        'objectives_quality_passed': objectives_quality_passed,
        'pillar_depth_passed': pillar_depth_passed,
        'roadmap_depth_passed': roadmap_depth_passed,
        'kpi_semantics_passed': kpi_semantics_passed,
        'risk_treatment_passed': risk_treatment_passed,
        'traceability_semantics_passed': traceability_semantics_passed,
        'arabic_language_passed': arabic_language_passed,
        'board_ready_substance_passed': board_ready_substance_passed,
        'failed_sections': failed_sections,
        'blocking_errors': blocking_errors,
        'action_taken': action_taken,
    }


def emit_substantive_content_quality_gate(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-SUBSTANTIVE-CONTENT-QUALITY-GATE] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
