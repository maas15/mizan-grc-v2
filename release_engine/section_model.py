"""Canonical section keys and legacy mapping."""

from __future__ import annotations

from typing import Dict, Optional

CANONICAL_SECTION_KEYS = (
    'executive_summary',
    'vision_objectives',
    'pillars',
    'environment',
    'gap_analysis',
    'roadmap',
    'kpi_kri',
    'confidence_risk',
    'governance',
    'traceability',
    'appendices',
)

_LEGACY_SECTION_MAP = {
    'vision': 'vision_objectives',
    'pillars': 'pillars',
    'environment': 'environment',
    'gaps': 'gap_analysis',
    'gap_analysis': 'gap_analysis',
    'roadmap': 'roadmap',
    'kpis': 'kpi_kri',
    'kpi_kri': 'kpi_kri',
    'confidence': 'confidence_risk',
    'confidence_risk': 'confidence_risk',
    'governance': 'governance',
    'traceability': 'traceability',
    'executive_summary': 'executive_summary',
    'appendices': 'appendices',
}


def empty_canonical_sections() -> Dict[str, str]:
    return {k: '' for k in CANONICAL_SECTION_KEYS}


def legacy_sections_to_canonical(
        sections: Optional[Dict[str, str]]) -> Dict[str, str]:
    out = empty_canonical_sections()
    if not isinstance(sections, dict):
        return out
    for key, body in sections.items():
        if not isinstance(body, str):
            continue
        canon = _LEGACY_SECTION_MAP.get((key or '').strip().lower())
        if canon:
            out[canon] = (body or '').strip()
    return out
