"""PR-REL1 canonical strategy artifact model."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

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

_SECTION_MARKER_RE = re.compile(
    r'\[SECTION[:\s]|<!--\s*section\s*:', re.IGNORECASE)


def legacy_sections_to_canonical(
        sections: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Map legacy H2 section dict keys into canonical REL1 section keys."""
    out: Dict[str, str] = {k: '' for k in CANONICAL_SECTION_KEYS}
    if not isinstance(sections, dict):
        return out
    for key, body in sections.items():
        if not isinstance(body, str):
            continue
        canon = _LEGACY_SECTION_MAP.get((key or '').strip().lower())
        if canon:
            out[canon] = (body or '').strip()
    return out


def _content_hash(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def structural_quality_issues(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        mandatory: Optional[List[str]] = None,
) -> List[str]:
    """Domain-agnostic structure gates (no global markdown regex blockers)."""
    issues: List[str] = []
    mandatory = mandatory or [
        'vision_objectives', 'pillars', 'environment',
        'gap_analysis', 'roadmap', 'kpi_kri', 'confidence_risk',
    ]
    blob = '\n'.join(sections.get(k, '') or '' for k in sections)
    if _SECTION_MARKER_RE.search(blob):
        issues.append('rel1_raw_section_marker_present')
    for key in mandatory:
        if not (sections.get(key) or '').strip():
            issues.append(f'rel1_missing_mandatory_section:{key}')
    return issues


def build_canonical_artifact(
        *,
        domain: str,
        language: str,
        document_type: str = 'strategy',
        legacy_sections: Optional[Dict[str, str]] = None,
        final_markdown: str = '',
        metadata: Optional[Dict[str, Any]] = None,
        quality_flags: Optional[Dict[str, Any]] = None,
        blocking_errors: Optional[List[str]] = None,
        tables: Optional[Dict[str, Any]] = None,
        sealed: bool = False,
        content_hash_fn=None,
) -> Dict[str, Any]:
    """Build the REL1 canonical artifact envelope."""
    canon_sections = legacy_sections_to_canonical(legacy_sections)
    md = final_markdown or ''
    if content_hash_fn is not None:
        fh = content_hash_fn(md)
    else:
        fh = _content_hash(md)
    lang = 'ar' if str(language or '').lower() in ('ar', 'arabic') else 'en'
    return {
        'domain': (domain or '').strip().lower(),
        'language': lang,
        'document_type': document_type or 'strategy',
        'sections': canon_sections,
        'tables': dict(tables or {}),
        'metadata': dict(metadata or {}),
        'quality_flags': dict(quality_flags or {}),
        'blocking_errors': list(blocking_errors or []),
        'final_hash': fh,
        'sealed': bool(sealed and not (blocking_errors or [])),
    }
