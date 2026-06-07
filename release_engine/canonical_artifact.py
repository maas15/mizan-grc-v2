"""PR-REL2 canonical artifact envelope."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

from release_engine.section_model import (
    CANONICAL_SECTION_KEYS,
    legacy_sections_to_canonical,
)

_SECTION_MARKER_RE = re.compile(
    r'\[SECTION[:\s]|<!--\s*section\s*:', re.IGNORECASE)


def content_hash(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def structural_quality_issues(
        sections: Dict[str, str],
        *,
        mandatory: Optional[List[str]] = None,
) -> List[str]:
    issues: List[str] = []
    mandatory = mandatory or [
        'vision_objectives', 'pillars', 'environment',
        'gap_analysis', 'roadmap', 'kpi_kri', 'confidence_risk',
    ]
    blob = '\n'.join(sections.get(k, '') or '' for k in sections)
    if _SECTION_MARKER_RE.search(blob):
        issues.append('rel2_raw_section_marker_present')
    for key in mandatory:
        if not (sections.get(key) or '').strip():
            issues.append(f'rel2_missing_mandatory_section:{key}')
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
        scoring: Optional[Dict[str, Any]] = None,
        sealed: bool = False,
        content_hash_fn=None,
) -> Dict[str, Any]:
    canon_sections = legacy_sections_to_canonical(legacy_sections)
    md = final_markdown or ''
    if content_hash_fn is not None:
        fh = content_hash_fn(md)
    else:
        fh = content_hash(md)
    lang = 'ar' if str(language or '').lower() in ('ar', 'arabic') else 'en'
    blockers = list(blocking_errors or [])
    return {
        'domain': (domain or '').strip().lower(),
        'language': lang,
        'document_type': document_type or 'strategy',
        'sections': canon_sections,
        'section_keys': list(CANONICAL_SECTION_KEYS),
        'metadata': dict(metadata or {}),
        'quality_flags': dict(quality_flags or {}),
        'blocking_errors': blockers,
        'scoring': dict(scoring or {}),
        'final_hash': fh,
        'sealed': bool(sealed and not blockers),
        'release_ready_final_passed': False,
    }
