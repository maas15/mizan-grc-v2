"""Traceability requirements per domain pack."""

from __future__ import annotations

import re
from typing import Any, Dict, List

_TRACE_RE = re.compile(r'<!--\s*trace:', re.IGNORECASE)


def traceability_issues(
        artifact: Dict[str, Any],
        *,
        domain_pack: Dict[str, Any],
) -> List[str]:
    req = domain_pack.get('traceability_requirements') or {}
    if not req.get('required'):
        return []
    md = artifact.get('final_markdown') or ''
    issues: List[str] = []
    if req.get('min_trace_markers', 0) > 0:
        count = len(_TRACE_RE.findall(md))
        if count < req['min_trace_markers']:
            issues.append('rel2_traceability_markers_insufficient')
    return issues
