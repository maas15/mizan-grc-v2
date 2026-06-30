"""Golden Matrix — domains × document types × routes × languages."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

GOLDEN_ROUTES: Tuple[str, ...] = ('preview', 'docx', 'pdf')
GOLDEN_LANGUAGES: Tuple[str, ...] = ('ar', 'en')

# Minimum matrix for enterprise finalization sprint (expand over time).
GOLDEN_MATRIX: List[Dict[str, Any]] = [
    # Cybersecurity
    {'domain': 'cyber', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P0'},
    {'domain': 'cyber', 'document_type': 'policy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'cyber', 'document_type': 'procedure', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'cyber', 'document_type': 'risk', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'cyber', 'document_type': 'audit', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'cyber', 'document_type': 'roadmap', 'lang': 'ar', 'tier': 'P1'},
    # Data Management
    {'domain': 'data', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'data', 'document_type': 'policy', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'data', 'document_type': 'procedure', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'data', 'document_type': 'risk', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'data', 'document_type': 'audit', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'data', 'document_type': 'roadmap', 'lang': 'ar', 'tier': 'P2'},
    # AI Governance
    {'domain': 'ai', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'ai', 'document_type': 'policy', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'ai', 'document_type': 'procedure', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'ai', 'document_type': 'risk', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'ai', 'document_type': 'audit', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'ai', 'document_type': 'roadmap', 'lang': 'ar', 'tier': 'P2'},
    # Digital Transformation
    {'domain': 'dt', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'dt', 'document_type': 'roadmap', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'dt', 'document_type': 'governance_model', 'lang': 'ar', 'tier': 'P2'},
    {'domain': 'dt', 'document_type': 'risk', 'lang': 'ar', 'tier': 'P2'},
    # ERM
    {'domain': 'erm', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'erm', 'document_type': 'risk', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'erm', 'document_type': 'executive_summary', 'lang': 'ar', 'tier': 'P2'},
    # Global Standards
    {'domain': 'global', 'document_type': 'gap_assessment', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'global', 'document_type': 'audit', 'lang': 'ar', 'tier': 'P2'},
]


def matrix_cases(*, tier: str = '', domain: str = '') -> List[Dict[str, Any]]:
    out = list(GOLDEN_MATRIX)
    if tier:
        out = [c for c in out if c.get('tier') == tier]
    if domain:
        out = [c for c in out if c.get('domain') == domain]
    return out


def case_key(case: Dict[str, Any], route: str = '') -> str:
    base = (
        f"{case.get('domain')}:{case.get('document_type')}:"
        f"{case.get('lang')}")
    return f'{base}:{route}' if route else base
