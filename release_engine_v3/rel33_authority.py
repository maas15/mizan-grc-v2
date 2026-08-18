"""PR-REL3.3 — platform-wide authoritative domain / document-type gates."""

from __future__ import annotations

from typing import Any, Dict, Optional

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code

REL33_AUTHORITATIVE_DOMAINS = frozenset({
    'cyber', 'data', 'ai', 'dt', 'erm', 'global',
})

REL33_COMPILER_FIRST_DOCUMENT_TYPES = frozenset({
    'strategy',
})

REL33_SUPPORTED_DOCUMENT_TYPES = frozenset({
    'strategy',
    'policy',
    'procedure',
    'risk',
    'audit',
    'roadmap',
    'executive_summary',
    'gap_assessment',
})

REL33_P1_ROUTES: tuple[Dict[str, str], ...] = (
    {'domain': 'cyber', 'document_type': 'strategy', 'lang': 'ar',
     'doc_subtype': 'technical', 'tier': 'P1'},
    {'domain': 'data', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'ai', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'dt', 'document_type': 'strategy', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'erm', 'document_type': 'risk', 'lang': 'ar', 'tier': 'P1'},
    {'domain': 'global', 'document_type': 'gap_assessment', 'lang': 'ar',
     'tier': 'P1'},
)


def is_rel33_domain_authoritative(
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        flags: Optional[Dict[str, Any]] = None) -> bool:
    """True when REL3.3 authoritative pipeline applies (domain + Arabic)."""
    flags = flags or {}
    if not flags.get('rel31') or not flags.get('rel3'):
        return False
    dcode = _normalize_rel31_domain_code(domain)
    if dcode not in REL33_AUTHORITATIVE_DOMAINS:
        return False
    return str(lang or '').lower().startswith('ar')


def is_rel33_compiler_first(
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        flags: Optional[Dict[str, Any]] = None,
        document_type: str = 'strategy') -> bool:
    """Compiler-first applies to strategy-like documents on REL3.3 routes."""
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype not in REL33_COMPILER_FIRST_DOCUMENT_TYPES:
        return False
    return is_rel33_domain_authoritative(domain=domain, lang=lang, flags=flags)


def route_key(
        *,
        domain: str,
        document_type: str,
        lang: str,
        doc_subtype: str = '') -> str:
    base = f'{domain}:{document_type}:{lang}'
    if doc_subtype:
        return f'{base}:{doc_subtype}'
    return base
