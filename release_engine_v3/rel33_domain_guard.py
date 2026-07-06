"""REL3.3 — export domain guard with compiler-first reference context."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Set

COMPILER_FIRST_DOMAIN_CODES = frozenset({'data', 'ai', 'dt'})

REFERENCE_CONTEXT_SECTIONS = frozenset({
    'environment', 'gaps', 'roadmap', 'kpis', 'confidence',
    'traceability', 'governance', 'flattened',
})

PRIMARY_IDENTITY_SECTIONS = frozenset({'vision', 'pillars'})

CYBER_PRIMARY_IDENTITY_MARKERS = (
    'nca ecc', 'nca dcc', 'essential cybersecurity controls',
    'csirt', 'security operations center', 'soc manager',
    'الأمن السيبراني', 'ضوابط الأمن السيبراني',
    'ecc-1', 'ecc 1:', 'tcc-', 'ضابط ecc',
)

CYBER_CANONICAL_HEADING_MARKERS = (
    'strategic vision', 'vision statement', 'الرؤية الاستراتيجية',
    'strategic pillars', 'الركائز الاستراتيجية',
)


def emit_rel33_domain_guard_decision(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-DOMAIN-GUARD-DECISION] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _norm_domain_code(domain: str, normalize_fn: Callable[[str], str]) -> str:
    try:
        return normalize_fn(domain or '')
    except Exception:  # noqa: BLE001
        return str(domain or '').strip().lower()


def _section_text(sections: Dict[str, Any], key: str) -> str:
    return str((sections or {}).get(key) or '')


def _has_cyber_primary_identity(text: str) -> bool:
    blob = (text or '').lower()
    if not blob.strip():
        return False
    hits = sum(1 for m in CYBER_PRIMARY_IDENTITY_MARKERS if m in blob)
    return hits >= 2 or (
        hits >= 1 and any(h in blob for h in CYBER_CANONICAL_HEADING_MARKERS))


def _is_cyber_canonical_strategy_sections(sections: Dict[str, Any]) -> bool:
    """True when sections look like a full Cyber strategy artifact."""
    if not isinstance(sections, dict):
        return False
    keys = {
        k for k, v in sections.items()
        if not str(k).startswith('_') and str(v or '').strip()}
    core = {'vision', 'pillars', 'gaps', 'roadmap', 'kpis'}
    if len(keys & core) < 4:
        return False
    vision = _section_text(sections, 'vision')
    pillars = _section_text(sections, 'pillars')
    return _has_cyber_primary_identity(vision) or _has_cyber_primary_identity(pillars)


def filter_compiler_first_contamination(
        contamination: List[Dict[str, Any]],
        *,
        domain_code: str,
        sections: Dict[str, Any],
        row_domain_code: str = '',
) -> List[Dict[str, Any]]:
    """Allow control/reference mentions in non-primary sections for data/ai/dt."""
    if domain_code not in COMPILER_FIRST_DOMAIN_CODES:
        return list(contamination or [])
    if row_domain_code and row_domain_code != domain_code:
        return list(contamination or [])
    if _is_cyber_canonical_strategy_sections(sections):
        return list(contamination or [])
    filtered: List[Dict[str, Any]] = []
    for rec in contamination or []:
        sec = str(rec.get('section') or '')
        terms = list(rec.get('found_terms') or [])
        if sec in PRIMARY_IDENTITY_SECTIONS:
            sec_text = _section_text(sections, sec)
            if _has_cyber_primary_identity(sec_text):
                filtered.append(rec)
            continue
        if sec in REFERENCE_CONTEXT_SECTIONS:
            sec_text = _section_text(sections, sec)
            if _has_cyber_primary_identity(sec_text):
                filtered.append({
                    'section': sec,
                    'domain': rec.get('domain'),
                    'found_terms': terms,
                    'reason': 'cyber_primary_in_reference_section',
                })
            continue
        filtered.append(rec)
    return filtered


def evaluate_export_domain_guard(
        sections_dict: Dict[str, Any],
        *,
        domain: str,
        language: str,
        artifact_type: str,
        artifact_id,
        route: str = '',
        document_type: str = 'strategy',
        row_domain: str = '',
        selected_frameworks: Optional[List[str]] = None,
        validate_fn: Callable[..., List[Dict[str, Any]]],
        domain_context_fn: Callable[..., Dict[str, Any]],
        normalize_domain_fn: Callable[[str], str],
        contamination_error_cls: type = RuntimeError,
        is_compiler_first_fn: Optional[Callable[..., bool]] = None,
        sealed_db_authority: bool = False,
) -> Dict[str, Any]:
    """Run domain isolation and return guard decision (raises on hard block)."""

    dtype = str(document_type or artifact_type or 'strategy').strip().lower()
    domain_code = _norm_domain_code(domain, normalize_domain_fn)
    row_code = _norm_domain_code(row_domain, normalize_domain_fn) if row_domain else domain_code
    compiler_first = False
    if callable(is_compiler_first_fn):
        try:
            compiler_first = bool(is_compiler_first_fn(
                domain=domain, lang=language, document_type=dtype))
        except Exception:  # noqa: BLE001
            compiler_first = domain_code in COMPILER_FIRST_DOMAIN_CODES

    diag: Dict[str, Any] = {
        'route': route or 'export',
        'domain': domain_code,
        'artifact_id': str(artifact_id or ''),
        'artifact_type': str(artifact_type or 'strategy'),
        'document_type': dtype,
        'guard_phase': route or 'export_domain_isolation',
        'contaminating_terms': [],
        'contaminating_sections': [],
        'allowed_framework_terms': list(selected_frameworks or []),
        'compiler_first_artifact': compiler_first,
        'sealed_db_authority': sealed_db_authority,
        'domain_guard_passed': False,
        'blocking_errors': [],
    }

    if (artifact_type or 'strategy') != 'strategy':
        diag['domain_guard_passed'] = True
        emit_rel33_domain_guard_decision(diag)
        return diag

    if row_code and row_code != domain_code:
        diag['blocking_errors'] = [
            f'artifact_domain_mismatch:row={row_code}:requested={domain_code}']
        emit_rel33_domain_guard_decision(diag)
        raise contamination_error_cls(
            f'Export blocked — artifact domain {row_code!r} does not match '
            f'requested {domain_code!r}')

    if _is_cyber_canonical_strategy_sections(sections_dict) and domain_code != 'cyber':
        diag['blocking_errors'] = ['cyber_canonical_artifact_in_non_cyber_domain']
        diag['contaminating_sections'] = ['vision', 'pillars']
        emit_rel33_domain_guard_decision(diag)
        raise contamination_error_cls(
            'Export blocked — saved artifact is a Cyber canonical strategy')

    ctx = domain_context_fn(
        domain, lang=(language or 'en'),
        selected_frameworks=selected_frameworks or None)
    raw_hits = validate_fn(sections_dict, ctx)
    hits = raw_hits
    if compiler_first and domain_code in COMPILER_FIRST_DOMAIN_CODES:
        hits = filter_compiler_first_contamination(
            raw_hits,
            domain_code=domain_code,
            sections=sections_dict,
            row_domain_code=row_code,
        )

    if hits:
        terms: Set[str] = set()
        secs: Set[str] = set()
        for rec in hits:
            secs.add(str(rec.get('section') or ''))
            for t in rec.get('found_terms') or []:
                terms.add(str(t))
        diag['contaminating_terms'] = sorted(terms)
        diag['contaminating_sections'] = sorted(secs)
        diag['blocking_errors'] = ['domain_contamination']
        emit_rel33_domain_guard_decision(diag)
        summary = '; '.join(
            f"{rec.get('section', '?')}={list(rec.get('found_terms', []))[:4]}"
            for rec in hits)
        raise contamination_error_cls(
            f'Export blocked — saved strategy contains cross-domain content '
            f'({ctx.get("display_en") or domain_code}): {summary}')

    diag['domain_guard_passed'] = True
    emit_rel33_domain_guard_decision(diag)
    return diag
