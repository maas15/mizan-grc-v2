"""PR-REL1 artifact orchestration — build, validate, seal."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from release_hardening.canonical_model import (
    build_canonical_artifact,
    legacy_sections_to_canonical,
    structural_quality_issues,
)
from release_hardening.validator_registry import (
    assert_no_post_sealed_blockers,
    run_scoped_validators,
)


def emit_release_hardening_diag(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[RELEASE-HARDENING-SCOPE] '
            f'{json.dumps(payload, ensure_ascii=False, default=str)}',
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def finalize_release_artifact(
        raw_artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        doc_subtype: str = 'technical',
        backend: Optional[Dict[str, Callable[..., Any]]] = None,
        domain_pack: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Wrap a builder artifact with REL1 canonical envelope and scoped validation.

    For cyber: trusts upstream ``_build_cyber_final_strategy_artifact`` then
    audits scoped validators and strips cross-section false positives.
    For other domains: structural validation + seal when sections complete.
    """
    backend = backend or {}
    domain_pack = domain_pack or {}
    dcode = (domain or '').strip().lower()
    legacy_sections = (
        raw_artifact.get('sections')
        or raw_artifact.get('sections_json')
        or {})
    final_md = raw_artifact.get('final_markdown') or ''
    blocking = list(raw_artifact.get('blocking_errors') or [])
    quality_flags = dict(raw_artifact.get('quality_flags') or {})
    is_cyber = dcode in ('cyber', 'cyber_security')

    canon = legacy_sections_to_canonical(legacy_sections)
    pack_mandatory = domain_pack.get('mandatory_canonical_sections') or [
        'vision_objectives', 'pillars', 'environment',
        'gap_analysis', 'roadmap', 'kpi_kri', 'confidence_risk',
    ]
    struct_issues: List[str] = []
    if not is_cyber:
        struct_issues = structural_quality_issues(
            canon, lang=lang, mandatory=pack_mandatory)

    strip_fn = backend.get('strip_stale_so_issues')
    if is_cyber and strip_fn and blocking:
        blocking = strip_fn(blocking, legacy_sections, lang) or blocking

    if not is_cyber:
        for si in struct_issues:
            if si not in blocking:
                blocking.append(si)
        scoped = run_scoped_validators(
            domain=dcode,
            lang=lang,
            legacy_sections=legacy_sections,
            backend=backend,
            cyber_only=True,
            audit_only=False,
        )
    else:
        # Cyber: upstream export contract already enforced gates; audit only.
        scoped = run_scoped_validators(
            domain=dcode,
            lang=lang,
            legacy_sections=legacy_sections,
            backend=backend,
            cyber_only=False,
            audit_only=True,
        )

    sealed = not blocking and bool(raw_artifact.get('sealed', not blocking))
    if is_cyber:
        sealed = not blocking

    hash_fn = backend.get('content_hash')
    canonical = build_canonical_artifact(
        domain=dcode or 'cyber',
        language=lang,
        document_type='strategy',
        legacy_sections=legacy_sections,
        final_markdown=final_md,
        metadata={
            'doc_subtype': doc_subtype,
            'rel1': True,
            **(raw_artifact.get('contract_meta') or {}),
        },
        quality_flags=quality_flags,
        blocking_errors=blocking,
        sealed=sealed,
        content_hash_fn=hash_fn,
    )

    post_sealed_violations = []
    if sealed and backend:
        post_sealed_violations = assert_no_post_sealed_blockers(
            {
                'sealed': True,
                'sections': legacy_sections,
                'blocking_errors': blocking,
                'domain': dcode,
            },
            backend=backend,
            lang=lang,
        )
        post_sealed_violations = [
            v for v in post_sealed_violations
            if v != 'rel1_audit_skipped_not_sealed']

    diag = {
        'task_id': raw_artifact.get('task_id') or '',
        'domain': dcode,
        'lang': lang,
        'phase': 'rel1_finalize',
        'doc_subtype': doc_subtype,
        'canonical_so_header_found': bool(
            quality_flags.get('strategic_objectives_valid')),
        'structural_issues': struct_issues,
        'scoped_validation': scoped.get('diag') or {},
        'post_sealed_audit_violations': post_sealed_violations,
        'blocking_error_if_any': blocking[:5],
        'sealed': sealed,
        'global_scan_disabled': True,
        'validators_using_canonical_extractor': [
            'strategic_objectives', 'roadmap', 'confidence_risk'],
        'action_taken': 'sealed' if sealed else 'blocked',
    }
    emit_release_hardening_diag(diag)

    merged = dict(raw_artifact)
    merged['rel1_canonical'] = canonical
    merged['blocking_errors'] = blocking
    merged['sealed'] = sealed
    merged['final_hash'] = canonical['final_hash']
    merged['diagnostics'] = dict(merged.get('diagnostics') or {})
    merged['diagnostics']['rel1'] = diag
    merged['artifact_builder'] = 'PR-REL1'
    return merged
