"""PR-REL2 artifact pipeline: parse → repair → validate → score → seal."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from release_engine.canonical_artifact import build_canonical_artifact, structural_quality_issues
from release_engine.diagnostics import build_rel2_diag, emit_rel2_diag
from release_engine.final_quality_contract import evaluate_final_quality
from release_engine.repair_registry import run_domain_repairs
from release_engine.scoring import score_artifact
from release_engine.section_model import legacy_sections_to_canonical
from release_engine.rel23_finalize import (
    apply_rel23_cyber_finalize,
    rel23_blocking_errors,
)
from release_engine.roadmap_model import finalize_roadmap
from release_engine.rel24_finalize import (
    apply_rel24_cyber_substance_finalize,
    rel24_blocking_errors,
)
from release_engine.rel25_finalize import (
    apply_rel25_cyber_evidence_finalize,
    rel25_blocking_errors,
)
from release_engine.rel26_finalize import (
    apply_rel26_cyber_export_evidence_finalize,
    rel26_blocking_errors,
)
from release_engine.validator_registry import (
    assert_no_post_sealed_blockers,
    run_rel2_validators,
)
from release_hardening.orchestrator import finalize_release_artifact as rel1_finalize


def _rebuild_markdown(sections: Dict[str, str]) -> str:
    order = (
        'vision', 'pillars', 'environment', 'gaps',
        'roadmap', 'kpis', 'confidence',
    )
    return '\n\n'.join(
        (sections.get(k) or '').strip()
        for k in order if (sections.get(k) or '').strip())


def process_release_artifact(
        raw_artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        doc_subtype: str = 'technical',
        document_type: str = 'strategy',
        backend: Optional[Dict[str, Callable[..., Any]]] = None,
        domain_pack: Optional[Dict[str, Any]] = None,
        skip_rel1: bool = False,
) -> Dict[str, Any]:
    """
    Unified REL2 engine. Cyber path: REL1 audit + REL2 scoring/contract.
    Non-cyber: structural repair + validation + scoring + seal.
    """
    backend = backend or {}
    domain_pack = domain_pack or {}
    dcode = (domain or raw_artifact.get('domain') or '').strip().lower()
    is_cyber = dcode in ('cyber', 'cyber_security')

    merged = dict(raw_artifact)
    if not skip_rel1 and not merged.get('rel1_canonical'):
        merged = rel1_finalize(
            merged,
            domain=dcode,
            lang=lang,
            doc_subtype=doc_subtype,
            backend=backend,
            domain_pack=domain_pack,
        )

    sections = dict(merged.get('sections') or {})
    blocking = list(merged.get('blocking_errors') or [])
    repair_actions = list(merged.get('repair_actions') or [])
    rel23_diags: dict = {}
    rel24_diags: dict = {}
    rel25_diags: dict = {}
    rel26_diags: dict = {}

    _stale_rel23_prefixes = (
        'rel2_section_parity_failed',
        'rel2_pillars_failed',
        'rel2_roadmap_failed',
        'rel2_kpi_failed',
        'rel2_arabic_quality_failed',
        'rel2_rendered_evidence_failed',
        'rel2_actual_export_evidence_failed',
        'export_hash_parity_invalid',
        'cyber_board_ready_pillars_failed',
        'pillar_sections_hash_mismatch',
        'kpi_metric_semantics_invalid',
        'kpi_formula_alignment_invalid',
        'kpi_numbering_invalid',
        'kpi_duplicate_numbers',
    )
    if is_cyber and document_type == 'strategy':
        blocking = [
            b for b in blocking
            if not any(
                (b or '').startswith(p) or (b or '') == p
                for p in _stale_rel23_prefixes)]

    if is_cyber and document_type == 'strategy':
        merged, rel23_repairs, rel23_diags = apply_rel23_cyber_finalize(
            merged,
            domain=dcode,
            lang=lang,
            backend=backend,
        )
        sections = dict(merged.get('sections') or {})
        repair_actions.extend(rel23_repairs)
        for rb in rel23_blocking_errors(rel23_diags):
            if rb not in blocking:
                blocking.append(rb)

        merged, rel24_repairs, rel24_diags = apply_rel24_cyber_substance_finalize(
            merged,
            domain=dcode,
            lang=lang,
            backend=backend,
        )
        sections = dict(merged.get('sections') or {})
        repair_actions.extend(rel24_repairs)
        for rb in rel24_blocking_errors(rel24_diags):
            if rb not in blocking:
                blocking.append(rb)
        if (rel24_diags.get('arabic') or {}).get('arabic_quality_passed'):
            blocking = [
                b for b in blocking
                if not (b or '').startswith('rel2_arabic_quality_failed')]
        if (rel24_diags.get('roadmap') or {}).get('roadmap_depth_passed'):
            _fws = (
                (merged.get('contract_meta') or {}).get('selected_frameworks')
                or merged.get('selected_frameworks') or [])
            sections, road_diag = finalize_roadmap(
                sections,
                lang=lang,
                domain=dcode,
                selected_frameworks=_fws,
                backend=backend,
            )
            rel23_diags['roadmap'] = road_diag
            merged['sections'] = sections
            merged['final_markdown'] = _rebuild_markdown(sections)
            _hash_fn = backend.get('content_hash')
            if _hash_fn:
                merged['final_hash'] = _hash_fn(merged['final_markdown'])
            blocking = [
                b for b in blocking
                if not (b or '').startswith('rel2_roadmap_failed')]
            _road_err = (road_diag.get('blocking_error_if_any') or '').strip()
            if _road_err and _road_err not in blocking:
                blocking.append(_road_err)

        merged, rel25_repairs, rel25_diags = apply_rel25_cyber_evidence_finalize(
            merged,
            domain=dcode,
            lang=lang,
            backend=backend,
        )
        sections = dict(merged.get('sections') or {})
        repair_actions.extend(rel25_repairs)
        for rb in rel25_blocking_errors(rel25_diags):
            if rb not in blocking:
                blocking.append(rb)

        merged, rel26_repairs, rel26_diags = (
            apply_rel26_cyber_export_evidence_finalize(
                merged,
                domain=dcode,
                lang=lang,
                backend=backend,
            ))
        sections = dict(merged.get('sections') or {})
        repair_actions.extend(rel26_repairs)
        for rb in rel26_blocking_errors(rel26_diags):
            if rb not in blocking:
                blocking.append(rb)
        if (rel26_diags.get('export') or {}).get('export_evidence_passed'):
            blocking = [
                b for b in blocking
                if not (b or '').startswith((
                    'rel2_rendered_evidence_failed',
                    'rel2_actual_export_evidence_failed',
                ))]

    if not is_cyber or merged.get('rel2_force_repair'):
        sections, repairs = run_domain_repairs(
            sections, domain=dcode, lang=lang, domain_pack=domain_pack)
        repair_actions.extend(repairs)
        if repairs:
            merged['sections'] = sections
            merged['final_markdown'] = _rebuild_markdown(sections)
            hash_fn = backend.get('content_hash')
            if hash_fn:
                merged['final_hash'] = hash_fn(merged['final_markdown'])

    canon = legacy_sections_to_canonical(sections)
    mandatory = domain_pack.get('mandatory_canonical_sections') or []
    if not is_cyber:
        for si in structural_quality_issues(canon, mandatory=mandatory or None):
            if si not in blocking:
                blocking.append(si)

    scoped = run_rel2_validators(
        domain=dcode,
        lang=lang,
        legacy_sections=sections,
        backend=backend,
        cyber_only=not is_cyber,
        audit_only=is_cyber,
    )
    scoped_blockers = scoped.get('blockers') or []
    if not is_cyber:
        for b in scoped_blockers:
            if b not in blocking:
                blocking.append(b)

    merged['sections'] = sections
    merged['blocking_errors'] = blocking
    merged['repair_actions'] = repair_actions
    merged['sealed'] = not blocking
    if rel23_diags or rel24_diags or rel25_diags or rel26_diags:
        merged['diagnostics'] = dict(merged.get('diagnostics') or {})
        _rel2_store = dict(merged['diagnostics'].get('rel2') or {})
        if rel23_diags:
            _rel2_store['rel23'] = rel23_diags
        if rel24_diags:
            _rel2_store['rel24'] = rel24_diags
        if rel25_diags:
            _rel2_store['rel25'] = rel25_diags
        if rel26_diags:
            _rel2_store['rel26'] = rel26_diags
            _rel2_store['rel27'] = rel26_diags
        merged['diagnostics']['rel2'] = _rel2_store

    scoring = score_artifact(
        merged,
        domain_pack=domain_pack,
        document_type=document_type,
        lang=lang,
    )
    contract = evaluate_final_quality(
        merged,
        domain_pack=domain_pack,
        document_type=document_type,
        lang=lang,
        export_route='preview',
        skip_structural=is_cyber,
    )
    blocking = contract['blocking_errors']
    merged['blocking_errors'] = blocking
    release_ready = contract['release_ready_final_passed']
    merged['sealed'] = release_ready or (not blocking and merged.get('sealed'))

    hash_fn = backend.get('content_hash')
    canonical = build_canonical_artifact(
        domain=dcode,
        language=lang,
        document_type=document_type,
        legacy_sections=sections,
        final_markdown=merged.get('final_markdown') or '',
        metadata={
            'doc_subtype': doc_subtype,
            'rel2': True,
            **(merged.get('contract_meta') or {}),
        },
        quality_flags=merged.get('quality_flags') or {},
        blocking_errors=blocking,
        scoring=contract['scoring'],
        sealed=merged['sealed'],
        content_hash_fn=hash_fn,
    )
    canonical['release_ready_final_passed'] = release_ready
    fh = merged.get('final_hash') or canonical['final_hash']
    canonical['final_hash'] = fh

    post_violations = []
    if merged['sealed'] and backend:
        post_violations = assert_no_post_sealed_blockers(
            {'sealed': True, 'sections': sections, 'blocking_errors': blocking,
             'domain': dcode},
            backend=backend,
            lang=lang,
        )
        if post_violations:
            merged['post_seal_mutation_detected'] = True
            release_ready = False
            canonical['release_ready_final_passed'] = False

    diag = build_rel2_diag(
        domain=dcode,
        lang=lang,
        document_type=document_type,
        phase='rel2_finalize',
        scoring=contract['scoring'],
        sealed=merged['sealed'],
        release_ready=release_ready,
        repair_actions=repair_actions,
        blocking=blocking,
        export_parity_ok=contract['export_parity_ok'],
    )
    diag['scoped_validation'] = scoped.get('diag') or {}
    diag['post_sealed_audit'] = post_violations
    if rel23_diags:
        diag['rel23'] = rel23_diags
    if rel24_diags:
        diag['rel24'] = rel24_diags
    if rel25_diags:
        diag['rel25'] = rel25_diags
    if rel26_diags:
        diag['rel26'] = rel26_diags
    emit_rel2_diag(diag)

    merged['rel2_canonical'] = canonical
    merged['final_hash'] = fh
    merged['release_ready_final_passed'] = release_ready
    merged['board_ready_score'] = contract['scoring'].get('total_score')
    merged['dimension_scores'] = contract['scoring'].get('dimension_scores')
    merged['failed_dimensions'] = contract['scoring'].get('failed_dimensions')
    merged['final_quality_contract'] = contract
    merged['diagnostics'] = dict(merged.get('diagnostics') or {})
    merged['diagnostics']['rel2'] = diag
    merged['artifact_builder'] = 'PR-REL2'
    return merged
