"""PR-REL3 — build and freeze canonical document artifacts."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from release_engine.section_model import legacy_sections_to_canonical
from release_engine_v3.contracts import (
    CanonicalSection,
    ExportManifest,
    FinalDocumentArtifact,
    compute_canonical_hash,
)
from release_engine_v3.section_models import (
    build_strategy_document,
    enrich_kpi_section,
    enrich_traceability_section,
    strategy_document_to_markdown,
)
from release_engine_v3.validators import validate_canonical_quality


_ARTIFACT_REGISTRY: Dict[str, FinalDocumentArtifact] = {}


def _artifact_id_from(legacy: Dict[str, Any]) -> str:
    aid = (
        str(legacy.get('artifact_id') or '')
        or str(legacy.get('strategy_id') or '')
        or str(legacy.get('task_id') or '')
    )
    if aid:
        return aid
    fh = legacy.get('final_hash') or ''
    if fh:
        return f'hash-{fh[:16]}'
    return f'rel3-{uuid.uuid4().hex[:12]}'


def _legacy_to_canonical_sections(
        legacy_sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, CanonicalSection], Dict[str, str]]:
    sections_src = dict(legacy_sections)
    try:
        from release_engine_v3.rel32_compiler import (
            compile_canonical_strategy_document,
            is_rel32_compiler_first,
        )
        flags = (backend or {}).get('flags') or {}
        if is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
            compiled = compile_canonical_strategy_document(
                sections_src,
                request_context={
                    'lang': lang,
                    'domain': domain,
                    'backend': backend or {},
                },
            )
            if compiled.legacy_sections:
                sections_src = dict(compiled.legacy_sections)
    except Exception:  # noqa: BLE001
        pass
    doc = build_strategy_document(sections_src)
    sections = doc.as_dict()
    raw_kpi = (
        sections_src.get('kpis')
        or sections_src.get('kpi_kri')
        or '')
    if raw_kpi:
        sections['kpi_kri'] = enrich_kpi_section(
            sections['kpi_kri'], raw_kpi)
    raw_trace = (
        sections_src.get('traceability')
        or sections_src.get('traceability_matrix')
        or '')
    if raw_trace:
        sections['traceability'] = enrich_traceability_section(
            sections['traceability'], raw_trace)
    return sections, sections_src


def _scrub_legacy_sections_arabic(
        sections: Dict[str, str], lang: str) -> Dict[str, str]:
    """Pre-scrub Arabic glue before canonical quality validation."""
    if str(lang or '').lower().startswith('en'):
        return sections
    from release_engine.arabic_language_gate import (
        apply_arabic_final_gate,
        repair_arabic_canonical_text_before_freeze,
    )
    from release_engine.rendered_evidence_validator import _repair_arabic_blob
    out = {
        k: _repair_arabic_blob(v)
        if isinstance(v, str) and not str(k).startswith('_') else v
        for k, v in sections.items()}
    out, _ = apply_arabic_final_gate(out, lang=lang)
    out, _ = repair_arabic_canonical_text_before_freeze(out, lang=lang)
    return out


def build_final_document_artifact(
        legacy_artifact: Dict[str, Any],
        *,
        freeze: bool = False,
        strategy_id: str = '',
) -> FinalDocumentArtifact:
    """Build FinalDocumentArtifact from post-REL2 legacy artifact dict."""
    legacy_sections = dict(legacy_artifact.get('sections') or {})
    if not legacy_sections:
        cj = legacy_artifact.get('content_json') or {}
        if isinstance(cj, dict):
            legacy_sections = dict(cj.get('sections') or {})
    meta = legacy_artifact.get('contract_meta') or {}
    fws = list(
        meta.get('selected_frameworks')
        or legacy_artifact.get('selected_frameworks')
        or [])
    domain = (
        legacy_artifact.get('domain')
        or meta.get('domain')
        or 'cyber')
    lang = meta.get('lang') or legacy_artifact.get('language') or 'ar'
    backend = dict(legacy_artifact.get('_rel32_backend') or {})
    backend.setdefault('flags', {
        'rel3': True,
        'rel31': True,
        'rel32': True,
    })
    backend.setdefault('selected_frameworks', fws)
    backend.setdefault('lang', lang)
    canon_map, legacy_sections = _legacy_to_canonical_sections(
        legacy_sections, lang=lang, domain=domain, backend=backend)
    canon_hash = compute_canonical_hash(canon_map)
    legacy_sections = _scrub_legacy_sections_arabic(legacy_sections, lang)
    blockers = list(legacy_artifact.get('blocking_errors') or [])
    quality = validate_canonical_quality(
        canon_map,
        legacy_sections=legacy_sections,
        domain=domain,
        lang=lang,
    )
    blockers.extend(quality.get('blocking_errors') or [])
    rel2 = ((legacy_artifact.get('diagnostics') or {}).get('rel2') or {})
    rel28 = rel2.get('rel28') or {}
    release_ready = bool(
        rel28.get('finalize_route', {}).get('export_return_allowed')
        if rel28 else not blockers)
    if blockers:
        release_ready = False
    aid = _artifact_id_from({**legacy_artifact, 'strategy_id': strategy_id})
    legacy_join = '\n\n'.join(
        str(v).strip()
        for k, v in legacy_sections.items()
        if isinstance(v, str) and v.strip() and not str(k).startswith('_'))
    md_view = legacy_join or strategy_document_to_markdown(
        build_strategy_document(legacy_sections))
    artifact = FinalDocumentArtifact(
        artifact_id=aid,
        strategy_id=strategy_id or aid,
        domain=str(domain).lower(),
        language='ar' if str(lang).lower().startswith('ar') else 'en',
        document_type='strategy',
        strategy_type=str(
            meta.get('doc_subtype') or legacy_artifact.get('strategy_type')
            or 'technical'),
        selected_frameworks=fws,
        canonical_sections=canon_map,
        quality_repairs=list(legacy_artifact.get('repair_actions') or []),
        quality_results=quality,
        frozen=bool(freeze and not blockers),
        canonical_hash=canon_hash,
        render_tree_hash='',
        export_manifest=ExportManifest(canonical_hash=canon_hash),
        blocking_errors=list(dict.fromkeys(blockers)),
        release_ready_final_passed=release_ready and not blockers,
        legacy_sections=legacy_sections,
        final_markdown_view=md_view,
    )
    return artifact


def freeze_artifact(artifact: FinalDocumentArtifact) -> FinalDocumentArtifact:
    if artifact.frozen:
        return artifact
    if artifact.blocking_errors:
        artifact.frozen = False
        return artifact
    artifact.frozen = True
    _ARTIFACT_REGISTRY[artifact.artifact_id] = artifact
    if artifact.strategy_id and artifact.strategy_id != artifact.artifact_id:
        _ARTIFACT_REGISTRY[artifact.strategy_id] = artifact
    return artifact


def get_frozen_artifact(
        artifact_or_id: Any,
        *,
        backend: Optional[Dict[str, Any]] = None) -> FinalDocumentArtifact:
    """Resolve frozen artifact by id or dict."""
    if isinstance(artifact_or_id, FinalDocumentArtifact):
        if not artifact_or_id.frozen:
            return freeze_artifact(artifact_or_id)
        return artifact_or_id
    if isinstance(artifact_or_id, dict):
        if artifact_or_id.get('_rel32_persisted_frozen'):
            from release_engine_v3.rel32_frozen_artifact_persist import (
                rehydrate_frozen_from_persisted_dict,
            )
            return rehydrate_frozen_from_persisted_dict(artifact_or_id)
        sealed = bool(artifact_or_id.get('sealed'))
        art = build_final_document_artifact(
            artifact_or_id,
            freeze=sealed,
            strategy_id=str(artifact_or_id.get('strategy_id') or ''),
        )
        if sealed and not art.blocking_errors:
            return freeze_artifact(art)
        if art.frozen:
            return art
        return freeze_artifact(art) if not art.blocking_errors else art
    key = str(artifact_or_id or '')
    if key in _ARTIFACT_REGISTRY:
        return _ARTIFACT_REGISTRY[key]
    if backend and backend.get('load_artifact'):
        loaded = backend['load_artifact'](key)
        if isinstance(loaded, dict):
            return get_frozen_artifact(loaded, backend=backend)
    raise KeyError(f'rel3_frozen_artifact_not_found:{key}')


def guard_post_seal_mutation(
        artifact: FinalDocumentArtifact,
        section_key: str,
        *,
        operation: str = 'mutate') -> Optional[str]:
    if not artifact.frozen:
        return None
    return f'rel3_post_seal_mutation_blocked:{section_key}:{operation}'


def store_artifact(artifact: FinalDocumentArtifact) -> None:
    _ARTIFACT_REGISTRY[artifact.artifact_id] = artifact
    if artifact.strategy_id:
        _ARTIFACT_REGISTRY[artifact.strategy_id] = artifact


def clear_artifact_registry() -> None:
    _ARTIFACT_REGISTRY.clear()
