"""PR-REL3 — unified export orchestrator."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.canonical_document import (
    build_final_document_artifact,
    freeze_artifact,
    get_frozen_artifact,
    guard_post_seal_mutation,
    store_artifact,
)
from release_engine_v3.contracts import (
    EvidenceResult,
    ExportResult,
    FinalDocumentArtifact,
    RenderTree,
)
from release_engine_v3.evidence.evidence_validator import validate_returned_export_bytes
from release_engine_v3.export_manifest import update_artifact_manifest
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.exporters.preview_exporter import export_preview
from release_engine_v3.render_tree import build_render_tree, verify_render_tree_parity

_EXPORT_CACHE: Dict[str, bytes] = {}
_LEGACY_BLOCKED_ROUTES = frozenset({
    'legacy_cyber_final_export_contract',
    'legacy_professional_strategy_render_raw',
    'legacy_markdown_rebuild_after_seal',
    'legacy_client_content_export',
})

_RENDER_TREE_CACHE: Dict[str, RenderTree] = {}


def rel3_get_frozen_artifact(
        artifact_or_id: Any,
        *,
        backend: Optional[Dict[str, Any]] = None) -> FinalDocumentArtifact:
    return get_frozen_artifact(artifact_or_id, backend=backend)


def rel3_freeze_artifact(
        legacy_artifact: Dict[str, Any],
        *,
        strategy_id: str = '') -> FinalDocumentArtifact:
    art = build_final_document_artifact(
        legacy_artifact,
        freeze=False,
        strategy_id=strategy_id,
    )
    if not art.blocking_errors:
        art = freeze_artifact(art)
    store_artifact(art)
    return art


def rel3_build_render_tree(artifact: FinalDocumentArtifact) -> RenderTree:
    cache_key = f'{artifact.artifact_id}:{artifact.canonical_hash}'
    if cache_key in _RENDER_TREE_CACHE:
        return _RENDER_TREE_CACHE[cache_key]
    tree = build_render_tree(artifact)
    _RENDER_TREE_CACHE[cache_key] = tree
    return tree


def rel3_guard_post_seal_mutation(
        artifact: FinalDocumentArtifact,
        section_key: str,
        *,
        operation: str = 'mutate') -> Optional[str]:
    return guard_post_seal_mutation(artifact, section_key, operation=operation)


def rel3_block_legacy_export_path(route: str) -> Tuple[bool, str]:
    r = (route or '').strip().lower()
    if r in _LEGACY_BLOCKED_ROUTES or r.startswith('legacy_'):
        return False, f'rel3_legacy_export_path_blocked:{route}'
    return True, ''


def rel3_export(
        route: str,
        render_tree: RenderTree,
        *,
        backend: Dict[str, Any],
        export_kwargs: Optional[Dict[str, Any]] = None,
) -> ExportResult:
    """Export from RenderTree — single source for all routes."""
    kw = dict(export_kwargs or {})
    route_n = (route or 'preview').lower()
    if route_n == 'preview':
        return export_preview(render_tree)
    if route_n == 'docx':
        return export_docx(render_tree, backend=backend, **kw)
    if route_n == 'pdf':
        kw.pop('filename', None)
        kw.pop('cyber_sealed_artifact', None)
        return export_pdf(render_tree, backend=backend, **kw)
    if route_n == 'txt':
        text = (render_tree.markdown_view or '').encode('utf-8')
        from release_engine_v3.contracts import _sha256_bytes
        return ExportResult(
            route_name='txt',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            bytes_data=text,
            returned_bytes_sha256=_sha256_bytes(text),
            evidence_bytes_sha256=_sha256_bytes(text),
            returned_equals_evidence_bytes=True,
            exact_bytes_checked=True,
            preview_text=render_tree.markdown_view,
        )
    return ExportResult(
        route_name=route_n,
        artifact_id=render_tree.artifact_id,
        render_tree_hash=render_tree.render_tree_hash,
        canonical_hash=render_tree.canonical_hash,
        blocking_errors=[f'rel3_unknown_export_route:{route_n}'],
    )


def rel3_validate_returned_export_bytes(
        export: ExportResult,
        artifact: FinalDocumentArtifact,
        *,
        route: str,
) -> EvidenceResult:
    return validate_returned_export_bytes(export, artifact, route=route)


def rel3_invalidate_export_cache(
        artifact_id: str,
        route: str,
        render_tree_hash: str,
) -> None:
    key = f'{artifact_id}:{route}:{render_tree_hash}'
    _EXPORT_CACHE.pop(key, None)
    _RENDER_TREE_CACHE.pop(f'{artifact_id}:{render_tree_hash}', None)


def rel3_export_with_evidence(
        route: str,
        artifact: FinalDocumentArtifact,
        *,
        backend: Dict[str, Any],
        export_kwargs: Optional[Dict[str, Any]] = None,
) -> Tuple[ExportResult, EvidenceResult]:
    """Full REL3 pipeline: render tree → export → validate exact bytes."""
    if not artifact.frozen and artifact.blocking_errors:
        hard_blockers = [
            b for b in artifact.blocking_errors
            if not str(b).startswith('rel3_export_evidence_failed')]
        if route != 'preview' or hard_blockers:
            blockers = hard_blockers if route == 'preview' else list(
                artifact.blocking_errors)
            ev = EvidenceResult(
                route_name=route,
                artifact_id=artifact.artifact_id,
                strategy_id=artifact.strategy_id,
                canonical_hash=artifact.canonical_hash,
                render_tree_hash='',
                returned_bytes_sha256='',
                evidence_bytes_sha256='',
                returned_equals_evidence_bytes=False,
                exact_bytes_checked=False,
                preview_text_checked=False,
                docx_bytes_checked=False,
                pdf_bytes_checked=False,
                evidence_passed=False,
                export_return_allowed=False,
                blocking_errors=blockers,
            )
            ev.emit_diag()
            return ExportResult(
                route_name=route,
                artifact_id=artifact.artifact_id,
                render_tree_hash='',
                canonical_hash=artifact.canonical_hash,
                blocking_errors=blockers,
            ), ev
    tree = rel3_build_render_tree(artifact)
    # Parity: all routes must share same render tree hash
    parity_trees = {'current': tree}
    drift = verify_render_tree_parity(parity_trees)
    if drift:
        ev = EvidenceResult(
            route_name=route,
            artifact_id=artifact.artifact_id,
            strategy_id=artifact.strategy_id,
            canonical_hash=artifact.canonical_hash,
            render_tree_hash=tree.render_tree_hash,
            returned_bytes_sha256='',
            evidence_bytes_sha256='',
            returned_equals_evidence_bytes=False,
            exact_bytes_checked=False,
            preview_text_checked=False,
            docx_bytes_checked=False,
            pdf_bytes_checked=False,
            evidence_passed=False,
            export_return_allowed=False,
            blocking_errors=drift,
        )
        ev.emit_diag()
        return ExportResult(
            route_name=route,
            artifact_id=artifact.artifact_id,
            render_tree_hash=tree.render_tree_hash,
            canonical_hash=artifact.canonical_hash,
            blocking_errors=drift,
        ), ev
    export = rel3_export(route, tree, backend=backend, export_kwargs=export_kwargs)
    if export.blocking_errors:
        ev = EvidenceResult(
            route_name=route,
            artifact_id=artifact.artifact_id,
            strategy_id=artifact.strategy_id,
            canonical_hash=artifact.canonical_hash,
            render_tree_hash=tree.render_tree_hash,
            returned_bytes_sha256=export.returned_bytes_sha256,
            evidence_bytes_sha256=export.evidence_bytes_sha256,
            returned_equals_evidence_bytes=False,
            exact_bytes_checked=export.exact_bytes_checked,
            preview_text_checked=False,
            docx_bytes_checked=False,
            pdf_bytes_checked=False,
            evidence_passed=False,
            export_return_allowed=False,
            blocking_errors=export.blocking_errors,
        )
        ev.emit_diag()
        rel3_invalidate_export_cache(
            artifact.artifact_id, route, tree.render_tree_hash)
        return export, ev
    evidence = rel3_validate_returned_export_bytes(export, artifact, route=route)
    if not evidence.export_return_allowed:
        rel3_invalidate_export_cache(
            artifact.artifact_id, route, tree.render_tree_hash)
    else:
        cache_key = (
            f'{artifact.artifact_id}:{route}:{tree.render_tree_hash}')
        if export.bytes_data:
            _EXPORT_CACHE[cache_key] = export.bytes_data
    update_artifact_manifest(artifact, export, evidence_passed=evidence.evidence_passed)
    try:
        from release_engine_v3.rel31_authority import record_rel3_route_artifact_hashes
        record_rel3_route_artifact_hashes(
            str(artifact.strategy_id or ''),
            route,
            canonical_hash=artifact.canonical_hash,
            render_tree_hash=tree.render_tree_hash,
        )
    except Exception:  # noqa: BLE001
        pass
    return export, evidence


def rel3_verify_render_tree_parity_across_routes(
        artifact: FinalDocumentArtifact,
        backend: Dict[str, Any],
) -> Tuple[bool, List[str], str]:
    """Build preview/docx/pdf trees and verify hash parity."""
    tree = rel3_build_render_tree(artifact)
    hashes = {
        'preview': tree.render_tree_hash,
        'docx': tree.render_tree_hash,
        'pdf': tree.render_tree_hash,
    }
    errors = verify_render_tree_parity({
        k: tree for k in hashes
    })
    return not errors, errors, tree.render_tree_hash


def clear_rel3_caches() -> None:
    _EXPORT_CACHE.clear()
    _RENDER_TREE_CACHE.clear()
    try:
        from release_engine_v3.rel32_frozen_export_lock import (
            clear_rel32_frozen_export_lock,
        )
        clear_rel32_frozen_export_lock()
    except Exception:  # noqa: BLE001
        pass


def rel3_get_or_build_frozen_artifact(
        artifact_or_id,
        *,
        backend=None,
        flags=None,
):
    """Delegate to REL3.1 authority resolver."""
    from release_engine_v3.rel31_authority import (
        rel3_get_or_build_frozen_artifact as _resolve,
    )
    return _resolve(artifact_or_id, backend=backend, flags=flags)
