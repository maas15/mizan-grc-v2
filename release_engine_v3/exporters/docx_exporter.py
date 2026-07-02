"""PR-REL3 — DOCX export from RenderTree only."""

from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Optional

from release_engine_v3.contracts import ExportResult, RenderTree, _sha256_bytes


def _filter_build_kwargs(build_fn: Callable[..., Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    try:
        sig = inspect.signature(build_fn)
    except (TypeError, ValueError):
        return kwargs
    if any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()):
        return kwargs
    return {k: v for k, v in kwargs.items() if k in sig.parameters}


def export_docx(
        render_tree: RenderTree,
        *,
        backend: Dict[str, Any],
        filename: str = 'strategy.docx',
        lang: str = 'ar',
        org_name: str = '',
        sector: str = '',
        doc_type: str = 'Strategy Document',
        domain: str = 'cyber',
        selected_frameworks=None,
        cyber_sealed_artifact: bool = False,
        frozen_artifact=None,
        artifact_dict: Optional[Dict[str, Any]] = None,
) -> ExportResult:
    """Build DOCX bytes from RenderTree markdown view — never raw client markdown."""
    build_fn = backend.get('build_docx_bytes')
    if not build_fn:
        return ExportResult(
            route_name='docx',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            blocking_errors=['rel3_export_failed:docx:build_docx_bytes_missing'],
        )

    content = render_tree.markdown_view or ''
    sec_map: Dict[str, str] = {}
    renderer_meta: Dict[str, Any] = {}

    if backend.get('_rel32_frozen_export_lock_active') and frozen_artifact is not None:
        from release_engine_v3.rel32_docx_renderer import (
            bind_rel32_docx_renderer_input,
            emit_rel32_docx_renderer_diag,
        )
        content, sec_map, renderer_meta = bind_rel32_docx_renderer_input(
            frozen_artifact,
            render_tree,
            backend=backend,
            artifact_dict=artifact_dict,
        )
        emit_rel32_docx_renderer_diag(renderer_meta)
        if renderer_meta.get('blocking_errors'):
            blockers = list(renderer_meta['blocking_errors'])
            return ExportResult(
                route_name='docx',
                artifact_id=render_tree.artifact_id,
                render_tree_hash=render_tree.render_tree_hash,
                canonical_hash=render_tree.canonical_hash,
                blocking_errors=blockers,
            )
    elif backend.get('_rel32_frozen_export_lock_active'):
        frozen_secs = backend.get('_rel31_frozen_sections') or {}
        if frozen_secs:
            sec_map = {
                k: v for k, v in dict(frozen_secs).items()
                if isinstance(v, str) and not str(k).startswith('_')}
        else:
            sections = backend.get('split_sections')
            sec_map = sections(content) if sections else {}
        content = render_tree.markdown_view or content
    else:
        sections = backend.get('split_sections')
        sec_map = sections(content) if sections else {}

    try:
        docx_bytes = build_fn(
            content,
            filename,
            lang,
            **_filter_build_kwargs(build_fn, {
                'org_name': org_name,
                'sector': sector,
                'doc_type': doc_type,
                'domain': domain,
                'selected_frameworks': selected_frameworks,
                'cyber_sealed_artifact': cyber_sealed_artifact,
                'sections': sec_map,
            }),
        )
    except ValueError as exc:
        from release_engine_v3.rel31_authority import normalize_rel3_export_blockers
        blockers = normalize_rel3_export_blockers([str(exc)], route='docx')
        return ExportResult(
            route_name='docx',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            blocking_errors=blockers or [str(exc)],
        )
    if not isinstance(docx_bytes, bytes):
        docx_bytes = bytes(docx_bytes or b'')
    sha = _sha256_bytes(docx_bytes)
    return ExportResult(
        route_name='docx',
        artifact_id=render_tree.artifact_id,
        render_tree_hash=render_tree.render_tree_hash,
        canonical_hash=render_tree.canonical_hash,
        bytes_data=docx_bytes,
        docx_bytes=docx_bytes,
        returned_bytes_sha256=sha,
        evidence_bytes_sha256=sha,
        returned_equals_evidence_bytes=True,
        exact_bytes_checked=True,
    )
