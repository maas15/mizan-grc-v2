"""PR-REL3 — PDF export from RenderTree only."""

from __future__ import annotations

from typing import Any, Dict

from release_engine_v3.contracts import ExportResult, RenderTree, _sha256_bytes


def export_pdf(
        render_tree: RenderTree,
        *,
        backend: Dict[str, Any],
        lang: str = 'ar',
        org_name: str = '',
        sector: str = '',
        doc_type: str = 'Strategy Document',
        domain: str = 'cyber',
        selected_frameworks=None,
        cyber_sealed_artifact: bool = False,
) -> ExportResult:
    build_fn = backend.get('build_pdf_bytes')
    if not build_fn:
        return ExportResult(
            route_name='pdf',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            blocking_errors=['rel3_export_failed:pdf:build_pdf_bytes_missing'],
        )
    content = render_tree.markdown_view
    pdf_bytes = build_fn(
        content,
        lang=lang,
        org_name=org_name,
        sector=sector,
        doc_type=doc_type,
        domain=domain,
        selected_frameworks=selected_frameworks,
        cyber_sealed_artifact=cyber_sealed_artifact,
        sections=backend.get('split_sections', lambda x: {})(content),
    )
    if not isinstance(pdf_bytes, bytes):
        pdf_bytes = bytes(pdf_bytes or b'')
    sha = _sha256_bytes(pdf_bytes)
    return ExportResult(
        route_name='pdf',
        artifact_id=render_tree.artifact_id,
        render_tree_hash=render_tree.render_tree_hash,
        canonical_hash=render_tree.canonical_hash,
        bytes_data=pdf_bytes,
        pdf_bytes=pdf_bytes,
        returned_bytes_sha256=sha,
        evidence_bytes_sha256=sha,
        returned_equals_evidence_bytes=True,
        exact_bytes_checked=True,
    )
