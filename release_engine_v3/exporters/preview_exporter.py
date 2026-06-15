"""PR-REL3 — preview export from RenderTree only."""

from __future__ import annotations

from release_engine_v3.contracts import ExportResult, RenderTree, _sha256_text


def export_preview(render_tree: RenderTree) -> ExportResult:
    preview_html = render_tree.preview_html or ''
    preview_text = render_tree.markdown_view or ''
    return ExportResult(
        route_name='preview',
        artifact_id=render_tree.artifact_id,
        render_tree_hash=render_tree.render_tree_hash,
        canonical_hash=render_tree.canonical_hash,
        preview_html=preview_html,
        preview_text=preview_text,
        returned_bytes_sha256=_sha256_text(preview_text),
        evidence_bytes_sha256=_sha256_text(preview_text),
        returned_equals_evidence_bytes=True,
        exact_bytes_checked=False,
    )
