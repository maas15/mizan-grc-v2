"""PR-REL3 — Unified Document Artifact & Export Engine."""

from release_engine_v3.orchestrator import (
    rel3_block_legacy_export_path,
    rel3_build_render_tree,
    rel3_export,
    rel3_freeze_artifact,
    rel3_get_frozen_artifact,
    rel3_guard_post_seal_mutation,
    rel3_invalidate_export_cache,
    rel3_validate_returned_export_bytes,
)

__all__ = [
    'rel3_block_legacy_export_path',
    'rel3_build_render_tree',
    'rel3_export',
    'rel3_freeze_artifact',
    'rel3_get_frozen_artifact',
    'rel3_guard_post_seal_mutation',
    'rel3_invalidate_export_cache',
    'rel3_validate_returned_export_bytes',
]
