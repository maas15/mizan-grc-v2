"""PR-REL3 — export manifest tracking per route."""

from __future__ import annotations

from typing import Any, Dict

from release_engine_v3.contracts import ExportManifest, ExportResult, FinalDocumentArtifact


def record_export(
        manifest: ExportManifest,
        result: ExportResult,
        *,
        evidence_passed: bool,
) -> ExportManifest:
    manifest.render_tree_hash = result.render_tree_hash
    manifest.canonical_hash = result.canonical_hash
    manifest.routes[result.route_name] = {
        'returned_bytes_sha256': result.returned_bytes_sha256,
        'evidence_bytes_sha256': result.evidence_bytes_sha256,
        'returned_equals_evidence_bytes': result.returned_equals_evidence_bytes,
        'exact_bytes_checked': result.exact_bytes_checked,
        'evidence_passed': evidence_passed,
        'render_tree_hash': result.render_tree_hash,
    }
    return manifest


def update_artifact_manifest(
        artifact: FinalDocumentArtifact,
        result: ExportResult,
        *,
        evidence_passed: bool,
) -> None:
    record_export(artifact.export_manifest, result, evidence_passed=evidence_passed)
