"""PR-REL3 — pre-freeze repair pipeline (never after seal)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from release_engine.rendered_evidence_validator import repair_sections_for_rendered_evidence
from release_engine_v3.canonical_document import guard_post_seal_mutation
from release_engine_v3.contracts import FinalDocumentArtifact


def apply_repair_pipeline(
        artifact: FinalDocumentArtifact,
        *,
        backend: Dict[str, Any],
        max_attempts: int = 2,
) -> Tuple[FinalDocumentArtifact, List[str]]:
    """Repair canonical content only before freeze."""
    if artifact.frozen:
        blocker = guard_post_seal_mutation(artifact, 'all', operation='repair')
        if blocker:
            artifact.blocking_errors.append(blocker)
        return artifact, []
    repairs: List[str] = []
    legacy = dict(artifact.legacy_sections)
    for attempt in range(max_attempts):
        repaired, actions = repair_sections_for_rendered_evidence(
            legacy,
            domain=artifact.domain,
            lang=artifact.language,
            backend=backend,
        )
        if actions:
            repairs.extend(actions)
            legacy = repaired
            artifact.legacy_sections = legacy
        else:
            break
    return artifact, repairs
