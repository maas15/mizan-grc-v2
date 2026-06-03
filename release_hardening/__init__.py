"""PR-REL1 — Unified canonical artifact engine and scoped validators."""

from release_hardening.canonical_model import (
    CANONICAL_SECTION_KEYS,
    build_canonical_artifact,
    legacy_sections_to_canonical,
)
from release_hardening.validator_registry import (
    VALIDATOR_REGISTRY,
    classify_legacy_gate,
    run_scoped_validators,
)

__all__ = [
    'CANONICAL_SECTION_KEYS',
    'VALIDATOR_REGISTRY',
    'build_canonical_artifact',
    'classify_legacy_gate',
    'legacy_sections_to_canonical',
    'run_scoped_validators',
]
