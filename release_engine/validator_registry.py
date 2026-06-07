"""PR-REL2 validator registry — delegates scoped cyber validators to REL1."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

# Re-use REL1 scoped registry and legacy classification
from release_hardening.validator_registry import (  # noqa: F401
    LEGACY_GATE_CLASSIFICATION,
    VALIDATOR_REGISTRY as REL1_VALIDATOR_REGISTRY,
    assert_no_post_sealed_blockers,
    classify_legacy_gate,
    run_scoped_validators,
)

VALIDATOR_REGISTRY: Dict[str, Dict[str, Any]] = dict(REL1_VALIDATOR_REGISTRY)

REL2_CONTENT_VALIDATORS = (
    'strategic_objectives',
    'roadmap',
    'kpi_kri',
    'confidence_risk',
    'traceability',
)

REL2_EXPORT_ONLY_VALIDATORS = (
    'pdf_render',
    'docmodel',
)


def run_rel2_validators(
        *,
        domain: str,
        lang: str,
        legacy_sections: Dict[str, str],
        backend: Dict[str, Callable[..., Any]],
        cyber_only: bool = False,
        audit_only: bool = False,
) -> Dict[str, Any]:
    return run_scoped_validators(
        domain=domain,
        lang=lang,
        legacy_sections=legacy_sections,
        backend=backend,
        cyber_only=cyber_only,
        audit_only=audit_only,
    )
