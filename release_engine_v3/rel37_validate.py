"""REL37 model validators — gates operate on CanonicalDocument, not markdown."""
from __future__ import annotations

from typing import List

from release_engine_v3.rel37_canonical_document import CanonicalDocument


def validate_model(model: CanonicalDocument) -> List[str]:
    """Return save blockers for a compiled REL37 model."""
    return list(model.validate())
