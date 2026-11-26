"""Render native Arabic governance sections through the source table layout.

The reused layout function is pure rendering: no saved-record identity,
ownership or saved-strategy authority is asserted by this route. The native
governance contract owns validation, and returned-file evidence remains
mandatory at the authoritative export boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from domains._registry import get_domain_pack
from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel33_governance_artifact import (
    governance_model_blockers,
    governance_model_markdown,
)


def render_governance_pdf(
        content: str,
        *,
        sections: Mapping[str, Any],
        metadata: Mapping[str, Any] | None,
        domain: str,
        lang: str,
        font: str,
) -> bytes:
    """Paint the exact four-section Arabic source with its original tables."""
    if str(lang or '').strip().lower() != 'ar':
        raise ValueError('rel33_governance_pdf_language_unsupported')
    code = normalize_domain_code(domain, default='')
    pack = get_domain_pack(code)
    if not pack or not pack.get('display_ar'):
        raise ValueError('rel33_governance_pdf_domain_unsupported')
    blockers = governance_model_blockers(sections)
    if blockers:
        raise ValueError(blockers[0])
    source = governance_model_markdown(sections)
    if content != source:
        raise ValueError('rel33_governance_pdf_source_mismatch')

    meta = metadata if isinstance(metadata, Mapping) else {}
    cover = {
        'document_title': str(meta.get('document_title') or 'نموذج الحوكمة'),
        'org_name': str(meta.get('org_name') or '—'),
        'domain_display': str(pack['display_ar']),
        'document_type_label': 'نموذج الحوكمة',
        'sector': str(meta.get('sector') or '—'),
        'artifact_status': str(meta.get('artifact_status') or '—'),
    }
    # This renderer uses the source headings and table schemas dynamically.
    # Pagination follows the actual content; there is no strategy section
    # order, invented table header or predetermined page count here.
    from release_engine_v3.exporters.saved_strategy_pdf import render_saved_pdf
    from release_engine_v3.exporters.saved_pdf_verification import verify_saved_pdf
    data = render_saved_pdf(source, cover, font)
    verify_saved_pdf(data, source, cover=cover)
    return data
