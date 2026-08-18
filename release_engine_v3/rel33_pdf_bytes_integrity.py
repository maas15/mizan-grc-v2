"""REL3.3 — PDF returned-bytes integrity diagnostic.

Surfaces why PDF export returned empty bytes instead of silently collapsing
quality-gate / render failures into ``empty_bytes``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional


def emit_rel33_pdf_bytes_integrity(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-PDF-BYTES-INTEGRITY] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def build_rel33_pdf_bytes_integrity(
        *,
        route: str = 'pdf',
        domain: str = '',
        document_type: str = 'strategy',
        artifact_id: Any = None,
        pdf_renderer: str = 'build_pdf_bytes',
        pdf_bytes: bytes = b'',
        content_type: str = 'application/pdf',
        render_exception: Optional[str] = None,
        table_lock_applied: bool = False,
        kpi_main_forced_table: bool = False,
        used_cards_fallback: bool = False,
        returned_file_evidence_started: bool = False,
        extra_blockers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    raw = pdf_bytes or b''
    length = len(raw)
    sha = hashlib.sha256(raw).hexdigest() if length else ''
    blockers: List[str] = list(extra_blockers or [])
    if render_exception:
        blockers.append(f'render_exception:{render_exception}')
    if length <= 0 and not any('empty_bytes' in b for b in blockers):
        blockers.append('rel3_export_evidence_failed:pdf:empty_bytes')
    passed = length > 0 and render_exception is None and not blockers
    diag = {
        'route': route,
        'domain': domain,
        'document_type': document_type,
        'artifact_id': artifact_id,
        'pdf_renderer': pdf_renderer,
        'pdf_bytes_len': length,
        'pdf_bytes_sha256': sha,
        'content_type': content_type,
        'render_exception': render_exception,
        'table_lock_applied': table_lock_applied,
        'kpi_main_forced_table': kpi_main_forced_table,
        'used_cards_fallback': used_cards_fallback,
        'returned_file_evidence_started': returned_file_evidence_started,
        'pdf_bytes_integrity_passed': passed,
        'blocking_errors': blockers,
    }
    emit_rel33_pdf_bytes_integrity(diag)
    return diag
