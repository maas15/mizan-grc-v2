"""REL3.3 — DOCX export authority diagnostic (no bypass, frozen/sections authority)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def evaluate_rel33_docx_export_authority(
        *,
        route: str,
        domain: str,
        document_type: str,
        artifact_id: str,
        build_docx_bytes_called: bool,
        called_from_authorized_export_pipeline: bool,
        frozen_artifact_loaded: bool,
        sections_json_loaded: bool,
        export_authority: str,
        blocking_errors: Optional[List[str]] = None,
        bypass_blocker: Optional[str] = None,
) -> Dict[str, Any]:
    """Build [REL33-DOCX-EXPORT-AUTHORITY-CHECK] payload."""
    blockers = list(blocking_errors or [])
    if bypass_blocker:
        blockers.append(str(bypass_blocker))
    bypass_detected = bool(bypass_blocker) or (
        build_docx_bytes_called and not called_from_authorized_export_pipeline)
    if bypass_detected and not any(
            'rel32_docx_export_bypass_detected' in str(b) for b in blockers):
        blockers.append('rel32_docx_export_bypass_detected:_build_docx_bytes')
    passed = not bypass_detected and not blockers
    return {
        'route': route or 'docx',
        'domain': domain or '',
        'document_type': document_type or 'strategy',
        'artifact_id': str(artifact_id or ''),
        'build_docx_bytes_called': bool(build_docx_bytes_called),
        'called_from_authorized_export_pipeline': bool(
            called_from_authorized_export_pipeline),
        'frozen_artifact_loaded': bool(frozen_artifact_loaded),
        'sections_json_loaded': bool(sections_json_loaded),
        'export_authority': export_authority or '',
        'bypass_detected': bypass_detected,
        'docx_export_authority_passed': passed,
        'blocking_errors': list(dict.fromkeys(blockers)),
    }


def emit_rel33_docx_export_authority_check(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-DOCX-EXPORT-AUTHORITY-CHECK] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
