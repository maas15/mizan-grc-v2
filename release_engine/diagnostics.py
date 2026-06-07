"""PR-REL2 structured diagnostics."""

from __future__ import annotations

import json
from typing import Any, Dict


def emit_rel2_diag(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[RELEASE-ENGINE-REL2] '
            f'{json.dumps(payload, ensure_ascii=False, default=str)}',
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def build_rel2_diag(
        *,
        domain: str,
        lang: str,
        document_type: str,
        phase: str,
        scoring: Dict[str, Any],
        sealed: bool,
        release_ready: bool,
        repair_actions: list,
        blocking: list,
        export_parity_ok: bool,
) -> Dict[str, Any]:
    return {
        'domain': domain,
        'lang': lang,
        'document_type': document_type,
        'phase': phase,
        'total_score': scoring.get('total_score'),
        'failed_dimensions': scoring.get('failed_dimensions'),
        'sealed': sealed,
        'release_ready_final_passed': release_ready,
        'repair_actions': repair_actions[:10],
        'blocking_errors': blocking[:8],
        'export_hash_parity': export_parity_ok,
        'global_scan_disabled': True,
        'patch_cycle_frozen': True,
    }
