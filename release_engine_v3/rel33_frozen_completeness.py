"""REL3.3 — document-type-aware frozen export completeness."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.contracts import FinalDocumentArtifact
from release_engine_v3.rel33_risk_treatment_evidence import (
    count_treatment_rows_from_sections,
)

STRATEGY_REQUIRED = (
    'canonical_hash',
    'render_tree_hash',
    'canonical_traceability_rows',
    'canonical_gap_rows',
    'canonical_sections',
)

RISK_REQUIRED = (
    'canonical_hash',
    'render_tree_hash',
    'risk_register_rows',
    'treatment_rows',
    'owner_severity_evidence',
)

GAP_REQUIRED = (
    'canonical_hash',
    'render_tree_hash',
    'scope',
    'gap_rows',
    'remediation_rows',
    'framework_mapping',
)


def emit_rel33_frozen_completeness_by_document_type(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-FROZEN-COMPLETENESS-BY-DOCUMENT-TYPE] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _count_table_rows(text: str, min_cols: int = 2) -> int:
    count = 0
    for ln in (text or '').splitlines():
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if len(cells) >= min_cols and cells[0] and not cells[0].startswith('#'):
            count += 1
    return count


def _has_hash(value: Any) -> bool:
    return bool(str(value or '').strip())


def evaluate_gap_assessment_sections_complete(
        sections: Dict[str, Any],
        *,
        final_hash: str = '',
) -> Tuple[bool, List[str], List[str]]:
    """Return (complete, present_components, missing_components)."""
    secs = dict(sections or {})
    present: List[str] = []
    missing: List[str] = []
    if (secs.get('scope') or '').strip():
        present.append('scope')
    else:
        missing.append('scope')
    gaps_blob = secs.get('gaps') or ''
    gap_rows = _count_table_rows(gaps_blob)
    if gap_rows >= 1:
        present.append('gap_rows')
    else:
        missing.append('gap_rows')
    rem_blob = (
        secs.get('remediation')
        or secs.get('recommendations')
        or secs.get('guides')
        or '')
    rem_rows = _count_table_rows(rem_blob)
    if rem_rows < 1 and rem_blob.strip():
        rem_rows = max(1, len([
            ln for ln in rem_blob.splitlines()
            if ln.strip() and not ln.strip().startswith('#')]))
    if rem_rows >= 1:
        present.append('remediation_rows')
    else:
        missing.append('remediation_rows')
    fw_hits = re.findall(
        r'ISO|NIST|ECC|DCC|CSF|27001|إطار|framework',
        gaps_blob + '\n' + (secs.get('scope') or ''),
        re.I,
    )
    if fw_hits:
        present.append('framework_mapping')
    else:
        missing.append('framework_mapping')
    if final_hash:
        if _has_hash(final_hash):
            present.append('canonical_hash')
        else:
            missing.append('canonical_hash')
    return (not missing, present, missing)


def evaluate_risk_sections_complete(
        sections: Dict[str, Any],
        *,
        final_hash: str = '',
) -> Tuple[bool, List[str], List[str]]:
    secs = dict(sections or {})
    present: List[str] = []
    missing: List[str] = []
    register = (
        secs.get('register')
        or secs.get('risk_register')
        or secs.get('confidence')
        or '')
    risk_n, treat_n = count_treatment_rows_from_sections(secs)
    if register.strip() or risk_n > 0:
        present.append('risk_register_rows')
    else:
        missing.append('risk_register_rows')
    if treat_n > 0:
        present.append('treatment_rows')
    else:
        missing.append('treatment_rows')
    blob = '\n'.join(str(v) for v in secs.values() if v)
    if re.search(r'مالك|owner|severity|شدة|احتمال|evidence|دليل', blob, re.I):
        present.append('owner_severity_evidence')
    else:
        missing.append('owner_severity_evidence')
    if final_hash:
        if _has_hash(final_hash):
            present.append('canonical_hash')
            present.append('render_tree_hash')
        else:
            missing.append('canonical_hash')
            missing.append('render_tree_hash')
    return (not missing, present, missing)


def evaluate_strategy_frozen_complete(
        frozen: FinalDocumentArtifact,
) -> Tuple[bool, List[str], List[str]]:
    """Cyber/strategy frozen artifact completeness (REL3.2 lock)."""
    missing: List[str] = []
    present: List[str] = []
    canon_hash = str(frozen.canonical_hash or frozen.export_manifest.canonical_hash or '').strip()
    tree_hash = str(frozen.render_tree_hash or frozen.export_manifest.render_tree_hash or '').strip()
    if canon_hash:
        present.append('canonical_hash')
    else:
        missing.append('canonical_hash')
    if tree_hash:
        present.append('render_tree_hash')
    else:
        missing.append('render_tree_hash')
    legacy = dict(frozen.legacy_sections or {})
    if str(legacy.get('traceability') or '').strip():
        present.append('canonical_traceability_rows')
    else:
        missing.append('canonical_traceability_rows')
    if str(legacy.get('gaps') or '').strip():
        present.append('canonical_gap_rows')
    else:
        missing.append('canonical_gap_rows')
    if frozen.canonical_sections:
        present.append('canonical_sections')
    else:
        missing.append('canonical_sections')
    return (not missing, present, missing)


def evaluate_persisted_blob_complete(
        blob: Optional[Dict[str, Any]],
        *,
        document_type: str = 'strategy',
) -> Tuple[bool, List[str], List[str]]:
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype == 'strategy':
        from release_engine_v3.rel32_frozen_artifact_persist import (
            missing_frozen_components,
        )
        missing = missing_frozen_components(blob or {})
        required = list(STRATEGY_REQUIRED)
        present = [c for c in required if c not in missing]
        return (not missing, present, missing)
    art = dict((blob or {}).get('artifact') or blob or {})
    legacy = dict(art.get('legacy_sections') or {})
    canon = str(
        (blob or {}).get('rel3_canonical_hash')
        or art.get('canonical_hash') or '').strip()
    tree = str(
        (blob or {}).get('rel3_render_tree_hash')
        or art.get('render_tree_hash') or '').strip()
    if dtype == 'gap_assessment':
        return evaluate_gap_assessment_sections_complete(
            legacy, final_hash=canon or tree)
    if dtype in ('risk', 'risk_assessment'):
        return evaluate_risk_sections_complete(legacy, final_hash=canon or tree)
    return True, [], []


def evaluate_frozen_completeness_by_document_type(
        *,
        document_type: str,
        artifact_type: str = '',
        artifact_id: str = '',
        frozen: Optional[FinalDocumentArtifact] = None,
        sections: Optional[Dict[str, Any]] = None,
        persisted_blob: Optional[Dict[str, Any]] = None,
        loaded_from: str = 'none',
        final_hash: str = '',
) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
    dtype = str(document_type or artifact_type or 'strategy').strip().lower()
    atype = str(artifact_type or dtype or 'strategy').strip().lower()
    complete = False
    present: List[str] = []
    missing: List[str] = []
    blocking: List[str] = []

    if frozen is not None and dtype == 'strategy':
        complete, present, missing = evaluate_strategy_frozen_complete(frozen)
        loaded_from = loaded_from or 'frozen_artifact'
    elif persisted_blob is not None:
        complete, present, missing = evaluate_persisted_blob_complete(
            persisted_blob, document_type=dtype)
        loaded_from = loaded_from or 'persisted_blob'
    elif sections is not None:
        if dtype == 'gap_assessment':
            complete, present, missing = evaluate_gap_assessment_sections_complete(
                sections, final_hash=final_hash)
            loaded_from = loaded_from or 'sections_json'
        elif dtype in ('risk', 'risk_assessment'):
            complete, present, missing = evaluate_risk_sections_complete(
                sections, final_hash=final_hash)
            loaded_from = loaded_from or 'risk_sections'
        else:
            from release_engine_v3.rel33_export_artifact import (
                sections_dict_export_complete,
            )
            if sections_dict_export_complete(sections):
                present = ['strategy_sections']
                missing = []
                complete = True
            else:
                missing = ['strategy_sections_incomplete']
                complete = False
            loaded_from = loaded_from or 'sections_json'
    else:
        missing = ['no_artifact_source']
        blocking = ['no_artifact_source']

    if missing:
        blocking = [f'missing:{m}' for m in missing]

    diag: Dict[str, Any] = {
        'document_type': dtype,
        'artifact_type': atype,
        'artifact_id': str(artifact_id or ''),
        'required_components': list(
            STRATEGY_REQUIRED if dtype == 'strategy'
            else GAP_REQUIRED if dtype == 'gap_assessment'
            else RISK_REQUIRED if dtype in ('risk', 'risk_assessment')
            else ['strategy_sections']),
        'present_components': present,
        'missing_components': missing,
        'complete_for_document_type': complete,
        'loaded_from': loaded_from,
        'blocking_errors': blocking,
    }
    emit_rel33_frozen_completeness_by_document_type(diag)
    return complete, present, missing, diag
