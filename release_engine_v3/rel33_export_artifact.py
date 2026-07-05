"""REL3.3 — load complete saved strategy artifacts for export (not client fragments)."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

STRATEGY_EXPORT_SECTION_KEYS = frozenset({
    'vision', 'pillars', 'environment', 'gaps', 'roadmap', 'kpis',
    'confidence', 'traceability', 'governance',
})

MIN_STRATEGY_SECTIONS_FOR_COMPLETE = 5


def sections_dict_export_complete(sections: Optional[Dict[str, Any]]) -> bool:
    """True when persisted sections_json carries enough strategy sections."""
    if not isinstance(sections, dict):
        return False
    keys = {
        k for k, v in sections.items()
        if not str(k).startswith('_') and str(v or '').strip()}
    core = STRATEGY_EXPORT_SECTION_KEYS - {'traceability', 'governance'}
    populated = keys & core
    if len(populated) < MIN_STRATEGY_SECTIONS_FOR_COMPLETE:
        return False
    if not (('vision' in keys) or ('pillars' in keys)):
        return False
    return True


def emit_rel33_export_complete_artifact_load(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-EXPORT-COMPLETE-ARTIFACT-LOAD] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def resolve_rel33_complete_export_artifact(
        *,
        artifact_type: str,
        artifact_id,
        strategy_id,
        user_id: int,
        domain: str = '',
        document_type: str = 'strategy',
        route: str = '',
        client_content: str = '',
        load_bundle: Callable[..., Dict[str, Any]],
        assemble_sections: Callable[[Dict[str, Any]], str],
        is_fragment: Callable[[str], tuple],
) -> Dict[str, Any]:
    """Load authoritative export content from DB by strategy_id."""
    from release_engine_v3.rel32_frozen_artifact_persist import (
        extract_persisted_frozen_blob,
        frozen_artifact_complete,
        rehydrate_artifact_dict_from_persisted,
    )

    diag: Dict[str, Any] = {
        'route': route,
        'domain': domain,
        'document_type': document_type,
        'strategy_id': str(strategy_id or artifact_id or ''),
        'artifact_id': str(artifact_id or ''),
        'loaded_from': 'none',
        'sections_json_loaded': False,
        'frozen_artifact_loaded': False,
        'client_content_used_as_authority': False,
        'export_fragment_checked_against': 'none',
        'complete_artifact_loaded': False,
        'canonical_hash': '',
        'render_tree_hash': '',
        'blocking_errors': [],
    }
    out: Dict[str, Any] = {
        'content': '',
        'sections': {},
        'bundle': {},
        'skip_fragment_gate': False,
        'diag': diag,
    }
    if str(artifact_type or '').lower() != 'strategy':
        diag['export_fragment_checked_against'] = 'non_strategy_artifact'
        emit_rel33_export_complete_artifact_load(diag)
        return out

    sid = strategy_id or artifact_id
    if not sid:
        diag['blocking_errors'] = ['missing_strategy_id']
        diag['export_fragment_checked_against'] = 'client_no_strategy_id'
        emit_rel33_export_complete_artifact_load(diag)
        return out

    bundle = load_bundle(sid, user_id) or {}
    out['bundle'] = bundle
    sections = dict(bundle.get('sections') or {})
    cm = dict(bundle.get('contract_meta') or {})
    _lang = cm.get('lang') or bundle.get('language') or 'ar'
    _domain = cm.get('domain') or bundle.get('domain') or domain

    persisted = extract_persisted_frozen_blob(bundle.get('content_json') or {})
    if persisted and frozen_artifact_complete(persisted):
        rehyd = rehydrate_artifact_dict_from_persisted(
            persisted,
            strategy_id=str(sid),
            contract_meta=cm,
            domain=_domain,
            lang=_lang,
        )
        sections = dict(rehyd.get('sections') or sections)
        content = (
            rehyd.get('final_markdown')
            or assemble_sections(sections)
            or '')
        diag.update({
            'loaded_from': 'frozen_artifact',
            'frozen_artifact_loaded': True,
            'sections_json_loaded': bool(sections),
            'canonical_hash': str(
                rehyd.get('rel3_canonical_hash')
                or cm.get('rel3_canonical_hash')
                or bundle.get('final_hash') or ''),
            'render_tree_hash': str(
                rehyd.get('rel3_render_tree_hash')
                or cm.get('rel3_render_tree_hash') or ''),
            'complete_artifact_loaded': True,
            'export_fragment_checked_against': 'skipped_db_complete_artifact',
        })
        out.update({
            'content': content,
            'sections': sections,
            'skip_fragment_gate': True,
        })
        emit_rel33_export_complete_artifact_load(diag)
        return out

    if sections_dict_export_complete(sections):
        content = assemble_sections(sections)
        if content.strip():
            diag.update({
                'loaded_from': 'sections_json',
                'sections_json_loaded': True,
                'canonical_hash': str(bundle.get('final_hash') or ''),
                'complete_artifact_loaded': True,
                'export_fragment_checked_against': 'skipped_db_sections_json',
            })
            out.update({
                'content': content,
                'sections': sections,
                'skip_fragment_gate': True,
            })
            emit_rel33_export_complete_artifact_load(diag)
            return out

    # Incomplete DB artifact — fall back to client only when no strategy_id path
    diag['export_fragment_checked_against'] = 'client_fragment'
    if client_content.strip():
        diag['client_content_used_as_authority'] = True
        try:
            _is_frag, _found, _why = is_fragment(client_content)
            if _is_frag:
                diag['blocking_errors'] = [
                    f'export_fragment_detected:{_why}']
        except Exception as exc:  # noqa: BLE001
            diag['blocking_errors'] = [str(exc)]
    else:
        diag['blocking_errors'] = ['no_db_or_client_content']
    emit_rel33_export_complete_artifact_load(diag)
    return out
