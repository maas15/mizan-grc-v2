"""REL3.3 — load complete saved strategy artifacts for export (not client fragments)."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional, Set

STRATEGY_EXPORT_SECTION_KEYS = frozenset({
    'vision', 'pillars', 'environment', 'gaps', 'roadmap', 'kpis',
    'confidence', 'traceability', 'governance',
})

MIN_STRATEGY_SECTIONS_FOR_COMPLETE = 5


def _section_keys(sections: Optional[Dict[str, Any]]) -> Set[str]:
    return {
        k for k, v in (sections or {}).items()
        if not str(k).startswith('_') and str(v or '').strip()}


def sections_dict_export_complete(sections: Optional[Dict[str, Any]]) -> bool:
    """True when persisted sections_json carries enough strategy sections."""
    if not isinstance(sections, dict):
        return False
    keys = _section_keys(sections)
    core = STRATEGY_EXPORT_SECTION_KEYS - {'traceability', 'governance'}
    populated = keys & core
    if len(populated) >= MIN_STRATEGY_SECTIONS_FOR_COMPLETE:
        if ('vision' in keys) or ('pillars' in keys):
            return True
    # Compiler-first artifacts often persist traceability+governance with core.
    if len(keys & STRATEGY_EXPORT_SECTION_KEYS) >= MIN_STRATEGY_SECTIONS_FOR_COMPLETE:
        return bool(keys & {'kpis', 'roadmap', 'gaps'} & keys or keys & core)
    return False


def emit_rel33_export_complete_artifact_load(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-EXPORT-COMPLETE-ARTIFACT-LOAD] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _legacy_sections_usable(sections: Dict[str, Any]) -> bool:
    keys = _section_keys(sections)
    if sections_dict_export_complete(sections):
        return True
    if len(keys) >= MIN_STRATEGY_SECTIONS_FOR_COMPLETE:
        return bool(keys & {'vision', 'pillars', 'kpis', 'gaps', 'roadmap'})
    return False


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
        split_content: Optional[Callable[[str], Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Load authoritative export content from DB by strategy_id."""
    from release_engine_v3.rel32_frozen_artifact_persist import (
        extract_persisted_frozen_blob,
        frozen_artifact_complete,
        rehydrate_artifact_dict_from_persisted,
    )

    dtype = str(document_type or 'strategy').strip().lower()
    atype = str(artifact_type or dtype or 'strategy').strip().lower()
    if atype != 'strategy' and dtype == 'strategy':
        atype = 'strategy'

    diag: Dict[str, Any] = {
        'route': route,
        'domain': domain,
        'document_type': dtype,
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

    if atype != 'strategy':
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
    stored_content = str(bundle.get('content') or bundle.get('stored_content') or '')
    cm = dict(bundle.get('contract_meta') or {})
    _lang = cm.get('lang') or bundle.get('language') or 'ar'
    _domain = cm.get('domain') or bundle.get('domain') or domain
    sealed_saved = bool(
        bundle.get('sealed')
        or cm.get('sealed')
        or cm.get('quality_gate_passed')
        or (bundle.get('final_hash') or '').strip())

    def _success(
            content: str,
            secs: Dict[str, Any],
            *,
            loaded_from: str,
            frozen: bool = False,
            canon_hash: str = '',
            tree_hash: str = '',
    ) -> Dict[str, Any]:
        diag.update({
            'loaded_from': loaded_from,
            'sections_json_loaded': bool(secs),
            'frozen_artifact_loaded': frozen,
            'canonical_hash': canon_hash or str(bundle.get('final_hash') or ''),
            'render_tree_hash': tree_hash,
            'complete_artifact_loaded': True,
            'export_fragment_checked_against': 'skipped_db_complete_artifact',
        })
        out.update({
            'content': content,
            'sections': dict(secs),
            'skip_fragment_gate': True,
        })
        emit_rel33_export_complete_artifact_load(diag)
        return out

    persisted = extract_persisted_frozen_blob(bundle.get('content_json') or {})
    if persisted:
        rehyd = rehydrate_artifact_dict_from_persisted(
            persisted,
            strategy_id=str(sid),
            contract_meta=cm,
            domain=_domain,
            lang=_lang,
        )
        rehyd_secs = dict(rehyd.get('sections') or sections)
        rehyd_content = (
            rehyd.get('final_markdown')
            or assemble_sections(rehyd_secs)
            or '')
        if frozen_artifact_complete(persisted) and rehyd_content.strip():
            return _success(
                rehyd_content,
                rehyd_secs,
                loaded_from='frozen_artifact',
                frozen=True,
                canon_hash=str(
                    rehyd.get('rel3_canonical_hash')
                    or cm.get('rel3_canonical_hash') or ''),
                tree_hash=str(
                    rehyd.get('rel3_render_tree_hash')
                    or cm.get('rel3_render_tree_hash') or ''),
            )
        if _legacy_sections_usable(rehyd_secs):
            content = rehyd_content or assemble_sections(rehyd_secs)
            if content.strip():
                return _success(
                    content,
                    rehyd_secs,
                    loaded_from='frozen_partial_legacy',
                    frozen=False,
                    canon_hash=str(
                        rehyd.get('rel3_canonical_hash') or ''),
                    tree_hash=str(
                        rehyd.get('rel3_render_tree_hash') or ''),
                )

    if sections_dict_export_complete(sections):
        content = assemble_sections(sections)
        if content.strip():
            return _success(content, sections, loaded_from='sections_json')

    if stored_content.strip():
        try:
            _is_frag, _, _why = is_fragment(stored_content)
        except Exception:  # noqa: BLE001
            _is_frag, _why = False, ''
        if not _is_frag:
            secs = sections
            if not _legacy_sections_usable(secs) and callable(split_content):
                try:
                    secs = split_content(stored_content) or secs
                except Exception:  # noqa: BLE001
                    pass
            return _success(
                stored_content,
                secs,
                loaded_from='strategies.content',
            )

    if stored_content.strip() and sealed_saved:
        secs = sections
        if not _legacy_sections_usable(secs) and callable(split_content):
            try:
                secs = split_content(stored_content) or secs
            except Exception:  # noqa: BLE001
                pass
        return _success(
            stored_content,
            secs,
            loaded_from='sealed_db_authority',
            canon_hash=str(bundle.get('final_hash') or cm.get('final_hash') or ''),
        )

    if not sections and stored_content.strip() and callable(split_content):
        try:
            sections = split_content(stored_content) or {}
        except Exception:  # noqa: BLE001
            sections = {}
        if sections_dict_export_complete(sections):
            content = assemble_sections(sections)
            if content.strip():
                return _success(content, sections, loaded_from='content_split')

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
