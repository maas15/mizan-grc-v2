"""PR-REL3.2 — frozen artifact export lock for route hash parity."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.contracts import FinalDocumentArtifact

_REL32_FROZEN_EXPORT_LOCK: Dict[str, Dict[str, Any]] = {}
_REL32_EXPORT_ROUTE_STATE: Dict[str, Dict[str, Any]] = {}


def clear_rel32_frozen_export_lock() -> None:
    _REL32_FROZEN_EXPORT_LOCK.clear()
    _REL32_EXPORT_ROUTE_STATE.clear()


def register_rel32_frozen_export_lock(
        artifact: FinalDocumentArtifact,
        *,
        render_tree_hash: str) -> None:
    sid = str(artifact.strategy_id or artifact.artifact_id or '').strip()
    if not sid:
        return
    _REL32_FROZEN_EXPORT_LOCK[sid] = {
        'strategy_id': sid,
        'artifact_id': artifact.artifact_id,
        'generation_canonical_hash': artifact.canonical_hash or '',
        'generation_render_tree_hash': render_tree_hash or '',
    }


def _client_sections_diverge(
        artifact_dict: Dict[str, Any],
        frozen: FinalDocumentArtifact) -> bool:
    client = dict(artifact_dict.get('sections') or {})
    frozen_secs = dict(frozen.legacy_sections or {})
    if not client or not frozen_secs:
        return False
    for key in ('traceability', 'kpis', 'roadmap', 'gaps', 'vision'):
        c = (client.get(key) or '').strip()
        f = (frozen_secs.get(key) or '').strip()
        if c and f and c != f:
            return True
    return False


def _rel32_lookup_keys(
        artifact_dict: Dict[str, Any],
        *,
        backend: Optional[Dict[str, Any]] = None) -> List[str]:
    keys: List[str] = []
    for field in ('strategy_id', 'artifact_id', '_numeric_strategy_id'):
        val = str((artifact_dict or {}).get(field) or '').strip()
        if val and val not in keys:
            keys.append(val)
    resolver = (backend or {}).get('resolve_strategy_id')
    uid = int((backend or {}).get('_rel32_export_user_id') or 0)
    if callable(resolver):
        for key in list(keys):
            try:
                numeric = resolver(key, uid)
            except Exception:  # noqa: BLE001
                numeric = None
            if numeric:
                num_s = str(numeric)
                if num_s not in keys:
                    keys.insert(0, num_s)
    return keys


def prepare_rel32_export_artifact_dict(
        artifact_dict: Dict[str, Any],
        *,
        backend: Optional[Dict[str, Any]] = None,
        flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Prefer generation-time frozen sections over client POST markdown."""
    from release_engine_v3.rel32_compiler import is_rel32_compiler_first

    art = dict(artifact_dict or {})
    domain = str(art.get('domain') or 'cyber')
    lang = str((art.get('contract_meta') or {}).get('lang') or 'ar')
    if not is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
        return art
    lookup_keys = _rel32_lookup_keys(art, backend=backend)
    if not lookup_keys:
        return art
    try:
        from release_engine_v3.orchestrator import rel3_get_frozen_artifact
        for sid in lookup_keys:
            try:
                frozen = rel3_get_frozen_artifact(sid, backend=backend)
            except KeyError:
                continue
            if frozen.frozen and not frozen.blocking_errors:
                art['sections'] = dict(frozen.legacy_sections or {})
                if frozen.final_markdown_view:
                    art['final_markdown'] = frozen.final_markdown_view
                art['sealed'] = True
                art['_rel32_frozen_loaded'] = True
                art['rel3_canonical_hash'] = frozen.canonical_hash
                if frozen.render_tree_hash:
                    art['rel3_render_tree_hash'] = frozen.render_tree_hash
                art['strategy_id'] = str(
                    frozen.strategy_id or sid or art.get('strategy_id') or '')
                break
    except KeyError:
        pass
    return art


def resolve_frozen_artifact_for_export(
        artifact_dict: Dict[str, Any],
        *,
        backend: Dict[str, Any],
        route: str,
        flags: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[FinalDocumentArtifact], Dict[str, Any]]:
    """Load generation-time frozen artifact; block client markdown divergence."""
    from release_engine_v3.rel32_compiler import is_rel32_compiler_first
    from release_engine_v3.orchestrator import rel3_get_frozen_artifact
    from release_engine_v3.rel31_authority import _bind_backend_sections

    flags = dict(flags or {})
    route_n = (route or '').lower()
    domain = str(artifact_dict.get('domain') or 'cyber')
    lang = str((artifact_dict.get('contract_meta') or {}).get('lang') or 'ar')
    sid = str(artifact_dict.get('strategy_id') or '').strip()
    aid = str(artifact_dict.get('artifact_id') or '').strip()

    meta: Dict[str, Any] = {
        'frozen_artifact_loaded_for_docx': False,
        'frozen_artifact_loaded_for_pdf': False,
        'frozen_artifact_loaded_for_preview': False,
        'docx_rebuilt_from_markdown': False,
        'pdf_rebuilt_from_markdown': False,
        'blocking_errors': [],
    }
    if not is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
        return None, meta

    frozen: Optional[FinalDocumentArtifact] = None
    for key in _rel32_lookup_keys(artifact_dict, backend=backend):
        if not key:
            continue
        try:
            candidate = rel3_get_frozen_artifact(key, backend=backend)
            if candidate.frozen and not candidate.blocking_errors:
                frozen = candidate
                break
        except KeyError:
            continue

    if frozen is None:
        if route_n == 'docx':
            meta['docx_rebuilt_from_markdown'] = True
        elif route_n == 'pdf':
            meta['pdf_rebuilt_from_markdown'] = True
        return None, meta

    # Client POST markdown is ignored when generation-time frozen artifact exists.
    if _client_sections_diverge(artifact_dict, frozen):
        meta['client_content_ignored'] = True

    _bind_backend_sections(backend, {
        'sections': dict(frozen.legacy_sections or {}),
    })
    backend['_rel32_frozen_export_lock_active'] = True
    backend['_rel32_frozen_canonical_hash'] = frozen.canonical_hash or ''
    backend['_rel32_frozen_render_tree_hash'] = (
        frozen.render_tree_hash or '')

    if route_n == 'docx':
        meta['frozen_artifact_loaded_for_docx'] = True
        meta['docx_rebuilt_from_markdown'] = False
    elif route_n == 'pdf':
        meta['frozen_artifact_loaded_for_pdf'] = True
        meta['pdf_rebuilt_from_markdown'] = False
    elif route_n == 'preview':
        meta['frozen_artifact_loaded_for_preview'] = True

    return frozen, meta


def track_rel32_export_route_state(
        strategy_id: str,
        route: str,
        lock_meta: Dict[str, Any],
) -> None:
    sid = str(strategy_id or '').strip()
    if not sid:
        return
    bucket = _REL32_EXPORT_ROUTE_STATE.setdefault(sid, {})
    route_n = (route or '').lower()
    if route_n == 'docx':
        if lock_meta.get('frozen_artifact_loaded_for_docx'):
            bucket['frozen_artifact_loaded_for_docx'] = True
        if not lock_meta.get('docx_rebuilt_from_markdown', False):
            bucket['docx_rebuilt_from_markdown'] = False
        elif lock_meta.get('docx_rebuilt_from_markdown'):
            bucket['docx_rebuilt_from_markdown'] = True
    if route_n == 'pdf':
        if lock_meta.get('frozen_artifact_loaded_for_pdf'):
            bucket['frozen_artifact_loaded_for_pdf'] = True
        if not lock_meta.get('pdf_rebuilt_from_markdown', False):
            bucket['pdf_rebuilt_from_markdown'] = False
        elif lock_meta.get('pdf_rebuilt_from_markdown'):
            bucket['pdf_rebuilt_from_markdown'] = True
    if route_n == 'preview' and lock_meta.get('frozen_artifact_loaded_for_preview'):
        bucket['frozen_artifact_loaded_for_preview'] = True


def guard_rel32_docx_export_bypass(function_name: str) -> Optional[str]:
    """Block _build_docx_bytes as route authority under REL3.2."""
    from release_engine_v3.rel31_authority import (
        is_rel3_authoritative,
        rel31_in_export_adapter,
    )
    if rel31_in_export_adapter():
        return None
    if is_rel3_authoritative(
            domain='cyber', lang='ar',
            flags={'rel3': True, 'rel31': True}):
        return f'rel32_docx_export_bypass_detected:{function_name}'
    return None


def emit_rel32_frozen_artifact_export_lock(
        strategy_id: str,
        *,
        route: str = '',
        lock_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from release_engine_v3.rel31_authority import _ROUTE_ARTIFACT_HASHES

    sid = str(strategy_id or '').strip()
    routes = _ROUTE_ARTIFACT_HASHES.get(sid) or {}
    gen_lock = _REL32_FROZEN_EXPORT_LOCK.get(sid) or {}
    route_state = dict(_REL32_EXPORT_ROUTE_STATE.get(sid) or {})
    if lock_meta:
        track_rel32_export_route_state(sid, route, lock_meta)
        route_state.update({
            k: v for k, v in lock_meta.items()
            if k.startswith('frozen_artifact_loaded')
            or k.endswith('_rebuilt_from_markdown')
        })

    def _h(route_name: str, key: str) -> str:
        return str((routes.get(route_name) or {}).get(key) or '')

    gen = routes.get('generation') or gen_lock
    canon_hashes = [
        _h('generation', 'canonical_hash')
        or str(gen_lock.get('generation_canonical_hash') or ''),
        _h('preview', 'canonical_hash'),
        _h('docx', 'canonical_hash'),
        _h('pdf', 'canonical_hash'),
    ]
    tree_hashes = [
        _h('generation', 'render_tree_hash')
        or str(gen_lock.get('generation_render_tree_hash') or ''),
        _h('preview', 'render_tree_hash'),
        _h('docx', 'render_tree_hash'),
        _h('pdf', 'render_tree_hash'),
    ]
    present_canon = [h for h in canon_hashes if h]
    present_tree = [h for h in tree_hashes if h]
    blockers: List[str] = list(lock_meta.get('blocking_errors') or []) if lock_meta else []

    all_canon_equal = len(set(present_canon)) <= 1 if present_canon else True
    all_tree_equal = len(set(present_tree)) <= 1 if present_tree else True
    if present_canon and not all_canon_equal:
        blockers.append('rel32_export_lock_canonical_hash_mismatch')
    if present_tree and not all_tree_equal:
        blockers.append('rel32_export_lock_render_tree_hash_mismatch')

    docx_loaded = bool(route_state.get('frozen_artifact_loaded_for_docx'))
    pdf_loaded = bool(route_state.get('frozen_artifact_loaded_for_pdf'))
    docx_rebuilt = bool(route_state.get('docx_rebuilt_from_markdown'))
    pdf_rebuilt = bool(route_state.get('pdf_rebuilt_from_markdown'))

    if _h('docx', 'canonical_hash') and not docx_loaded and route == 'docx':
        docx_rebuilt = True
    if _h('pdf', 'canonical_hash') and not pdf_loaded and route == 'pdf':
        pdf_rebuilt = True

    if docx_rebuilt:
        blockers.append('rel32_docx_rebuilt_from_markdown')
    if pdf_rebuilt:
        blockers.append('rel32_pdf_rebuilt_from_markdown')

    export_lock_passed = (
        all_canon_equal
        and all_tree_equal
        and not docx_rebuilt
        and not pdf_rebuilt
        and not blockers)

    payload = {
        'strategy_id': sid,
        'artifact_id': str(gen_lock.get('artifact_id') or ''),
        'generation_canonical_hash': (
            _h('generation', 'canonical_hash')
            or str(gen_lock.get('generation_canonical_hash') or '')),
        'preview_canonical_hash': _h('preview', 'canonical_hash'),
        'docx_canonical_hash': _h('docx', 'canonical_hash'),
        'pdf_canonical_hash': _h('pdf', 'canonical_hash'),
        'generation_render_tree_hash': (
            _h('generation', 'render_tree_hash')
            or str(gen_lock.get('generation_render_tree_hash') or '')),
        'preview_render_tree_hash': _h('preview', 'render_tree_hash'),
        'docx_render_tree_hash': _h('docx', 'render_tree_hash'),
        'pdf_render_tree_hash': _h('pdf', 'render_tree_hash'),
        'frozen_artifact_loaded_for_docx': docx_loaded,
        'frozen_artifact_loaded_for_pdf': pdf_loaded,
        'docx_rebuilt_from_markdown': docx_rebuilt,
        'pdf_rebuilt_from_markdown': pdf_rebuilt,
        'export_lock_passed': export_lock_passed,
        'blocking_errors': list(dict.fromkeys(blockers)),
    }
    try:
        print(
            '[REL32-FROZEN-ARTIFACT-EXPORT-LOCK] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
    return payload
