"""PR-REL3.2.2 — persist and rehydrate complete frozen export artifacts."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.contracts import (
    CanonicalSection,
    ExportManifest,
    FinalDocumentArtifact,
    TableRow,
)

REL32_FROZEN_DB_KEY = '_rel32_frozen_export_artifact'
REL32_PERSIST_VERSION = 'rel32.2'

LEGACY_SECTION_KEYS_ONLY = frozenset({
    'confidence',
    'environment',
    'gaps',
    'kpis',
    'pillars',
    'roadmap',
    'vision',
})

_LAST_DB_LOAD_DIAG: Dict[str, Any] = {}


def clear_rel32_db_load_diag() -> None:
    _LAST_DB_LOAD_DIAG.clear()


def get_rel32_db_load_diag() -> Dict[str, Any]:
    return dict(_LAST_DB_LOAD_DIAG)


def _section_keys(sections: Dict[str, Any]) -> frozenset:
    return frozenset(
        k for k, v in (sections or {}).items()
        if not str(k).startswith('_') and str(v or '').strip())


def is_legacy_section_bundle(sections: Dict[str, Any]) -> bool:
    """True when DB bundle is the legacy 7-section set without traceability."""
    keys = _section_keys(sections)
    if not keys:
        return False
    if keys <= LEGACY_SECTION_KEYS_ONLY:
        return True
    required = {'traceability', 'governance'}
    if not required.issubset(keys) and keys <= (
            LEGACY_SECTION_KEYS_ONLY | {'governance'}):
        return 'traceability' not in keys
    return False


def missing_frozen_components(blob: Dict[str, Any]) -> List[str]:
    """Return missing required fields for a complete REL3.2 frozen artifact."""
    missing: List[str] = []
    art = dict(blob.get('artifact') or blob)
    canon_hash = (
        blob.get('rel3_canonical_hash')
        or art.get('canonical_hash')
        or '')
    tree_hash = (
        blob.get('rel3_render_tree_hash')
        or art.get('render_tree_hash')
        or '')
    if not str(canon_hash).strip():
        missing.append('canonical_hash')
    if not str(tree_hash).strip():
        missing.append('render_tree_hash')
    legacy = dict(art.get('legacy_sections') or {})
    if not str(legacy.get('traceability') or '').strip():
        missing.append('canonical_traceability_rows')
    if not str(legacy.get('gaps') or '').strip():
        missing.append('canonical_gap_rows')
    if not art.get('canonical_sections'):
        missing.append('canonical_sections')
    route_eq = blob.get('route_equivalence') or art.get('route_equivalence')
    if not route_eq:
        missing.append('route_equivalence_metadata')
    if not art.get('artifact_id') and not blob.get('artifact_id'):
        missing.append('artifact_id')
    return missing


def frozen_artifact_complete(blob: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(blob, dict):
        return False
    return not missing_frozen_components(blob)


def final_document_artifact_from_dict(d: Dict[str, Any]) -> FinalDocumentArtifact:
    canon: Dict[str, CanonicalSection] = {}
    for k, v in (d.get('canonical_sections') or {}).items():
        if not isinstance(v, dict):
            continue
        rows = tuple(
            TableRow(cells=tuple(r))
            for r in (v.get('table_rows') or []))
        canon[k] = CanonicalSection(
            key=str(v.get('key') or k),
            title=str(v.get('title') or ''),
            narrative=str(v.get('narrative') or ''),
            table_rows=rows,
        )
    em_raw = d.get('export_manifest') or {}
    export_manifest = ExportManifest(
        routes=dict(em_raw.get('routes') or {}),
        render_tree_hash=str(
            em_raw.get('render_tree_hash') or d.get('render_tree_hash') or ''),
        canonical_hash=str(
            em_raw.get('canonical_hash') or d.get('canonical_hash') or ''),
    )
    return FinalDocumentArtifact(
        artifact_id=str(d.get('artifact_id') or ''),
        strategy_id=str(d.get('strategy_id') or d.get('artifact_id') or ''),
        domain=str(d.get('domain') or 'cyber'),
        language=str(d.get('language') or 'ar'),
        document_type=str(d.get('document_type') or 'strategy'),
        strategy_type=str(d.get('strategy_type') or 'technical'),
        selected_frameworks=list(d.get('selected_frameworks') or []),
        canonical_sections=canon,
        quality_repairs=list(d.get('quality_repairs') or []),
        quality_results=dict(d.get('quality_results') or {}),
        frozen=True,
        canonical_hash=str(d.get('canonical_hash') or ''),
        render_tree_hash=str(d.get('render_tree_hash') or ''),
        export_manifest=export_manifest,
        blocking_errors=list(d.get('blocking_errors') or []),
        release_ready_final_passed=bool(d.get('release_ready_final_passed')),
        legacy_sections=dict(d.get('legacy_sections') or {}),
        final_markdown_view=str(d.get('final_markdown_view') or ''),
    )


def build_persist_blob_from_generation_art(
        cy80_art: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rel3_art = dict(cy80_art.get('rel3_artifact') or {})
    if not rel3_art:
        return None
    canon = cy80_art.get('rel3_canonical_hash') or rel3_art.get('canonical_hash')
    tree = cy80_art.get('rel3_render_tree_hash') or rel3_art.get('render_tree_hash')
    if canon and not rel3_art.get('canonical_hash'):
        rel3_art['canonical_hash'] = canon
    if tree and not rel3_art.get('render_tree_hash'):
        rel3_art['render_tree_hash'] = tree
    blob = {
        'version': REL32_PERSIST_VERSION,
        'artifact': rel3_art,
        'rel3_canonical_hash': str(canon or ''),
        'rel3_render_tree_hash': str(tree or ''),
        'route_equivalence': {
            'generation': {
                'canonical_hash': str(canon or ''),
                'render_tree_hash': str(tree or ''),
            },
        },
        'frozen_artifact_complete': True,
    }
    if missing_frozen_components(blob):
        blob['frozen_artifact_complete'] = False
    return blob


def embed_rel32_frozen_artifact(
        content_json_obj: Dict[str, Any],
        cy80_art: Dict[str, Any]) -> Dict[str, Any]:
    blob = build_persist_blob_from_generation_art(cy80_art)
    if not blob:
        return content_json_obj
    content_json_obj[REL32_FROZEN_DB_KEY] = blob
    return content_json_obj


def extract_persisted_frozen_blob(
        content_json: Any) -> Optional[Dict[str, Any]]:
    if isinstance(content_json, str):
        try:
            import json as _json
            content_json = _json.loads(content_json)
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(content_json, dict):
        return None
    blob = content_json.get(REL32_FROZEN_DB_KEY)
    if isinstance(blob, dict):
        return blob
    rel3 = content_json.get('rel3_artifact')
    if isinstance(rel3, dict) and rel3.get('canonical_hash'):
        return {
            'version': REL32_PERSIST_VERSION,
            'artifact': rel3,
            'rel3_canonical_hash': rel3.get('canonical_hash') or '',
            'rel3_render_tree_hash': rel3.get('render_tree_hash') or '',
            'route_equivalence': content_json.get('route_equivalence') or {
                'generation': {
                    'canonical_hash': rel3.get('canonical_hash') or '',
                    'render_tree_hash': rel3.get('render_tree_hash') or '',
                },
            },
        }
    return None


def rehydrate_artifact_dict_from_persisted(
        blob: Dict[str, Any],
        *,
        strategy_id: str = '',
        contract_meta: Optional[Dict[str, Any]] = None,
        domain: str = 'cyber',
        lang: str = 'ar',
) -> Dict[str, Any]:
    art = dict(blob.get('artifact') or {})
    legacy = dict(art.get('legacy_sections') or {})
    canon_hash = (
        blob.get('rel3_canonical_hash')
        or art.get('canonical_hash')
        or '')
    tree_hash = (
        blob.get('rel3_render_tree_hash')
        or art.get('render_tree_hash')
        or '')
    sid = str(strategy_id or art.get('strategy_id') or art.get('artifact_id') or '')
    cm = dict(contract_meta or {})
    cm.setdefault('lang', lang)
    cm.setdefault('domain', domain)
    cm['rel3_canonical_hash'] = canon_hash
    cm['rel3_render_tree_hash'] = tree_hash
    md = '\n\n'.join(
        str(v).strip()
        for k, v in legacy.items()
        if isinstance(v, str) and v.strip() and not str(k).startswith('_'))
    return {
        'rel3_artifact': art,
        '_rel32_persisted_frozen': True,
        'sealed': True,
        'strategy_id': sid,
        'artifact_id': str(art.get('artifact_id') or sid),
        'rel3_canonical_hash': canon_hash,
        'rel3_render_tree_hash': tree_hash,
        'sections': legacy,
        'final_markdown': md,
        'domain': str(art.get('domain') or domain),
        'contract_meta': cm,
        '_rel32_artifact_loaded_from': 'db_complete_artifact',
        '_rel32_traceability_rows_loaded_from': 'canonical_artifact',
        'frozen_artifact_complete': True,
    }


def rehydrate_frozen_from_persisted_dict(
        artifact_dict: Dict[str, Any]) -> FinalDocumentArtifact:
    from release_engine_v3.canonical_document import store_artifact

    raw = dict(artifact_dict.get('rel3_artifact') or {})
    if artifact_dict.get('rel3_render_tree_hash') and not raw.get('render_tree_hash'):
        raw['render_tree_hash'] = artifact_dict['rel3_render_tree_hash']
    if artifact_dict.get('rel3_canonical_hash') and not raw.get('canonical_hash'):
        raw['canonical_hash'] = artifact_dict['rel3_canonical_hash']
    if artifact_dict.get('strategy_id') and not raw.get('strategy_id'):
        raw['strategy_id'] = artifact_dict['strategy_id']
    built = final_document_artifact_from_dict(raw)
    built.frozen = True
    store_artifact(built)
    return built


def assess_db_bundle_for_export(
        sections: Dict[str, Any],
        persisted_blob: Optional[Dict[str, Any]],
        *,
        document_type: str = 'strategy',
        domain: str = '',
        lang: str = 'ar',
        flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from release_engine_v3.rel33_frozen_completeness import (
        evaluate_frozen_completeness_by_document_type,
        rel33_compiler_first_sections_authority,
    )

    dtype = str(document_type or 'strategy').strip().lower()
    db_keys = sorted(_section_keys(sections))
    diag: Dict[str, Any] = {
        'db_sections_loaded': db_keys,
        'frozen_artifact_complete': False,
        'missing_frozen_components': [],
        'artifact_loaded_from': 'none',
        'traceability_rows_loaded_from': 'inferred_text',
        'incomplete_frozen_artifact': False,
        'document_type': dtype,
        'domain': domain,
    }
    if dtype == 'gap_assessment':
        complete, _, missing, _fc_diag = (
            evaluate_frozen_completeness_by_document_type(
                document_type=dtype,
                domain=domain,
                sections=sections,
                persisted_blob=persisted_blob,
                loaded_from='sections_json',
                flags=flags,
            ))
        if complete:
            diag.update({
                'frozen_artifact_complete': True,
                'artifact_loaded_from': 'gap_assessment_sections',
                'traceability_rows_loaded_from': 'gap_assessment',
                'completeness_rule_used': _fc_diag.get(
                    'completeness_rule_used'),
            })
            return diag
        diag.update({
            'incomplete_frozen_artifact': True,
            'missing_frozen_components': missing,
            'artifact_loaded_from': 'gap_assessment_sections',
        })
        return diag
    if rel33_compiler_first_sections_authority(
            {'sections': sections},
            domain=domain,
            lang=lang,
            flags=flags,
            document_type=dtype):
        complete, _, missing, _fc_diag = (
            evaluate_frozen_completeness_by_document_type(
                document_type=dtype,
                domain=domain,
                sections=sections,
                loaded_from='sections_json',
                flags=flags,
            ))
        if complete:
            diag.update({
                'frozen_artifact_complete': True,
                'artifact_loaded_from': 'rel33_compiler_first_sections',
                'traceability_rows_loaded_from': 'sections_json',
                'completeness_rule_used': _fc_diag.get(
                    'completeness_rule_used'),
            })
            return diag
    if persisted_blob:
        complete, _, missing, _ = evaluate_frozen_completeness_by_document_type(
            document_type=dtype,
            persisted_blob=persisted_blob,
            loaded_from='persisted_blob',
        )
        if complete:
            diag.update({
                'frozen_artifact_complete': True,
                'artifact_loaded_from': 'db_complete_artifact',
                'traceability_rows_loaded_from': 'canonical_artifact',
            })
            return diag
        if dtype == 'strategy' and frozen_artifact_complete(persisted_blob):
            diag.update({
                'frozen_artifact_complete': True,
                'artifact_loaded_from': 'db_complete_artifact',
                'traceability_rows_loaded_from': 'canonical_artifact',
            })
            return diag
    if is_legacy_section_bundle(sections) and dtype == 'strategy':
        diag.update({
            'incomplete_frozen_artifact': True,
            'artifact_loaded_from': 'legacy_sections',
            'traceability_rows_loaded_from': 'legacy_rebuild',
            'missing_frozen_components': (
                missing_frozen_components(persisted_blob or {})
                or [
                    'canonical_hash',
                    'render_tree_hash',
                    'canonical_traceability_rows',
                    'canonical_gap_rows',
                    'canonical_sections',
                    'route_equivalence_metadata',
                ]),
        })
        return diag
    if persisted_blob:
        diag['missing_frozen_components'] = missing_frozen_components(
            persisted_blob)
        diag['incomplete_frozen_artifact'] = True
        diag['artifact_loaded_from'] = 'legacy_sections'
        diag['traceability_rows_loaded_from'] = 'legacy_rebuild'
    return diag


def record_db_load_diag(diag: Dict[str, Any]) -> None:
    _LAST_DB_LOAD_DIAG.clear()
    _LAST_DB_LOAD_DIAG.update(diag)
