"""PR-REL3.2.3 — bind DOCX renderer input to complete frozen artifacts."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.contracts import FinalDocumentArtifact, RenderTree

REL32_DOCX_RENDERER_REQUIRED = frozenset({
    'vision',
    'pillars',
    'environment',
    'gaps',
    'roadmap',
    'kpis',
    'confidence',
    'governance',
    'traceability',
})

_CANON_TO_LEGACY = (
    ('vision_objectives', 'vision'),
    ('pillars', 'pillars'),
    ('environment', 'environment'),
    ('gap_analysis', 'gaps'),
    ('roadmap', 'roadmap'),
    ('kpi_kri', 'kpis'),
    ('confidence_risk', 'confidence'),
    ('governance', 'governance'),
    ('traceability', 'traceability'),
)


def _section_keys(sections: Dict[str, Any]) -> List[str]:
    return sorted(
        k for k, v in (sections or {}).items()
        if not str(k).startswith('_') and str(v or '').strip())


def sections_from_frozen_artifact(
        frozen: FinalDocumentArtifact,
        *,
        render_tree: Optional[RenderTree] = None) -> Dict[str, str]:
    """Build legacy section map for DOCX from frozen artifact only."""
    from release_engine_v3.section_models import section_to_markdown

    sections = {
        k: v for k, v in dict(frozen.legacy_sections or {}).items()
        if isinstance(v, str) and not str(k).startswith('_')}
    for canon_key, legacy_key in _CANON_TO_LEGACY:
        if str(sections.get(legacy_key) or '').strip():
            continue
        sec = (frozen.canonical_sections or {}).get(canon_key)
        if sec is not None:
            rendered = section_to_markdown(sec)
            if rendered.strip():
                sections[legacy_key] = rendered
    if render_tree is not None:
        for node in render_tree.nodes or []:
            sec_key = str(node.get('section_key') or '')
            legacy_key = {
                'vision_objectives': 'vision',
                'gap_analysis': 'gaps',
                'kpi_kri': 'kpis',
                'confidence_risk': 'confidence',
            }.get(sec_key, sec_key)
            body = str(node.get('rendered_text') or '').strip()
            if body and not str(sections.get(legacy_key) or '').strip():
                sections[legacy_key] = body
    return sections


def validate_docx_renderer_sections(
        sections: Dict[str, str],
        *,
        frozen_complete: bool = False) -> Tuple[bool, List[str]]:
    blockers: List[str] = []
    if not str(sections.get('traceability') or '').strip():
        blockers.append('rel32_docx_renderer_missing_frozen_traceability')
    if frozen_complete and not str(sections.get('governance') or '').strip():
        blockers.append('rel32_docx_renderer_missing_frozen_governance')
    return (not blockers, blockers)


def bind_rel32_docx_renderer_input(
        frozen: FinalDocumentArtifact,
        render_tree: RenderTree,
        *,
        backend: Dict[str, Any],
        artifact_dict: Optional[Dict[str, Any]] = None,
        traceability_source: str = 'canonical_artifact',
) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    """Force DOCX renderer content/sections from frozen artifact + RenderTree."""
    sections = sections_from_frozen_artifact(frozen, render_tree=render_tree)
    content = str(render_tree.markdown_view or '').strip()
    if not content:
        content = '\n\n'.join(
            str(v).strip()
            for k, v in sections.items()
            if str(v or '').strip())
    frozen_complete = bool(
        (artifact_dict or {}).get('frozen_artifact_complete')
        or (artifact_dict or {}).get('_rel32_frozen_loaded')
        or backend.get('_rel32_frozen_export_lock_active'))
    ok, blockers = validate_docx_renderer_sections(
        sections, frozen_complete=frozen_complete)
    trace_src = str(
        (artifact_dict or {}).get('_rel32_traceability_rows_loaded_from')
        or traceability_source
        or 'canonical_artifact')
    if not str(sections.get('traceability') or '').strip():
        trace_src = 'legacy_rebuild'
    meta: Dict[str, Any] = {
        'docx_renderer_source': (
            'frozen_artifact' if frozen_complete else 'legacy_content'),
        'docx_renderer_sections': _section_keys(sections),
        'docx_renderer_received_traceability': bool(
            str(sections.get('traceability') or '').strip()),
        'docx_renderer_received_governance': bool(
            str(sections.get('governance') or '').strip()),
        'docx_renderer_traceability_rows_source': trace_src,
        'returned_docx_source_matches_export_lock': bool(
            frozen_complete and ok),
        'blocking_errors': blockers,
    }
    backend['_rel32_docx_renderer_meta'] = meta
    backend['_rel32_docx_renderer_content'] = content
    backend['_rel32_docx_renderer_sections'] = sections
    backend['_rel31_frozen_sections'] = dict(sections)
    backend['_rel31_sections_bound'] = True
    backend['split_sections'] = (
        lambda _content, _secs=sections: dict(_secs))
    return content, sections, meta


def emit_rel32_docx_renderer_diag(meta: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(meta or {})
    try:
        print(
            '[REL32-DOCX-RENDERER] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
    return payload
