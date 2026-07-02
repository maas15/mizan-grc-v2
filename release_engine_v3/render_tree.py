"""PR-REL3 — single render tree for all export routes."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from release_engine_v3.contracts import (
    FinalDocumentArtifact,
    RenderTree,
    compute_render_tree_hash,
)
from release_engine_v3.section_models import section_to_markdown


def build_render_tree(artifact: FinalDocumentArtifact) -> RenderTree:
    """Build one immutable RenderTree from frozen canonical sections."""
    if not artifact.frozen and artifact.blocking_errors:
        pass  # still build for diagnostics; export will fail closed
    nodes: List[Dict[str, Any]] = []
    order = (
        ('executive_summary', 'executive_summary'),
        ('vision_objectives', 'vision_objectives'),
        ('pillars', 'pillars'),
        ('environment', 'environment'),
        ('gap_analysis', 'gap_analysis'),
        ('roadmap', 'roadmap'),
        ('kpi_kri', 'kpi_kri'),
        ('confidence_risk', 'confidence_risk'),
        ('governance', 'governance'),
        ('traceability', 'traceability'),
        ('appendices', 'appendices'),
    )
    md_parts: List[str] = []
    for node_key, sec_key in order:
        sec = artifact.canonical_sections.get(sec_key)
        if not sec:
            continue
        rendered = section_to_markdown(sec)
        nodes.append({
            'key': node_key,
            'section_key': sec_key,
            'title': sec.title,
            'rendered_text': rendered,
            'table_row_count': len(sec.table_rows),
        })
        if rendered.strip():
            md_parts.append(rendered)
    markdown_view = '\n\n'.join(md_parts)
    # Prefer frozen canonical section markdown for preview/export parity.
    # Legacy sealed markdown may still contain pre-repair shallow pillars,
    # gap-table bleed, and Arabic residues that DOCX no longer has.
    legacy_md = (artifact.final_markdown_view or '').strip()
    if not legacy_md and artifact.legacy_sections:
        legacy_md = '\n\n'.join(
            str(v).strip()
            for k, v in sorted(artifact.legacy_sections.items())
            if isinstance(v, str) and v.strip() and not str(k).startswith('_'))
    if legacy_md.strip() and not markdown_view.strip():
        markdown_view = legacy_md
    tree_hash = compute_render_tree_hash(nodes)
    preview_html = _markdown_to_preview_html(markdown_view)
    artifact.render_tree_hash = tree_hash
    return RenderTree(
        artifact_id=artifact.artifact_id,
        canonical_hash=artifact.canonical_hash,
        render_tree_hash=tree_hash,
        nodes=nodes,
        markdown_view=markdown_view,
        preview_html=preview_html,
    )


def _markdown_to_preview_html(markdown: str) -> str:
    """Simple markdown → HTML for preview (derived from RenderTree only)."""
    if not markdown:
        return ''
    lines = markdown.splitlines()
    html: List[str] = ['<div class="rel3-preview">']
    in_table = False
    for ln in lines:
        if ln.strip().startswith('## '):
            if in_table:
                html.append('</table>')
                in_table = False
            title = ln.strip()[3:].strip()
            html.append(f'<h2>{title}</h2>')
        elif ln.strip().startswith('|') and '---' not in ln:
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if not in_table:
                html.append('<table>')
                in_table = True
            tag = 'th' if not any('</tr>' in x for x in html[-3:]) and len(
                [x for x in html if x.startswith('<tr>')]) == 0 else 'td'
            if tag == 'th' and html[-1] != '<table>':
                tag = 'td'
            row = ''.join(f'<{tag}>{c}</{tag}>' for c in cells)
            html.append(f'<tr>{row}</tr>')
        elif ln.strip():
            if in_table:
                html.append('</table>')
                in_table = False
            html.append(f'<p>{ln.strip()}</p>')
    if in_table:
        html.append('</table>')
    html.append('</div>')
    return '\n'.join(html)


def verify_render_tree_parity(
        trees: Dict[str, RenderTree]) -> List[str]:
    """Block when route-specific render trees diverge."""
    if not trees:
        return ['rel3_render_tree_missing']
    hashes = {route: t.render_tree_hash for route, t in trees.items()}
    unique = set(hashes.values())
    if len(unique) > 1:
        return [
            'rel3_export_model_drift:render_tree_hash_mismatch:'
            + ','.join(f'{k}={v[:8]}' for k, v in sorted(hashes.items()))
        ]
    return []
