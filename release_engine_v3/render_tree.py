"""PR-REL3 — single render tree for all export routes."""

from __future__ import annotations

import hashlib
import json as _json_rt
import re as _re_rt
from typing import Any, Dict, List, Optional

from release_engine_v3.contracts import (
    FinalDocumentArtifact,
    RenderTree,
    compute_render_tree_hash,
)
from release_engine_v3.section_models import section_to_markdown

_RISK_DOCUMENT_TYPES = ('risk', 'risk_assessment')

# Forbidden strategy heading markers — asserted absent from a risk render tree.
_RT_FORBIDDEN_STRATEGY_HEADINGS = (
    'الرؤية', 'الأهداف الاستراتيجية', 'الاهداف الاستراتيجية',
    'الركائز الاستراتيجية', 'خارطة الطريق', 'خريطة الطريق',
    'مصفوفة التتبع', 'مصفوفة تتبع', 'نموذج الحوكمة',
    'مؤشرات الأداء الرئيسية', 'المواءمة الاستراتيجية',
    'المبادرات الاستراتيجية', 'strategic objectives', 'strategic pillars',
    'roadmap', 'traceability matrix', 'governance model', 'strategic vision',
)


def _rt_heading_keys(markdown: str) -> List[str]:
    return [
        ln.strip().lstrip('#').strip()
        for ln in str(markdown or '').splitlines()
        if ln.strip().startswith('##')]


def _rt_forbidden_headings_in(markdown: str) -> List[str]:
    hits: List[str] = []
    for h in _rt_heading_keys(markdown):
        hl = h.lower()
        for m in _RT_FORBIDDEN_STRATEGY_HEADINGS:
            if m.lower() in hl:
                hits.append(h)
                break
    return list(dict.fromkeys(hits))


def _rt_sha16(text: str) -> str:
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()[:16]


def _emit_rel33_render_tree_document_type_diag(diag: Dict[str, Any]) -> None:
    try:
        print('[REL33-RENDER-TREE-DOCUMENT-TYPE-DIAG] '
              + _json_rt.dumps(diag, ensure_ascii=False, default=str),
              flush=True)
    except Exception:  # noqa: BLE001
        pass


def _risk_native_markdown_from_sections(
        artifact: FinalDocumentArtifact) -> str:
    """Join risk-native ``legacy_sections`` (never strategy slots/titles).

    ``legacy_sections`` for a risk artifact are risk-native keyed (register,
    treatments, وصف_السيناريو, …) — see canonical_document. Joining their
    values reproduces risk-native headings and never emits strategy titles.
    """
    secs = dict(artifact.legacy_sections or {})
    parts = [
        str(v).strip()
        for k, v in secs.items()
        if isinstance(v, str) and str(v).strip() and not str(k).startswith('_')]
    return '\n\n'.join(parts).strip()


def _build_risk_render_tree(
        artifact: FinalDocumentArtifact, *, document_type: str) -> RenderTree:
    """Risk-native RenderTree — never strategy order/titles.

    markdown_view source preference:
      1. ``final_markdown_view`` (the compiled risk-native markdown);
      2. risk-native join of ``legacy_sections``;
      3. fail closed (``rel33_risk_render_tree_empty``).
    """
    final_md = str(artifact.final_markdown_view or '').strip()
    md_source = ''
    risk_markdown_preferred = False
    if final_md:
        markdown_view = final_md
        md_source = 'compiled_risk_content'
        risk_markdown_preferred = True
    else:
        markdown_view = _risk_native_markdown_from_sections(artifact)
        md_source = 'risk_native_sections' if markdown_view else 'none'

    blocking: List[str] = []
    if not markdown_view.strip():
        blocking.append('rel33_risk_render_tree_empty')

    # Nodes derived from the risk markdown headings (risk-native titles only).
    nodes: List[Dict[str, Any]] = []
    cur_title = ''
    buf: List[str] = []

    def _flush():
        if cur_title or buf:
            body = '\n'.join(buf).strip()
            nodes.append({
                'key': _re_rt.sub(r'\W+', '_', cur_title.lower())[:40] or 'body',
                'section_key': _re_rt.sub(r'\W+', '_', cur_title.lower())[:40]
                or 'body',
                'title': cur_title,
                'rendered_text': (
                    (f'## {cur_title}\n' if cur_title else '') + body).strip(),
                'table_row_count': sum(
                    1 for ln in buf
                    if ln.strip().startswith('|') and '---' not in ln),
            })

    for ln in markdown_view.splitlines():
        if ln.strip().startswith('##'):
            _flush()
            cur_title = ln.strip().lstrip('#').strip()
            buf = []
        else:
            buf.append(ln)
    _flush()

    tree_hash = compute_render_tree_hash(nodes)
    preview_html = _markdown_to_preview_html(markdown_view)
    artifact.render_tree_hash = tree_hash

    final_heads = _rt_heading_keys(final_md) if final_md else []
    rt_heads = _rt_heading_keys(markdown_view)
    forbidden = _rt_forbidden_headings_in(markdown_view)
    final_hash = _rt_sha16(final_md)
    rt_hash = _rt_sha16(markdown_view)
    _emit_rel33_render_tree_document_type_diag({
        'tag': '[REL33-RENDER-TREE-DOCUMENT-TYPE-DIAG]',
        'route': 'build_render_tree',
        'output_type': 'render_tree',
        'domain': str(getattr(artifact, 'domain', '') or ''),
        'document_type': str(document_type or ''),
        'artifact_type': 'risk',
        'risk_id': str(getattr(artifact, 'artifact_id', '') or ''),
        'render_profile': 'risk_native',
        'markdown_view_source': md_source,
        'canonical_sections_count': len(artifact.canonical_sections or {}),
        'canonical_section_keys': list((artifact.canonical_sections or {}).keys()),
        'strategy_render_order_applied': False,
        'strategy_render_skipped_reason': 'document_type_risk',
        'risk_render_order_applied': not risk_markdown_preferred,
        'risk_markdown_preferred': bool(risk_markdown_preferred),
        'final_markdown_hash': final_hash,
        'render_tree_markdown_hash': rt_hash,
        'hashes_match_final_to_render_tree': bool(
            final_md and final_hash == rt_hash),
        'final_heading_keys': final_heads,
        'render_tree_heading_keys': rt_heads,
        'forbidden_strategy_headings_in_render_tree': forbidden,
        'blocking_errors': list(blocking),
        'passed': not forbidden and not blocking,
    })
    return RenderTree(
        artifact_id=artifact.artifact_id,
        canonical_hash=artifact.canonical_hash,
        render_tree_hash=tree_hash,
        nodes=nodes,
        markdown_view=markdown_view,
        preview_html=preview_html,
    )


def build_render_tree(artifact: FinalDocumentArtifact) -> RenderTree:
    """Build one immutable RenderTree from frozen canonical sections.

    REL3.3 — document_type-aware: a risk artifact is rendered risk-native
    (compiled risk markdown / risk-native sections), NEVER via the strategy
    render order/titles below (which would emit ``## الرؤية والأهداف
    الاستراتيجية`` from the ``vision_objectives`` slot and be blocked by the
    domain guard). Strategy/gap_assessment keep the existing behavior.
    """
    _dtype = str(getattr(artifact, 'document_type', '') or '').strip().lower()
    if _dtype in _RISK_DOCUMENT_TYPES:
        return _build_risk_render_tree(artifact, document_type=_dtype)
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
