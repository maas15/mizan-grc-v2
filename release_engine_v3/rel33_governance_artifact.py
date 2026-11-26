"""Source-preserving sections for a governance model, without strategy repair.

Only the schema is owned here. Document prose, headings and table headers come
from the supplied sections; this module never supplies replacement content.
"""

from __future__ import annotations

from collections.abc import Mapping
from html import escape
from typing import Any, Dict, List, Tuple

from release_engine_v3.contracts import CanonicalSection
from release_engine_v3.registries.platform_registries import (
    DOCUMENT_TYPE_SCHEMA_REGISTRY,
)


def governance_model_section_order() -> Tuple[str, ...]:
    """Use the registered native schema rather than strategy section slots."""
    return tuple(
        DOCUMENT_TYPE_SCHEMA_REGISTRY['governance_model']['sections'])


def governance_model_blockers(sections: Any) -> List[str]:
    """Require real source strings for every registered governance section.

    Unexpected content is rejected instead of silently dropping it. Private
    metadata keys may accompany the four native sections but are never prose.
    """
    if not isinstance(sections, Mapping):
        return ['rel33_governance_sections_invalid']
    required = governance_model_section_order()
    blockers: List[str] = []
    for key in required:
        value = sections.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            blockers.append(f'rel33_section_missing:{key}')
        elif not isinstance(value, str):
            blockers.append(f'rel33_section_invalid_type:{key}')
    for key in sections:
        if not isinstance(key, str):
            blockers.append('rel33_governance_section_key_invalid')
        elif key not in required and not key.startswith('_'):
            blockers.append(f'rel33_governance_section_unexpected:{key}')
    return list(dict.fromkeys(blockers))


def governance_model_canonical_sections(
        sections: Mapping[str, Any]) -> Dict[str, CanonicalSection]:
    """Retain native Markdown, including the original RACI table header.

    The narrative holds the complete source section. Parsing through the
    strategy table model would discard native keys and invent column headers.
    Invalid or absent strings stay absent for diagnostics; callers keep the
    blockers and refuse generation/export before invoking a writer.
    """
    return {
        key: CanonicalSection(
            key=key, title='', narrative=sections[key], table_rows=())
        for key in governance_model_section_order()
        if isinstance(sections.get(key), str) and sections[key].strip()
    }


def governance_model_markdown(sections: Mapping[str, Any]) -> str:
    """Join exact native section strings in schema order without repairing them."""
    return '\n\n'.join(
        sections[key]
        for key in governance_model_section_order()
        if isinstance(sections.get(key), str) and sections[key].strip())


def governance_model_preview_html(markdown: str) -> str:
    """Render actual source table boundaries; never render separator rows."""
    from release_engine_v3.canonical_document import parse_saved_markdown_structure
    blocks, error = parse_saved_markdown_structure(markdown)
    if error:
        raise ValueError('rel33_governance_source_markdown_invalid')
    html = ['<div class="rel3-preview" data-document-type="governance_model" dir="rtl">']
    for block in blocks:
        if block['kind'] == 'heading':
            level = block['level']
            html.append(f'<h{level}>{escape(block["text"])}</h{level}>')
        elif block['kind'] == 'prose':
            html.append('<p>' + escape(block['text']).replace('\n', '<br>') + '</p>')
        elif block['kind'] == 'table':
            html.append('<table><thead><tr>' + ''.join(
                '<th>' + escape(value) + '</th>' for value in block['header'])
                + '</tr></thead><tbody>')
            for row in block['rows']:
                html.append('<tr>' + ''.join(
                    '<td>' + escape(value) + '</td>' for value in row) + '</tr>')
            html.append('</tbody></table>')
    html.append('</div>')
    return '\n'.join(html)
