"""PR-REL3 — canonical artifact and export contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    if not data:
        return ''
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class TableRow:
    """One typed table row — not a pipe-table string."""
    cells: tuple


@dataclass(frozen=True)
class CanonicalSection:
    key: str
    title: str
    narrative: str
    table_rows: tuple = ()
    metadata: tuple = ()


@dataclass
class ExportManifest:
    routes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    render_tree_hash: str = ''
    canonical_hash: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'routes': dict(self.routes),
            'render_tree_hash': self.render_tree_hash,
            'canonical_hash': self.canonical_hash,
        }


@dataclass
class FinalDocumentArtifact:
    artifact_id: str
    domain: str
    language: str
    document_type: str
    strategy_type: str
    selected_frameworks: List[str]
    canonical_sections: Dict[str, CanonicalSection]
    quality_repairs: List[str]
    quality_results: Dict[str, Any]
    frozen: bool
    canonical_hash: str
    render_tree_hash: str
    export_manifest: ExportManifest
    blocking_errors: List[str]
    release_ready_final_passed: bool
    strategy_id: str = ''
    legacy_sections: Dict[str, str] = field(default_factory=dict)
    final_markdown_view: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'artifact_id': self.artifact_id,
            'strategy_id': self.strategy_id,
            'domain': self.domain,
            'language': self.language,
            'document_type': self.document_type,
            'strategy_type': self.strategy_type,
            'selected_frameworks': list(self.selected_frameworks),
            'canonical_sections': {
                k: {
                    'key': v.key,
                    'title': v.title,
                    'narrative': v.narrative,
                    'table_rows': [list(r.cells) for r in v.table_rows],
                }
                for k, v in (self.canonical_sections or {}).items()
            },
            'quality_repairs': list(self.quality_repairs),
            'quality_results': dict(self.quality_results),
            'frozen': self.frozen,
            'canonical_hash': self.canonical_hash,
            'render_tree_hash': self.render_tree_hash,
            'export_manifest': self.export_manifest.to_dict(),
            'blocking_errors': list(self.blocking_errors),
            'release_ready_final_passed': self.release_ready_final_passed,
            'legacy_sections': dict(self.legacy_sections),
        }


@dataclass
class RenderTree:
    artifact_id: str
    canonical_hash: str
    render_tree_hash: str
    nodes: List[Dict[str, Any]]
    markdown_view: str
    preview_html: str = ''

    def section_hashes(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for node in self.nodes:
            key = node.get('key') or ''
            body = node.get('rendered_text') or ''
            if key:
                out[key] = _sha256_text(body)
        return out


@dataclass
class ExportResult:
    route_name: str
    artifact_id: str
    render_tree_hash: str
    canonical_hash: str
    bytes_data: bytes = b''
    preview_html: str = ''
    preview_text: str = ''
    docx_bytes: bytes = b''
    pdf_bytes: bytes = b''
    returned_bytes_sha256: str = ''
    evidence_bytes_sha256: str = ''
    returned_equals_evidence_bytes: bool = False
    exact_bytes_checked: bool = False
    blocking_errors: List[str] = field(default_factory=list)


@dataclass
class EvidenceResult:
    route_name: str
    artifact_id: str
    strategy_id: str
    canonical_hash: str
    render_tree_hash: str
    returned_bytes_sha256: str
    evidence_bytes_sha256: str
    returned_equals_evidence_bytes: bool
    exact_bytes_checked: bool
    preview_text_checked: bool
    docx_bytes_checked: bool
    pdf_bytes_checked: bool
    evidence_passed: bool
    export_return_allowed: bool
    blocking_errors: List[str]
    gate: Dict[str, Any] = field(default_factory=dict)

    def emit_diag(self) -> Dict[str, Any]:
        payload = {
            'route_name': self.route_name,
            'artifact_id': self.artifact_id,
            'strategy_id': self.strategy_id,
            'canonical_hash': self.canonical_hash,
            'render_tree_hash': self.render_tree_hash,
            'returned_bytes_sha256': self.returned_bytes_sha256,
            'evidence_bytes_sha256': self.evidence_bytes_sha256,
            'returned_equals_evidence_bytes': self.returned_equals_evidence_bytes,
            'exact_bytes_checked': self.exact_bytes_checked,
            'preview_text_checked': self.preview_text_checked,
            'docx_bytes_checked': self.docx_bytes_checked,
            'pdf_bytes_checked': self.pdf_bytes_checked,
            'evidence_passed': self.evidence_passed,
            'export_return_allowed': self.export_return_allowed,
            'blocking_errors': list(self.blocking_errors),
        }
        print(
            '[REL3-RETURNED-FILE-EVIDENCE] '
            + json.dumps(payload, ensure_ascii=False),
            flush=True,
        )
        return payload


def compute_canonical_hash(sections: Dict[str, CanonicalSection]) -> str:
    blob = json.dumps(
        {
            k: {
                'narrative': v.narrative,
                'rows': [list(r.cells) for r in v.table_rows],
            }
            for k, v in sorted((sections or {}).items())
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return _sha256_text(blob)


def compute_render_tree_hash(nodes: List[Dict[str, Any]]) -> str:
    blob = json.dumps(nodes, ensure_ascii=False, sort_keys=True)
    return _sha256_text(blob)
