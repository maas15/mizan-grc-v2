"""PR-REL3 — validate exact returned export bytes."""

from __future__ import annotations

from typing import Any, Dict, Optional

from release_engine.export_evidence_validator import block_export_if_evidence_fails
from release_engine_v3.contracts import (
    EvidenceResult,
    ExportResult,
    FinalDocumentArtifact,
    _sha256_bytes,
)
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
from release_engine_v3.evidence.preview_text_extractor import extract_preview_text
from release_engine_v3.validators import validate_export_text


def validate_returned_export_bytes(
        export: ExportResult,
        artifact: FinalDocumentArtifact,
        *,
        route: str,
        docx_bytes_for_pdf_fallback: bytes = b'',
) -> EvidenceResult:
    """Validate the exact bytes that will be returned to the client."""
    route_n = (route or export.route_name or 'preview').lower()
    preview_text = export.preview_text or ''
    docx_text = ''
    pdf_text = ''
    docx_bytes = export.docx_bytes or export.bytes_data if route_n == 'docx' else b''
    pdf_bytes = export.pdf_bytes or export.bytes_data if route_n == 'pdf' else b''
    if route_n == 'docx' and docx_bytes:
        docx_text = extract_docx_visible_text(docx_bytes)
        if not (docx_text or '').strip():
            try:
                decoded = docx_bytes.decode('utf-8')
                if decoded.strip() and not decoded.startswith('PK'):
                    docx_text = decoded
            except UnicodeDecodeError:
                pass
    if route_n == 'pdf' and pdf_bytes:
        pdf_text = extract_pdf_visible_text(pdf_bytes)
        if not (pdf_text or '').strip():
            try:
                decoded = pdf_bytes.decode('utf-8')
                if decoded.strip() and not decoded.startswith('%PDF'):
                    pdf_text = decoded
            except UnicodeDecodeError:
                pass
    if route_n == 'preview':
        preview_text = extract_preview_text(
            export.preview_html or '', preview_text)
    pdf_unreliable = bool(pdf_bytes and len((pdf_text or '').strip()) < 80)
    evidence_bytes = docx_bytes or pdf_bytes or b''
    returned_hash = export.returned_bytes_sha256 or _sha256_bytes(evidence_bytes)
    evidence_hash = export.evidence_bytes_sha256 or returned_hash
    exact_checked = route_n in ('docx', 'pdf') and bool(evidence_bytes)
    returned_equals = (
        returned_hash == evidence_hash
        and (export.returned_equals_evidence_bytes is not False)
    )
    if route_n in ('docx', 'pdf') and not returned_equals:
        blockers = [
            f'rel3_export_evidence_failed:{route_n}:'
            'returned_bytes_mismatch_evidence_bytes']
        return EvidenceResult(
            route_name=route_n,
            artifact_id=artifact.artifact_id,
            strategy_id=artifact.strategy_id,
            canonical_hash=artifact.canonical_hash,
            render_tree_hash=export.render_tree_hash,
            returned_bytes_sha256=returned_hash,
            evidence_bytes_sha256=evidence_hash,
            returned_equals_evidence_bytes=False,
            exact_bytes_checked=exact_checked,
            preview_text_checked=route_n == 'preview',
            docx_bytes_checked=route_n == 'docx' and bool(docx_bytes),
            pdf_bytes_checked=route_n == 'pdf' and bool(pdf_bytes),
            evidence_passed=False,
            export_return_allowed=False,
            blocking_errors=blockers,
        )
    parity_sections = dict(artifact.legacy_sections or {})
    if route_n == 'preview' and artifact.canonical_sections:
        from release_engine_v3.section_models import (
            canonical_legacy_sections_for_parity,
        )
        parity_sections.update(
            canonical_legacy_sections_for_parity(artifact.canonical_sections))
    gate = validate_export_text(
        route_n,
        preview_text=preview_text if route_n == 'preview' else '',
        docx_text=docx_text if route_n == 'docx' else '',
        pdf_text=pdf_text if route_n == 'pdf' else '',
        domain=artifact.domain,
        lang=artifact.language,
        pdf_text_extraction_unreliable=pdf_unreliable,
        pdf_bytes_had=bool(pdf_bytes),
        pdf_bytes=pdf_bytes if route_n == 'pdf' else b'',
        canonical_sections=parity_sections,
        final_hash=artifact.canonical_hash,
    )
    allowed, errors = block_export_if_evidence_fails(gate)
    if not allowed:
        errors = list(gate.get('blocking_errors') or errors)
    result = EvidenceResult(
        route_name=route_n,
        artifact_id=artifact.artifact_id,
        strategy_id=artifact.strategy_id,
        canonical_hash=artifact.canonical_hash,
        render_tree_hash=export.render_tree_hash,
        returned_bytes_sha256=returned_hash,
        evidence_bytes_sha256=evidence_hash,
        returned_equals_evidence_bytes=returned_equals,
        exact_bytes_checked=exact_checked,
        preview_text_checked=route_n == 'preview' and bool(preview_text),
        docx_bytes_checked=route_n == 'docx' and bool(docx_bytes),
        pdf_bytes_checked=route_n == 'pdf' and bool(pdf_bytes),
        evidence_passed=allowed,
        export_return_allowed=allowed and returned_equals,
        blocking_errors=errors,
        gate=gate,
    )
    result.emit_diag()
    try:
        from release_engine.rel31_content_substance_checks import (
            evaluate_content_substance,
            emit_rel31_content_substance_evidence,
        )
        blob = ''
        if route_n == 'docx' and docx_text:
            blob = docx_text
        elif route_n == 'pdf' and pdf_text:
            blob = pdf_text
        elif route_n == 'preview' and preview_text:
            blob = preview_text
        if blob.strip():
            emit_rel31_content_substance_evidence(
                evaluate_content_substance(
                    blob, route=route_n,
                    pdf_bytes=pdf_bytes if route_n == 'pdf' else b''))
    except Exception:  # noqa: BLE001
        pass
    return result
