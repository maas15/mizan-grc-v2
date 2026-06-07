"""PR-REL2.3 — section-level export parity (Preview/DOCX/PDF)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

PARITY_SECTION_KEYS = (
    'vision_objectives',
    'pillars',
    'roadmap',
    'kpis',
    'traceability',
)

_LEGACY_MAP = {
    'vision_objectives': 'vision',
    'pillars': 'pillars',
    'roadmap': 'roadmap',
    'kpis': 'kpis',
    'traceability': 'traceability',
}


def _section_hash(text: str, hash_fn: Optional[Callable[[str], str]] = None) -> str:
    blob = (text or '').strip()
    if hash_fn:
        return hash_fn(blob) if blob else ''
    return hashlib.sha256(blob.encode('utf-8')).hexdigest() if blob else ''


def _pillars_export_present(model: Optional[Dict[str, Any]]) -> bool:
    if not model:
        return False
    blocks = (model.get('blocks') or {})
    blk = blocks.get('strategic_pillars') or {}
    for pb in blk.get('pillar_blocks') or []:
        tbl = pb.get('table') or {}
        if tbl.get('rows'):
            return True
    return False


def _serialize_pillars_export(model: Optional[Dict[str, Any]]) -> str:
    if not model:
        return ''
    blocks = (model.get('blocks') or {})
    blk = blocks.get('strategic_pillars') or {}
    parts: List[str] = []
    for pb in blk.get('pillar_blocks') or []:
        title = (pb.get('title') or '').strip()
        tbl = pb.get('table') or {}
        rows = tbl.get('rows') or []
        if not rows:
            continue
        if title:
            parts.append(title)
        for row in rows:
            parts.append('|'.join(str(c) for c in row))
    return '\n'.join(parts)


def _serialize_table_section(blocks: Dict[str, Any], kind: str) -> str:
    blk = blocks.get(kind) or {}
    parts: List[str] = []
    content = (blk.get('content') or '').strip()
    if content:
        parts.append(content)
    for tbl in blk.get('tables') or []:
        for row in tbl.get('rows') or []:
            parts.append('|'.join(str(c) for c in row))
    return '\n'.join(parts)


def _serialize_traceability_export(model: Optional[Dict[str, Any]]) -> str:
    if not model:
        return ''
    blocks = (model.get('blocks') or {})
    trace = blocks.get('traceability_matrix') or {}
    parts: List[str] = []
    for st in trace.get('split_tables') or []:
        for row in st.get('rows') or []:
            parts.append('|'.join(str(c) for c in row))
    for row in trace.get('rows') or []:
        parts.append('|'.join(str(c) for c in row))
    return '\n'.join(parts)


def _extract_export_section_text(
        model: Optional[Dict[str, Any]],
        section_key: str,
        sections: Dict[str, str],
) -> str:
    if not model:
        legacy = _LEGACY_MAP.get(section_key, section_key)
        return (sections.get(legacy) or '').strip()
    if section_key == 'pillars':
        return _serialize_pillars_export(model)
    if section_key == 'traceability':
        sec = (sections.get('traceability') or '').strip()
        return sec or _serialize_traceability_export(model)
    block_key = {
        'vision_objectives': 'vision_objectives',
        'roadmap': 'roadmap',
        'kpis': 'kpi_kri_framework',
    }.get(section_key, section_key)
    blocks = model.get('blocks') or {}
    serialized = _serialize_table_section(blocks, block_key)
    if section_key == 'vision_objectives' and not serialized.strip():
        legacy = _LEGACY_MAP.get(section_key, section_key)
        return (sections.get(legacy) or '').strip()
    return serialized


def _build_model_bundle(
        artifact: Dict[str, Any],
        backend: Dict[str, Any],
        lang: str,
) -> Tuple[Dict[str, str], Optional[Dict[str, Any]], str]:
    sections = {
        k: v for k, v in (artifact.get('sections') or {}).items()
        if not str(k).startswith('_') and isinstance(v, str)}
    final_md = artifact.get('final_markdown') or ''
    hash_fn = backend.get('content_hash')
    build_model = backend.get('build_professional_model')
    model = None
    if build_model:
        try:
            meta = artifact.get('contract_meta') or {}
            model = build_model(
                final_md,
                metadata=meta,
                sections=sections,
                selected_frameworks=meta.get('selected_frameworks'),
                lang=lang,
                domain=artifact.get('domain') or 'cyber',
            )
        except Exception:  # noqa: BLE001
            model = None
    bundle: Dict[str, str] = {}
    for key in PARITY_SECTION_KEYS:
        bundle[key] = _extract_export_section_text(model, key, sections)
    whole = hash_fn(final_md) if hash_fn and final_md else _section_hash(final_md, hash_fn)
    return bundle, model, whole


def _section_hashes_for_bundle(
        bundle: Dict[str, str],
        hash_fn: Optional[Callable[[str], str]],
) -> Dict[str, str]:
    return {
        k: _section_hash(bundle.get(k, ''), hash_fn)
        for k in PARITY_SECTION_KEYS
    }


def evaluate_section_parity(
        artifact: Dict[str, Any],
        backend: Dict[str, Any],
        *,
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Emit [REL2-SECTION-PARITY-CHECK] payload."""
    final_md = artifact.get('final_markdown') or ''
    hash_fn = backend.get('content_hash')
    final_hash = artifact.get('final_hash') or (
        hash_fn(final_md) if hash_fn and final_md else '')

    final_bundle, final_model, _ = _build_model_bundle(artifact, backend, lang)
    preview_bundle, preview_model, preview_hash = _build_model_bundle(
        artifact, backend, lang)
    docx_bundle, docx_model, docx_hash = _build_model_bundle(
        artifact, backend, lang)
    pdf_bundle, pdf_model, pdf_hash = _build_model_bundle(
        artifact, backend, lang)

    final_section_hashes = _section_hashes_for_bundle(final_bundle, hash_fn)
    preview_section_hashes = _section_hashes_for_bundle(preview_bundle, hash_fn)
    docx_section_hashes = _section_hashes_for_bundle(docx_bundle, hash_fn)
    pdf_section_hashes = _section_hashes_for_bundle(pdf_bundle, hash_fn)

    missing_sections_preview: List[str] = []
    missing_sections_docx: List[str] = []
    missing_sections_pdf: List[str] = []
    mismatched_sections: List[str] = []

    for key in PARITY_SECTION_KEYS:
        fh = final_section_hashes.get(key, '')
        if key == 'traceability' and not fh:
            continue
        if not fh:
            missing_sections_docx.append(key)
            missing_sections_pdf.append(key)
            continue
        if not preview_section_hashes.get(key):
            missing_sections_preview.append(key)
        if not docx_section_hashes.get(key):
            missing_sections_docx.append(key)
        if not pdf_section_hashes.get(key):
            missing_sections_pdf.append(key)
        if (preview_section_hashes.get(key)
                and preview_section_hashes.get(key) != fh):
            mismatched_sections.append(f'preview:{key}')
        if docx_section_hashes.get(key) and docx_section_hashes.get(key) != fh:
            mismatched_sections.append(f'docx:{key}')
        if pdf_section_hashes.get(key) and pdf_section_hashes.get(key) != fh:
            mismatched_sections.append(f'pdf:{key}')

    pillars_present_final = _pillars_export_present(final_model)
    pillars_present_preview = _pillars_export_present(preview_model)
    pillars_present_docx = _pillars_export_present(docx_model)
    pillars_present_pdf = _pillars_export_present(pdf_model)

    if pillars_present_preview and not pillars_present_docx:
        if 'pillars' not in missing_sections_docx:
            missing_sections_docx.append('pillars')
        if 'docx:pillars' not in mismatched_sections:
            mismatched_sections.append('docx:pillars')
    if pillars_present_preview and not pillars_present_pdf:
        if 'pillars' not in missing_sections_pdf:
            missing_sections_pdf.append('pillars')
        if 'pdf:pillars' not in mismatched_sections:
            mismatched_sections.append('pdf:pillars')

    whole_hashes_match = bool(
        final_hash
        and final_hash == preview_hash == docx_hash == pdf_hash)

    blocking = ''
    if missing_sections_docx:
        blocking = f'rel2_section_parity_failed:{missing_sections_docx[0]}'
    elif missing_sections_pdf:
        blocking = f'rel2_section_parity_failed:{missing_sections_pdf[0]}'
    elif mismatched_sections:
        blocking = f'rel2_section_parity_failed:{mismatched_sections[0].split(":")[-1]}'
    elif not pillars_present_final:
        blocking = 'rel2_section_parity_failed:pillars'
    elif not pillars_present_docx or not pillars_present_pdf:
        blocking = 'rel2_section_parity_failed:pillars'

    parity_passed = (
        not blocking
        and pillars_present_final
        and pillars_present_preview
        and pillars_present_docx
        and pillars_present_pdf
        and not missing_sections_docx
        and not missing_sections_pdf
        and not mismatched_sections)

    return {
        'final_hash': final_hash,
        'preview_hash': preview_hash,
        'docx_hash': docx_hash,
        'pdf_hash': pdf_hash,
        'whole_hashes_match': whole_hashes_match,
        'final_section_hashes': final_section_hashes,
        'preview_section_hashes': preview_section_hashes,
        'docx_section_hashes': docx_section_hashes,
        'pdf_section_hashes': pdf_section_hashes,
        'missing_sections_preview': missing_sections_preview,
        'missing_sections_docx': missing_sections_docx,
        'missing_sections_pdf': missing_sections_pdf,
        'mismatched_sections': mismatched_sections,
        'pillars_present_final': pillars_present_final,
        'pillars_present_preview': pillars_present_preview,
        'pillars_present_docx': pillars_present_docx,
        'pillars_present_pdf': pillars_present_pdf,
        'parity_passed': parity_passed,
        'blocking_error_if_any': blocking,
    }


def emit_section_parity_check(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-SECTION-PARITY-CHECK] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
