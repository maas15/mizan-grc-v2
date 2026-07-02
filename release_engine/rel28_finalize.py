"""PR-REL2.8 — route-bound export evidence diagnostics (preview/docx/pdf/finalize)."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from release_engine.export_evidence_validator import (
    collect_actual_export_texts,
    validate_actual_export_evidence,
)


def build_route_evidence_diagnostics(
        artifact: Dict[str, Any],
        backend: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        preview_html: str = '',
) -> Dict[str, Any]:
    """Build per-route gate payloads from the same exported byte texts."""
    preview_text, docx_text, pdf_text, pdf_unreliable, pdf_had = (
        collect_actual_export_texts(
            artifact, backend, lang=lang, domain=domain,
            preview_html=preview_html))
    sections = {
        k: v for k, v in (artifact.get('sections') or {}).items()
        if isinstance(v, str) and not str(k).startswith('_')}
    if sections and not preview_html:
        preview_text = '\n\n'.join(
            (sections.get(k) or '').strip()
            for k in (
                'vision', 'pillars', 'environment', 'gaps',
                'roadmap', 'kpis', 'confidence', 'traceability',
            )
            if (sections.get(k) or '').strip())
    hash_fn = backend.get('content_hash')
    final_hash = artifact.get('final_hash') or ''
    routes: Dict[str, Any] = {}
    for route in ('preview', 'docx', 'pdf', 'finalize'):
        routes[route] = validate_actual_export_evidence(
            preview_text,
            docx_text,
            pdf_text,
            domain=domain,
            lang=lang,
            pdf_text_extraction_unreliable=pdf_unreliable,
            pdf_bytes_had=pdf_had,
            route_name=route,
            final_hash=final_hash,
            canonical_sections=sections or None,
            hash_fn=hash_fn,
        )
    return {
        'routes': routes,
        'preview_text_len': len(preview_text or ''),
        'docx_text_len': len(docx_text or ''),
        'pdf_text_len': len(pdf_text or ''),
        'pdf_text_extraction_unreliable': pdf_unreliable,
        'pdf_bytes_had': pdf_had,
    }


def apply_rel28_cyber_route_evidence_finalize(
        artifact: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        backend: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    """Attach REL2.8 per-route evidence snapshots; no artifact mutation."""
    dcode = (domain or artifact.get('domain') or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security') or lang != 'ar':
        return artifact, [], {}
    if not backend.get('validate_export_evidence'):
        return artifact, [], {}

    diag = build_route_evidence_diagnostics(
        artifact, backend, domain=dcode, lang=lang)
    finalize = diag.get('routes', {}).get('finalize') or {}
    routes = diag.get('routes') or {}
    return artifact, [], {
        'route_evidence': diag,
        'preview_route': routes.get('preview') or {},
        'docx_route': routes.get('docx') or {},
        'pdf_route': routes.get('pdf') or {},
        'finalize_route': finalize,
        'route_bound_evidence_valid': bool(
            finalize.get('route_bound_evidence_valid')),
        'export_return_allowed': bool(finalize.get('export_return_allowed')),
    }


def rel28_blocking_errors(diags: Dict[str, Any]) -> List[str]:
    fin = diags.get('finalize_route') or {}
    if fin.get('export_return_allowed'):
        return []
    return list(fin.get('blocking_errors') or [])
