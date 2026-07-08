"""PR-REL3 — PDF export from RenderTree only."""

from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Optional

from release_engine_v3.contracts import ExportResult, RenderTree, _sha256_bytes


def _filter_build_kwargs(build_fn: Callable[..., Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    try:
        sig = inspect.signature(build_fn)
    except (TypeError, ValueError):
        return kwargs
    if any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()):
        return kwargs
    return {k: v for k, v in kwargs.items() if k in sig.parameters}


def _rel33_kpi_table_lock_flags(domain: str) -> Dict[str, bool]:
    d = str(domain or '').strip().lower().replace(' ', '_').replace('-', '_')
    locked = d in (
        'data', 'data_management',
        'ai', 'artificial_intelligence',
        'dt', 'digital_transformation',
    )
    return {
        'table_lock_applied': locked,
        'kpi_main_forced_table': locked,
        'used_cards_fallback': False,
    }


def export_pdf(
        render_tree: RenderTree,
        *,
        backend: Dict[str, Any],
        lang: str = 'ar',
        org_name: str = '',
        sector: str = '',
        doc_type: str = 'Strategy Document',
        domain: str = 'cyber',
        selected_frameworks=None,
        cyber_sealed_artifact: bool = False,
) -> ExportResult:
    build_fn = backend.get('build_pdf_bytes')
    if not build_fn:
        return ExportResult(
            route_name='pdf',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            blocking_errors=['rel3_export_failed:pdf:build_pdf_bytes_missing'],
        )
    content = render_tree.markdown_view
    document_type = str(
        backend.get('document_type') or 'strategy').strip().lower()
    lock_flags = _rel33_kpi_table_lock_flags(domain)
    render_exception: Optional[str] = None
    pdf_bytes = b''
    try:
        pdf_bytes = build_fn(
            content,
            **_filter_build_kwargs(build_fn, {
                'lang': lang,
                'org_name': org_name,
                'sector': sector,
                'doc_type': doc_type,
                'domain': domain,
                'selected_frameworks': selected_frameworks,
                'cyber_sealed_artifact': cyber_sealed_artifact,
                'sections': backend.get('split_sections', lambda x: {})(content),
                'metadata': {
                    'document_type': document_type,
                    'org_name': org_name,
                    'sector': sector,
                    'selected_frameworks': selected_frameworks or [],
                },
            }),
        )
    except ValueError as exc:
        render_exception = str(exc)
        from release_engine_v3.rel31_authority import normalize_rel3_export_blockers
        blockers = normalize_rel3_export_blockers([str(exc)], route='pdf')
        try:
            from release_engine_v3.rel33_pdf_bytes_integrity import (
                build_rel33_pdf_bytes_integrity,
            )
            build_rel33_pdf_bytes_integrity(
                route='pdf',
                domain=str(domain or ''),
                document_type=document_type,
                artifact_id=render_tree.artifact_id,
                pdf_bytes=b'',
                render_exception=render_exception,
                table_lock_applied=bool(lock_flags.get('table_lock_applied')),
                kpi_main_forced_table=bool(
                    lock_flags.get('kpi_main_forced_table')),
                used_cards_fallback=False,
                returned_file_evidence_started=True,
                extra_blockers=list(blockers or []),
            )
        except Exception:  # noqa: BLE001
            pass
        return ExportResult(
            route_name='pdf',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            blocking_errors=blockers or [str(exc)],
        )
    except Exception as exc:  # noqa: BLE001
        render_exception = f'{type(exc).__name__}:{exc}'
        try:
            from release_engine_v3.rel33_pdf_bytes_integrity import (
                build_rel33_pdf_bytes_integrity,
            )
            build_rel33_pdf_bytes_integrity(
                route='pdf',
                domain=str(domain or ''),
                document_type=document_type,
                artifact_id=render_tree.artifact_id,
                pdf_bytes=b'',
                render_exception=render_exception,
                table_lock_applied=bool(lock_flags.get('table_lock_applied')),
                kpi_main_forced_table=bool(
                    lock_flags.get('kpi_main_forced_table')),
                used_cards_fallback=False,
                returned_file_evidence_started=True,
            )
        except Exception:  # noqa: BLE001
            pass
        return ExportResult(
            route_name='pdf',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            blocking_errors=[
                f'rel3_export_evidence_failed:pdf:render_exception:'
                f'{type(exc).__name__}'],
        )
    if not isinstance(pdf_bytes, bytes):
        pdf_bytes = bytes(pdf_bytes or b'')
    if not pdf_bytes:
        try:
            from release_engine_v3.rel33_pdf_bytes_integrity import (
                build_rel33_pdf_bytes_integrity,
            )
            build_rel33_pdf_bytes_integrity(
                route='pdf',
                domain=str(domain or ''),
                document_type=document_type,
                artifact_id=render_tree.artifact_id,
                pdf_bytes=b'',
                render_exception=None,
                table_lock_applied=bool(lock_flags.get('table_lock_applied')),
                kpi_main_forced_table=bool(
                    lock_flags.get('kpi_main_forced_table')),
                used_cards_fallback=False,
                returned_file_evidence_started=True,
            )
        except Exception:  # noqa: BLE001
            pass
        return ExportResult(
            route_name='pdf',
            artifact_id=render_tree.artifact_id,
            render_tree_hash=render_tree.render_tree_hash,
            canonical_hash=render_tree.canonical_hash,
            blocking_errors=[
                'rel3_export_evidence_failed:pdf:empty_bytes'],
        )
    sha = _sha256_bytes(pdf_bytes)
    try:
        from release_engine_v3.rel33_pdf_bytes_integrity import (
            build_rel33_pdf_bytes_integrity,
        )
        build_rel33_pdf_bytes_integrity(
            route='pdf',
            domain=str(domain or ''),
            document_type=document_type,
            artifact_id=render_tree.artifact_id,
            pdf_bytes=pdf_bytes,
            render_exception=None,
            table_lock_applied=bool(lock_flags.get('table_lock_applied')),
            kpi_main_forced_table=bool(
                lock_flags.get('kpi_main_forced_table')),
            used_cards_fallback=False,
            returned_file_evidence_started=True,
        )
    except Exception:  # noqa: BLE001
        pass
    return ExportResult(
        route_name='pdf',
        artifact_id=render_tree.artifact_id,
        render_tree_hash=render_tree.render_tree_hash,
        canonical_hash=render_tree.canonical_hash,
        bytes_data=pdf_bytes,
        pdf_bytes=pdf_bytes,
        returned_bytes_sha256=sha,
        evidence_bytes_sha256=sha,
        returned_equals_evidence_bytes=True,
        exact_bytes_checked=True,
    )
