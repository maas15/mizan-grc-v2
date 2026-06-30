"""Canonical Document Factory — platform-wide compile/freeze/export authority."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.factory.post_render_guard import (
    emit_post_render_guard_diag,
    verify_immutable_traceability_routes,
)
from release_engine_v3.factory.request_context import DocumentRequestContext
from release_engine_v3.registries.platform_registries import (
    immutable_traceability_row,
    resolve_registries,
)


@dataclass
class CompileResult:
    canonical_document: Any
    final_artifact: Any = None
    render_tree: Any = None
    legacy_sections: Dict[str, str] = field(default_factory=dict)
    export_evidence: Dict[str, Any] = field(default_factory=dict)
    blocking_errors: List[str] = field(default_factory=list)


class CanonicalDocumentFactory:
    """Single entry: raw AI → canonical → frozen artifact → render tree."""

    def compile(
            self,
            raw_ai_output: Dict[str, str],
            *,
            domain: str,
            document_type: str,
            lang: str,
            request_context: Optional[DocumentRequestContext] = None,
    ) -> CompileResult:
        ctx = request_context or DocumentRequestContext(
            domain=domain,
            document_type=document_type,
            lang=lang,
        )
        dcode = ctx.normalized_domain()
        dtype = ctx.normalized_document_type()
        registries = resolve_registries(
            domain=dcode, document_type=dtype, lang=lang)

        sections = dict(raw_ai_output or {})
        blocking: List[str] = []
        canonical_doc = None
        artifact = None

        if dtype == 'strategy' and dcode == 'cyber' and lang == 'ar':
            try:
                from release_engine_v3.rel32_compiler import (
                    compile_canonical_strategy_document,
                    is_rel32_compiler_first,
                )
                flags = ctx.flags or {}
                if is_rel32_compiler_first(
                        domain=dcode, lang=lang, flags=flags):
                    compiled = compile_canonical_strategy_document(
                        sections,
                        request_context={
                            'lang': lang,
                            'domain': dcode,
                            'backend': ctx.backend,
                            'flags': flags,
                        },
                    )
                    sections = dict(compiled.legacy_sections or sections)
                    canonical_doc = compiled.document
                    blocking.extend(compiled.blocking_errors or [])
            except Exception as exc:  # noqa: BLE001
                blocking.append(f'compiler_first_failed:{exc}')

        try:
            from release_engine_v3.canonical_document import (
                build_final_document_artifact,
            )
            legacy_art = {
                'sections': sections,
                'domain': dcode,
                'language': lang,
                'strategy_id': ctx.strategy_id or ctx.artifact_id,
                'contract_meta': {
                    'lang': lang,
                    'domain': dcode,
                    'selected_frameworks': ctx.frameworks,
                },
                '_rel32_backend': ctx.backend,
            }
            artifact = build_final_document_artifact(
                legacy_art,
                strategy_id=ctx.strategy_id or ctx.artifact_id,
            )
            if canonical_doc is None:
                canonical_doc = artifact
        except Exception as exc:  # noqa: BLE001
            blocking.append(f'artifact_build_failed:{exc}')

        frozen_trace = [
            immutable_traceability_row(fam)
            for fam in registries.get('traceability', {})
            if immutable_traceability_row(fam)
        ]

        return CompileResult(
            canonical_document=canonical_doc,
            final_artifact=artifact,
            legacy_sections=sections,
            export_evidence={
                'registries': {
                    'domain': dcode,
                    'document_type': dtype,
                    'lang': lang,
                },
                'immutable_traceability_rows': frozen_trace,
            },
            blocking_errors=blocking,
        )

    def evaluate_quality(
            self,
            compile_result: CompileResult,
            *,
            preview_text: str = '',
            docx_text: str = '',
            pdf_text: str = '',
            pdf_bytes: bytes = b'',
            domain: str = 'cyber',
            document_type: str = 'strategy',
            lang: str = 'ar',
    ) -> Dict[str, Any]:
        from release_engine_v3.document_excellence_gate import DocumentExcellenceGate

        return DocumentExcellenceGate.evaluate(
            canonical_document=compile_result.canonical_document,
            render_tree=compile_result.render_tree,
            preview_text=preview_text,
            docx_text=docx_text,
            pdf_text=pdf_text,
            domain=domain,
            document_type=document_type,
            lang=lang,
            pdf_bytes=pdf_bytes,
        )

    def export(
            self,
            route: str,
            compile_result: CompileResult,
            *,
            backend: Dict[str, Any],
            kwargs: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Any, Dict[str, Any]]:
        """Export one route from frozen canonical artifact (no raw markdown)."""
        from release_engine_v3.rel31_authority import rel3_export_authoritative

        kw = dict(kwargs or {})
        art = compile_result.final_artifact
        if art is None:
            return None, {
                'export_return_allowed': False,
                'blocking_errors': ['no_final_artifact'],
            }
        legacy = compile_result.legacy_sections
        content = '\n\n'.join(
            v for v in legacy.values() if isinstance(v, str) and v.strip())
        result = rel3_export_authoritative(
            route,
            content,
            artifact=art if isinstance(art, dict) else {},
            backend=backend,
            **kw,
        )
        evidence = result.get('evidence') or {}
        trace_guard = verify_immutable_traceability_routes(
            preview_text=evidence.get('preview_text') or '',
            docx_text=evidence.get('docx_text') or '',
            pdf_text=evidence.get('pdf_text') or '',
        )
        emit_post_render_guard_diag({
            'route': route,
            'trace_guard_passed': trace_guard.get('passed'),
            'blocking': trace_guard.get('blocking_errors') or [],
        })
        if not trace_guard.get('passed'):
            evidence['export_return_allowed'] = False
            evidence.setdefault('blocking_errors', []).extend(
                trace_guard.get('blocking_errors') or [])
        return result, evidence


def emit_factory_diag(payload: Dict[str, Any]) -> None:
    try:
        print(
            f'[FINAL-DOC-FACTORY] {json.dumps(payload, ensure_ascii=False)}',
            flush=True)
    except Exception:  # noqa: BLE001
        pass
