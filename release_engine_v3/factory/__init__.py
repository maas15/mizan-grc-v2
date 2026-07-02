"""Final Document Factory public API."""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = [
    'CanonicalDocumentFactory',
    'CompileResult',
    'DocumentRequestContext',
    'emit_factory_diag',
]

if TYPE_CHECKING:
    from release_engine_v3.factory.canonical_document_factory import (
        CanonicalDocumentFactory as CanonicalDocumentFactory,
        CompileResult as CompileResult,
        emit_factory_diag as emit_factory_diag,
    )
    from release_engine_v3.factory.request_context import (
        DocumentRequestContext as DocumentRequestContext,
    )


def __getattr__(name: str):
    if name in ('CanonicalDocumentFactory', 'CompileResult', 'emit_factory_diag'):
        from release_engine_v3.factory import canonical_document_factory as _mod
        return getattr(_mod, name)
    if name == 'DocumentRequestContext':
        from release_engine_v3.factory.request_context import DocumentRequestContext
        return DocumentRequestContext
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
