"""REL37 Phase 1 supported-framework selection gate."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel37_coverage_registry import normalize_framework_token
from release_engine_v3.rel37_framework_aliases import canonicalize_framework_labels
from release_engine_v3.rel37_schema_registry import (
    DOMAIN_DEFAULT_FRAMEWORKS,
    PHASE1_ALLOWED_FRAMEWORKS,
    PHASE1_DOMAINS,
    PHASE1_LANGS,
)

# Map request aliases onto the Phase 1 canonical codes. Tokens that do not
# resolve here are unsupported for REL37 (no silent subset compile).
_ALIAS_TO_CANONICAL = {
    'ndmo': 'ndmo',
    'ndmo_dga': 'ndmo',
    'national_data_management_office': 'ndmo',
    'pdpl': 'pdpl',
    'personal_data_protection_law': 'pdpl',
    'sdaia': 'sdaia',
    'sdaia_ai_ethics': 'sdaia',
    'national_ai_authority': 'sdaia',
    'dga': 'dga',
    'digital_government_authority': 'dga',
}

_LAST_SELECTION_DIAG: Dict[str, Any] = {}


@dataclass(frozen=True)
class SupportedSelectionResult:
    supported: bool
    reason: str
    normalized_frameworks: Tuple[str, ...]
    default_expanded: bool
    unsupported_frameworks: Tuple[str, ...]
    explicit_selection: bool
    domain: str = ''
    lang: str = ''
    document_type: str = ''
    selected_frameworks_input: Tuple[str, ...] = ()
    selected_frameworks_original: Tuple[str, ...] = ()
    selected_frameworks_canonical: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normalize_lang(value: object) -> str:
    raw = str(value or 'ar').strip().lower()
    if raw.startswith('ar'):
        return 'ar'
    if raw.startswith('en'):
        return 'en'
    return raw


def _canonicalize_token(value: object) -> Tuple[str, Optional[str]]:
    """Return (original_normalized, canonical_or_none)."""
    token = normalize_framework_token(value)
    if not token:
        return '', None
    if token in _ALIAS_TO_CANONICAL:
        return token, _ALIAS_TO_CANONICAL[token]
    # Compact forms such as ncaecc / nistairmf still count as explicit input.
    compact = token.replace('_', '')
    for alias, canonical in _ALIAS_TO_CANONICAL.items():
        if compact == alias.replace('_', ''):
            return token, canonical
    return token, None


def _input_tokens(selected_frameworks: Optional[Iterable[object]]) -> List[str]:
    if selected_frameworks is None:
        return []
    if isinstance(selected_frameworks, str):
        parts = [
            part.strip()
            for part in selected_frameworks.replace('|', ',').split(',')
            if part.strip()
        ]
        return parts
    return [str(item) for item in selected_frameworks if str(item).strip()]


def emit_selection_diagnostic(result: SupportedSelectionResult) -> Dict[str, Any]:
    payload = {
        'domain': result.domain,
        'lang': result.lang,
        'document_type': result.document_type,
        'selected_frameworks_input': list(result.selected_frameworks_input),
        'selected_frameworks_original': list(result.selected_frameworks_original),
        'selected_frameworks_canonical': list(result.selected_frameworks_canonical),
        'explicit_selection': result.explicit_selection,
        'normalized_frameworks': list(result.normalized_frameworks),
        'unsupported_frameworks': list(result.unsupported_frameworks),
        'default_expanded': result.default_expanded,
        'supported': result.supported,
        'reason': result.reason,
    }
    _LAST_SELECTION_DIAG.clear()
    _LAST_SELECTION_DIAG.update(payload)
    print(
        '[REL37-SUPPORTED-FRAMEWORK-SELECTION] '
        + json.dumps(payload, ensure_ascii=False, sort_keys=True),
        flush=True,
    )
    return dict(payload)


def last_selection_diagnostic() -> Dict[str, Any]:
    return dict(_LAST_SELECTION_DIAG)


def rel37_supported_selection(
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Sequence[object]] = None,
        explicit_selection: bool = False,
) -> SupportedSelectionResult:
    """Return whether REL37 may compile this request.

    Frameworks come only from trusted request metadata. Body text is ignored.
    Any unsupported token fails closed — the supported subset is not compiled.
    """
    dcode = normalize_domain_code(str(domain or ''), default='')
    lang_n = _normalize_lang(lang)
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    raw_input = tuple(_input_tokens(selected_frameworks))
    canon = canonicalize_framework_labels(
        raw_input,
        domain=dcode,
        lang=lang_n,
        document_type=dtype,
        explicit_selection=bool(explicit_selection),
        emit=True,
    )

    def _result(
            *,
            supported: bool,
            reason: str,
            normalized: Sequence[str] = (),
            unsupported: Sequence[str] = (),
            default_expanded: bool = False,
    ) -> SupportedSelectionResult:
        out = SupportedSelectionResult(
            supported=supported,
            reason=reason,
            normalized_frameworks=tuple(normalized),
            default_expanded=default_expanded,
            unsupported_frameworks=tuple(unsupported),
            explicit_selection=bool(explicit_selection),
            domain=dcode,
            lang=lang_n,
            document_type=dtype,
            selected_frameworks_input=raw_input,
            selected_frameworks_original=raw_input,
            selected_frameworks_canonical=tuple(normalized),
        )
        emit_selection_diagnostic(out)
        return out

    if dtype not in ('strategy', ''):
        return _result(supported=False, reason='document_type_unsupported')
    if dcode not in PHASE1_DOMAINS:
        return _result(supported=False, reason='domain_not_phase1')
    if lang_n not in PHASE1_LANGS:
        return _result(supported=False, reason='lang_unsupported')

    allowed = tuple(PHASE1_ALLOWED_FRAMEWORKS.get(dcode, ()))
    defaults = tuple(DOMAIN_DEFAULT_FRAMEWORKS.get(dcode, ()))

    if not raw_input:
        if explicit_selection:
            return _result(
                supported=False,
                reason='unsupported_empty_explicit',
            )
        return _result(
            supported=True,
            reason='default_expanded',
            normalized=defaults,
            default_expanded=True,
        )

    normalized = list(canon.selected_frameworks_canonical)
    unsupported = list(canon.unsupported_frameworks)

    if unsupported:
        return _result(
            supported=False,
            reason='unsupported_frameworks',
            normalized=normalized,
            unsupported=unsupported,
        )
    if not normalized:
        return _result(supported=False, reason='unsupported_empty_after_normalize')

    allowed_set = set(allowed)
    if set(normalized) - allowed_set:
        return _result(
            supported=False,
            reason='unsupported_frameworks',
            normalized=normalized,
            unsupported=sorted(set(normalized) - allowed_set),
        )
    return _result(
        supported=True,
        reason='supported_selection',
        normalized=normalized,
    )
