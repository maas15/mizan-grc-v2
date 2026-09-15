"""REL37.0.5 — canonicalize live UI framework display labels.

Trusted request metadata only. Body text is never used. Exact alias
matches plus short IDs. Unsupported labels stay unsupported; mixed
explicit selections are not silently subset-compiled.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel37_schema_registry import PHASE1_ALLOWED_FRAMEWORKS

DIAGNOSTIC_TAG = '[REL37-FRAMEWORK-LABEL-CANONICALIZATION]'

CANONICAL_IDS = ('ndmo', 'pdpl', 'sdaia', 'dga')

REL37_ORIGINAL_FW_KEY = '_rel37_selected_frameworks_original'
REL37_CANONICAL_FW_KEY = '_rel37_selected_frameworks_canonical'

_LAST_CANON_DIAG: Dict[str, Any] = {}

_PUNCT_RE = re.compile(r'[^\w\u0600-\u06FF]+', flags=re.UNICODE)
_WS_RE = re.compile(r'\s+')

# Exact lookup keys after lookup_key(). Do not use loose substring matches.
_ALIAS_TO_CANONICAL: Dict[str, str] = {
    # NDMO
    'ndmo': 'ndmo',
    'ndmo dga': 'ndmo',
    'ndmo data governance framework': 'ndmo',
    'ndmo data management framework': 'ndmo',
    'national data management office': 'ndmo',
    'sdaia ndmo': 'ndmo',
    'sdaia/ndmo': 'ndmo',
    'مكتب إدارة البيانات': 'ndmo',
    'اطار حوكمة البيانات': 'ndmo',
    'إطار حوكمة البيانات': 'ndmo',
    'اطار إدارة البيانات الوطنية': 'ndmo',
    'إطار إدارة البيانات الوطنية': 'ndmo',
    'اطار مكتب إدارة البيانات': 'ndmo',
    'إطار مكتب إدارة البيانات': 'ndmo',
    'اطار حوكمة البيانات مكتب إدارة البيانات الوطنية': 'ndmo',
    'إطار حوكمة البيانات مكتب إدارة البيانات الوطنية': 'ndmo',
    'اطار حوكمة البيانات مكتب إدارة البيانات الوطنية ndmo': 'ndmo',
    'إطار حوكمة البيانات مكتب إدارة البيانات الوطنية ndmo': 'ndmo',
    # PDPL
    'pdpl': 'pdpl',
    'pdpl personal data protection law': 'pdpl',
    'personal data protection law': 'pdpl',
    'personal data protection law pdpl': 'pdpl',
    'ksa pdpl': 'pdpl',
    'saudi pdpl': 'pdpl',
    'نظام حماية البيانات الشخصية': 'pdpl',
    'قانون حماية البيانات الشخصية': 'pdpl',
    'حماية البيانات الشخصية': 'pdpl',
    'نظام حماية البيانات الشخصية pdpl': 'pdpl',
    # SDAIA
    'sdaia': 'sdaia',
    'sdaia ai ethics': 'sdaia',
    'sdaia ai ethics principles': 'sdaia',
    'sdaia ai ethics and governance principles': 'sdaia',
    'sdaia ai ethics governance principles': 'sdaia',
    'sdaia ai governance framework': 'sdaia',
    'sdaia responsible ai': 'sdaia',
    'sdaia responsible ai framework': 'sdaia',
    'national ai authority': 'sdaia',
    'مبادئ أخلاقيات الذكاء الاصطناعي': 'sdaia',
    'مبادئ سدايا': 'sdaia',
    'سدايا': 'sdaia',
    'اطار أخلاقيات الذكاء الاصطناعي سدايا': 'sdaia',
    'إطار أخلاقيات الذكاء الاصطناعي سدايا': 'sdaia',
    'اطار أخلاقيات الذكاء الاصطناعي سدايا sdaia': 'sdaia',
    'إطار أخلاقيات الذكاء الاصطناعي سدايا sdaia': 'sdaia',
    # DGA — Saudi Digital Government Authority, not EU Data Governance Act
    'dga': 'dga',
    'dga digital government framework': 'dga',
    'dga digital government policy': 'dga',
    'dga digital transformation standards': 'dga',
    'digital government authority': 'dga',
    'digital government authority framework': 'dga',
    'digital government framework': 'dga',
    'dga interoperability': 'dga',
    'digital government authority dga': 'dga',
    'هيئة الحكومة الرقمية': 'dga',
    'اطار الحكومة الرقمية': 'dga',
    'إطار الحكومة الرقمية': 'dga',
    'الحكومة الرقمية': 'dga',
}

_UNSUPPORTED_EXACT = frozenset((
    'nca',
    'nca ecc',
    'nca dcc',
    'nca ecc essential cybersecurity controls',
    'nca dcc data cybersecurity controls',
    'nist csf',
    'nist ai rmf',
    'nist ai rmf risk management framework',
    'eu ai act',
    'unesco',
    'unesco ai ethics',
    'iso 27001',
    'iso 27001 2022 isms',
    'sama csf',
    'sama csf cybersecurity framework',
    'gdpr',
    'gdpr general data protection regulation',
    'data governance act',
    'data governance act dga',
    'uae pdpl',
    'uae pdpl personal data protection law',
    'sdaia data classification policy',
))

_UNSUPPORTED_PREFIXES = (
    'nca ',
    'nist ',
    'gdpr ',
    'unesco ',
    'sama ',
    'fedramp',
    'hipaa',
    'iso 27001',
    'eu ai ',
    'uae ',
    'qatar ',
    'bahrain ',
    'oman ',
    'kuwait ',
    'data governance act',
)


def lookup_key(value: object) -> str:
    raw = str(value or '').strip()
    if not raw:
        return ''
    raw = raw.replace('&', ' and ')
    raw = _PUNCT_RE.sub(' ', raw)
    raw = _WS_RE.sub(' ', raw).strip()
    return raw.casefold()


def _input_tokens(selected_frameworks: Optional[Iterable[object]]) -> List[str]:
    if selected_frameworks is None:
        return []
    if isinstance(selected_frameworks, str):
        return [
            part.strip()
            for part in selected_frameworks.replace('|', ',').split(',')
            if part.strip()
        ]
    return [str(item).strip() for item in selected_frameworks if str(item).strip()]


def classify_framework_label(value: object) -> Tuple[Optional[str], str]:
    """Return (canonical_or_none, match_kind)."""
    original = str(value or '').strip()
    key = lookup_key(original)
    if not key:
        return None, 'empty'
    if key in _UNSUPPORTED_EXACT:
        return None, 'unsupported_exact'
    if key.startswith(_UNSUPPORTED_PREFIXES) or any(
            key.startswith(prefix) for prefix in _UNSUPPORTED_PREFIXES):
        return None, 'unsupported_prefix'
    if key in _ALIAS_TO_CANONICAL:
        return _ALIAS_TO_CANONICAL[key], 'alias'
    if key in CANONICAL_IDS:
        return key, 'short_id'
    return None, 'unrecognized'


@dataclass
class FrameworkCanonicalizationResult:
    selected_frameworks_input: Tuple[str, ...] = ()
    selected_frameworks_original: Tuple[str, ...] = ()
    selected_frameworks_canonical: Tuple[str, ...] = ()
    alias_matches: Tuple[Dict[str, str], ...] = ()
    unsupported_frameworks: Tuple[str, ...] = ()
    explicit_selection: bool = False
    domain: str = ''
    lang: str = ''
    document_type: str = 'strategy'
    body_text_used_for_selection: bool = False
    supported_before: bool = False
    supported_after: bool = False
    support_reason_before: str = ''
    support_reason_after: str = ''
    compiler_used_after: bool = False
    old_path_blockers_avoided: Tuple[str, ...] = ()
    passed: bool = False
    task_id: str = ''

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload['selected_frameworks_input'] = list(self.selected_frameworks_input)
        payload['selected_frameworks_original'] = list(self.selected_frameworks_original)
        payload['selected_frameworks_canonical'] = list(self.selected_frameworks_canonical)
        payload['alias_matches'] = [dict(item) for item in self.alias_matches]
        payload['unsupported_frameworks'] = list(self.unsupported_frameworks)
        payload['old_path_blockers_avoided'] = list(self.old_path_blockers_avoided)
        return payload


def emit_framework_label_diagnostic(payload: Dict[str, Any]) -> Dict[str, Any]:
    _LAST_CANON_DIAG.clear()
    _LAST_CANON_DIAG.update(payload)
    print(
        DIAGNOSTIC_TAG + ' '
        + json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
        flush=True,
    )
    return dict(payload)


def last_framework_label_diagnostic() -> Dict[str, Any]:
    return dict(_LAST_CANON_DIAG)


def _legacy_token_supported(raw: str, allowed: Sequence[str]) -> bool:
    from release_engine_v3.rel37_coverage_registry import normalize_framework_token
    token = normalize_framework_token(raw)
    if not token:
        return False
    legacy = {
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
    canonical = legacy.get(token)
    if canonical is None:
        compact = token.replace('_', '')
        for alias, mapped in legacy.items():
            if compact == alias.replace('_', ''):
                canonical = mapped
                break
    return bool(canonical and canonical in allowed)


def canonicalize_framework_labels(
        selected_frameworks: Optional[Iterable[object]] = None,
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        explicit_selection: bool = False,
        task_id: str = '',
        emit: bool = True,
) -> FrameworkCanonicalizationResult:
    dcode = normalize_domain_code(str(domain or ''), default='')
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    raw_input = tuple(_input_tokens(selected_frameworks))
    allowed = tuple(PHASE1_ALLOWED_FRAMEWORKS.get(dcode, ()))

    alias_matches: List[Dict[str, str]] = []
    canonical: List[str] = []
    unsupported: List[str] = []
    seen = set()
    for raw in raw_input:
        mapped, kind = classify_framework_label(raw)
        if mapped and mapped in allowed:
            alias_matches.append({
                'input': raw,
                'canonical': mapped,
                'match': kind,
            })
            if mapped not in seen:
                seen.add(mapped)
                canonical.append(mapped)
            continue
        if mapped and mapped not in allowed:
            unsupported.append(raw)
            continue
        if str(raw).strip():
            unsupported.append(raw)

    before_ok = bool(raw_input) and all(
        _legacy_token_supported(item, allowed) for item in raw_input
    )
    after_ok = bool(canonical) and not unsupported
    reason_before = (
        'supported_selection' if before_ok
        else ('unsupported_empty_explicit' if explicit_selection and not raw_input
              else 'unsupported_frameworks')
    )
    if not raw_input and not explicit_selection and allowed:
        reason_after = 'default_expanded'
        after_ok = True
        compiler = True
        canonical = list(allowed)
    elif after_ok:
        reason_after = 'supported_selection'
        compiler = True
    elif not raw_input and explicit_selection:
        reason_after = 'unsupported_empty_explicit'
        compiler = False
    else:
        reason_after = 'unsupported_frameworks'
        compiler = False

    avoided: Tuple[str, ...] = ()
    if compiler:
        avoided = (
            'gap_implementation_guides_missing',
            'synth_failed:kpis',
            'specialized_function_missing',
            'forbidden_soc_leakage',
        )

    passed = bool(
        (compiler and after_ok and not unsupported)
        or (not compiler and not after_ok)
    )
    result = FrameworkCanonicalizationResult(
        selected_frameworks_input=raw_input,
        selected_frameworks_original=raw_input,
        selected_frameworks_canonical=tuple(canonical),
        alias_matches=tuple(alias_matches),
        unsupported_frameworks=tuple(unsupported),
        explicit_selection=bool(explicit_selection),
        domain=dcode,
        lang=str(lang or ''),
        document_type=dtype,
        body_text_used_for_selection=False,
        supported_before=before_ok,
        supported_after=after_ok,
        support_reason_before=reason_before,
        support_reason_after=reason_after,
        compiler_used_after=compiler,
        old_path_blockers_avoided=avoided,
        passed=passed,
        task_id=str(task_id or ''),
    )
    if emit:
        emit_framework_label_diagnostic(result.to_dict())
    return result


def canonicalize_request_frameworks(
        selected_frameworks: Optional[Iterable[object]],
        *,
        domain: str = '',
) -> List[str]:
    """Map known UI labels to short IDs; keep unknown tokens as-is."""
    out: List[str] = []
    seen = set()
    for raw in _input_tokens(selected_frameworks):
        mapped, _kind = classify_framework_label(raw)
        token = mapped or lookup_key(raw).replace(' ', '_')
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    if out:
        return out
    return []
