"""Narrow REL37 feature switch and live-path overlay for Data / AI / DT strategy."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.rel37_canonical_document import CanonicalDocument
from release_engine_v3.rel37_compilers import compile_for_domain
from release_engine_v3.rel37_render import model_to_markdown, model_to_sections
from release_engine_v3.rel37_schema_registry import rel37_compiler_flag_enabled
from release_engine_v3.rel37_selection import rel37_supported_selection

REL37_APPLIED_KEY = '_rel37_applied'
REL37_MODEL_KEY = '_rel37_canonical'
REL37_HASH_KEY = '_rel37_model_hash'
REL37_SELECTION_REASON_KEY = '_rel37_selection_reason'
REL37_SELECTION_SUPPORTED_KEY = '_rel37_selection_supported'
REL37_SOURCE_KEY = '_rel37_source_hash'
REL37_MARKDOWN_KEY = '_rel37_markdown'

_SUPPORTED_REASONS = frozenset(('supported_selection', 'default_expanded'))
_AUTHORITY_KEYS = (
    REL37_APPLIED_KEY, REL37_MODEL_KEY, REL37_HASH_KEY,
    REL37_SOURCE_KEY, REL37_MARKDOWN_KEY,
)


def _normalize_lang(value: object) -> str:
    raw = str(value or 'ar').strip().lower()
    if raw.startswith('ar'):
        return 'ar'
    if raw.startswith('en'):
        return 'en'
    return raw


def _infer_explicit_selection(
        selected_frameworks: Optional[List[str]],
        request: Optional[Dict[str, Any]],
        explicit_selection: Optional[bool],
) -> bool:
    if explicit_selection is not None:
        return bool(explicit_selection)
    ctx = dict(request or {})
    if ctx.get('explicit_selection') is not None:
        return bool(ctx.get('explicit_selection'))
    values = []
    if selected_frameworks is not None:
        values = [item for item in selected_frameworks if str(item).strip()]
    elif ctx.get('selected_frameworks') is not None:
        raw = ctx.get('selected_frameworks')
        if isinstance(raw, str):
            values = [part for part in raw.replace('|', ',').split(',') if part.strip()]
        elif isinstance(raw, (list, tuple, set)):
            values = [item for item in raw if str(item).strip()]
    # Live UI sends an empty list when the user picked nothing. That is the
    # documented default-expansion case, not an explicit empty selection.
    return bool(values)


def rel37_should_apply(
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        sections: Optional[Dict[str, Any]] = None,
        flags: Optional[Dict[str, Any]] = None,
        selected_frameworks: Optional[List[str]] = None,
        explicit_selection: Optional[bool] = None,
        request: Optional[Dict[str, Any]] = None,
) -> bool:
    if not rel37_compiler_flag_enabled():
        return False
    flags = flags or {}
    if flags.get('rel37_data_ai_dt_compiler') in (0, False, '0', 'false', 'off'):
        return False
    # sections/body text must not influence selection. Frameworks come from
    # trusted request metadata only.
    _ = sections
    explicit = _infer_explicit_selection(
        selected_frameworks, request, explicit_selection)
    result = rel37_supported_selection(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks
        if selected_frameworks is not None
        else (request or {}).get('selected_frameworks'),
        explicit_selection=explicit,
    )
    return bool(result.supported)


def is_rel37_authoritative(sections: Optional[Dict[str, Any]]) -> bool:
    secs = sections or {}
    applied = str(secs.get(REL37_APPLIED_KEY) or '').strip().lower()
    return applied in ('1', 'true', 'yes', 'on') and bool(secs.get(REL37_MODEL_KEY))


def serialize_model(model: CanonicalDocument) -> str:
    return json.dumps(model.to_dict(), ensure_ascii=False, sort_keys=True)


def load_model(sections: Optional[Dict[str, Any]]) -> Optional[CanonicalDocument]:
    raw = (sections or {}).get(REL37_MODEL_KEY)
    if not raw:
        return None
    try:
        payload = json.loads(raw) if isinstance(raw, str) else dict(raw)
        return CanonicalDocument.from_dict(payload)
    except Exception:
        return None


def rel37_kpi_row_count(sections: Optional[Dict[str, Any]]) -> int:
    model = load_model(sections)
    if model is None:
        return 0
    return len(model.kpis)


def rel37_kpi_main_header_count(sections: Optional[Dict[str, Any]]) -> int:
    if not is_rel37_authoritative(sections):
        return 0
    model = load_model(sections)
    if model is None or not model.kpis:
        return 0
    return 1


def apply_rel37_to_sections(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str,
        lang: str,
        document_type: str = 'strategy',
        selected_frameworks: Optional[List[str]] = None,
        org_name: str = '',
        task_id: str = '',
        flags: Optional[Dict[str, Any]] = None,
        request: Optional[Dict[str, Any]] = None,
        explicit_selection: Optional[bool] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    out = dict(sections or {})
    flags = flags or {}
    explicit = _infer_explicit_selection(
        selected_frameworks, request, explicit_selection)
    selection = rel37_supported_selection(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks
        if selected_frameworks is not None
        else (request or {}).get('selected_frameworks'),
        explicit_selection=explicit,
    )
    if (
            not rel37_compiler_flag_enabled()
            or flags.get('rel37_data_ai_dt_compiler') in (0, False, '0', 'false', 'off')
            or not selection.supported):
        # Do not stamp a stale unsupported reason onto an already-applied
        # model. That is how Data/DT latest showed applied=true plus
        # unsupported_frameworks after a later no-op overlay.
        if is_rel37_authoritative(out):
            return out, []
        for key in _AUTHORITY_KEYS:
            out.pop(key, None)
        out[REL37_SELECTION_REASON_KEY] = selection.reason
        out[REL37_SELECTION_SUPPORTED_KEY] = 'false'
        return out, []
    payload = dict(request or {})
    payload.setdefault('domain', domain)
    payload.setdefault('lang', _normalize_lang(lang))
    payload.setdefault('org_name', org_name or payload.get('org_name') or '')
    payload.setdefault('task_id', task_id)
    payload['selected_frameworks'] = list(selection.normalized_frameworks)
    model = compile_for_domain(domain, payload)
    rendered = model_to_sections(model)
    for key, value in rendered.items():
        out[key] = value
    out[REL37_APPLIED_KEY] = '1'
    out[REL37_MODEL_KEY] = serialize_model(model)
    out[REL37_HASH_KEY] = model.model_hash
    out[REL37_SOURCE_KEY] = model.model_hash
    out[REL37_MARKDOWN_KEY] = model_to_markdown(model)
    out[REL37_SELECTION_REASON_KEY] = (
        selection.reason if selection.reason in _SUPPORTED_REASONS
        else 'supported_selection')
    out[REL37_SELECTION_SUPPORTED_KEY] = 'true'
    repairs = ['rel37:deterministic_compiler']
    if model.blockers:
        repairs.append('rel37:validate_blockers')
    return out, repairs


def overlay_rel37_if_applicable(
        sections: Optional[Dict[str, Any]],
        request_context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str], List[str]]:
    ctx = dict(request_context or {})
    backend = dict(ctx.get('backend') or {})
    domain = str(
        ctx.get('domain')
        or backend.get('domain')
        or '')
    lang = str(ctx.get('lang') or backend.get('lang') or 'ar')
    document_type = str(
        ctx.get('document_type')
        or backend.get('document_type')
        or 'strategy')
    org_name = str(
        ctx.get('org_name')
        or ctx.get('organization')
        or backend.get('org_name')
        or '')
    if 'selected_frameworks' in ctx:
        selected = ctx.get('selected_frameworks')
    elif 'selected_frameworks' in backend:
        selected = backend.get('selected_frameworks')
    elif 'frameworks' in ctx:
        selected = ctx.get('frameworks')
    else:
        selected = None
    if isinstance(selected, str):
        selected_list = [
            part for part in selected.replace('|', ',').split(',') if part.strip()]
    elif isinstance(selected, (list, tuple, set)):
        selected_list = list(selected)
    else:
        selected_list = None
    out, repairs = apply_rel37_to_sections(
        sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_list,
        org_name=org_name,
        task_id=str(ctx.get('task_id') or ctx.get('strategy_id') or ''),
        flags=dict(ctx.get('flags') or backend.get('flags') or {}),
        request=ctx,
        explicit_selection=ctx.get('explicit_selection'),
    )
    blockers: List[str] = []
    model = load_model(out)
    if model is not None:
        blockers.extend(model.validate() if not model.blockers else list(model.blockers))
    return out, repairs, blockers


def rel37_completeness_override(
        sections: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not is_rel37_authoritative(sections):
        return None
    model = load_model(sections)
    if model is None:
        return {
            'passed': False,
            'completeness_gate_passed': False,
            'blocking_errors': ['rel37_model_missing'],
            'details': {'compiler': 'rel37'},
        }
    blockers = list(model.blockers or model.validate())
    passed = not blockers
    return {
        'passed': passed,
        'completeness_gate_passed': passed,
        'saved_content_complete': passed,
        'blocking_errors': list(blockers),
        'details': {
            'compiler': 'rel37',
            'model_hash': model.model_hash,
            'kpi_row_count': len(model.kpis),
            'gap_row_count': len(model.gaps),
        },
    }
