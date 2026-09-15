"""Narrow REL37 feature switch and live-path overlay for Data / AI / DT strategy."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.rel37_canonical_document import CanonicalDocument
from release_engine_v3.rel37_compilers import compile_for_domain
from release_engine_v3.rel37_render import model_to_markdown, model_to_sections
from release_engine_v3.rel37_schema_registry import rel37_compiler_flag_enabled
from release_engine_v3.rel37_framework_aliases import (
    REL37_CANONICAL_FW_KEY,
    REL37_ORIGINAL_FW_KEY,
)
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


def rel37_confidence_count(sections: Optional[Dict[str, Any]]) -> int:
    model = load_model(sections)
    if model is None:
        return 0
    return len(model.confidence)


def rel37_risk_count(sections: Optional[Dict[str, Any]]) -> int:
    model = load_model(sections)
    if model is None:
        return 0
    return len(model.risks)


def _rel37_normalize_lang(value: object) -> str:
    return _normalize_lang(value)


def rel37_request_model_consistent(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> Tuple[bool, List[str]]:
    """Identity check for REL37 persist/export. Applied-flag alone is not enough."""
    from release_engine_v3.domain_codes import normalize_domain_code
    from release_engine_v3.rel37_framework_aliases import (
        classify_framework_label,
    )

    errors: List[str] = []
    if not is_rel37_authoritative(sections):
        return False, ['rel37_not_authoritative']
    model = load_model(sections)
    if model is None:
        return False, ['rel37_model_unreadable']
    stored_hash = str((sections or {}).get(REL37_HASH_KEY) or '').strip()
    recomputed = model.compute_model_hash()
    if not model.model_hash:
        errors.append('rel37_model_hash_missing')
    elif recomputed != model.model_hash:
        errors.append('rel37_model_hash_stale')
    if stored_hash and model.model_hash and stored_hash != model.model_hash:
        errors.append('rel37_model_hash_mismatch')
    want_domain = normalize_domain_code(str(domain or ''), default='')
    if want_domain and model.domain != want_domain:
        errors.append(f'rel37_domain_mismatch:{model.domain}:{want_domain}')
    want_lang = _rel37_normalize_lang(lang) if lang else ''
    if want_lang and model.lang != want_lang:
        errors.append(f'rel37_lang_mismatch:{model.lang}:{want_lang}')
    want_type = str(document_type or 'strategy').strip().lower() or 'strategy'
    if model.document_type != want_type:
        errors.append(
            f'rel37_document_type_mismatch:{model.document_type}:{want_type}')
    if org_name and model.org_name != org_name:
        errors.append('rel37_org_name_mismatch')
    request_canon: List[str] = []
    for raw in list(selected_frameworks or []):
        mapped, _kind = classify_framework_label(raw)
        if mapped:
            request_canon.append(mapped)
    model_canon = [str(item).strip().lower() for item in model.selected_frameworks if str(item).strip()]
    stored_canon = [
        str(item).strip().lower()
        for item in ((sections or {}).get(REL37_CANONICAL_FW_KEY) or [])
        if str(item).strip()
    ]
    if request_canon and set(request_canon) != set(model_canon):
        errors.append('rel37_frameworks_mismatch')
    if stored_canon and set(stored_canon) != set(model_canon):
        errors.append('rel37_stored_frameworks_mismatch')
    return (not errors), errors


def rel37_confidence_risk_structures_ok(
        sections: Optional[Dict[str, Any]],
) -> List[str]:
    """Complete typed confidence/risk rows under the existing REL37 schema."""
    model = load_model(sections)
    if model is None:
        return ['rel37_model_unreadable']
    errors: List[str] = []
    if not model.confidence:
        errors.append('rel37_confidence_missing')
    else:
        for index, row in enumerate(model.confidence):
            if not all(str(cell).strip() for cell in row.cells()):
                errors.append(f'rel37_confidence_row_incomplete:{index}')
    if not model.risks:
        errors.append('rel37_risks_missing')
    else:
        for index, row in enumerate(model.risks):
            if not all(str(cell).strip() for cell in row.cells()):
                errors.append(f'rel37_risk_row_incomplete:{index}')
    return errors


def rel37_confidence_risk_post_repair_result(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> Optional[List[str]]:
    """REL37-authoritative persist gate.

    Returns None when this is not a REL37-authoritative route (caller must
    keep the legacy heading grammar). Otherwise returns blocking errors —
    empty list means the typed model is current, identity-matched, and
    has complete confidence/risk structures.
    """
    if not is_rel37_authoritative(sections):
        return None
    model = load_model(sections)
    if model is None:
        return ['rel37_model_unreadable']
    blockers = list(model.blockers or model.validate())
    _ok, identity = rel37_request_model_consistent(
        sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
        org_name=org_name,
        selected_frameworks=selected_frameworks,
    )
    blockers.extend(identity)
    blockers.extend(rel37_confidence_risk_structures_ok(sections))
    return list(dict.fromkeys(blockers))


def rel37_validated_export_markdown(
        sections: Optional[Dict[str, Any]],
) -> str:
    """REL37 markdown only when the typed model is current and valid.

    Applied-flag alone is not enough: the model must load, validate, and
    match the stored hash. Empty string means callers keep the legacy view.
    """
    if not is_rel37_authoritative(sections):
        return ''
    model = load_model(sections)
    if model is None:
        return ''
    if list(model.blockers or model.validate()):
        return ''
    stored_hash = str((sections or {}).get(REL37_HASH_KEY) or '').strip()
    if not model.model_hash:
        model.compute_hashes()
    if stored_hash and model.model_hash and stored_hash != model.model_hash:
        return ''
    from release_engine_v3.rel37_live_attach import canonical_markdown_from_sections
    return canonical_markdown_from_sections(sections) or ''


def rel37_bind_export_sections(
        candidate: Optional[Dict[str, Any]],
        fallback: Optional[Dict[str, Any]] = None,
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Prefer identity-matched saved REL37 sections over H2-split markdown.

    Forged ``_rel37_applied`` without a model, hash mismatch, and incomplete
    typed confidence/risk keep the fallback (legacy) sections.
    """
    blockers = rel37_confidence_risk_post_repair_result(
        candidate,
        domain=domain,
        lang=lang,
        document_type=document_type,
        org_name=org_name,
        selected_frameworks=selected_frameworks,
    )
    if blockers == []:
        return dict(candidate or {})
    return dict(fallback or {})


def rel37_export_heading_token_extras() -> Dict[str, Tuple[str, ...]]:
    """REL37 English titles the legacy fragment detector did not know.

    Arabic REL32 titles already match the 2024 heading tokens. English
    compiler titles use Environment and Drivers / Gap Assessment /
    Confidence and Risk, which the legacy detector treated as missing.
    """
    return {
        'environment': ('environment and drivers',),
        'gaps': ('gap assessment',),
        'confidence': ('confidence and risk',),
    }


_REL37_KPI_SEMANTICS_DOMAINS = frozenset(('data', 'ai', 'dt'))


def rel37_sections_for_professional_render(
        candidate: Optional[Dict[str, Any]],
        fallback: Optional[Dict[str, Any]] = None,
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Prefer identity-matched saved REL37 sections for professional render.

    H2-split fallbacks keep their visible text when the candidate is not
    identity-matched. Applied-flag alone does not win.
    """
    if is_rel37_authoritative(candidate):
        bound = rel37_bind_export_sections(
            candidate,
            fallback,
            domain=domain,
            lang=lang,
            document_type=document_type,
            org_name=org_name,
            selected_frameworks=selected_frameworks,
        )
        if is_rel37_authoritative(bound):
            return bound
    out = dict(fallback or {})
    out.update(rel37_authority_snapshot(candidate))
    return out


def rel37_authority_snapshot(
        sections: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Copy only REL37 authority keys for later identity re-validation."""
    secs = sections or {}
    keys = (
        REL37_APPLIED_KEY, REL37_MODEL_KEY, REL37_HASH_KEY,
        REL37_CANONICAL_FW_KEY, REL37_ORIGINAL_FW_KEY, REL37_SOURCE_KEY,
    )
    return {key: secs[key] for key in keys if key in secs}


def rel37_skip_cyber_kpi_semantics(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> bool:
    """True only for identity-matched REL37 Data/AI/DT compiler KPIs.

    Applied-flag alone is never enough. Cyber / ERM / Global keep the
    existing PR-CY61 semantic normalizer and quality gate.
    """
    from release_engine_v3.domain_codes import normalize_domain_code

    dcode = normalize_domain_code(str(domain or ''), default='')
    if dcode not in _REL37_KPI_SEMANTICS_DOMAINS:
        return False
    blockers = rel37_confidence_risk_post_repair_result(
        sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
        org_name=org_name,
        selected_frameworks=selected_frameworks,
    )
    return blockers == []


def rel37_export_completeness_ok(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> Optional[bool]:
    """Typed-model completeness for the export fragment gate.

    Returns None when this is not a REL37-authoritative route (caller keeps
    the legacy heading grammar). True means the current model is valid,
    identity-matched, and carries the core strategy sections. False means
    the route is REL37-authoritative but must not skip the legacy check.
    Applied-flag alone is never enough.
    """
    blockers = rel37_confidence_risk_post_repair_result(
        sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
        org_name=org_name,
        selected_frameworks=selected_frameworks,
    )
    if blockers is None:
        return None
    if blockers:
        return False
    keys = {
        str(key)
        for key, value in (sections or {}).items()
        if not str(key).startswith('_') and str(value or '').strip()
    }
    core = {
        'vision', 'pillars', 'environment', 'gaps', 'roadmap',
        'kpis', 'confidence',
    }
    populated = keys & core
    if len(populated) < 5:
        return False
    if not (populated & {'vision', 'pillars'}):
        return False
    return True


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
        out[REL37_ORIGINAL_FW_KEY] = list(selection.selected_frameworks_original)
        out[REL37_CANONICAL_FW_KEY] = list(selection.selected_frameworks_canonical)
        return out, []
    payload = dict(request or {})
    payload.setdefault('domain', domain)
    payload.setdefault('lang', _normalize_lang(lang))
    payload.setdefault('org_name', org_name or payload.get('org_name') or '')
    payload.setdefault('task_id', task_id)
    payload['selected_frameworks'] = list(selection.normalized_frameworks)
    payload['selected_frameworks_original'] = list(
        selection.selected_frameworks_original)
    payload['selected_frameworks_canonical'] = list(
        selection.normalized_frameworks)
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
    out[REL37_ORIGINAL_FW_KEY] = list(selection.selected_frameworks_original)
    out[REL37_CANONICAL_FW_KEY] = list(selection.normalized_frameworks)
    from release_engine_v3.rel37_preview_section_contract import (
        apply_rel37_preview_section_contract,
    )
    out, _psc = apply_rel37_preview_section_contract(
        out,
        domain=domain,
        lang=_normalize_lang(lang),
        document_type=document_type,
        model=model,
        emit=False,
    )
    repairs = ['rel37:deterministic_compiler']
    if model.blockers:
        repairs.append('rel37:validate_blockers')
    if _psc.get('alias_map_applied'):
        repairs.append('rel37:preview_gap_analysis_alias')
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
