"""Narrow REL37 feature switch and live-path overlay for Data / AI / DT strategy."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel37_canonical_document import CanonicalDocument
from release_engine_v3.rel37_compilers import compile_for_domain
from release_engine_v3.rel37_render import model_to_markdown, model_to_sections
from release_engine_v3.rel37_schema_registry import (
    PHASE1_DOMAINS,
    PHASE1_LANGS,
    rel37_compiler_flag_enabled,
)

REL37_APPLIED_KEY = '_rel37_applied'
REL37_MODEL_KEY = '_rel37_canonical'
REL37_HASH_KEY = '_rel37_model_hash'


def _normalize_lang(value: object) -> str:
    raw = str(value or 'ar').strip().lower()
    if raw.startswith('ar'):
        return 'ar'
    if raw.startswith('en'):
        return 'en'
    return raw


def rel37_should_apply(
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        sections: Optional[Dict[str, Any]] = None,
        flags: Optional[Dict[str, Any]] = None,
) -> bool:
    if not rel37_compiler_flag_enabled():
        return False
    flags = flags or {}
    if flags.get('rel37_data_ai_dt_compiler') in (0, False, '0', 'false', 'off'):
        return False
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype not in ('strategy', ''):
        return False
    dcode = normalize_domain_code(str(domain or ''), default='')
    if dcode not in PHASE1_DOMAINS:
        return False
    if _normalize_lang(lang) not in PHASE1_LANGS:
        return False
    return True


def is_rel37_authoritative(sections: Optional[Dict[str, Any]]) -> bool:
    secs = sections or {}
    return str(secs.get(REL37_APPLIED_KEY) or '') == '1' and bool(
        secs.get(REL37_MODEL_KEY))


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
) -> Tuple[Dict[str, Any], List[str]]:
    out = dict(sections or {})
    if not rel37_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            sections=out, flags=flags):
        return out, []
    payload = dict(request or {})
    payload.setdefault('domain', domain)
    payload.setdefault('lang', _normalize_lang(lang))
    payload.setdefault('org_name', org_name or payload.get('org_name') or '')
    payload.setdefault('task_id', task_id)
    if selected_frameworks is not None:
        payload['selected_frameworks'] = list(selected_frameworks)
    elif 'selected_frameworks' not in payload:
        payload['selected_frameworks'] = []
    model = compile_for_domain(domain, payload)
    rendered = model_to_sections(model)
    for key, value in rendered.items():
        out[key] = value
    out[REL37_APPLIED_KEY] = '1'
    out[REL37_MODEL_KEY] = serialize_model(model)
    out[REL37_HASH_KEY] = model.model_hash
    out['_rel37_markdown'] = model_to_markdown(model)
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
    selected = (
        ctx.get('selected_frameworks')
        or backend.get('selected_frameworks')
        or []
    )
    out, repairs = apply_rel37_to_sections(
        sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=list(selected) if selected else [],
        org_name=org_name,
        task_id=str(ctx.get('task_id') or ctx.get('strategy_id') or ''),
        flags=dict(ctx.get('flags') or backend.get('flags') or {}),
        request=ctx,
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
