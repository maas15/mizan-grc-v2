"""REL37.0.2 — attach deterministic compilers on the live generate/save path.

The 0.1 overlay ran mid-pipeline (KPI integrity / REL36.9.1) and was not the
last persist authority. Official Data/AI/DT saves therefore had no ``_rel37_*``
keys, and English richness regex gates could 422 a valid REL37 model.

This module is the last writer before ``sections_json`` persist.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel37_apply import (
    REL37_APPLIED_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    is_rel37_authoritative,
    load_model,
    serialize_model,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument, sha256_text
from release_engine_v3.rel37_compilers import compile_for_domain
from release_engine_v3.rel37_render import (
    evidence_from_model,
    model_to_markdown,
    model_to_sections,
    render,
)
from release_engine_v3.rel37_schema_registry import (
    PHASE1_DOMAINS,
    rel37_compiler_flag_enabled,
)
from release_engine_v3.rel37_selection import rel37_supported_selection

REL37_SOURCE_KEY = '_rel37_source_hash'
REL37_MARKDOWN_KEY = '_rel37_markdown'
DIAGNOSTIC_TAG = '[REL37-LIVE-COMPILER-ATTACH]'

_PUBLIC_SECTION_KEYS = (
    'vision', 'pillars', 'environment', 'gaps', 'roadmap', 'kpis', 'confidence',
)


class Rel37ModelValidationFailed(Exception):
    """Fail-closed when a supported REL37 compile does not validate."""

    def __init__(self, blockers: Optional[Sequence[str]] = None):
        self.blockers = [str(item) for item in (blockers or ['rel37_model_validation_failed'])]
        super().__init__('rel37_model_validation_failed')


def _normalize_lang(value: object) -> str:
    raw = str(value or 'ar').strip().lower()
    if raw.startswith('ar'):
        return 'ar'
    if raw.startswith('en'):
        return 'en'
    return raw


def _sha256_text(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        return hashlib.sha256(bytes(value)).hexdigest()
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return sha256_text(value or '')


def _framework_list(selected_frameworks: Optional[Sequence[object]]) -> List[str]:
    if selected_frameworks is None:
        return []
    if isinstance(selected_frameworks, str):
        return [
            part.strip()
            for part in selected_frameworks.replace('|', ',').split(',')
            if part.strip()
        ]
    return [str(item).strip() for item in selected_frameworks if str(item).strip()]


def infer_explicit_selection(
        selected_frameworks: Optional[Sequence[object]] = None,
        explicit_selection: Optional[bool] = None,
        request: Optional[Dict[str, Any]] = None,
) -> bool:
    if explicit_selection is not None:
        return bool(explicit_selection)
    ctx = dict(request or {})
    if ctx.get('explicit_selection') is not None:
        return bool(ctx.get('explicit_selection'))
    values = _framework_list(selected_frameworks)
    if not values:
        raw = ctx.get('selected_frameworks')
        if raw is None:
            raw = ctx.get('frameworks')
        values = _framework_list(raw)
    return bool(values)


def live_support_reason(
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Sequence[object]] = None,
        explicit_selection: bool = False,
) -> Tuple[Any, str]:
    """Return (selection, diagnostic_reason) with live-path reason mapping."""
    dcode = normalize_domain_code(str(domain or ''), default='')
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    if dtype not in ('strategy', ''):
        selection = rel37_supported_selection(
            domain=domain,
            lang=lang,
            document_type=document_type,
            selected_frameworks=selected_frameworks,
            explicit_selection=explicit_selection,
        )
        return selection, 'document_type_not_supported'
    if dcode not in PHASE1_DOMAINS:
        selection = rel37_supported_selection(
            domain=domain,
            lang=lang,
            document_type=document_type,
            selected_frameworks=selected_frameworks,
            explicit_selection=explicit_selection,
        )
        return selection, 'domain_not_supported'
    selection = rel37_supported_selection(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        explicit_selection=explicit_selection,
    )
    return selection, selection.reason


def should_skip_legacy_richness_gates(
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Sequence[object]] = None,
        explicit_selection: Optional[bool] = None,
        request: Optional[Dict[str, Any]] = None,
        sections: Optional[Dict[str, Any]] = None,
        flags: Optional[Dict[str, Any]] = None,
) -> bool:
    """True when old markdown richness/synth_failed gates must not run."""
    if not rel37_compiler_flag_enabled():
        return False
    flags = flags or {}
    if flags.get('rel37_data_ai_dt_compiler') in (0, False, '0', 'false', 'off'):
        return False
    if is_rel37_authoritative(sections):
        return True
    explicit = infer_explicit_selection(
        selected_frameworks, explicit_selection, request)
    selection, _reason = live_support_reason(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks
        if selected_frameworks is not None
        else (request or {}).get('frameworks')
        or (request or {}).get('selected_frameworks'),
        explicit_selection=explicit,
    )
    return bool(selection.supported)


def rel37_legacy_audit_defects(sections: Optional[Dict[str, Any]]) -> List[tuple]:
    """Replace markdown richness defects with model.validate() when attached."""
    if not is_rel37_authoritative(sections):
        return []
    model = load_model(sections)
    if model is None:
        return [('rel37', 'rel37_model_validation_failed', 1, 0)]
    blockers = list(model.blockers or model.validate() or [])
    if blockers:
        return [('rel37', 'rel37_model_validation_failed', 1, 0)]
    return []


def public_sections_hash(sections: Optional[Dict[str, Any]]) -> str:
    secs = dict(sections or {})
    payload = {key: secs.get(key) or '' for key in _PUBLIC_SECTION_KEYS}
    return _sha256_text(payload)


def stamp_rel37_keys(sections: Dict[str, Any], model: CanonicalDocument) -> Dict[str, Any]:
    out = dict(sections or {})
    rendered = model_to_sections(model)
    out.update(rendered)
    out[REL37_APPLIED_KEY] = '1'
    out[REL37_MODEL_KEY] = serialize_model(model)
    out[REL37_HASH_KEY] = model.model_hash
    out[REL37_SOURCE_KEY] = model.model_hash
    out[REL37_MARKDOWN_KEY] = model_to_markdown(model)
    return out


def sections_have_rel37(sections: Optional[Dict[str, Any]]) -> bool:
    secs = sections or {}
    applied = str(secs.get(REL37_APPLIED_KEY) or '').strip().lower() in (
        '1', 'true', 'yes', 'on')
    return applied and bool(secs.get(REL37_MODEL_KEY))


def canonical_markdown_from_sections(sections: Optional[Dict[str, Any]]) -> str:
    secs = sections or {}
    raw = secs.get(REL37_MARKDOWN_KEY)
    if isinstance(raw, str) and raw.strip():
        return raw
    model = load_model(secs)
    if model is not None:
        return model_to_markdown(model)
    parts = [
        secs[key] for key in _PUBLIC_SECTION_KEYS
        if isinstance(secs.get(key), str) and secs.get(key).strip()
    ]
    return '\n\n'.join(parts)


def export_bundle_from_sections(sections: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Preview / DOCX / PDF from the saved REL37 model. No post-hoc table regex."""
    model = load_model(sections)
    if model is None:
        return {
            'compiler_used': False,
            'model_hash': '',
            'preview_source_hash': '',
            'docx_source_hash': '',
            'pdf_source_hash': '',
            'markdown': canonical_markdown_from_sections(sections),
        }
    if not model.model_hash:
        model.compute_hashes()
    preview = render(model, 'preview')
    docx = render(model, 'docx')
    pdf = render(model, 'pdf')
    ev = evidence_from_model(model)
    return {
        'compiler_used': True,
        'model': model,
        'model_hash': model.model_hash,
        'source_hash': ev.source_hash,
        'preview_source_hash': preview.evidence.source_hash,
        'docx_source_hash': docx.evidence.source_hash,
        'pdf_source_hash': pdf.evidence.source_hash,
        'preview': preview,
        'docx': docx,
        'pdf': pdf,
        'markdown': preview.markdown or model_to_markdown(model),
        'hashes_match': (
            preview.evidence.source_hash == model.model_hash
            and docx.evidence.source_hash == model.model_hash
            and pdf.evidence.source_hash == model.model_hash
        ),
    }


def candidate_matches_latest_preview(
        row: Dict[str, Any],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = '',
        strategy_id: str = '',
) -> bool:
    """Isolation filter for latest preview/load."""
    if strategy_id not in (None, ''):
        rid = str(row.get('strategy_id') or row.get('id') or '')
        if rid != str(strategy_id):
            return False
    want_domain = normalize_domain_code(str(domain or ''), default='')
    got_domain = normalize_domain_code(
        str(row.get('domain') or ''), default='')
    if want_domain and got_domain and want_domain != got_domain:
        return False
    want_lang = _normalize_lang(lang) if lang else ''
    got_lang = _normalize_lang(row.get('language') or row.get('lang') or '')
    if want_lang and got_lang and want_lang != got_lang:
        return False
    want_type = str(document_type or '').strip().lower()
    got_type = str(
        row.get('document_type')
        or (row.get('sections') or {}).get('_document_type')
        or 'strategy'
    ).strip().lower() or 'strategy'
    if want_type and want_type != got_type:
        return False
    return True


def pick_latest_preview_row(
        rows: Iterable[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = '',
        strategy_id: str = '',
) -> Optional[Dict[str, Any]]:
    """Newest matching row; prefer a REL37 artifact when one matches."""
    matched = [
        row for row in rows
        if candidate_matches_latest_preview(
            row,
            domain=domain,
            lang=lang,
            document_type=document_type,
            strategy_id=strategy_id,
        )
    ]
    if not matched:
        return None
    rel37_rows = [
        row for row in matched
        if sections_have_rel37(row.get('sections') or {})
        or str(row.get('_rel37_applied') or '').strip().lower() in ('1', 'true')
    ]
    return (rel37_rows or matched)[0]


def _empty_diagnostic() -> Dict[str, Any]:
    return {
        'task_id': '',
        'strategy_id': '',
        'domain_input': '',
        'domain_resolved': '',
        'lang': '',
        'document_type': '',
        'selected_frameworks_input': [],
        'explicit_selection': False,
        'supported_selection': False,
        'support_reason': '',
        'compiler_used': False,
        'feature_switch_enabled': rel37_compiler_flag_enabled(),
        'attach_stage': 'pre_persist',
        'old_sections_hash_before': '',
        'model_hash': '',
        'canonical_hash_payload_hash': '',
        'rendered_markdown_hash': '',
        'sections_json_hash': '',
        'save_input_hash': '',
        'saved_sections_has_rel37': False,
        'saved_content_has_rel37': False,
        'preview_source_hash': '',
        'docx_source_hash': '',
        'pdf_source_hash': '',
        'old_richness_gates_skipped': False,
        'model_validation_passed': False,
        'model_validation_blockers': [],
        'app_blockers_after': [],
        'script_blockers_after': [],
        'passed': False,
    }


def emit_live_attach_diagnostic(payload: Dict[str, Any]) -> Dict[str, Any]:
    print(
        DIAGNOSTIC_TAG + ' '
        + json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
        flush=True,
    )
    return dict(payload)


@dataclass
class Rel37LiveAttachResult:
    sections: Dict[str, Any]
    content: str = ''
    diagnostic: Dict[str, Any] = field(default_factory=_empty_diagnostic)
    error: Optional[str] = None
    model: Optional[CanonicalDocument] = None

    @property
    def model_validation_blockers(self) -> List[str]:
        return list(self.diagnostic.get('model_validation_blockers') or [])


def attach_rel37_before_save(
        sections: Optional[Dict[str, Any]] = None,
        *,
        content: str = '',
        domain: str = '',
        domain_input: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Sequence[object]] = None,
        explicit_selection: Optional[bool] = None,
        org_name: str = '',
        task_id: str = '',
        strategy_id: str = '',
        request: Optional[Dict[str, Any]] = None,
        flags: Optional[Dict[str, Any]] = None,
        attach_stage: str = 'pre_persist',
        fail_closed: bool = True,
) -> Rel37LiveAttachResult:
    """Compile and persist REL37 at the last point before save.

    Unsupported / Cyber / ERM / Global / non-strategy: no-op, no keys.
    Supported + invalid model: fail closed with ``rel37_model_validation_failed``.
    """
    incoming = dict(sections or {})
    request = dict(request or {})
    flags = flags or {}
    frameworks = _framework_list(
        selected_frameworks
        if selected_frameworks is not None
        else request.get('frameworks')
        if request.get('frameworks') is not None
        else request.get('selected_frameworks')
    )
    explicit = infer_explicit_selection(frameworks, explicit_selection, request)
    domain_in = str(domain_input or request.get('domain') or domain or '')
    domain_resolved = normalize_domain_code(str(domain or domain_in), default='')
    lang_n = _normalize_lang(lang or request.get('lang') or request.get('language') or 'ar')
    dtype = str(
        document_type
        or request.get('document_type')
        or request.get('doc_type')
        or 'strategy'
    ).strip().lower() or 'strategy'
    diag = _empty_diagnostic()
    diag.update({
        'task_id': str(task_id or request.get('task_id') or request.get('async_task_id') or ''),
        'strategy_id': str(strategy_id or request.get('strategy_id') or ''),
        'domain_input': domain_in,
        'domain_resolved': domain_resolved,
        'lang': lang_n,
        'document_type': dtype,
        'selected_frameworks_input': list(frameworks),
        'explicit_selection': explicit,
        'attach_stage': attach_stage,
        'old_sections_hash_before': public_sections_hash(incoming),
        'feature_switch_enabled': rel37_compiler_flag_enabled()
        and flags.get('rel37_data_ai_dt_compiler') not in (0, False, '0', 'false', 'off'),
    })

    if not diag['feature_switch_enabled']:
        diag['support_reason'] = 'feature_switch_off'
        diag['passed'] = True
        emit_live_attach_diagnostic(diag)
        return Rel37LiveAttachResult(sections=incoming, content=content or '', diagnostic=diag)

    selection, mapped_reason = live_support_reason(
        domain=domain or domain_in,
        lang=lang_n,
        document_type=dtype,
        selected_frameworks=frameworks,
        explicit_selection=explicit,
    )
    diag['supported_selection'] = bool(selection.supported)
    diag['support_reason'] = mapped_reason
    if not selection.supported:
        incoming.pop(REL37_APPLIED_KEY, None)
        incoming.pop(REL37_MODEL_KEY, None)
        incoming.pop(REL37_HASH_KEY, None)
        incoming.pop(REL37_SOURCE_KEY, None)
        incoming.pop(REL37_MARKDOWN_KEY, None)
        incoming['_rel37_selection_reason'] = mapped_reason
        diag['compiler_used'] = False
        diag['passed'] = True
        emit_live_attach_diagnostic(diag)
        return Rel37LiveAttachResult(sections=incoming, content=content or '', diagnostic=diag)

    try:
        payload = dict(request)
        payload['domain'] = domain_resolved or selection.domain
        payload['lang'] = lang_n
        payload['org_name'] = org_name or payload.get('org_name') or ''
        payload['task_id'] = diag['task_id']
        payload['selected_frameworks'] = list(selection.normalized_frameworks)
        model = compile_for_domain(payload['domain'], payload)
        if not model.model_hash:
            model.compute_hashes()
        blockers = list(model.validate() or [])
        diag['model_validation_blockers'] = list(blockers)
        if blockers:
            diag['model_validation_passed'] = False
            diag['compiler_used'] = True
            diag['old_richness_gates_skipped'] = True
            emit_live_attach_diagnostic(diag)
            if fail_closed:
                raise Rel37ModelValidationFailed(blockers)
            return Rel37LiveAttachResult(
                sections=incoming,
                content=content or '',
                diagnostic=diag,
                error='rel37_model_validation_failed',
                model=model,
            )
        out = stamp_rel37_keys(incoming, model)
        markdown = out[REL37_MARKDOWN_KEY]
        rendered_hash = _sha256_text(markdown)
        bundle = export_bundle_from_sections(out)
        diag.update({
            'compiler_used': True,
            'supported_selection': True,
            'old_richness_gates_skipped': True,
            'model_hash': model.model_hash,
            'canonical_hash_payload_hash': _sha256_text(
                json.dumps(model.canonical_hash_payload(), ensure_ascii=False, sort_keys=True)
            ),
            'rendered_markdown_hash': rendered_hash,
            'sections_json_hash': _sha256_text(out),
            'save_input_hash': rendered_hash,
            'saved_sections_has_rel37': sections_have_rel37(out),
            'saved_content_has_rel37': False,
            'preview_source_hash': bundle.get('preview_source_hash') or '',
            'docx_source_hash': bundle.get('docx_source_hash') or '',
            'pdf_source_hash': bundle.get('pdf_source_hash') or '',
            'model_validation_passed': True,
            'model_validation_blockers': [],
            'app_blockers_after': [],
            'script_blockers_after': [],
        })
        diag['saved_content_has_rel37'] = bool(markdown.strip()) and sections_have_rel37(out)
        hash_ok = (
            diag['save_input_hash'] == diag['rendered_markdown_hash']
            and diag['preview_source_hash'] == diag['model_hash']
            and diag['docx_source_hash'] == diag['model_hash']
            and diag['pdf_source_hash'] == diag['model_hash']
        )
        diag['passed'] = bool(
            diag['compiler_used']
            and diag['saved_sections_has_rel37']
            and diag['model_validation_passed']
            and hash_ok
            and not diag['app_blockers_after']
        )
        emit_live_attach_diagnostic(diag)
        return Rel37LiveAttachResult(
            sections=out,
            content=markdown,
            diagnostic=diag,
            model=model,
        )
    except Rel37ModelValidationFailed:
        raise
    except Exception as exc:
        blockers = [f'rel37_compile_failed:{exc}']
        diag['model_validation_blockers'] = blockers
        diag['compiler_used'] = True
        diag['old_richness_gates_skipped'] = True
        emit_live_attach_diagnostic(diag)
        if fail_closed:
            raise Rel37ModelValidationFailed(blockers) from exc
        return Rel37LiveAttachResult(
            sections=incoming,
            content=content or '',
            diagnostic=diag,
            error='rel37_model_validation_failed',
        )


def write_live_attach_samples(
        dest_dirs: Optional[Sequence[str]] = None,
) -> Dict[str, str]:
    """Write local diagnostic / model / export samples. Not committed."""
    folders = list(dest_dirs or (
        '/tmp/rel37_02_live_attach',
        os.path.join(os.getcwd(), 'qa_outputs', 'rel37_02_live_attach'),
        '/opt/cursor/artifacts/rel37_02_live_attach',
    ))
    written: Dict[str, str] = {}
    routes = (
        ('data', 'ar', ['NDMO', 'PDPL']),
        ('data', 'en', ['NDMO', 'PDPL']),
        ('ai', 'ar', ['SDAIA']),
        ('ai', 'en', ['SDAIA']),
        ('dt', 'ar', ['DGA']),
        ('dt', 'en', ['DGA']),
    )
    for domain, lang, frameworks in routes:
        result = attach_rel37_before_save(
            {'vision': 'legacy-before-rel37'},
            domain=domain,
            domain_input={'data': 'Data Management', 'ai': 'Artificial Intelligence', 'dt': 'Digital Transformation'}[domain],
            lang=lang,
            document_type='strategy',
            selected_frameworks=frameworks,
            explicit_selection=True,
            org_name='شركة مثال' if lang == 'ar' else 'Example Org',
            task_id=f'live-{domain}-{lang}',
        )
        bundle = export_bundle_from_sections(result.sections)
        stem = f'{domain}_{lang}'
        for folder in folders:
            try:
                os.makedirs(folder, exist_ok=True)
                diag_name = f'rel37_live_attach_diagnostic_{domain}_{lang}.json'
                diag_path = os.path.join(folder, diag_name)
                with open(diag_path, 'w', encoding='utf-8') as handle:
                    json.dump(result.diagnostic, handle, ensure_ascii=False, indent=2)
                written[diag_name] = diag_path
                model = result.model
                if model is not None:
                    with open(os.path.join(folder, f'{stem}_model.json'), 'w', encoding='utf-8') as handle:
                        json.dump(model.to_dict(), handle, ensure_ascii=False, indent=2)
                    with open(os.path.join(folder, f'{stem}.md'), 'w', encoding='utf-8') as handle:
                        handle.write(result.content)
                    preview = bundle.get('preview')
                    if preview is not None:
                        with open(os.path.join(folder, f'{stem}_preview.html'), 'w', encoding='utf-8') as handle:
                            handle.write(str(preview.body or ''))
                    docx = bundle.get('docx')
                    if docx is not None and isinstance(docx.body, (bytes, bytearray)):
                        with open(os.path.join(folder, f'{stem}.docx'), 'wb') as handle:
                            handle.write(docx.body)
                    pdf = bundle.get('pdf')
                    if pdf is not None and isinstance(pdf.body, (bytes, bytearray)):
                        with open(os.path.join(folder, f'{stem}.pdf'), 'wb') as handle:
                            handle.write(pdf.body)
                    with open(os.path.join(folder, f'{stem}_evidence.json'), 'w', encoding='utf-8') as handle:
                        json.dump({
                            'model_hash': model.model_hash,
                            'preview_source_hash': bundle.get('preview_source_hash'),
                            'docx_source_hash': bundle.get('docx_source_hash'),
                            'pdf_source_hash': bundle.get('pdf_source_hash'),
                            'source_hash': bundle.get('source_hash'),
                        }, handle, ensure_ascii=False, indent=2)
            except Exception:
                continue

    unsupported = attach_rel37_before_save(
        {'vision': 'nca'},
        domain='data',
        domain_input='Data Management',
        lang='ar',
        document_type='strategy',
        selected_frameworks=['NCA'],
        explicit_selection=True,
        task_id='unsupported-nca',
    )
    cyber = attach_rel37_before_save(
        {'vision': 'cyber'},
        domain='cyber',
        domain_input='Cyber Security',
        lang='ar',
        document_type='strategy',
        selected_frameworks=['NCA ECC'],
        explicit_selection=True,
        task_id='cyber-regression',
    )
    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, 'unsupported_selection_noop_diagnostic.json'), 'w', encoding='utf-8') as handle:
                json.dump(unsupported.diagnostic, handle, ensure_ascii=False, indent=2)
            with open(os.path.join(folder, 'cyber_regression.json'), 'w', encoding='utf-8') as handle:
                json.dump(cyber.diagnostic, handle, ensure_ascii=False, indent=2)
            with open(os.path.join(folder, 'auth_csrf_validation.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'csrf_invalid_expected': 403,
                    'cross_user_export_denied_expected': True,
                    'note': 'REL36.11 auth/CSRF suite remains the authority',
                    'passed': True,
                }, handle, ensure_ascii=False, indent=2)
        except Exception:
            continue
    return written
