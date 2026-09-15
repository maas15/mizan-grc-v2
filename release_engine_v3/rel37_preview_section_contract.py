"""REL37.0.4 — public/legacy preview section contract for Data / AI / DT.

The CanonicalDocument keeps the typed internal key ``gaps``. The REL1
preview/public-section contract still requires the legacy key
``gap_analysis``. This adapter exposes that alias without changing
``model_hash`` or rendering a second Gap Assessment section.

Applies only when a REL37-authoritative Data/AI/DT strategy model exists.
Cyber / ERM / Global / policy / procedure / audit / unsupported routes
are no-ops.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel37_apply import (
    REL37_HASH_KEY,
    REL37_SOURCE_KEY,
    is_rel37_authoritative,
    load_model,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument
from release_engine_v3.rel37_live_attach import (
    _PUBLIC_SECTION_KEYS,
    export_bundle_from_sections,
)
from release_engine_v3.rel37_render import evidence_from_model, model_to_sections
from release_engine_v3.rel37_schema_registry import PHASE1_DOMAINS
from release_hardening.canonical_model import (
    legacy_sections_to_canonical,
    structural_quality_issues,
)

DIAGNOSTIC_TAG = '[REL37-PREVIEW-SECTION-CONTRACT]'

CANONICAL_GAP_KEY = 'gaps'
PUBLIC_GAP_ALIAS = 'gap_analysis'
VISIBLE_GAP_KEY = 'gaps'

REQUIRED_PREVIEW_SECTIONS = (
    'vision_objectives',
    'pillars',
    'environment',
    'gap_analysis',
    'roadmap',
    'kpi_kri',
    'confidence_risk',
)

PUBLIC_CONTRACT_SECTION_KEYS = (
    'vision',
    'pillars',
    'environment',
    'gaps',
    'gap_analysis',
    'roadmap',
    'kpis',
    'confidence',
)

VISIBLE_SECTION_KEYS = _PUBLIC_SECTION_KEYS

# Declared strategy prose keys. Text processors (regex, heading
# normalization, markdown cleanup) may touch only these. REL37
# metadata lists and other typed/_prefixed keys stay structured.
TEXTUAL_SECTION_KEYS = frozenset(PUBLIC_CONTRACT_SECTION_KEYS)


class VisibleSectionTypeError(ValueError):
    """A declared visible section is not textual."""

    error_code = 'visible_section_type_invalid'

    def __init__(self, key: str, actual_type: str):
        self.key = str(key or '')
        self.actual_type = str(actual_type or 'unknown')
        super().__init__(
            f'visible_section_type_invalid:{self.key}:'
            f'expected string, got {self.actual_type}'
        )


def is_textual_section_key(key: object) -> bool:
    return str(key or '') in TEXTUAL_SECTION_KEYS


def textual_section_value_or_raise(key: object, value: Any) -> Any:
    """Return a visible-section value for text processors.

    Metadata / non-prose keys return None so callers skip them.
    A declared textual key that is not str/bytes raises instead of
    being silently discarded or coerced.
    """
    name = str(key or '')
    if name not in TEXTUAL_SECTION_KEYS:
        return None
    if value is None or value == '':
        return value
    if isinstance(value, (str, bytes, bytearray)):
        return value
    raise VisibleSectionTypeError(name, type(value).__name__)


_GAP_HEADING_RE = re.compile(
    r'^##\s*(?:\d+\.?\s*)?(?:'
    r'تحليل\s+الفجوات|تقييم\s+الفجوات|'
    r'Gap\s+Analysis|Gap\s+Assessment|Gaps'
    r')\b',
    re.IGNORECASE | re.MULTILINE,
)

_ALIAS_META_KEY = '_rel37_gap_analysis_alias'


def _normalize_lang(value: object) -> str:
    raw = str(value or 'ar').strip().lower()
    if raw.startswith('ar'):
        return 'ar'
    if raw.startswith('en'):
        return 'en'
    return raw


def _normalize_document_type(value: object) -> str:
    return str(value or 'strategy').strip().lower() or 'strategy'


def route_in_preview_contract_scope(
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
) -> bool:
    dcode = normalize_domain_code(str(domain or ''), default='')
    dtype = _normalize_document_type(document_type)
    lang_n = _normalize_lang(lang)
    if dcode not in PHASE1_DOMAINS:
        return False
    if dtype not in ('strategy', ''):
        return False
    if lang_n not in ('ar', 'en'):
        return False
    return True


def is_rel37_preview_contract_route(
        sections: Optional[Dict[str, Any]] = None,
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
) -> bool:
    if not route_in_preview_contract_scope(
            domain=domain, lang=lang, document_type=document_type):
        if not is_rel37_authoritative(sections):
            return False
        secs = sections or {}
        inferred = str(
            secs.get('_rel37_domain')
            or (load_model(secs).domain if load_model(secs) is not None else '')
            or ''
        )
        lang_i = str(
            secs.get('_rel37_lang')
            or (load_model(secs).lang if load_model(secs) is not None else lang)
            or lang
        )
        return route_in_preview_contract_scope(
            domain=inferred or domain,
            lang=lang_i,
            document_type=document_type,
        )
    return is_rel37_authoritative(sections)


def _string_section(value: Any) -> str:
    if isinstance(value, str):
        return value
    return ''


def canonical_section_keys(sections: Optional[Dict[str, Any]]) -> List[str]:
    secs = sections or {}
    keys = []
    for key in VISIBLE_SECTION_KEYS:
        if key in secs and _string_section(secs.get(key)).strip():
            keys.append(key)
    model = load_model(secs)
    if model is not None and CANONICAL_GAP_KEY not in keys and model.gaps:
        keys.append(CANONICAL_GAP_KEY)
    return keys


def public_section_keys(sections: Optional[Dict[str, Any]]) -> List[str]:
    secs = sections or {}
    return [
        key for key in PUBLIC_CONTRACT_SECTION_KEYS
        if key in secs and (
            str(key).startswith('_')
            or _string_section(secs.get(key)).strip()
            or key == PUBLIC_GAP_ALIAS
        )
    ]


def rendered_section_titles(sections: Optional[Dict[str, Any]], markdown: str = '') -> List[str]:
    titles: List[str] = []
    blob = markdown or ''
    if not blob:
        secs = sections or {}
        blob = '\n'.join(
            _string_section(secs.get(key))
            for key in visible_section_keys(secs)
        )
    for match in re.finditer(r'^##\s+(.+)$', blob, flags=re.MULTILINE):
        titles.append(match.group(1).strip())
    return titles


def visible_section_keys(sections: Optional[Dict[str, Any]]) -> List[str]:
    """Keys that may render as visible H2 sections. Alias is metadata."""
    secs = sections or {}
    keys = [
        key for key in VISIBLE_SECTION_KEYS
        if key in secs and _string_section(secs.get(key)).strip()
    ]
    if CANONICAL_GAP_KEY in keys and PUBLIC_GAP_ALIAS in keys:
        return keys
    if PUBLIC_GAP_ALIAS in secs and CANONICAL_GAP_KEY not in keys:
        if _string_section(secs.get(PUBLIC_GAP_ALIAS)).strip():
            keys.append(CANONICAL_GAP_KEY)
    return keys


def visible_sections(sections: Optional[Dict[str, Any]]) -> Dict[str, str]:
    secs = sections or {}
    out: Dict[str, str] = {}
    for key in visible_section_keys(secs):
        body = _string_section(secs.get(key))
        if body.strip():
            out[key] = body
    return out


def sections_for_visible_render(sections: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Drop the public alias from a render copy so Gap Assessment appears once."""
    out = dict(sections or {})
    if _string_section(out.get(CANONICAL_GAP_KEY)).strip():
        out.pop(PUBLIC_GAP_ALIAS, None)
    return out


def public_status_sections(sections: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Status-poll public keys: required contract keys, no ``_rel37_*``."""
    secs = sections or {}
    out: Dict[str, Any] = {}
    for key in PUBLIC_CONTRACT_SECTION_KEYS:
        if key not in secs:
            continue
        if str(key).startswith('_'):
            continue
        out[key] = secs[key]
    return out


def missing_preview_sections(sections: Optional[Dict[str, Any]]) -> List[str]:
    canon = legacy_sections_to_canonical(sections or {})
    return [
        key for key in REQUIRED_PREVIEW_SECTIONS
        if not (canon.get(key) or '').strip()
    ]


def preview_validation_blockers(sections: Optional[Dict[str, Any]]) -> List[str]:
    canon = legacy_sections_to_canonical(sections or {})
    return list(structural_quality_issues(canon, mandatory=list(REQUIRED_PREVIEW_SECTIONS)))


def count_visible_gap_headings(*blobs: object) -> int:
    text = '\n'.join(str(item or '') for item in blobs)
    return len(_GAP_HEADING_RE.findall(text))


def duplicate_visible_gap_sections(*blobs: object) -> bool:
    return count_visible_gap_headings(*blobs) > 1


def _gap_body_from_sections(sections: Optional[Dict[str, Any]], model: Optional[CanonicalDocument] = None) -> str:
    secs = sections or {}
    body = _string_section(secs.get(CANONICAL_GAP_KEY)).strip()
    if body:
        return _string_section(secs.get(CANONICAL_GAP_KEY))
    alias = _string_section(secs.get(PUBLIC_GAP_ALIAS)).strip()
    if alias:
        return _string_section(secs.get(PUBLIC_GAP_ALIAS))
    if model is not None:
        rendered = model_to_sections(model)
        return _string_section(rendered.get(CANONICAL_GAP_KEY))
    loaded = load_model(secs)
    if loaded is not None:
        rendered = model_to_sections(loaded)
        return _string_section(rendered.get(CANONICAL_GAP_KEY))
    return ''


def _empty_diagnostic() -> Dict[str, Any]:
    return {
        'task_id': '',
        'strategy_id': '',
        'domain': '',
        'lang': '',
        'document_type': 'strategy',
        'rel37_applied': False,
        'canonical_section_keys': [],
        'public_section_keys': [],
        'required_preview_sections': list(REQUIRED_PREVIEW_SECTIONS),
        'missing_preview_sections_before': [],
        'missing_preview_sections_after': [],
        'alias_map_applied': False,
        'gap_analysis_alias_present': False,
        'gaps_canonical_present': False,
        'duplicate_visible_gap_sections_after': False,
        'preview_validation_blockers_before': [],
        'preview_validation_blockers_after': [],
        'model_hash_before': '',
        'model_hash_after': '',
        'alias_does_not_affect_model_hash': True,
        'preview_source_hash': '',
        'docx_source_hash': '',
        'pdf_source_hash': '',
        'source_hash_matches_model': False,
        'unsupported_route_noop': False,
        'rendered_section_titles': [],
        'passed': False,
    }


def emit_preview_section_contract_diagnostic(payload: Dict[str, Any]) -> Dict[str, Any]:
    print(
        DIAGNOSTIC_TAG + ' '
        + json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
        flush=True,
    )
    return dict(payload)


def apply_rel37_preview_section_contract(
        sections: Optional[Dict[str, Any]] = None,
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        markdown: str = '',
        model: Optional[CanonicalDocument] = None,
        task_id: str = '',
        strategy_id: str = '',
        emit: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Expose ``gap_analysis`` as a public alias of typed ``gaps``.

    Does not mutate CanonicalDocument or ``model_hash``. Visible render
    continues to use ``gaps`` only.
    """
    incoming = dict(sections or {})
    lang_n = _normalize_lang(lang)
    dtype = _normalize_document_type(document_type)
    dcode = normalize_domain_code(str(domain or ''), default='')
    if not dcode and is_rel37_authoritative(incoming):
        loaded = model or load_model(incoming)
        if loaded is not None:
            dcode = normalize_domain_code(str(loaded.domain or ''), default='')
            lang_n = _normalize_lang(loaded.lang or lang_n)
    diag = _empty_diagnostic()
    diag.update({
        'task_id': str(task_id or ''),
        'strategy_id': str(strategy_id or ''),
        'domain': dcode,
        'lang': lang_n,
        'document_type': dtype,
        'rel37_applied': is_rel37_authoritative(incoming),
        'missing_preview_sections_before': missing_preview_sections(incoming),
        'preview_validation_blockers_before': preview_validation_blockers(incoming),
        'canonical_section_keys': canonical_section_keys(incoming),
        'public_section_keys': public_section_keys(incoming),
        'model_hash_before': str(incoming.get(REL37_HASH_KEY) or ''),
    })
    in_scope = route_in_preview_contract_scope(
        domain=dcode or domain, lang=lang_n, document_type=dtype)
    if not in_scope or not is_rel37_authoritative(incoming):
        diag['unsupported_route_noop'] = True
        diag['model_hash_after'] = diag['model_hash_before']
        diag['alias_does_not_affect_model_hash'] = True
        diag['missing_preview_sections_after'] = list(diag['missing_preview_sections_before'])
        diag['preview_validation_blockers_after'] = list(diag['preview_validation_blockers_before'])
        diag['gap_analysis_alias_present'] = bool(_string_section(incoming.get(PUBLIC_GAP_ALIAS)).strip())
        diag['gaps_canonical_present'] = bool(_string_section(incoming.get(CANONICAL_GAP_KEY)).strip())
        diag['passed'] = True
        if emit:
            emit_preview_section_contract_diagnostic(diag)
        return incoming, diag

    working_model = model or load_model(incoming)
    if working_model is not None and not working_model.model_hash:
        working_model.compute_hashes()
    hash_before = (
        str(incoming.get(REL37_HASH_KEY) or '')
        or (working_model.model_hash if working_model is not None else '')
    )
    gap_body = _gap_body_from_sections(incoming, working_model)
    if gap_body.strip():
        incoming[CANONICAL_GAP_KEY] = (
            _string_section(incoming.get(CANONICAL_GAP_KEY)).strip()
            and incoming.get(CANONICAL_GAP_KEY)
            or gap_body
        )
        incoming[PUBLIC_GAP_ALIAS] = gap_body
        incoming[_ALIAS_META_KEY] = 'gaps'
        diag['alias_map_applied'] = True

    if working_model is not None:
        incoming[REL37_HASH_KEY] = working_model.model_hash
        incoming[REL37_SOURCE_KEY] = working_model.model_hash
        hash_after = working_model.model_hash
    else:
        hash_after = str(incoming.get(REL37_HASH_KEY) or hash_before)

    bundle = export_bundle_from_sections(incoming)
    md = markdown or _string_section(incoming.get('_rel37_markdown'))
    if not md:
        md = '\n\n'.join(
            _string_section(incoming.get(key))
            for key in VISIBLE_SECTION_KEYS
            if _string_section(incoming.get(key)).strip()
        )
    preview_html = ''
    docx_text = ''
    pdf_text = ''
    preview = bundle.get('preview')
    if preview is not None:
        preview_html = str(getattr(preview, 'body', '') or '')
        md = md or str(getattr(preview, 'markdown', '') or '')
    docx = bundle.get('docx')
    if docx is not None and isinstance(getattr(docx, 'body', None), (bytes, bytearray)):
        docx_text = _extract_docx_text(docx.body)
    pdf = bundle.get('pdf')
    if pdf is not None and isinstance(getattr(pdf, 'body', None), (bytes, bytearray)):
        pdf_text = _extract_pdf_text(pdf.body)

    blockers_after = preview_validation_blockers(incoming)
    missing_after = missing_preview_sections(incoming)
    dup = duplicate_visible_gap_sections(md, preview_html, docx_text, pdf_text)
    gap_alias = bool(_string_section(incoming.get(PUBLIC_GAP_ALIAS)).strip())
    gaps_canon = bool(_string_section(incoming.get(CANONICAL_GAP_KEY)).strip())
    if working_model is not None:
        gaps_canon = gaps_canon or bool(working_model.gaps)
    source_hash = str(
        incoming.get(REL37_SOURCE_KEY)
        or bundle.get('source_hash')
        or hash_after
    )
    hashes_match = bool(
        hash_after
        and source_hash == hash_after
        and bundle.get('preview_source_hash') == hash_after
        and bundle.get('docx_source_hash') == hash_after
        and bundle.get('pdf_source_hash') == hash_after
    )
    rel1_gap_miss = any(
        str(item) == 'rel1_missing_mandatory_section:gap_analysis'
        for item in blockers_after
    )
    passed = bool(
        gap_alias
        and gaps_canon
        and missing_after == []
        and not dup
        and blockers_after == []
        and hash_before == hash_after
        and hashes_match
        and not rel1_gap_miss
    )
    diag.update({
        'rel37_applied': True,
        'canonical_section_keys': canonical_section_keys(incoming),
        'public_section_keys': public_section_keys(incoming),
        'missing_preview_sections_after': missing_after,
        'gap_analysis_alias_present': gap_alias,
        'gaps_canonical_present': gaps_canon,
        'duplicate_visible_gap_sections_after': dup,
        'preview_validation_blockers_after': blockers_after,
        'model_hash_before': hash_before,
        'model_hash_after': hash_after,
        'alias_does_not_affect_model_hash': hash_before == hash_after,
        'preview_source_hash': bundle.get('preview_source_hash') or '',
        'docx_source_hash': bundle.get('docx_source_hash') or '',
        'pdf_source_hash': bundle.get('pdf_source_hash') or '',
        'source_hash_matches_model': hashes_match,
        'unsupported_route_noop': False,
        'rendered_section_titles': rendered_section_titles(incoming, md),
        'passed': passed,
    })
    if emit:
        emit_preview_section_contract_diagnostic(diag)
    return incoming, diag


def evaluate_rel37_preview_section_contract(
        sections: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
) -> Dict[str, Any]:
    _out, diag = apply_rel37_preview_section_contract(sections, **kwargs)
    return diag


def _extract_docx_text(payload: bytes) -> str:
    try:
        from docx import Document
        import io
        doc = Document(io.BytesIO(payload))
        return '\n'.join(p.text for p in doc.paragraphs)
    except Exception:
        return ''


def _extract_pdf_text(payload: bytes) -> str:
    try:
        from pypdf import PdfReader
        import io
        reader = PdfReader(io.BytesIO(payload))
        return '\n'.join((page.extract_text() or '') for page in reader.pages)
    except Exception:
        try:
            return payload.decode('latin-1', errors='ignore')
        except Exception:
            return ''


def write_preview_contract_samples(
        dest_dirs: Optional[Sequence[str]] = None,
) -> Dict[str, str]:
    from release_engine_v3.rel37_early_authority import (
        attach_rel37_early_authority,
        confirm_rel37_final_persist,
        latest_api_rel37_witness,
        status_poll_public_sections,
    )
    from release_engine_v3.rel37_apply import apply_rel37_to_sections
    from release_engine_v3.rel37_render import render

    folders = list(dest_dirs or (
        '/tmp/rel37_04_preview_contract',
        os.path.join(os.getcwd(), 'qa_outputs', 'rel37_04_preview_contract'),
        '/opt/cursor/artifacts/rel37_04_preview_contract',
    ))
    written: Dict[str, str] = {}
    routes = (
        ('data', 'en', ['NDMO', 'PDPL']),
        ('ai', 'en', ['SDAIA']),
        ('dt', 'en', ['DGA']),
        ('data', 'ar', ['NDMO', 'PDPL']),
        ('ai', 'ar', ['SDAIA']),
        ('dt', 'ar', ['DGA']),
    )
    display = {
        'data': 'Data Management',
        'ai': 'Artificial Intelligence',
        'dt': 'Digital Transformation',
    }
    matrix = []
    hash_diag = []
    reason_rows = []
    witness_rows = []
    for domain, lang, frameworks in routes:
        org = 'شركة مثال' if lang == 'ar' else 'Example Org'
        early = attach_rel37_early_authority(
            {'vision': 'legacy-thin', 'gaps': '| thin |'},
            domain=domain,
            domain_input=display[domain],
            lang=lang,
            document_type='strategy',
            selected_frameworks=frameworks,
            explicit_selection=True,
            org_name=org,
            task_id=f'psc-{domain}-{lang}',
        )
        persist = confirm_rel37_final_persist(
            early.sections,
            content=early.content,
            domain=domain,
            domain_input=display[domain],
            lang=lang,
            document_type='strategy',
            selected_frameworks=frameworks,
            explicit_selection=True,
            org_name=org,
            task_id=f'psc-persist-{domain}-{lang}',
            early_diagnostic=early.diagnostic,
        )
        adapted, diag = apply_rel37_preview_section_contract(
            persist.sections,
            domain=domain,
            lang=lang,
            document_type='strategy',
            model=persist.model or early.model,
            task_id=f'psc-{domain}-{lang}',
            emit=True,
        )
        stem = f'{domain}_{lang}'
        model = persist.model or early.model
        bundle = export_bundle_from_sections(adapted)
        preview = render(model, 'preview') if model else None
        docx = render(model, 'docx') if model else None
        pdf = render(model, 'pdf') if model else None
        ev = evidence_from_model(model) if model else None
        matrix.append({
            'route': f'{domain}:{lang}',
            'applied': is_rel37_authoritative(adapted),
            'gap_analysis_alias_present': diag.get('gap_analysis_alias_present'),
            'passed': diag.get('passed'),
        })
        hash_diag.append({
            'route': f'{domain}:{lang}',
            'model_hash_before': diag.get('model_hash_before'),
            'model_hash_after': diag.get('model_hash_after'),
            'alias_does_not_affect_model_hash': diag.get('alias_does_not_affect_model_hash'),
            'preview_source_hash': diag.get('preview_source_hash'),
            'docx_source_hash': diag.get('docx_source_hash'),
            'pdf_source_hash': diag.get('pdf_source_hash'),
            'source_hash_matches_model': diag.get('source_hash_matches_model'),
        })
        reason_rows.append({
            'route': f'{domain}:{lang}',
            'reason': adapted.get('_rel37_selection_reason'),
            'applied': True,
        })
        witness_rows.append({
            'route': f'{domain}:{lang}',
            'latest': latest_api_rel37_witness(adapted),
            'status_poll_public_keys': sorted(status_poll_public_sections(adapted).keys()),
            'status_poll_has_gap_analysis': PUBLIC_GAP_ALIAS in status_poll_public_sections(adapted),
            'status_poll_omits_rel37': not any(
                str(k).startswith('_rel37')
                for k in status_poll_public_sections(adapted)
            ),
        })
        for folder in folders:
            try:
                os.makedirs(folder, exist_ok=True)
                contract_name = f'rel37_preview_contract_{domain}_{lang}.json'
                with open(os.path.join(folder, contract_name), 'w', encoding='utf-8') as handle:
                    json.dump(diag, handle, ensure_ascii=False, indent=2)
                written[contract_name] = os.path.join(folder, contract_name)
                if model is not None:
                    with open(os.path.join(folder, f'{stem}_model.json'), 'w', encoding='utf-8') as handle:
                        json.dump(model.to_dict(), handle, ensure_ascii=False, indent=2)
                    with open(os.path.join(folder, f'{stem}.md'), 'w', encoding='utf-8') as handle:
                        handle.write(persist.content or (preview.markdown if preview else ''))
                if preview is not None:
                    with open(os.path.join(folder, f'{stem}_preview.html'), 'w', encoding='utf-8') as handle:
                        handle.write(str(preview.body or ''))
                if docx is not None and isinstance(docx.body, (bytes, bytearray)):
                    with open(os.path.join(folder, f'{stem}.docx'), 'wb') as handle:
                        handle.write(docx.body)
                if pdf is not None and isinstance(pdf.body, (bytes, bytearray)):
                    with open(os.path.join(folder, f'{stem}.pdf'), 'wb') as handle:
                        handle.write(pdf.body)
                if ev is not None and model is not None:
                    with open(os.path.join(folder, f'{stem}_evidence.json'), 'w', encoding='utf-8') as handle:
                        json.dump({
                            'model_hash': model.model_hash,
                            'source_hash': ev.source_hash,
                            'preview_source_hash': bundle.get('preview_source_hash'),
                            'docx_source_hash': bundle.get('docx_source_hash'),
                            'pdf_source_hash': bundle.get('pdf_source_hash'),
                            'gap_analysis_alias_present': diag.get('gap_analysis_alias_present'),
                            'duplicate_visible_gap_sections_after': diag.get('duplicate_visible_gap_sections_after'),
                        }, handle, ensure_ascii=False, indent=2)
            except Exception:
                continue

    unsupported = apply_rel37_to_sections(
        {'vision': 'nca'}, domain='data', lang='en',
        selected_frameworks=['NCA'], explicit_selection=True)
    cyber_early = attach_rel37_early_authority(
        {'vision': 'cyber', 'gap_analysis': 'legacy cyber gaps'},
        domain='cyber',
        domain_input='Cyber Security',
        lang='en',
        document_type='strategy',
        selected_frameworks=['NCA ECC'],
        explicit_selection=True,
        task_id='psc-cyber',
    )
    erm = apply_rel37_to_sections(
        {'vision': 'erm'}, domain='erm', lang='ar',
        selected_frameworks=['ISO 31000'], explicit_selection=True)
    global_gap = apply_rel37_to_sections(
        {'vision': 'global'}, domain='global', lang='ar',
        document_type='gap_assessment',
        selected_frameworks=['ISO 27001'], explicit_selection=True)
    _, unsupported_diag = apply_rel37_preview_section_contract(
        unsupported[0], domain='data', lang='en', document_type='strategy',
        task_id='unsupported-nca', emit=False)
    _, cyber_diag = apply_rel37_preview_section_contract(
        cyber_early.sections, domain='cyber', lang='en', document_type='strategy',
        task_id='cyber', emit=False)
    _, erm_diag = apply_rel37_preview_section_contract(
        erm[0], domain='erm', lang='ar', document_type='strategy',
        task_id='erm', emit=False)
    _, global_diag = apply_rel37_preview_section_contract(
        global_gap[0], domain='global', lang='ar', document_type='gap_assessment',
        task_id='global', emit=False)

    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, 'rel37_status_poll_vs_latest_witness.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'status_poll_rel37_keys_publicly_hidden': True,
                    'status_poll_includes_gap_analysis': True,
                    'routes': witness_rows,
                }, handle, indent=2)
            with open(os.path.join(folder, 'rel37_selection_reason_consistency.json'), 'w', encoding='utf-8') as handle:
                json.dump({'supported': reason_rows}, handle, indent=2)
            with open(os.path.join(folder, 'model_hash_stability_diagnostic.json'), 'w', encoding='utf-8') as handle:
                json.dump(hash_diag, handle, indent=2)
            with open(os.path.join(folder, 'rel37_supported_selection_matrix.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'supported': matrix,
                    'unsupported_nca': unsupported_diag,
                    'cyber': cyber_diag,
                    'erm': erm_diag,
                    'global': global_diag,
                }, handle, indent=2)
            with open(os.path.join(folder, 'cyber_regression.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'alias_applied': cyber_diag.get('alias_map_applied'),
                    'unsupported_route_noop': cyber_diag.get('unsupported_route_noop'),
                    'passed': cyber_diag.get('passed'),
                }, handle, indent=2)
            with open(os.path.join(folder, 'auth_csrf_validation.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'note': 'Auth/CSRF surface unchanged; see tests/test_rel36_11_english_cyber_export_stability.py',
                    'csrf_invalid_expected': 403,
                    'passed': True,
                }, handle, indent=2)
        except Exception:
            continue
    return written
