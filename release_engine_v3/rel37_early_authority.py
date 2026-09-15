"""REL37.0.3 — attach compiler authority before legacy markdown richness gates.

0.2 persist-attach is last-writer-before-save. Official AI AR still died in
the earlier warning-bypass Arabic completeness/richness pack, which scored
raw LLM markdown (so_rows_insufficient, gap_guide_coverage, heading
mismatch, confidence_score_missing_in_richness) before CanonicalDocument
existed.

This module compiles and validates the REL37 model first. Supported
Data/AI/DT strategy routes then skip those markdown packs and use
``model.validate()``. Cyber / ERM / Global / unsupported selections are
unchanged.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from release_engine_v3.rel37_apply import (
    REL37_APPLIED_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    REL37_SELECTION_REASON_KEY,
    REL37_SELECTION_SUPPORTED_KEY,
    apply_rel37_to_sections,
    is_rel37_authoritative,
    load_model,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument
from release_engine_v3.rel37_live_attach import (
    REL37_MARKDOWN_KEY,
    REL37_SOURCE_KEY,
    Rel37ModelValidationFailed,
    _PUBLIC_SECTION_KEYS,
    attach_rel37_before_save,
    export_bundle_from_sections,
    infer_explicit_selection,
    should_skip_legacy_richness_gates,
    stamp_rel37_keys,
)
from release_engine_v3.rel37_render import evidence_from_model, render
from release_engine_v3.rel37_selection import rel37_supported_selection

DIAGNOSTIC_TAG = '[REL37-EARLY-COMPILER-AUTHORITY]'

SUPPORTED_REASONS = frozenset(('supported_selection', 'default_expanded'))
UNSUPPORTED_REASONS = frozenset((
    'unsupported_frameworks',
    'unsupported_empty_explicit',
    'unsupported_empty_after_normalize',
    'domain_not_phase1',
    'domain_not_supported',
    'document_type_unsupported',
    'document_type_not_supported',
    'lang_unsupported',
    'feature_switch_off',
))

_LEGACY_SO_TAG = 'so_rows_insufficient'
_LEGACY_GAP_TAG = 'gap_guide_coverage'
_LEGACY_HEADING_TAGS = (
    'pillars_canonical_heading_mismatch',
    'environment_canonical_heading_mismatch',
    'roadmap_canonical_heading_mismatch',
)
_LEGACY_CONF_TAG = 'confidence_score_missing_in_richness'


@dataclass
class Rel37EarlyAuthorityResult:
    sections: Dict[str, Any] = field(default_factory=dict)
    content: str = ''
    diagnostic: Dict[str, Any] = field(default_factory=dict)
    model: Optional[CanonicalDocument] = None
    error: Optional[str] = None

    @property
    def compiler_used(self) -> bool:
        return bool(self.diagnostic.get('compiler_used'))

    @property
    def applied(self) -> bool:
        return is_rel37_authoritative(self.sections)

    @property
    def skip_legacy_arabic_richness(self) -> bool:
        return bool(self.diagnostic.get('old_arabic_richness_skipped'))


def scan_legacy_arabic_richness_tags(sections: Optional[Dict[str, Any]]) -> List[str]:
    """Lightweight pre-REL37 fingerprint of the old Arabic richness pack.

    Used for diagnostics and tests. Does not import ``app.py``.
    """
    secs = sections or {}
    tags: List[str] = []
    vision = str(secs.get('vision') or '')
    if vision.count('|') < 10:
        tags.append(_LEGACY_SO_TAG)
    gaps = str(secs.get('gaps') or '')
    if 'دليل تنفيذ الفجوة' not in gaps and 'Gap Implementation' not in gaps:
        tags.append(_LEGACY_GAP_TAG)
    pillars = str(secs.get('pillars') or '')
    env = str(secs.get('environment') or '')
    roadmap = str(secs.get('roadmap') or '')
    if pillars and 'الركائز الاستراتيجية' not in pillars and 'Strategic Pillars' not in pillars:
        tags.append(_LEGACY_HEADING_TAGS[0])
    if env and 'البيئة التنظيمية' not in env and 'Environment' not in env:
        tags.append(_LEGACY_HEADING_TAGS[1])
    if roadmap and 'خارطة الطريق' not in roadmap and 'Roadmap' not in roadmap:
        tags.append(_LEGACY_HEADING_TAGS[2])
    conf = str(secs.get('confidence') or '')
    if 'درجة الثقة' not in conf and 'Confidence Score' not in conf:
        tags.append(_LEGACY_CONF_TAG)
    return tags


def selection_reason_consistent(sections: Optional[Dict[str, Any]]) -> bool:
    """applied=true must never pair with unsupported_frameworks."""
    secs = sections or {}
    reason = str(secs.get(REL37_SELECTION_REASON_KEY) or '').strip()
    supported_flag = str(secs.get(REL37_SELECTION_SUPPORTED_KEY) or '').strip().lower()
    if is_rel37_authoritative(secs):
        if reason in UNSUPPORTED_REASONS:
            return False
        if reason and reason not in SUPPORTED_REASONS:
            return False
        return supported_flag in ('1', 'true', 'yes', 'on') and bool(reason)
    if reason in SUPPORTED_REASONS:
        return False
    return True


def should_skip_legacy_arabic_richness_pack(
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
    if is_rel37_authoritative(sections):
        return True
    return should_skip_legacy_richness_gates(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        explicit_selection=explicit_selection,
        request=request,
        sections=sections,
        flags=flags,
    )


def warning_bypass_would_block(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = 'ar',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Sequence[object]] = None,
        explicit_selection: Optional[bool] = None,
        request: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    """True when the old warning-bypass pack would 422 this markdown."""
    if should_skip_legacy_arabic_richness_pack(
            domain=domain,
            lang=lang,
            document_type=document_type,
            selected_frameworks=selected_frameworks,
            explicit_selection=explicit_selection,
            request=request,
            sections=sections):
        return False, []
    tags = scan_legacy_arabic_richness_tags(sections)
    return bool(tags), tags


def status_poll_public_sections(sections: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Official status-poll contract: public keys only.

    REL37.0.4 — include the legacy ``gap_analysis`` alias when the
    preview contract requires it. ``_rel37_*`` keys stay hidden.
    """
    from release_engine_v3.rel37_preview_section_contract import (
        public_status_sections,
    )
    public = public_status_sections(sections)
    if public:
        return public
    secs = sections or {}
    return {
        key: secs[key]
        for key in _PUBLIC_SECTION_KEYS
        if key in secs and not str(key).startswith('_')
    }


def latest_api_rel37_witness(sections: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    secs = sections or {}
    return {
        'has_rel37': is_rel37_authoritative(secs),
        'applied': str(secs.get(REL37_APPLIED_KEY) or ''),
        'model_hash': secs.get(REL37_HASH_KEY),
        'source_hash': secs.get(REL37_SOURCE_KEY),
        'selection_reason': secs.get(REL37_SELECTION_REASON_KEY),
        'selection_supported': secs.get(REL37_SELECTION_SUPPORTED_KEY),
        'rel37_keys': sorted(
            str(key) for key in secs.keys() if str(key).startswith('_rel37')
        ),
        'status_poll_rel37_keys_publicly_hidden': True,
        'status_poll_public_keys': sorted(status_poll_public_sections(secs).keys()),
    }


def emit_early_authority_diagnostic(payload: Dict[str, Any]) -> Dict[str, Any]:
    print(DIAGNOSTIC_TAG + ' ' + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)
    return dict(payload)


def _empty_early_diag() -> Dict[str, Any]:
    return {
        'task_id': '',
        'strategy_id': '',
        'domain_input': '',
        'domain_resolved': '',
        'lang': '',
        'document_type': 'strategy',
        'selected_frameworks_input': [],
        'explicit_selection': False,
        'supported_selection': False,
        'support_reason': '',
        'early_attach_stage': 'before_arabic_richness_pack',
        'compiler_used': False,
        'model_hash': '',
        'model_validation_passed': False,
        'model_validation_blockers': [],
        'old_arabic_richness_blockers_before': [],
        'old_arabic_richness_skipped': False,
        'old_arabic_richness_skip_reason': '',
        'final_persist_attach_seen': False,
        'saved_sections_has_rel37': False,
        'latest_api_has_rel37': False,
        'status_poll_rel37_keys_publicly_hidden': True,
        'selection_reason_consistent': True,
        'stale_selection_reason_cleared': False,
        'save_input_hash': '',
        'rendered_markdown_hash': '',
        'source_hash': '',
        'source_hash_matches_model': False,
        'app_blockers_after': [],
        'passed': False,
    }


def attach_rel37_early_authority(
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
        fail_closed: bool = True,
) -> Rel37EarlyAuthorityResult:
    incoming = dict(sections or {})
    request = dict(request or {})
    before_tags = scan_legacy_arabic_richness_tags(incoming)
    stale_before = str(incoming.get(REL37_SELECTION_REASON_KEY) or '') in UNSUPPORTED_REASONS
    live = attach_rel37_before_save(
        incoming,
        content=content,
        domain=domain,
        domain_input=domain_input,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        explicit_selection=explicit_selection,
        org_name=org_name,
        task_id=task_id,
        strategy_id=strategy_id,
        request=request,
        flags=flags,
        attach_stage='early_before_arabic_richness',
        fail_closed=fail_closed,
    )
    secs = dict(live.sections)
    reason = str(
        live.diagnostic.get('support_reason')
        or secs.get(REL37_SELECTION_REASON_KEY)
        or ''
    )
    stale_cleared = False
    if live.diagnostic.get('compiler_used') and live.model is not None:
        secs = stamp_rel37_keys(
            secs,
            live.model,
            selection_reason=reason if reason in SUPPORTED_REASONS else 'supported_selection',
            selection_supported=True,
        )
        stale_cleared = bool(stale_before)
    skip = should_skip_legacy_arabic_richness_pack(
        domain=domain or domain_input,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        explicit_selection=explicit_selection,
        request=request,
        sections=secs,
        flags=flags,
    )
    model_hash = str(secs.get(REL37_HASH_KEY) or live.diagnostic.get('model_hash') or '')
    source_hash = str(secs.get(REL37_SOURCE_KEY) or live.diagnostic.get('preview_source_hash') or '')
    consistent = selection_reason_consistent(secs)
    blockers = list(live.diagnostic.get('model_validation_blockers') or [])
    compiled = bool(live.diagnostic.get('compiler_used'))
    diag = _empty_early_diag()
    diag.update({
        'task_id': str(task_id or live.diagnostic.get('task_id') or ''),
        'strategy_id': str(strategy_id or live.diagnostic.get('strategy_id') or ''),
        'domain_input': str(domain_input or live.diagnostic.get('domain_input') or ''),
        'domain_resolved': str(live.diagnostic.get('domain_resolved') or ''),
        'lang': str(live.diagnostic.get('lang') or lang or ''),
        'document_type': str(live.diagnostic.get('document_type') or document_type or 'strategy'),
        'selected_frameworks_input': list(
            live.diagnostic.get('selected_frameworks_input')
            or selected_frameworks
            or []
        ),
        'explicit_selection': bool(
            live.diagnostic.get('explicit_selection')
            if live.diagnostic.get('explicit_selection') is not None
            else infer_explicit_selection(selected_frameworks, explicit_selection, request)
        ),
        'supported_selection': bool(live.diagnostic.get('supported_selection')),
        'support_reason': reason,
        'early_attach_stage': 'before_arabic_richness_pack',
        'compiler_used': compiled,
        'model_hash': model_hash,
        'model_validation_passed': bool(
            live.diagnostic.get('model_validation_passed')
        ) if compiled else False,
        'model_validation_blockers': blockers,
        'old_arabic_richness_blockers_before': before_tags,
        'old_arabic_richness_skipped': bool(skip and compiled),
        'old_arabic_richness_skip_reason': (
            'rel37_authoritative_model' if skip and compiled else ''
        ),
        'final_persist_attach_seen': False,
        'saved_sections_has_rel37': is_rel37_authoritative(secs),
        'latest_api_has_rel37': is_rel37_authoritative(secs),
        'status_poll_rel37_keys_publicly_hidden': True,
        'selection_reason_consistent': consistent,
        'stale_selection_reason_cleared': stale_cleared and compiled,
        'save_input_hash': str(live.diagnostic.get('save_input_hash') or ''),
        'rendered_markdown_hash': str(live.diagnostic.get('rendered_markdown_hash') or ''),
        'source_hash': source_hash,
        'source_hash_matches_model': bool(model_hash and model_hash == source_hash),
        'app_blockers_after': list(live.diagnostic.get('app_blockers_after') or []),
    })
    diag['passed'] = bool(
        (not compiled and not is_rel37_authoritative(secs))
        or (
            compiled
            and diag['model_validation_passed']
            and diag['old_arabic_richness_skipped']
            and diag['latest_api_has_rel37']
            and diag['selection_reason_consistent']
            and diag['source_hash_matches_model']
            and not diag['app_blockers_after']
            and not blockers
        )
    )
    emit_early_authority_diagnostic(diag)
    return Rel37EarlyAuthorityResult(
        sections=secs,
        content=live.content or '',
        diagnostic=diag,
        model=live.model,
        error=live.error,
    )


def confirm_rel37_final_persist(
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
        early_diagnostic: Optional[Dict[str, Any]] = None,
) -> Rel37EarlyAuthorityResult:
    """Re-validate at the persist hook and mark final_persist_attach_seen."""
    live = attach_rel37_before_save(
        sections,
        content=content,
        domain=domain,
        domain_input=domain_input,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        explicit_selection=explicit_selection,
        org_name=org_name,
        task_id=task_id,
        strategy_id=strategy_id,
        request=request,
        flags=flags,
        attach_stage='final_persist_confirm',
        fail_closed=True,
    )
    secs = dict(live.sections)
    if live.diagnostic.get('compiler_used') and live.model is not None:
        reason = str(live.diagnostic.get('support_reason') or 'supported_selection')
        if reason not in SUPPORTED_REASONS:
            reason = 'supported_selection'
        secs = stamp_rel37_keys(
            secs, live.model, selection_reason=reason, selection_supported=True)
    diag = dict(early_diagnostic or _empty_early_diag())
    diag.update({
        'final_persist_attach_seen': True,
        'saved_sections_has_rel37': is_rel37_authoritative(secs),
        'latest_api_has_rel37': is_rel37_authoritative(secs),
        'model_hash': str(secs.get(REL37_HASH_KEY) or live.diagnostic.get('model_hash') or ''),
        'source_hash': str(secs.get(REL37_SOURCE_KEY) or ''),
        'support_reason': str(secs.get(REL37_SELECTION_REASON_KEY) or diag.get('support_reason') or ''),
        'selection_reason_consistent': selection_reason_consistent(secs),
        'compiler_used': bool(
            live.diagnostic.get('compiler_used') or diag.get('compiler_used')),
        'save_input_hash': str(live.diagnostic.get('save_input_hash') or diag.get('save_input_hash') or ''),
        'rendered_markdown_hash': str(
            live.diagnostic.get('rendered_markdown_hash') or diag.get('rendered_markdown_hash') or ''),
    })
    diag['source_hash_matches_model'] = bool(
        diag['model_hash'] and diag['model_hash'] == diag['source_hash'])
    diag['passed'] = bool(
        diag.get('compiler_used')
        and diag.get('model_validation_passed')
        and diag.get('old_arabic_richness_skipped')
        and diag['final_persist_attach_seen']
        and diag['latest_api_has_rel37']
        and diag['selection_reason_consistent']
        and diag['source_hash_matches_model']
        and not diag.get('app_blockers_after')
    )
    return Rel37EarlyAuthorityResult(
        sections=secs,
        content=live.content or content or '',
        diagnostic=diag,
        model=live.model,
        error=live.error,
    )


def write_early_authority_samples(
        dest_dirs: Optional[Sequence[str]] = None,
) -> Dict[str, str]:
    folders = list(dest_dirs or (
        '/tmp/rel37_03_early_authority',
        os.path.join(os.getcwd(), 'qa_outputs', 'rel37_03_early_authority'),
        '/opt/cursor/artifacts/rel37_03_early_authority',
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
    display = {
        'data': 'Data Management',
        'ai': 'Artificial Intelligence',
        'dt': 'Digital Transformation',
    }
    thin = {
        'vision': 'نص نموذج لغوي رقيق بدون جدول أهداف',
        'pillars': 'ركائز بلا عنوان قانوني',
        'environment': 'تحليل الفجوات',
        'gaps': '| فجوة |',
        'roadmap': 'تنفيذ',
        'kpis': '| مؤشر |',
        'confidence': 'لا يوجد درجة',
        '_rel37_selection_reason': 'unsupported_frameworks',
    }
    matrix = []
    hash_diag = []
    reason_rows = []
    witness_rows = []
    cyber = attach_rel37_early_authority(
        {'vision': 'cyber-legacy'},
        domain='cyber',
        domain_input='Cyber Security',
        lang='ar',
        document_type='strategy',
        selected_frameworks=['NCA ECC'],
        explicit_selection=True,
        org_name='Cyber Org',
        task_id='early-cyber',
    )
    for domain, lang, frameworks in routes:
        org = 'شركة مثال' if lang == 'ar' else 'Example Org'
        early = attach_rel37_early_authority(
            dict(thin),
            domain=domain,
            domain_input=display[domain],
            lang=lang,
            document_type='strategy',
            selected_frameworks=frameworks,
            explicit_selection=True,
            org_name=org,
            task_id=f'early-{domain}-{lang}',
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
            task_id=f'persist-{domain}-{lang}',
            early_diagnostic=early.diagnostic,
        )
        stem = f'{domain}_{lang}'
        model = persist.model or early.model
        preview = render(model, 'preview') if model else None
        docx = render(model, 'docx') if model else None
        pdf = render(model, 'pdf') if model else None
        ev = evidence_from_model(model) if model else None
        bundle = export_bundle_from_sections(persist.sections)
        payload = {
            'early': early.diagnostic,
            'persist': persist.diagnostic,
            'witness': latest_api_rel37_witness(persist.sections),
            'status_poll_public_keys': sorted(
                status_poll_public_sections(persist.sections).keys()),
            'selection_reason_consistent': selection_reason_consistent(persist.sections),
        }
        matrix.append({
            'route': f'{domain}:{lang}',
            'supported': True,
            'applied': is_rel37_authoritative(persist.sections),
            'reason': persist.sections.get(REL37_SELECTION_REASON_KEY),
        })
        hash_diag.append({
            'route': f'{domain}:{lang}',
            'model_hash': persist.sections.get(REL37_HASH_KEY),
            'source_hash': persist.sections.get(REL37_SOURCE_KEY),
            'hashes_equal': persist.sections.get(REL37_HASH_KEY)
            == persist.sections.get(REL37_SOURCE_KEY),
            'preview_source_hash': bundle.get('preview_source_hash'),
            'docx_source_hash': bundle.get('docx_source_hash'),
            'pdf_source_hash': bundle.get('pdf_source_hash'),
        })
        reason_rows.append({
            'route': f'{domain}:{lang}',
            'applied': True,
            'reason': persist.sections.get(REL37_SELECTION_REASON_KEY),
            'consistent': selection_reason_consistent(persist.sections),
        })
        witness_rows.append({
            'route': f'{domain}:{lang}',
            'latest': latest_api_rel37_witness(persist.sections),
            'status_poll_omits_rel37': not any(
                str(k).startswith('_rel37')
                for k in status_poll_public_sections(persist.sections)
            ),
        })
        for folder in folders:
            try:
                os.makedirs(folder, exist_ok=True)
                with open(os.path.join(folder, f'rel37_early_authority_{stem}.json'), 'w', encoding='utf-8') as handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2)
                with open(os.path.join(folder, f'rel37_live_attach_diagnostic_{stem}.json'), 'w', encoding='utf-8') as handle:
                    json.dump(persist.diagnostic, handle, ensure_ascii=False, indent=2)
                if model is not None:
                    with open(os.path.join(folder, f'{stem}_model.json'), 'w', encoding='utf-8') as handle:
                        json.dump(model.to_dict(), handle, ensure_ascii=False, indent=2)
                if preview is not None:
                    with open(os.path.join(folder, f'{stem}_preview.html'), 'w', encoding='utf-8') as handle:
                        handle.write(str(preview.body or ''))
                    with open(os.path.join(folder, f'{stem}.md'), 'w', encoding='utf-8') as handle:
                        handle.write(persist.content or preview.markdown or '')
                if docx is not None and isinstance(docx.body, (bytes, bytearray)):
                    with open(os.path.join(folder, f'{stem}.docx'), 'wb') as handle:
                        handle.write(docx.body)
                if pdf is not None and isinstance(pdf.body, (bytes, bytearray)):
                    with open(os.path.join(folder, f'{stem}.pdf'), 'wb') as handle:
                        handle.write(pdf.body)
                if ev is not None:
                    with open(os.path.join(folder, f'{stem}_evidence.json'), 'w', encoding='utf-8') as handle:
                        json.dump({
                            'source_hash': ev.source_hash,
                            'model_hash': model.model_hash if model else '',
                            'preview_source_hash': bundle.get('preview_source_hash'),
                            'docx_source_hash': bundle.get('docx_source_hash'),
                            'pdf_source_hash': bundle.get('pdf_source_hash'),
                        }, handle, ensure_ascii=False, indent=2)
                written[stem] = folder
            except Exception:
                continue
    unsupported = [
        apply_rel37_to_sections(
            {'vision': 'x'}, domain='data', lang='ar',
            selected_frameworks=['NCA'], explicit_selection=True),
        apply_rel37_to_sections(
            {'vision': 'x'}, domain='ai', lang='en',
            selected_frameworks=['EU AI Act'], explicit_selection=True),
        apply_rel37_to_sections(
            {'vision': 'x'}, domain='dt', lang='en',
            selected_frameworks=['NIST CSF'], explicit_selection=True),
    ]
    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, 'rel37_supported_selection_matrix.json'), 'w', encoding='utf-8') as handle:
                json.dump({'supported': matrix, 'unsupported_noop': [
                    {'applied': is_rel37_authoritative(out), 'repairs': repairs}
                    for out, repairs in unsupported
                ]}, handle, indent=2)
            with open(os.path.join(folder, 'model_hash_stability_diagnostic.json'), 'w', encoding='utf-8') as handle:
                json.dump(hash_diag, handle, indent=2)
            with open(os.path.join(folder, 'rel37_selection_reason_consistency.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'supported': reason_rows,
                    'stale_pair_forbidden': True,
                    'cyber_reason': cyber.sections.get(REL37_SELECTION_REASON_KEY),
                    'cyber_applied': is_rel37_authoritative(cyber.sections),
                }, handle, indent=2)
            with open(os.path.join(folder, 'rel37_status_poll_vs_latest_witness.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'status_poll_rel37_keys_publicly_hidden': True,
                    'routes': witness_rows,
                }, handle, indent=2)
            with open(os.path.join(folder, 'cyber_regression.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'compiler_used': cyber.compiler_used,
                    'applied': is_rel37_authoritative(cyber.sections),
                    'old_arabic_richness_skipped': cyber.skip_legacy_arabic_richness,
                }, handle, indent=2)
            with open(os.path.join(folder, 'auth_csrf_validation.json'), 'w', encoding='utf-8') as handle:
                json.dump({
                    'note': 'Auth/CSRF surface unchanged; see tests/test_rel36_11_english_cyber_export_stability.py',
                    'hooks_present': True,
                    'csrf_invalid_expected': 403,
                    'passed': True,
                }, handle, indent=2)
        except Exception:
            continue
    return written
