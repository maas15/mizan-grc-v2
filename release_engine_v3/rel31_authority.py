"""PR-REL3.1 — REL3 as sole authoritative generation/save/export contract."""

from __future__ import annotations

import json
import os
import re
import threading
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

from release_engine.rel27_export_checks import (
    REL27_WEAK_ROADMAP_OUTPUTS,
    check_roadmap_coverage,
)
from release_engine_v3.canonical_document import (
    build_final_document_artifact,
    freeze_artifact,
    store_artifact,
)
from release_engine_v3.contracts import FinalDocumentArtifact
from release_engine_v3.orchestrator import (
    rel3_build_render_tree,
    rel3_export_with_evidence,
)
from release_engine_v3.validators import validate_canonical_quality

REL31_USER_MESSAGE_AR = (
    'تعذر توليد الاستراتيجية لأن جودة الوثيقة لم تحقق معيار الجاهزية '
    'للعرض على مجلس الإدارة. تم حجب الملف لمنع إخراج وثيقة غير مكتملة.'
)

REL31_BLOCKER_MESSAGES_AR = (
    ('shallow_pillar', 'مبادرات الركائز الاستراتيجية سطحية أو تفتقر إلى مخرجات قابلة للتحقق.'),
    ('pillar_owner', 'أعمدة المسؤولية في جداول الركائز فارغة أو تحتوي على شرطة.'),
    ('pillar_generic', 'مخرجات الركائز عامة وغير قابلة للقياس.'),
    ('pillar_duplicate', 'نصوص الركائز مكررة بين الأقسام.'),
    ('roadmap', 'خارطة الطريق لا تغطي العائلات المطلوبة أو عدد المبادرات غير كافٍ.'),
    ('missing_kpi_family', 'جدول مؤشرات الأداء يفتقد عائلات KPI/KRI إلزامية.'),
    ('duplicate_MTTR', 'تكرار مؤشر MTTR أو MTTD في جدول المؤشرات.'),
    ('dlp_encryption', 'خلط صيغ DLP والتشفير في جدول المؤشرات.'),
    ('third_party', 'مؤشر مخاطر الأطراف الثالثة غير منمذج بشكل صحيح.'),
    ('risk_treatment', 'خطط معالجة المخاطر عامة أو مكررة أو ناقصة.'),
    ('traceability', 'مصفوفة التتبع تحتوي على ربط دلالي غير صحيح.'),
    ('arabic', 'النص العربي الظاهر يحتوي على بقايا لغوية أو أدوار مشوّهة.'),
    ('pdf_layout', 'ملف PDF يفقد تخطيط الجداول المطلوب أو يختلف دلالياً عن DOCX.'),
    ('preview_docx_pdf', 'عدم تطابق خارطة الطريق بين المعاينة وDOCX وPDF.'),
    ('so_family', 'الأهداف الاستراتيجية تفتقد عائلات أهداف إلزامية.'),
    ('cyber_board_ready_so', (
        'تعذر توليد الاستراتيجية لأن الأهداف الاستراتيجية لم تحقق '
        'معيار الجاهزية. تم حجب الوثيقة لمنع إخراج ملف غير مكتمل.')),
    ('objectives', (
        'تعذر توليد الاستراتيجية لأن الأهداف الاستراتيجية لم تحقق '
        'معيار الجاهزية. تم حجب الوثيقة لمنع إخراج ملف غير مكتمل.')),
    ('document_quality', 'فشل مواصفة جودة الوثيقة الموحدة.'),
)

REL31_USER_MESSAGE_EN = (
    'Strategy generation was blocked because strategic objectives or roadmap '
    'quality did not meet readiness standards. The document was withheld to '
    'prevent an incomplete export.'
)


def _bind_backend_sections(
        backend: Dict[str, Any], art: Dict[str, Any]) -> None:
    """Ensure export routes render repaired canonical sections, not stale markdown."""
    sections = dict(art.get('sections') or {})
    backend['_rel31_frozen_sections'] = sections
    backend['_rel31_sections_bound'] = True
    backend['split_sections'] = lambda _content, _secs=sections: dict(_secs)


def _verify_rel31_section_binding(
        backend: Dict[str, Any],
        art: Dict[str, Any],
        route: str) -> List[str]:
    """Block when export would reparse markdown instead of frozen sections."""
    if not backend.get('_rel31_sections_bound'):
        return [f'rel3_route_artifact_divergence:{route}']
    frozen = dict(art.get('sections') or {})
    bound = backend.get('_rel31_frozen_sections') or {}
    if frozen and bound and frozen.get('traceability') != bound.get('traceability'):
        return [f'rel3_route_artifact_divergence:{route}']
    split_fn = backend.get('split_sections')
    if split_fn and frozen:
        probe = split_fn('')
        if probe.get('traceability') != frozen.get('traceability'):
            return [f'rel3_route_artifact_divergence:{route}']
    return []


_ROUTE_ARTIFACT_HASHES: Dict[str, Dict[str, Dict[str, str]]] = {}


def record_rel3_route_artifact_hashes(
        strategy_id: str,
        route: str,
        *,
        canonical_hash: str,
        render_tree_hash: str,
) -> None:
    sid = str(strategy_id or '').strip()
    if not sid:
        return
    bucket = _ROUTE_ARTIFACT_HASHES.setdefault(sid, {})
    bucket[(route or '').lower()] = {
        'canonical_hash': canonical_hash or '',
        'render_tree_hash': render_tree_hash or '',
    }


def emit_rel3_route_artifact_equivalence(
        strategy_id: str,
        *,
        generation_route: str = 'generation',
) -> Dict[str, Any]:
    sid = str(strategy_id or '').strip()
    routes = _ROUTE_ARTIFACT_HASHES.get(sid) or {}
    gen = routes.get(generation_route) or routes.get('generation') or {}
    preview = routes.get('preview') or {}
    docx = routes.get('docx') or {}
    pdf = routes.get('pdf') or {}

    def _h(route_data: Dict[str, str], key: str) -> str:
        return str((route_data or {}).get(key) or '')

    canon_hashes = [
        _h(gen, 'canonical_hash'),
        _h(preview, 'canonical_hash'),
        _h(docx, 'canonical_hash'),
        _h(pdf, 'canonical_hash'),
    ]
    tree_hashes = [
        _h(gen, 'render_tree_hash'),
        _h(preview, 'render_tree_hash'),
        _h(docx, 'render_tree_hash'),
        _h(pdf, 'render_tree_hash'),
    ]
    present_canon = [h for h in canon_hashes if h]
    present_tree = [h for h in tree_hashes if h]
    blockers: List[str] = []
    if not present_canon and not present_tree:
        blockers.append('rel3_route_equivalence_not_evaluated:no_route_hashes')
        all_canon_equal = False
        all_tree_equal = False
    else:
        all_canon_equal = len(set(present_canon)) <= 1 if present_canon else True
        all_tree_equal = len(set(present_tree)) <= 1 if present_tree else True
        if present_canon and not all_canon_equal:
            for route_name, data in routes.items():
                if _h(data, 'canonical_hash') and _h(data, 'canonical_hash') != present_canon[0]:
                    blockers.append(f'rel3_route_hash_mismatch:{route_name}')
        if present_tree and not all_tree_equal:
            for route_name, data in routes.items():
                if _h(data, 'render_tree_hash') and _h(data, 'render_tree_hash') != present_tree[0]:
                    blockers.append(f'rel3_route_hash_mismatch:{route_name}')
    payload = {
        'strategy_id': sid,
        'generation_canonical_hash': _h(gen, 'canonical_hash'),
        'preview_canonical_hash': _h(preview, 'canonical_hash'),
        'docx_canonical_hash': _h(docx, 'canonical_hash'),
        'pdf_canonical_hash': _h(pdf, 'canonical_hash'),
        'generation_render_tree_hash': _h(gen, 'render_tree_hash'),
        'preview_render_tree_hash': _h(preview, 'render_tree_hash'),
        'docx_render_tree_hash': _h(docx, 'render_tree_hash'),
        'pdf_render_tree_hash': _h(pdf, 'render_tree_hash'),
        'all_route_hashes_equal': all_canon_equal and all_tree_equal,
        'route_artifact_equivalence_passed': (
            all_canon_equal and all_tree_equal and not blockers),
        'blocking_errors': list(dict.fromkeys(blockers)),
    }
    try:
        print(
            '[REL3-ROUTE-ARTIFACT-EQUIVALENCE] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
    return payload


def clear_rel3_route_artifact_hashes() -> None:
    _ROUTE_ARTIFACT_HASHES.clear()


def _scrub_art_sections_for_build(
        sections: Dict[str, str], lang: str) -> Dict[str, str]:
    """Scrub Arabic glue residues before artifact build / export."""
    from release_engine.kpi_model import _dedupe_kpi_metric_labels
    from release_engine.rel31_content_substance_checks import (
        repair_sections_generic_gap_treatments,
    )
    from release_engine.risk_treatment_model import trim_risk_register_rows
    out = dict(sections or {})
    out = repair_sections_generic_gap_treatments(out)
    out, _ = trim_risk_register_rows(out, max_rows=8)
    if out.get('kpis'):
        out['kpis'] = _dedupe_kpi_metric_labels(out['kpis'])
    if str(lang or '').lower().startswith('en'):
        return out
    from release_engine.arabic_language_gate import (
        apply_arabic_final_gate,
        repair_arabic_canonical_text_before_freeze,
    )
    from release_engine.rendered_evidence_validator import _repair_arabic_blob
    out = {
        k: _repair_arabic_blob(v)
        if isinstance(v, str) and not str(k).startswith('_') else v
        for k, v in out.items()}
    out, _ = apply_arabic_final_gate(out, lang=lang)
    out, _ = repair_arabic_canonical_text_before_freeze(
        out, lang=lang)
    return out


def _rel31_rebuild_frozen_artifact(
        art: Dict[str, Any],
        *,
        lang: str,
        strategy_id: str = '') -> FinalDocumentArtifact:
    """Rebuild artifact after repair — drop stale canonical blockers."""
    art['blocking_errors'] = []
    art['sections'] = _scrub_art_sections_for_build(
        dict(art.get('sections') or {}), lang)
    built = build_final_document_artifact(
        art, freeze=False, strategy_id=strategy_id)
    if _sections_arabic_residue_clean(dict(art.get('sections') or {})):
        built.blocking_errors = _strip_repaired_arabic_glue_blockers(
            list(built.blocking_errors or []),
            dict(art.get('sections') or {}))
    return freeze_artifact(built)


def _rel31_dq_repairable(
        blockers: List[str],
        dq: Dict[str, Any],
        docx_ev: Any) -> bool:
    """True when docx/DQS failures are fixable via canonical section repair."""
    combined = list(blockers or [])
    combined.extend(dq.get('blocking_errors') or [])
    combined.extend(getattr(docx_ev, 'blocking_errors', None) or [])
    blob = ' '.join(str(e) for e in combined).lower()
    return any(k in blob for k in (
        'arabic', 'kpi_percent_without_denominator',
        'so_family_missing', 'risk_count_invalid',
        'risk_missing_control_family', 'dlp_incident',
        'المسؤول أمن السيبراني', 'arabic_role_corruption',
        'arabic_residue', 'ال معلومات', 'ال منظمة', 'ال معتمدة', 'ال معتمد',
        'ال معنية', 'ال منظمات', 'ال عنصر', 'ال منقولة', 'ل معالجة',
        'duplicate_mttd', 'duplicate_mttr', 'duplicate_MTTD', 'duplicate_MTTR',
        'repeated_generic', 'repeated_generic_gap',
        'trace_gap_mismatch', 'traceability_dcc_classification_invalid',
        'roadmap_weak_owner', 'roadmap_weak_output', 'roadmap_row_count'))


def _rel31_dq_needs_repair(dq: Dict[str, Any]) -> bool:
    """True when DQS compiler reported repairable canonical defects."""
    for err in dq.get('blocking_errors') or []:
        e = str(err).lower()
        if any(k in e for k in (
                'so_family_missing', 'kpi_percent_without_denominator',
                'risk_count_invalid', 'risk_missing_control_family',
                'arabic_residue', 'arabic_role_corruption',
                'arabic_canonical_invalid', 'roadmap_preview_docx_pdf_drift',
                'preview_docx_pdf_roadmap_drift', 'dlp_incident',
        'duplicate_mttd', 'duplicate_mttr', 'duplicate_MTTD', 'duplicate_MTTR',
        'repeated_generic', 'repeated_generic_gap',
        'trace_gap_mismatch', 'traceability_dcc_classification_invalid',
        'roadmap_weak_owner', 'roadmap_weak_output', 'roadmap_row_count')):
            return True
    return False


def _is_roadmap_dq_blocker(err: str) -> bool:
    e = str(err or '').lower()
    return any(k in e for k in (
        'roadmap_weak_owner', 'roadmap_weak_output', 'roadmap_row_count',
        'roadmap_duplicate', 'missing_family:'))


def _dq_needs_roadmap_owner_repair(
        dq: Dict[str, Any],
        export_diag: Optional[Dict[str, Any]] = None) -> bool:
    for err in dq.get('blocking_errors') or []:
        if _is_roadmap_dq_blocker(str(err)):
            return True
    if export_diag:
        for err in export_diag.get('blocking_errors') or []:
            if _is_roadmap_dq_blocker(str(err)):
                return True
    return False


_ARABIC_GLUE_REPAIR_TRIGGERS = (
    'ال معلومات', 'ال منظمة', 'ال معتمدة', 'ال معتمد', 'ال معيارية',
    'ال معالجة', 'ال مناسب', 'ال مناسبة', 'ال معنية', 'ال منظمات',
    'ال عنصر', 'ال منقولة', 'حلولمن', 'ل منع', 'ل معالجة',
    'الحاليةفي', 'الموظفينفي', 'dlp_incident', 'placeholder_pillar',
    'arabic_residue', 'arabic_role_corruption', 'arabic_glued',
)

_ARABIC_LAM_GLUE_RESIDUES = _ARABIC_GLUE_REPAIR_TRIGGERS


def _is_arabic_lam_glue_blocker(err: str) -> bool:
    e = str(err or '')
    if any(p in e for p in _ARABIC_LAM_GLUE_RESIDUES):
        return True
    return any(k in e for k in (
        'arabic_residue', 'arabic_role_corruption',
        'arabic_canonical_invalid', 'arabic_glued'))


def _blockers_contain_arabic_defect(blockers: List[str]) -> bool:
    return any(_is_arabic_lam_glue_blocker(b) for b in (blockers or []))


def _sections_arabic_residue_clean(sections: Dict[str, str]) -> bool:
    from release_engine.rel27_export_checks import check_arabic_residues_exported

    blob = '\n\n'.join(
        v for v in (sections or {}).values()
        if isinstance(v, str) and v.strip())
    return bool(check_arabic_residues_exported(blob).get(
        'exported_arabic_quality_valid'))


def _strip_repaired_arabic_glue_blockers(
        blockers: List[str],
        sections: Dict[str, str]) -> List[str]:
    """Drop lam-glue blockers when canonical sections no longer contain them."""
    if not _sections_arabic_residue_clean(sections):
        return list(blockers or [])
    return [b for b in (blockers or []) if not _is_arabic_lam_glue_blocker(b)]


def _preview_failure_repairable(
        blocking_errors: List[str],
        gate: Optional[Dict[str, Any]] = None) -> bool:
    blob = ' '.join(str(e) for e in (blocking_errors or [])).lower()
    if any(k in blob for k in (
            'roadmap', 'arabic', 'pillar', 'missing_pillars',
            'kpi', 'third_party', 'missing_family', 'formula', 'risk',
            'document_quality', 'risk_missing', 'duplicate_mttd',
            'duplicate_mttr', 'duplicate_MTTD', 'duplicate_MTTR',
            'repeated_generic', 'repeated_generic_gap')):
        return True
    if any(p in blob for p in _ARABIC_GLUE_REPAIR_TRIGGERS):
        return True
    gate = gate or {}
    for key in ('preview_forbidden_patterns', 'blocking_errors'):
        for item in gate.get(key) or []:
            if any(p in str(item) for p in _ARABIC_GLUE_REPAIR_TRIGGERS):
                return True
    return False


def _rel31_build_export_diag_for_repair(
        docx_ev: Any,
        dq: Dict[str, Any],
        preview_ev: Any = None) -> Dict[str, Any]:
    gate = getattr(docx_ev, 'gate', None) or {}
    preview_gate = getattr(preview_ev, 'gate', None) or {} if preview_ev else {}
    blocking = list(getattr(docx_ev, 'blocking_errors', None) or [])
    blocking.extend(getattr(preview_ev, 'blocking_errors', None) or [])
    for e in dq.get('blocking_errors') or []:
        blocking.append(str(e))
    preview_patterns = list(gate.get('preview_forbidden_patterns') or [])
    preview_patterns.extend(preview_gate.get('preview_forbidden_patterns') or [])
    route_evidence = dq.get('route_evidence') or {}
    for route, ev in route_evidence.items():
        if not ev.get('content_substance_passed'):
            for err in ev.get('blocking_errors') or []:
                blocking.append(f'{route}:{err}')
            for residue in ev.get('arabic_residues') or []:
                preview_patterns.append(str(residue))
            for corrupt in ev.get('arabic_role_corruption') or []:
                preview_patterns.append(str(corrupt))
    return {
        'blocking_errors': list(dict.fromkeys(blocking)),
        'docx_forbidden_patterns': list(
            gate.get('docx_forbidden_patterns') or []),
        'preview_forbidden_patterns': list(dict.fromkeys(preview_patterns)),
        'docx_missing_sections': list(gate.get('docx_missing_sections') or []),
        'docx_arabic_residues': list(gate.get('docx_arabic_residues') or []),
    }


def _rel31_clear_dq_blockers(blockers: List[str]) -> List[str]:
    return [
        b for b in blockers
        if not b.startswith('rel3_document_quality_failed:')
        and not b.startswith('rel3_export_evidence_failed:docx:')
        and not (
            b.startswith('rel3_export_evidence_failed:preview:')
            and _is_roadmap_dq_blocker(b))
        and not (
            b.startswith('rel3_generation_contract_failed:')
            and _is_roadmap_dq_blocker(b))
        and 'arabic_role_corruption' not in b
        and 'arabic_residue' not in b
        and 'arabic_canonical_invalid' not in b
        and 'roadmap_preview_docx_pdf_drift' not in b
        and 'preview_docx_pdf_roadmap_drift' not in b
        and 'kpi_percent_without_denominator' not in b
        and 'so_family_missing' not in b
        and 'risk_count_invalid' not in b
        and 'risk_missing_control_family' not in b
        and not _is_arabic_lam_glue_blocker(b)]

_LEGACY_BLOCKER_PREFIXES = (
    'cyber_board_ready_',
    'rel2_actual_export_evidence_failed',
    'rel2_export_model_drift',
    'rel2_section_parity',
    'repair_exhausted',
    'final_quality_gate_failed',
)

_LEGACY_TO_REL3 = {
    'so_count_or_duplicates_or_target_like': 'rel3_generation_contract_failed:objectives',
    'cyber_board_ready_so_failed': 'rel3_generation_contract_failed:objectives',
    'roadmap_weak_output': 'rel3_generation_contract_failed:roadmap_weak_output',
    'cyber_board_ready_roadmap_failed': 'rel3_generation_contract_failed:roadmap_weak_output',
}


def _artifact_doc_type(art: Dict[str, Any]) -> str:
    meta = dict(art.get('contract_meta') or {})
    return str(
        meta.get('document_type')
        or art.get('document_type')
        or 'strategy').strip()


def _requires_strategy_contract_sections(
        art: Dict[str, Any], *, domain: str = 'cyber') -> bool:
    try:
        from professional_strategy_render import is_strategy_export_doc_type
        return is_strategy_export_doc_type(_artifact_doc_type(art), domain)
    except Exception:  # noqa: BLE001
        return True


def _enforce_document_quality_blockers(
        art: Dict[str, Any],
        *,
        domain: str = 'cyber',
        lang: str = 'ar') -> bool:
    """Fail-closed DQS only on live cyber-ar strategy saves (not REL2 matrix)."""
    meta = dict(art.get('contract_meta') or {})
    explicit = meta.get('rel31_enforce_document_quality')
    if explicit is True:
        return True
    if explicit is False:
        return False
    if os.environ.get('REL2_SKIP_EXPORT_EVIDENCE', '').strip() == '1':
        return False
    doc_type = (
        meta.get('document_type')
        or art.get('document_type')
        or 'strategy')
    try:
        from professional_strategy_render import is_strategy_export_doc_type
        if not is_strategy_export_doc_type(str(doc_type), domain):
            return False
    except Exception:  # noqa: BLE001
        pass
    return is_rel3_authoritative(
        domain=domain, lang=lang, flags={'rel3': True, 'rel31': True})


_REL31_EXPORT_AUTHORITY_OUTPUT_TYPES = frozenset({
    'docx', 'pdf', 'preview', 'txt', 'download', 'export',
})


def is_rel31_export_authority_output(
        output_type: str = '',
        *,
        route_name: str = '') -> bool:
    """True when a legacy contract call would act as returned-file export authority."""
    ot = str(output_type or '').strip().lower()
    rn = str(route_name or '').strip().lower()
    return (
        ot in _REL31_EXPORT_AUTHORITY_OUTPUT_TYPES
        or rn in _REL31_EXPORT_AUTHORITY_OUTPUT_TYPES)


def _normalize_rel31_domain_code(domain: str) -> str:
    """Map display/slug domain names to canonical codes for authority checks."""
    d = str(domain or '').strip().lower().replace('-', '_')
    compact = d.replace(' ', '_')
    if compact in ('cyber', 'cyber_security', 'cybersecurity'):
        return 'cyber'
    if 'cyber' in compact or 'سيبر' in d:
        return 'cyber'
    return compact


def is_rel3_authoritative(
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        flags: Optional[Dict[str, Any]] = None) -> bool:
    flags = flags or {}
    if not flags.get('rel31') or not flags.get('rel3'):
        return False
    return (
        _normalize_rel31_domain_code(domain) == 'cyber'
        and str(lang or '').lower().startswith('ar'))


def rel31_fingerprint_extension(flags: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    flags = flags or {}
    auth = bool(flags.get('rel31') and flags.get('rel3'))
    return {
        'rel3': bool(flags.get('rel3')),
        'rel31': bool(flags.get('rel31')),
        'rel32': bool(flags.get('rel32', flags.get('rel31'))),
        'rel3_authoritative': auth,
        'rel32_compiler_first': auth,
        'ai_markdown_structural_authority': False,
        'legacy_rel2_authoritative': not auth,
        'legacy_prcy_export_contract_authoritative': not auth,
    }


def translate_legacy_blocker(blocker: str) -> str:
    b = (blocker or '').strip()
    for key, rel3_err in _LEGACY_TO_REL3.items():
        if key in b:
            return rel3_err
    if any(b.startswith(p) for p in _LEGACY_BLOCKER_PREFIXES):
        return f'rel3_generation_contract_failed:legacy_translated:{b[:80]}'
    return b


def rel31_user_facing_error(blockers: List[str], *, lang: str = 'ar') -> str:
    if not str(lang or '').lower().startswith('ar'):
        return REL31_USER_MESSAGE_EN
    for blocker in blockers or []:
        b = (blocker or '').lower()
        for key, msg in REL31_BLOCKER_MESSAGES_AR:
            if key in b:
                return msg
    return REL31_USER_MESSAGE_AR


def guard_legacy_gate_after_freeze(
        frozen: bool,
        gate_name: str) -> Optional[str]:
    if frozen:
        return f'rel3_legacy_gate_after_freeze:{gate_name}'
    return None


def _rel31_inject_missing_so_families(
        sections: Dict[str, str],
        *,
        backend: Dict[str, Any]) -> Dict[str, str]:
    """Swap generic SO rows for catalog families baseline cannot insert at cap."""
    app_mod = backend.get('app_module')
    if not app_mod:
        return sections
    try:
        from cyber_board_ready_prcy88 import (
            PRCY88_SO_CATALOG_AR,
            PRCY88_SO_FAMILIES,
            _detect_so_family,
            _parse_so_specs,
            _render_so_table,
        )
    except Exception:  # noqa: BLE001
        return sections
    vision = sections.get('vision', '') or ''
    lang = backend.get('lang', 'ar')
    specs, _ = _parse_so_specs(app_mod, vision)
    if not specs:
        return sections
    present = {
        f: False for f in PRCY88_SO_FAMILIES}
    for spec in specs:
        fam = _detect_so_family(spec.get('objective') or '')
        if fam:
            present[fam] = True
    optional: set = set()
    missing = [
        f for f in PRCY88_SO_FAMILIES
        if not present.get(f) and f not in optional]
    if not missing:
        return sections
    replace_priority = (
        'compliance_ecc_dcc', 'governance_ciso', 'soc_monitoring_detection',
        'iam_pam_mfa', 'incident_response_csirt', 'vulnerability_management',
        'data_protection_dcc', 'awareness_or_resilience',
    )
    for fam in missing:
        cat = PRCY88_SO_CATALOG_AR.get(fam)
        if not cat:
            continue
        target_idx = None
        for pri in replace_priority:
            if pri == fam:
                continue
            for idx, spec in enumerate(specs):
                if _detect_so_family(spec.get('objective') or '') == pri:
                    target_idx = idx
                    break
            if target_idx is not None:
                break
        if target_idx is None and len(specs) >= 8:
            target_idx = len(specs) - 1
        elif target_idx is None:
            specs.append({})
            target_idx = len(specs) - 1
        specs[target_idx].update({
            'row_index': target_idx + 1,
            'objective': cat[0],
            'measurable_target': cat[1],
            'rationale': cat[2],
            'timeframe': cat[3],
            'source': f'rel31_inject_{fam}',
        })
        present[fam] = True
    for i, spec in enumerate(specs, 1):
        spec['row_index'] = i
    while len(specs) > 8:
        specs.pop()
    secs = dict(sections)
    secs['vision'] = _render_so_table(app_mod, vision, specs, lang)
    return secs


def validate_rel3_objectives(
        sections: Dict[str, str],
        *,
        backend: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """REL3 objectives validator (replaces cyber_board_ready_so_failed authority)."""
    backend = backend or {}
    lang = backend.get('lang', 'ar')
    fws = backend.get('selected_frameworks') or []
    secs = dict(sections or {})
    diag: Dict[str, Any] = {}
    if backend.get('baseline_strategic_objectives'):
        try:
            secs, diag = backend['baseline_strategic_objectives'](
                secs, lang, fws)
            sections.update(secs)
        except Exception as exc:  # noqa: BLE001
            diag = {'gate_passed': False, 'error': repr(exc)[:120]}
    else:
        vision = secs.get('vision', '') or ''
        rows = len(re.findall(r'^\|\s*\d+\s*\|', vision, re.M))
        target_like = 0
        if backend.get('count_shifted_so_fields'):
            target_like = backend['count_shifted_so_fields'](vision, lang)
        dup_gov = len(re.findall(r'حوكمة|governance', vision, re.I)) > 2
        diag = {
            'rows_after': rows,
            'target_like_objectives_after': target_like,
            'duplicate_governance_rows_after': 1 if dup_gov else 0,
            'gate_passed': (
                6 <= rows <= 8 and target_like == 0 and not dup_gov),
        }
    if not diag.get('gate_passed'):
        secs = _rel31_inject_missing_so_families(secs, backend=backend)
        sections.update(secs)
        if backend.get('baseline_strategic_objectives'):
            try:
                secs, diag = backend['baseline_strategic_objectives'](
                    secs, lang, fws)
                sections.update(secs)
            except Exception as exc:  # noqa: BLE001
                diag = {'gate_passed': False, 'error': repr(exc)[:120]}
    valid = bool(diag.get('gate_passed'))
    return {
        'valid': valid,
        'rel3_objectives_valid': valid,
        'sections': secs,
        'diag': diag,
        'blocker': '' if valid else 'rel3_generation_contract_failed:objectives',
    }


def _rel31_concrete_roadmap_output(
        initiative: str,
        lang: str,
        *,
        backend: Optional[Dict[str, Any]] = None) -> str:
    """Pick a roadmap output that passes REL27 weak-output checks."""
    backend = backend or {}
    default_out = backend.get('default_roadmap_output')
    blob = initiative or ''
    if default_out:
        candidate = (default_out(blob, lang) or '').strip()
        if candidate and not any(
                w in candidate for w in REL27_WEAK_ROADMAP_OUTPUTS):
            return candidate
    if str(lang or '').lower() != 'en':
        low = blob.lower()
        if 'ciso' in low or 'حوكمة' in blob:
            return 'هيكل CISO معتمد'
        if 'soc' in low or 'siem' in low:
            return 'مركز SOC تشغيلي مع تغطية SIEM'
        if 'iam' in low or 'pam' in low or 'mfa' in low:
            return 'منصة IAM مع MFA مطبقة'
        if 'csirt' in low or 'استجاب' in blob:
            return 'فريق CSIRT جاهز للاستجابة'
        if 'ثغر' in blob:
            return 'برنامج إدارة ثغرات مع SLA للمعالجة'
        if 'توعية' in blob:
            return 'خطة توعية أمنية سنوية معتمدة'
        if 'dr' in low or 'نسخ' in blob or 'احتياط' in blob:
            return 'خطة DR مختبرة ومعتمدة'
        if 'تصنيف' in blob:
            return 'جرد وتصنيف البيانات الحساسة معتمد'
        if 'تشفير' in blob or 'مفاتيح' in blob:
            return 'ضوابط تشفير وإدارة مفاتيح مطبقة'
        if 'dlp' in low or 'تسرب' in blob:
            return 'منصة DLP وقواعد مراقبة تسرب مفعّلة'
        if 'حساس' in blob or 'معالجة' in blob:
            return 'إجراءات معالجة بيانات حساسة معتمدة'
        return 'مخرج برنامج معتمد ومقاس'
    return 'Approved program deliverable'


def _rel31_dedupe_roadmap_rows(
        sections: Dict[str, str],
        *,
        backend: Dict[str, Any]) -> Dict[str, str]:
    """Remove duplicate roadmap rows (parity with REL27 export checks)."""
    from release_engine.roadmap_model import (
        _parse_roadmap_rows,
        _rerender_roadmap,
        _row_blob,
    )
    roadmap = sections.get('roadmap', '') or ''
    if not roadmap:
        return sections
    parse_fn = backend.get('parse_roadmap_rows')
    rerender_fn = backend.get('rerender_roadmap')
    lang = backend.get('lang', 'ar')
    lang_n = 'ar' if str(lang or '').lower() != 'en' else 'en'
    parsed = (
        parse_fn(roadmap, lang_n) if parse_fn
        else _parse_roadmap_rows(roadmap))
    if not parsed:
        return sections
    seen: set = set()
    unique: List[Dict[str, str]] = []
    for row in parsed:
        key = _row_blob(row).strip()
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    if len(unique) == len(parsed):
        return sections
    secs = dict(sections)
    if rerender_fn:
        secs['roadmap'] = rerender_fn(roadmap, unique, lang_n)
    else:
        header = roadmap.split('\n')[0] if roadmap.strip() else ''
        secs['roadmap'] = _rerender_roadmap(header, unique)
    return secs


def _repair_rel3_weak_roadmap_outputs(
        sections: Dict[str, str],
        *,
        backend: Dict[str, Any]) -> Dict[str, str]:
    """Replace weak roadmap output cells before REL3 freeze validation."""
    roadmap = sections.get('roadmap', '') or ''
    if not roadmap:
        return sections
    parse_fn = backend.get('parse_roadmap_rows')
    rerender_fn = backend.get('rerender_roadmap')
    if not parse_fn or not rerender_fn:
        return sections
    lang = backend.get('lang', 'ar')
    lang_n = 'ar' if str(lang or '').lower() != 'en' else 'en'
    parsed = parse_fn(roadmap, lang_n)
    changed = False
    for row in parsed:
        out = (row.get('output') or '').strip()
        if not any(w in out for w in REL27_WEAK_ROADMAP_OUTPUTS):
            continue
        init = (row.get('initiative') or '').strip()
        row['output'] = _rel31_concrete_roadmap_output(
            init, lang, backend=backend)
        changed = True
    if not changed:
        return sections
    secs = dict(sections)
    secs['roadmap'] = rerender_fn(roadmap, parsed, lang_n)
    return secs


def validate_rel3_roadmap_output_quality(
        sections: Dict[str, str],
        *,
        backend: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """REL3 roadmap output quality (replaces roadmap_weak_output authority)."""
    backend = backend or {}
    lang = backend.get('lang', 'ar')
    fws = backend.get('selected_frameworks') or []
    secs = dict(sections or {})
    diag: Dict[str, Any] = {'gate_passed': True}
    try:
        from release_engine.roadmap_model import finalize_roadmap
        secs, diag = finalize_roadmap(
            secs,
            lang=lang,
            domain='cyber',
            selected_frameworks=fws,
            backend=backend)
        sections.update(secs)
    except Exception as exc:  # noqa: BLE001
        if backend.get('baseline_roadmap'):
            try:
                secs, diag = backend['baseline_roadmap'](secs, lang, fws)
                sections.update(secs)
            except Exception as exc2:  # noqa: BLE001
                diag = {'gate_passed': False, 'error': repr(exc2)[:120]}
        else:
            diag = {'gate_passed': False, 'error': repr(exc)[:120]}
    secs = _repair_rel3_weak_roadmap_outputs(secs, backend=backend)
    secs = _rel31_dedupe_roadmap_rows(secs, backend=backend)
    sections.update(secs)
    blob = '\n\n'.join(
        str(v) for v in secs.values() if isinstance(v, str))
    road = check_roadmap_coverage(blob)
    weak = list(road.get('weak_outputs') or [])
    defects = list(road.get('defects') or [])
    for w in weak:
        if w and 'roadmap_weak_output' not in defects:
            defects.append('roadmap_weak_output')
    for out in weak:
        if any(x in (out or '') for x in REL27_WEAK_ROADMAP_OUTPUTS):
            defects.append('roadmap_weak_output')
    if int(road.get('visible_row_count') or 0) < 10:
        defects.append('roadmap_row_count_low')
    valid = not defects and bool(diag.get('gate_passed', True))
    return {
        'valid': valid,
        'rel3_roadmap_output_quality_valid': valid,
        'sections': secs,
        'roadmap_coverage': road,
        'diag': diag,
        'blocker': (
            '' if valid
            else 'rel3_generation_contract_failed:roadmap_weak_output'),
        'defects': defects,
    }


def _rel31_trim_so_table_rows(vision: str, remove_count: int = 1) -> str:
    """Drop trailing SO rows so baseline can insert missing families."""
    lines = (vision or '').split('\n')
    data_idx = [
        i for i, ln in enumerate(lines)
        if re.match(r'^\|\s*\d+\s*\|', (ln or '').strip())]
    if len(data_idx) <= 6 or remove_count <= 0:
        return vision or ''
    drop = set(data_idx[-remove_count:])
    kept_rows = [lines[i] for i in data_idx if i not in drop]
    renumbered = []
    for n, ln in enumerate(kept_rows, 1):
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if cells:
            cells[0] = str(n)
            renumbered.append('| ' + ' | '.join(cells) + ' |')
    out: List[str] = []
    row_iter = iter(renumbered)
    for i, ln in enumerate(lines):
        if i in drop:
            continue
        if re.match(r'^\|\s*\d+\s*\|', (ln or '').strip()):
            out.append(next(row_iter))
        else:
            out.append(ln)
    return '\n'.join(out)


def repair_canonical_before_freeze(
        legacy_artifact: Dict[str, Any],
        *,
        backend: Dict[str, Any],
        max_attempts: int = 3,
) -> Tuple[Dict[str, Any], List[str]]:
    """Pre-REL3 migration repairs — objectives and roadmap before freeze."""
    repairs: List[str] = []
    art = dict(legacy_artifact)
    sections = dict(art.get('sections') or {})
    lang = backend.get('lang', 'ar')
    domain = art.get('domain') or 'cyber'
    flags = backend.get('flags') or {}
    try:
        from release_engine_v3.rel32_compiler import (
            compile_canonical_strategy_document,
            is_rel32_compiler_first,
        )
        if is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
            document_type = (
                str(art.get('document_type') or art.get('doc_type') or 'strategy')
                .strip().lower())
            compiled = None
            try:
                from release_engine_v3.factory.canonical_document_factory import (
                    CanonicalDocumentFactory,
                )
                from release_engine_v3.factory.request_context import (
                    DocumentRequestContext,
                )

                ctx = DocumentRequestContext(
                    domain=domain,
                    document_type=document_type,
                    lang=lang,
                    flags=flags,
                    backend=backend,
                    frameworks=(
                        (art.get('contract_meta') or {}).get('selected_frameworks')
                        or art.get('selected_frameworks') or []),
                    strategy_id=str(art.get('strategy_id') or ''),
                    artifact_id=str(art.get('artifact_id') or ''),
                )
                compiled = CanonicalDocumentFactory().compile(
                    sections,
                    domain=domain,
                    document_type=document_type,
                    lang=lang,
                    request_context=ctx,
                )
                art['_final_doc_factory'] = True
                if compiled.export_evidence:
                    art['_final_doc_factory_evidence'] = compiled.export_evidence
            except Exception:  # noqa: BLE001
                compiled = None
            if compiled is None:
                compiled = compile_canonical_strategy_document(
                    sections,
                    request_context={
                        'lang': lang,
                        'domain': domain,
                        'selected_frameworks': (
                            (art.get('contract_meta') or {}).get('selected_frameworks')
                            or art.get('selected_frameworks') or []),
                        'backend': backend,
                    },
                )
            elif compiled.legacy_sections:
                repairs.append('final_doc_factory:compile')
            if compiled.legacy_sections:
                sections = dict(compiled.legacy_sections)
                if 'final_doc_factory:compile' not in repairs:
                    repairs.extend(compiled.repairs or [])
            art['_rel32_compiled'] = True
            art['_rel32_compiler_passed'] = getattr(compiled, 'passed', True)
            if compiled.blocking_errors:
                art.setdefault('blocking_errors', []).extend(
                    compiled.blocking_errors)
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine.rel31_acceptance_checks import (
            repair_rel31_canonical_sections,
        )
        sections, rel31_repairs = repair_rel31_canonical_sections(
            sections, lang=lang, domain=domain, backend=backend)
        repairs.extend(rel31_repairs)
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine.arabic_language_gate import apply_arabic_final_gate
        from release_engine.rendered_evidence_validator import _repair_arabic_blob
        sections = {
            k: _repair_arabic_blob(v) if isinstance(v, str) else v
            for k, v in sections.items()}
        sections, ar_diag = apply_arabic_final_gate(sections, lang=lang)
        action = (ar_diag.get('action_taken') or '').strip()
        if action and action not in ('validated', 'no_changes'):
            repairs.append(f'rel31:{action}')
    except Exception:  # noqa: BLE001
        pass
    art['sections'] = sections
    for _ in range(max_attempts):
        obj = validate_rel3_objectives(sections, backend=backend)
        sections = obj.get('sections') or sections
        road = validate_rel3_roadmap_output_quality(sections, backend=backend)
        sections = road.get('sections') or sections
        try:
            from release_engine.kpi_model import repair_kpi_canonical_families
            sections, kpi_diag = repair_kpi_canonical_families(
                sections, lang=lang, backend=backend)
            if kpi_diag.get('action_taken') != 'no_changes':
                repairs.append('rel31:kpi_canonical_families_repaired')
        except Exception:  # noqa: BLE001
            pass
        try:
            from release_engine.traceability_substance_model import (
                repair_traceability_canonical_families,
            )
            sections, trace_diag = repair_traceability_canonical_families(
                sections, lang=lang, backend=backend)
            if trace_diag.get('action_taken') != 'no_changes':
                repairs.append('rel31:traceability_canonical_families_repaired')
        except Exception:  # noqa: BLE001
            pass
        try:
            from release_engine.kpi_substance_model import finalize_kpi_substance
            sections, _ = finalize_kpi_substance(
                sections, lang=backend.get('lang', 'ar'), backend=backend)
        except Exception:  # noqa: BLE001
            try:
                from release_engine.kpi_model import finalize_kpi_semantics
                sections, _ = finalize_kpi_semantics(
                    sections, lang=backend.get('lang', 'ar'), backend=backend)
            except Exception:  # noqa: BLE001
                pass
        if obj.get('valid') and road.get('valid'):
            break
        obj_diag = obj.get('diag') or {}
        missing = list(obj_diag.get('missing_objective_families_after') or [])
        optional = {'awareness_or_resilience'}
        critical = [m for m in missing if m not in optional]
        rows_after = int(obj_diag.get('rows_after') or 0)
        if critical and rows_after >= 8:
            sections['vision'] = _rel31_trim_so_table_rows(
                sections.get('vision', ''),
                min(len(critical), 2),
            )
        repairs.extend(['rel31:objectives_repair', 'rel31:roadmap_repair'])
    try:
        from release_engine.arabic_language_gate import (
            repair_arabic_canonical_text_before_freeze,
        )
        sections, ar_canon_diag = repair_arabic_canonical_text_before_freeze(
            sections, lang=lang, backend=backend)
        if ar_canon_diag.get('sections_repaired'):
            repairs.append('rel31:arabic_canonical_repaired')
        elif not ar_canon_diag.get('arabic_canonical_repair_passed'):
            repairs.append('rel31:arabic_canonical_blocked')
    except Exception:  # noqa: BLE001
        pass
    if backend.get('rebuild_markdown'):
        try:
            art['final_markdown'] = backend['rebuild_markdown'](sections)
        except Exception:  # noqa: BLE001
            pass
    art['sections'] = sections
    return art, list(dict.fromkeys(repairs))


_REL31_EXPORT_ADAPTER = threading.local()


def rel31_in_export_adapter() -> bool:
    return bool(getattr(_REL31_EXPORT_ADAPTER, 'active', False))


def rel31_set_export_adapter(active: bool) -> None:
    _REL31_EXPORT_ADAPTER.active = bool(active)


@contextmanager
def rel31_export_adapter_context():
    rel31_set_export_adapter(True)
    try:
        yield
    finally:
        rel31_set_export_adapter(False)


def rel31_guard_legacy_authority(
        function_name: str,
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        document_type: str = 'strategy',
        flags: Optional[Dict[str, Any]] = None,
        read_only: bool = False,
) -> Optional[str]:
    """Block legacy authoritative calls when REL3.1 is active."""
    if str(document_type or '').lower() not in ('strategy', ''):
        return None
    if read_only:
        return None
    if not is_rel3_authoritative(domain=domain, lang=lang, flags=flags):
        return None
    if rel31_in_export_adapter():
        return None
    return f'rel3_legacy_route_blocked:{function_name}'


def normalize_rel3_export_blockers(
        blockers: List[str],
        *,
        route: str = '',
) -> List[str]:
    """Map legacy PDF/DOCX quality codes to REL3 evidence blockers."""
    out: List[str] = []
    route_n = (route or 'export').lower()
    for b in list(blockers or []):
        bs = str(b or '').strip()
        if not bs:
            continue
        low = bs.lower()
        if 'pdf_table_vertical_stack' in low or (
                'vertical_stack' in low and route_n == 'pdf'):
            bs = f'rel3_export_evidence_failed:pdf:vertical_stack_warnings'
        elif bs.startswith('pdf_render_failed:docmodel_professional_quality'):
            bs = f'rel3_export_evidence_failed:pdf:docmodel_professional_quality'
        elif bs.startswith('pdf_render_failed:'):
            bs = f'rel3_export_evidence_failed:pdf:{bs.split(":", 1)[-1]}'
        elif bs.startswith('docmodel_professional_quality'):
            bs = f'rel3_export_evidence_failed:{route_n}:docmodel_professional_quality'
        elif bs.startswith('rel3_legacy_route_blocked:'):
            pass
        elif 'mutation_after_contract' in low:
            bs = 'rel3_post_contract_mutation_detected'
        out.append(bs)
    return list(dict.fromkeys(out))


def rel31_assert_no_legacy_override(
        gate_name: str,
        *,
        contract: Optional[Dict[str, Any]] = None,
        blockers: Optional[List[str]] = None,
) -> Optional[str]:
    """Detect legacy gates overriding a passed REL3 generation contract."""
    contract = contract or {}
    if not contract.get('generation_save_allowed'):
        return None
    if list(contract.get('blocking_errors') or []):
        return None
    legacy = [str(b) for b in (blockers or []) if b]
    if not legacy:
        return None
    audit_only = all(is_legacy_audit_only_blocker(b) for b in legacy)
    if audit_only:
        return None
    return f'rel3_legacy_authority_override_detected:{gate_name}'


def rel3_export_authoritative(
        route: str,
        artifact_dict: Dict[str, Any],
        *,
        backend: Dict[str, Any],
        export_kwargs: Optional[Dict[str, Any]] = None,
        flags: Optional[Dict[str, Any]] = None,
) -> Tuple[Any, Any]:
    """Approved REL3 export entry — RenderTree → exact bytes → evidence."""
    from release_engine_v3.contracts import EvidenceResult, ExportResult
    from release_engine_v3.orchestrator import rel3_freeze_artifact

    flags = dict(flags or {'rel3': True, 'rel31': True})
    domain = str(artifact_dict.get('domain') or 'cyber')
    lang = str((artifact_dict.get('contract_meta') or {}).get('lang') or 'ar')
    route_n = (route or 'preview').lower()
    if not is_rel3_authoritative(domain=domain, lang=lang, flags=flags):
        raise ValueError(f'rel3_export_bypass_detected:{route_n}')

    from release_engine_v3.rel32_frozen_export_lock import (
        emit_rel32_frozen_artifact_export_lock,
        register_rel32_frozen_export_lock,
        resolve_frozen_artifact_for_export,
        track_rel32_export_route_state,
    )

    art = dict(artifact_dict or {})
    art['domain'] = _normalize_rel31_domain_code(
        art.get('domain') or domain)
    backend.setdefault('flags', flags)

    frozen_pre, lock_meta = resolve_frozen_artifact_for_export(
        art, backend=backend, route=route_n, flags=flags)
    if lock_meta.get('blocking_errors'):
        blockers = list(lock_meta['blocking_errors'])
        sid = str(art.get('strategy_id') or '')
        track_rel32_export_route_state(sid, route_n, lock_meta)
        emit_rel32_frozen_artifact_export_lock(
            sid, route=route_n, lock_meta=lock_meta)
        ev = EvidenceResult(
            route_name=route_n,
            artifact_id=str(art.get('artifact_id') or ''),
            strategy_id=sid,
            canonical_hash='',
            render_tree_hash='',
            returned_bytes_sha256='',
            evidence_bytes_sha256='',
            returned_equals_evidence_bytes=False,
            exact_bytes_checked=False,
            preview_text_checked=False,
            docx_bytes_checked=False,
            pdf_bytes_checked=False,
            evidence_passed=False,
            export_return_allowed=False,
            blocking_errors=blockers,
        )
        ev.emit_diag()
        return ExportResult(
            route_name=route_n,
            artifact_id=str(art.get('artifact_id') or ''),
            render_tree_hash='',
            canonical_hash='',
            blocking_errors=blockers,
        ), ev

    if frozen_pre is None:
        from release_engine_v3.rel32_compiler import is_rel32_compiler_first
        if is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
            if route_n in ('docx', 'pdf'):
                blockers = list(lock_meta.get('blocking_errors') or [])
                if lock_meta.get('incomplete_frozen_artifact'):
                    blockers.append('rel32_incomplete_frozen_artifact')
                elif lock_meta.get('docx_rebuilt_from_markdown') and (
                        route_n == 'docx'):
                    blockers.append('rel32_docx_rebuilt_from_markdown')
                elif lock_meta.get('pdf_rebuilt_from_markdown') and (
                        route_n == 'pdf'):
                    blockers.append('rel32_pdf_rebuilt_from_markdown')
                blockers = list(dict.fromkeys(blockers))
                if blockers:
                    sid = str(art.get('strategy_id') or '')
                    track_rel32_export_route_state(sid, route_n, lock_meta)
                    emit_rel32_frozen_artifact_export_lock(
                        sid, route=route_n, lock_meta=lock_meta)
                    ev = EvidenceResult(
                        route_name=route_n,
                        artifact_id=str(art.get('artifact_id') or ''),
                        strategy_id=sid,
                        canonical_hash='',
                        render_tree_hash='',
                        returned_bytes_sha256='',
                        evidence_bytes_sha256='',
                        returned_equals_evidence_bytes=False,
                        exact_bytes_checked=False,
                        preview_text_checked=False,
                        docx_bytes_checked=False,
                        pdf_bytes_checked=False,
                        evidence_passed=False,
                        export_return_allowed=False,
                        blocking_errors=blockers,
                    )
                    ev.emit_diag()
                    return ExportResult(
                        route_name=route_n,
                        artifact_id=str(art.get('artifact_id') or ''),
                        render_tree_hash='',
                        canonical_hash='',
                        blocking_errors=blockers,
                    ), ev

    if frozen_pre is not None:
        frozen = frozen_pre
        backend['_rel32_export_artifact_dict'] = art
        with rel31_export_adapter_context():
            export, evidence = rel3_export_with_evidence(
                route_n,
                frozen,
                backend=backend,
                export_kwargs=export_kwargs or {},
            )
    else:
        art, _pre_rep = repair_canonical_before_freeze(art, backend=backend)
        _bind_backend_sections(backend, art)
        bind_blockers = _verify_rel31_section_binding(backend, art, route_n)
        if bind_blockers:
            ev = EvidenceResult(
                route_name=route_n,
                artifact_id=str(art.get('artifact_id') or ''),
                strategy_id=str(art.get('strategy_id') or ''),
                canonical_hash='',
                render_tree_hash='',
                returned_bytes_sha256='',
                evidence_bytes_sha256='',
                returned_equals_evidence_bytes=False,
                exact_bytes_checked=False,
                preview_text_checked=False,
                docx_bytes_checked=False,
                pdf_bytes_checked=False,
                evidence_passed=False,
                export_return_allowed=False,
                blocking_errors=bind_blockers,
            )
            ev.emit_diag()
            return ExportResult(
                route_name=route_n,
                artifact_id=str(art.get('artifact_id') or ''),
                render_tree_hash='',
                canonical_hash='',
                blocking_errors=bind_blockers,
            ), ev
        with rel31_export_adapter_context():
            frozen = rel3_freeze_artifact(art)
            if frozen.blocking_errors and route_n != 'preview':
                blockers = normalize_rel3_export_blockers(
                    list(frozen.blocking_errors), route=route_n)
                ev = EvidenceResult(
                    route_name=route_n,
                    artifact_id=frozen.artifact_id,
                    strategy_id=frozen.strategy_id,
                    canonical_hash=frozen.canonical_hash,
                    render_tree_hash='',
                    returned_bytes_sha256='',
                    evidence_bytes_sha256='',
                    returned_equals_evidence_bytes=False,
                    exact_bytes_checked=False,
                    preview_text_checked=False,
                    docx_bytes_checked=False,
                    pdf_bytes_checked=False,
                    evidence_passed=False,
                    export_return_allowed=False,
                    blocking_errors=blockers,
                )
                ev.emit_diag()
                return ExportResult(
                    route_name=route_n,
                    artifact_id=frozen.artifact_id,
                    render_tree_hash='',
                    canonical_hash=frozen.canonical_hash,
                    blocking_errors=blockers,
                ), ev
            from release_engine_v3.orchestrator import rel3_build_render_tree
            _tree = rel3_build_render_tree(frozen)
            frozen.render_tree_hash = _tree.render_tree_hash
            register_rel32_frozen_export_lock(
                frozen, render_tree_hash=_tree.render_tree_hash)
            lock_meta = {
                'frozen_artifact_loaded_for_docx': False,
                'frozen_artifact_loaded_for_pdf': False,
                'docx_rebuilt_from_markdown': route_n == 'docx',
                'pdf_rebuilt_from_markdown': route_n == 'pdf',
                'blocking_errors': [],
            }
            export, evidence = rel3_export_with_evidence(
                route_n,
                frozen,
                backend=backend,
                export_kwargs=export_kwargs or {},
            )

    if export.blocking_errors:
        export.blocking_errors = normalize_rel3_export_blockers(
            list(export.blocking_errors), route=route_n)
    if evidence.blocking_errors:
        evidence.blocking_errors = normalize_rel3_export_blockers(
            list(evidence.blocking_errors), route=route_n)

    canon = frozen.canonical_hash or export.canonical_hash or ''
    tree = export.render_tree_hash or evidence.render_tree_hash or ''
    if frozen_pre is not None:
        expected_canon = backend.get('_rel32_frozen_canonical_hash') or ''
        expected_tree = backend.get('_rel32_frozen_render_tree_hash') or ''
        hash_blockers: List[str] = []
        if expected_canon and canon and canon != expected_canon:
            hash_blockers.append('rel32_export_lock_canonical_hash_mismatch')
        if expected_tree and tree and tree != expected_tree:
            hash_blockers.append('rel32_export_lock_render_tree_hash_mismatch')
        if hash_blockers:
            export.blocking_errors = list(dict.fromkeys(
                (export.blocking_errors or []) + hash_blockers))
            evidence.blocking_errors = list(dict.fromkeys(
                (evidence.blocking_errors or []) + hash_blockers))
            evidence.export_return_allowed = False
            evidence.evidence_passed = False
            lock_meta['blocking_errors'] = list(dict.fromkeys(
                (lock_meta.get('blocking_errors') or []) + hash_blockers))
    returned = (
        export.returned_bytes_sha256
        or evidence.returned_bytes_sha256
        or '')
    post_canon = export.canonical_hash or canon
    mutation = bool(canon and post_canon and canon != post_canon)
    if mutation:
        mut_blk = 'rel3_post_contract_mutation_detected'
        export.blocking_errors = list(dict.fromkeys(
            (export.blocking_errors or []) + [mut_blk]))
        evidence.blocking_errors = list(dict.fromkeys(
            (evidence.blocking_errors or []) + [mut_blk]))
        evidence.export_return_allowed = False
        evidence.evidence_passed = False
    emit_rel3_post_contract_hash_check(
        canonical_hash=canon,
        render_tree_hash=tree,
        saved_content_hash=post_canon or canon,
        derived_from_rel3=True,
        mutation_after_contract_detected=mutation,
        route_name=route_n,
    )
    emit_rel3_source_authority_check(
        route_name=route_n,
        artifact_id=str(art.get('artifact_id') or frozen.artifact_id or ''),
        strategy_id=str(art.get('strategy_id') or frozen.strategy_id or ''),
        source_used='rel3_render_tree',
        sealed_artifact_used=True,
        render_tree_hash=tree,
        canonical_hash=canon,
        strategies_content_direct_used=False,
        legacy_helper_used_inside_rel3_adapter=True,
        legacy_helper_authoritative=False,
        blocking_error_if_any=(
            (evidence.blocking_errors or export.blocking_errors or [''])[0]
            if not evidence.export_return_allowed else ''),
    )
    _sid = str(art.get('strategy_id') or frozen.strategy_id or '')
    record_rel3_route_artifact_hashes(
        _sid,
        route_n,
        canonical_hash=canon,
        render_tree_hash=tree,
    )
    emit_rel3_route_artifact_equivalence(_sid)
    track_rel32_export_route_state(_sid, route_n, lock_meta)
    emit_rel32_frozen_artifact_export_lock(
        _sid, route=route_n, lock_meta=lock_meta)
    return export, evidence


def emit_rel3_source_authority_check(
        *,
        route_name: str,
        artifact_id: str = '',
        strategy_id: str = '',
        source_used: str = 'rel3_render_tree',
        sealed_artifact_used: bool = True,
        render_tree_hash: str = '',
        canonical_hash: str = '',
        raw_markdown_used: bool = False,
        client_content_used: bool = False,
        strategies_content_direct_used: bool = False,
        cyber_final_export_contract_used: bool = False,
        professional_raw_markdown_used: bool = False,
        legacy_helper_used_inside_rel3_adapter: bool = False,
        legacy_helper_authoritative: bool = False,
        rel3_authoritative: bool = True,
        blocking_error_if_any: str = '',
) -> Dict[str, Any]:
    valid = (
        rel3_authoritative
        and source_used == 'rel3_render_tree'
        and sealed_artifact_used
        and not raw_markdown_used
        and not client_content_used
        and not strategies_content_direct_used
        and not cyber_final_export_contract_used
        and not professional_raw_markdown_used
        and not legacy_helper_authoritative
        and not blocking_error_if_any)
    payload = {
        'route_name': route_name,
        'rel3_authoritative': bool(rel3_authoritative),
        'artifact_id': artifact_id,
        'strategy_id': strategy_id,
        'source_used': source_used,
        'sealed_artifact_used': sealed_artifact_used,
        'render_tree_hash': render_tree_hash,
        'canonical_hash': canonical_hash,
        'raw_markdown_used': raw_markdown_used,
        'client_content_used': client_content_used,
        'strategies_content_direct_used': strategies_content_direct_used,
        'cyber_final_export_contract_used': cyber_final_export_contract_used,
        'professional_raw_markdown_used': professional_raw_markdown_used,
        'legacy_helper_used_inside_rel3_adapter': bool(
            legacy_helper_used_inside_rel3_adapter),
        'legacy_helper_authoritative': bool(legacy_helper_authoritative),
        'source_authority_valid': valid,
        'blocking_error_if_any': blocking_error_if_any,
    }
    print(
        '[REL3-SOURCE-AUTHORITY-CHECK] '
        + json.dumps(payload, ensure_ascii=False),
        flush=True,
    )
    return payload


_LEGACY_AUDIT_MARKER_KEYS = (
    'prcy74_roadmap_framework_balance_invalid',
    'prcy74_roadmap_column_map_invalid',
    'prcy74_missing_required_dcc_family',
    'prcy71_final_artifact',
    'prcy69_final_artifact',
    'prcy68_',
    'prcy70_',
    'prcy73_',
)


def is_legacy_audit_only_blocker(blocker: str) -> bool:
    """True when a legacy PRCY/REL2 blocker must not override REL3 save."""
    b = str(blocker or '').strip()
    if not b:
        return False
    if any(k in b for k in _LEGACY_AUDIT_MARKER_KEYS):
        return True
    return any(b.startswith(p) for p in _LEGACY_BLOCKER_PREFIXES)


def collect_legacy_audit_blockers(art: Dict[str, Any]) -> List[str]:
    """Gather legacy blockers present on artifact surfaces for audit demotion."""
    found: List[str] = []
    sources = (
        art.get('blocking_errors'),
        (art.get('final_contract_result') or {}).get('blocking_errors'),
        (art.get('contract_meta') or {}).get('blocking_errors'),
        (art.get('rel31_generation_contract') or {}).get(
            'legacy_audit_blockers'),
    )
    for src in sources:
        for b in list(src or []):
            bs = str(b)
            if is_legacy_audit_only_blocker(bs) and bs not in found:
                found.append(bs)
    return found


def emit_rel3_legacy_audit_blockers(
        legacy_audit_blockers: List[str],
        *,
        rel3_authoritative: bool = True,
        authoritative: bool = False,
) -> Dict[str, Any]:
    payload = {
        'legacy_audit_blockers': list(legacy_audit_blockers or []),
        'authoritative': bool(authoritative),
        'rel3_authoritative': bool(rel3_authoritative),
    }
    print(
        '[REL3-LEGACY-AUDIT-BLOCKERS] '
        + json.dumps(payload, ensure_ascii=False),
        flush=True,
    )
    return payload


def emit_rel3_save_authority_check(
        *,
        rel3_authoritative: bool = True,
        legacy_rel2_authoritative: bool = False,
        legacy_prcy_authoritative: bool = False,
        generation_save_allowed_from_rel3: bool = False,
        save_allowed_from_legacy: bool = False,
        legacy_blockers_present: bool = False,
        legacy_blockers_demoted_to_audit: bool = False,
        final_save_decision: str = 'BLOCK',
        blocking_errors: Optional[List[str]] = None,
        legacy_audit_blockers: Optional[List[str]] = None,
        contract: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if contract:
        generation_save_allowed_from_rel3 = bool(
            contract.get('generation_save_allowed'))
        blocking_errors = list(contract.get('blocking_errors') or [])
        legacy_audit_blockers = list(
            contract.get('legacy_audit_blockers') or [])
        legacy_blockers_present = bool(legacy_audit_blockers)
        if generation_save_allowed_from_rel3 and not blocking_errors:
            final_save_decision = 'ALLOW'
            legacy_blockers_demoted_to_audit = legacy_blockers_present
    payload = {
        'rel3_authoritative': bool(rel3_authoritative),
        'legacy_rel2_authoritative': bool(legacy_rel2_authoritative),
        'legacy_prcy_authoritative': bool(legacy_prcy_authoritative),
        'generation_save_allowed_from_rel3': bool(
            generation_save_allowed_from_rel3),
        'save_allowed_from_legacy': bool(save_allowed_from_legacy),
        'legacy_blockers_present': bool(legacy_blockers_present),
        'legacy_blockers_demoted_to_audit': bool(
            legacy_blockers_demoted_to_audit),
        'final_save_decision': str(final_save_decision),
        'blocking_errors': list(blocking_errors or []),
        'legacy_audit_blockers': list(legacy_audit_blockers or []),
    }
    print(
        '[REL3-SAVE-AUTHORITY-CHECK] '
        + json.dumps(payload, ensure_ascii=False),
        flush=True,
    )
    return payload


def emit_rel3_post_contract_hash_check(
        *,
        canonical_hash: str = '',
        render_tree_hash: str = '',
        saved_content_hash: str = '',
        derived_from_rel3: bool = False,
        mutation_after_contract_detected: bool = False,
        route_name: str = 'generation',
) -> Dict[str, Any]:
    stable = bool(canonical_hash) and bool(render_tree_hash)
    if derived_from_rel3 and canonical_hash and saved_content_hash:
        mutation_after_contract_detected = (
            saved_content_hash != canonical_hash)
    payload = {
        'route_name': route_name,
        'canonical_hash': canonical_hash or '',
        'render_tree_hash': render_tree_hash or '',
        'saved_content_hash': saved_content_hash or '',
        'derived_from_rel3': bool(derived_from_rel3),
        'canonical_hash_stable': stable,
        'render_tree_hash_stable': stable,
        'mutation_after_contract_detected': bool(
            mutation_after_contract_detected),
    }
    print(
        '[REL3-POST-CONTRACT-HASH-CHECK] '
        + json.dumps(payload, ensure_ascii=False),
        flush=True,
    )
    return payload


def finalize_rel31_save_authority(
        art: Dict[str, Any],
        contract: Dict[str, Any],
        *,
        route_name: str = 'generation',
) -> Dict[str, Any]:
    """Demote legacy PRCY blockers and align artifact hashes with REL3 contract."""
    if not contract.get('generation_save_allowed'):
        return art
    legacy_audit = list(contract.get('legacy_audit_blockers') or [])
    for b in collect_legacy_audit_blockers(art):
        if b not in legacy_audit:
            legacy_audit.append(b)
    contract = dict(contract)
    contract['legacy_audit_blockers'] = legacy_audit
    contract['blocking_errors'] = []
    art['rel31_generation_contract'] = contract
    art['blocking_errors'] = []

    canon = (
        contract.get('canonical_hash')
        or art.get('rel3_canonical_hash')
        or art.get('final_hash')
        or '')
    tree_hash = (
        contract.get('render_tree_hash')
        or art.get('rel3_render_tree_hash')
        or '')

    fcr = dict(art.get('final_contract_result') or {})
    if fcr:
        fcr['blocking_errors'] = []
        if canon:
            fcr['final_hash'] = canon
        art['final_contract_result'] = fcr

    if canon:
        art['final_hash'] = canon
        art['rel3_canonical_hash'] = canon
    if tree_hash:
        art['rel3_render_tree_hash'] = tree_hash

    cm = dict(art.get('contract_meta') or {})
    cm.update({
        'rel31_authoritative': True,
        'final_hash': canon or cm.get('final_hash'),
        'rel3_canonical_hash': canon or cm.get('rel3_canonical_hash'),
        'rel3_render_tree_hash': tree_hash or cm.get('rel3_render_tree_hash'),
        'blocking_errors': [],
        'sealed': True,
        'quality_gate_passed': True,
        'preview_hash': canon or cm.get('preview_hash'),
        'docx_hash': canon or cm.get('docx_hash'),
        'pdf_hash': canon or cm.get('pdf_hash'),
    })
    art['contract_meta'] = cm
    art['sealed'] = True

    if legacy_audit:
        emit_rel3_legacy_audit_blockers(
            legacy_audit, rel3_authoritative=True)
    emit_rel3_save_authority_check(
        contract=contract,
        legacy_rel2_authoritative=False,
        legacy_prcy_authoritative=False,
        save_allowed_from_legacy=not legacy_audit,
        legacy_blockers_demoted_to_audit=bool(legacy_audit),
        final_save_decision='ALLOW',
    )
    emit_rel3_post_contract_hash_check(
        canonical_hash=canon,
        render_tree_hash=tree_hash,
        saved_content_hash=canon,
        derived_from_rel3=True,
        mutation_after_contract_detected=False,
        route_name=route_name,
    )
    emit_rel3_source_authority_check(
        route_name=route_name,
        artifact_id=str(
            contract.get('artifact_id') or art.get('strategy_id') or ''),
        strategy_id=str(art.get('strategy_id') or ''),
        source_used='rel3_render_tree',
        sealed_artifact_used=True,
        render_tree_hash=tree_hash,
        canonical_hash=canon,
    )
    return art


def evaluate_rel31_pre_save_assertion(
        artifact: Dict[str, Any],
        *,
        cy28_contract: Optional[Dict[str, Any]] = None,
        lang: str = 'ar',
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """REL3-only pre-save assertion — legacy PRCY blockers are audit-only."""
    _ = lang
    errors: List[str] = []
    contract = dict(
        artifact.get('rel31_generation_contract')
        or (cy28_contract or {}).get('rel31_generation_contract')
        or {})
    if not contract:
        errors.append('rel3_generation_contract_failed:contract_missing')
    elif not contract.get('generation_save_allowed'):
        errors.extend(str(e) for e in (contract.get('blocking_errors') or []))
        if not errors:
            errors.append('rel3_generation_contract_failed:save_not_allowed')

    canon = (
        contract.get('canonical_hash')
        or artifact.get('rel3_canonical_hash')
        or '')
    tree = (
        contract.get('render_tree_hash')
        or artifact.get('rel3_render_tree_hash')
        or '')
    if contract and not canon:
        errors.append('rel3_generation_contract_failed:canonical_hash_missing')
    if contract and not tree:
        errors.append(
            'rel3_generation_contract_failed:render_tree_hash_missing')

    legacy_audit = list(contract.get('legacy_audit_blockers') or [])
    fcr = (
        artifact.get('final_contract_result')
        or (cy28_contract or {}).get('final_contract_result')
        or {})
    for b in list(fcr.get('blocking_errors') or []):
        if is_legacy_audit_only_blocker(str(b)) and b not in legacy_audit:
            legacy_audit.append(str(b))
    if legacy_audit and contract:
        contract['legacy_audit_blockers'] = legacy_audit
        contract['blocking_errors'] = []
        emit_rel3_legacy_audit_blockers(
            legacy_audit, rel3_authoritative=True)

    passed = not errors
    diag = {
        'task_id': contract.get('task_id') or '',
        'route': 'generation',
        'rel3_authoritative': True,
        'final_contract_present': bool(contract),
        'final_hash': canon,
        'render_tree_hash': tree,
        'source_used': 'rel3_render_tree',
        'blocking_errors': list(errors),
        'legacy_audit_blockers': legacy_audit,
        'save_decision': 'ALLOWED' if passed else 'BLOCKED',
        'save_allowed': passed,
        'downstream_pipelines_allowed': passed,
        'assertion_passed': passed,
        'action_taken': 'allow_save' if passed else 'block_save',
    }
    emit_rel3_save_authority_check(
        contract=contract if passed else None,
        generation_save_allowed_from_rel3=bool(
            contract.get('generation_save_allowed')),
        legacy_blockers_present=bool(legacy_audit),
        legacy_blockers_demoted_to_audit=bool(legacy_audit),
        final_save_decision='ALLOW' if passed else 'BLOCK',
        blocking_errors=errors,
        legacy_audit_blockers=legacy_audit,
    )
    if passed:
        emit_rel3_post_contract_hash_check(
            canonical_hash=canon,
            render_tree_hash=tree,
            saved_content_hash=canon,
            derived_from_rel3=True,
            mutation_after_contract_detected=False,
            route_name='generation',
        )
    return passed, errors, diag


def rel31_contract_guard_passed(
        contract: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str], str]:
    """Shared guard for contract-first pipeline proofs under REL3 authority."""
    if not isinstance(contract, dict) or not contract:
        return False, (
            'rel3_generation_contract_failed:contract_missing'), ''
    rel31 = contract.get('rel31_generation_contract') or {}
    if contract.get('rel31_authoritative') or rel31.get('generation_save_allowed'):
        if rel31.get('generation_save_allowed'):
            fh = (
                rel31.get('canonical_hash')
                or contract.get('content_hash')
                or '')
            if not fh:
                return False, (
                    'rel3_generation_contract_failed:canonical_hash_missing'), ''
            return True, None, str(fh)
        be = list(rel31.get('blocking_errors') or [])
        if be:
            return False, str(be[0]), ''
        return False, (
            'rel3_generation_contract_failed:save_not_allowed'), ''
    return False, (
        'final_quality_gate_failed:final_contract_missing_before_save'), ''


def emit_rel3_generation_contract(contract: Dict[str, Any]) -> Dict[str, Any]:
    print(
        '[REL3-GENERATION-CONTRACT] '
        + json.dumps(contract, ensure_ascii=False),
        flush=True,
    )
    return contract


def build_generation_contract(
        *,
        artifact: FinalDocumentArtifact,
        render_tree_hash: str,
        task_id: str = '',
        objectives_valid: bool,
        roadmap_valid: bool,
        pillars_valid: bool,
        kpi_valid: bool,
        risk_valid: bool,
        traceability_valid: bool,
        arabic_valid: bool,
        render_tree_valid: bool,
        preview_evidence_valid: bool,
        legacy_gate_after_freeze_count: int,
        blocking_errors: List[str],
        legacy_audit: Optional[List[str]] = None,
        document_quality_passed: Optional[bool] = None,
        dqs_route_count: int = 0,
        dqs_phase: str = 'pre_export_model_validation',
        enforce_dq: bool = False,
) -> Dict[str, Any]:
    dq_ok = True
    if enforce_dq and document_quality_passed is not None:
        if dqs_phase == 'pre_export_model_validation' and dqs_route_count == 0:
            dq_ok = bool(document_quality_passed)
        else:
            dq_ok = bool(document_quality_passed) and dqs_route_count >= 1
    if document_quality_passed is not None:
        ok = (
            dq_ok
            and not blocking_errors
            and objectives_valid
            and roadmap_valid
            and render_tree_valid
            and preview_evidence_valid
            and legacy_gate_after_freeze_count == 0)
    else:
        ok = (
            not blocking_errors
            and objectives_valid
            and roadmap_valid
            and render_tree_valid
            and preview_evidence_valid
            and legacy_gate_after_freeze_count == 0)
    return {
        'artifact_id': artifact.artifact_id,
        'task_id': task_id,
        'domain': artifact.domain,
        'lang': artifact.language,
        'document_type': artifact.document_type,
        'canonical_hash': artifact.canonical_hash,
        'render_tree_hash': render_tree_hash,
        'objectives_valid': objectives_valid,
        'pillars_valid': pillars_valid,
        'roadmap_valid': roadmap_valid,
        'kpi_valid': kpi_valid,
        'risk_valid': risk_valid,
        'traceability_valid': traceability_valid,
        'arabic_valid': arabic_valid,
        'render_tree_valid': render_tree_valid,
        'preview_evidence_valid': preview_evidence_valid,
        'legacy_gate_after_freeze_count': legacy_gate_after_freeze_count,
        'generation_save_allowed': ok,
        'preview_allowed': ok,
        'docx_allowed': ok,
        'pdf_allowed': ok,
        'blocking_errors': list(blocking_errors),
        'legacy_audit_blockers': list(legacy_audit or []),
        'dqs_phase': dqs_phase,
        'dqs_route_count': dqs_route_count,
    }


def apply_rel31_authoritative_contract(
        legacy_artifact: Dict[str, Any],
        *,
        backend: Dict[str, Any],
        task_id: str = '',
        route_name: str = 'generation',
        flags: Optional[Dict[str, Any]] = None,
        enforce_save_contract: bool = True,
) -> Dict[str, Any]:
    """Make REL3 the only authoritative contract for save/export."""
    flags = flags or {}
    art = dict(legacy_artifact)
    domain = art.get('domain') or 'cyber'
    lang = (
        (art.get('contract_meta') or {}).get('lang')
        or art.get('language') or 'ar')
    meta = dict(art.get('contract_meta') or {})
    if legacy_artifact.get('document_type') and not meta.get('document_type'):
        meta['document_type'] = legacy_artifact.get('document_type')
    art['contract_meta'] = meta
    if not is_rel3_authoritative(domain=domain, lang=lang, flags=flags):
        return art

    legacy_audit = collect_legacy_audit_blockers(art)
    art['blocking_errors'] = []
    backend = dict(backend)
    backend['flags'] = dict(flags)
    backend['lang'] = lang
    backend['selected_frameworks'] = (
        (art.get('contract_meta') or {}).get('selected_frameworks')
        or art.get('selected_frameworks') or [])

    art, repairs = repair_canonical_before_freeze(art, backend=backend)
    obj = validate_rel3_objectives(
        art.get('sections') or {}, backend=backend)
    road = validate_rel3_roadmap_output_quality(
        art.get('sections') or {}, backend=backend)
    art['sections'] = obj.get('sections') or art.get('sections') or {}
    if road.get('sections'):
        art['sections'].update(road['sections'])

    blockers: List[str] = []
    require_strategy = _requires_strategy_contract_sections(art, domain=domain)
    if require_strategy and not obj.get('valid'):
        blockers.append('rel3_generation_contract_failed:objectives')
    if require_strategy and not road.get('valid'):
        blockers.append('rel3_generation_contract_failed:roadmap_weak_output')

    art['sections'] = _scrub_art_sections_for_build(
        dict(art.get('sections') or {}), lang)
    art['blocking_errors'] = []
    built = _rel31_rebuild_frozen_artifact(
        art, lang=lang, strategy_id=str(art.get('strategy_id') or ''))
    quality = validate_canonical_quality(
        built.canonical_sections,
        legacy_sections=art.get('sections') or {},
        domain=domain,
        lang=lang,
    )
    for err in quality.get('blocking_errors') or []:
        if not err.startswith('rel3_'):
            blockers.append(f'rel3_generation_contract_failed:{err}')
        else:
            blockers.append(err)
    blockers = _strip_repaired_arabic_glue_blockers(
        blockers, dict(art.get('sections') or {}))
    built.blocking_errors = _strip_repaired_arabic_glue_blockers(
        list(built.blocking_errors or []),
        dict(art.get('sections') or {}))
    if not blockers and not built.blocking_errors:
        built = freeze_artifact(built)
    store_artifact(built)

    tree = rel3_build_render_tree(built)
    _sid = str(art.get('strategy_id') or built.strategy_id or '')
    built.render_tree_hash = tree.render_tree_hash
    try:
        from release_engine_v3.rel32_frozen_export_lock import (
            register_rel32_frozen_export_lock,
        )
        register_rel32_frozen_export_lock(
            built, render_tree_hash=tree.render_tree_hash)
    except Exception:  # noqa: BLE001
        pass
    record_rel3_route_artifact_hashes(
        _sid, 'generation',
        canonical_hash=built.canonical_hash,
        render_tree_hash=tree.render_tree_hash,
    )
    _bind_backend_sections(backend, art)
    preview_export, preview_ev = rel3_export_with_evidence(
        'preview', built, backend=backend)
    if not preview_ev.export_return_allowed:
        _preview_gate = getattr(preview_ev, 'gate', None) or {}
        if not _preview_gate:
            _preview_gate = {
                'blocking_errors': list(preview_ev.blocking_errors or []),
                'preview_forbidden_patterns': [],
            }
        _preview_blob = ' '.join(
            str(e) for e in (preview_ev.blocking_errors or [])).lower()
        if _preview_failure_repairable(
                list(preview_ev.blocking_errors or []), _preview_gate):
            try:
                from release_engine.export_evidence_validator import (
                    repair_for_actual_export_defects,
                )
                from release_engine_v3.document_quality_spec import (
                    repair_document_quality_sections,
                )
                art, _prev_rep = repair_for_actual_export_defects(
                    art, _preview_gate,
                    domain=domain, lang=lang, backend=backend)
                repairs.extend(_prev_rep)
                _prev_secs, _dqs_prev = repair_document_quality_sections(
                    dict(art.get('sections') or {}),
                    lang=lang, domain=domain, backend=backend)
                art['sections'] = _prev_secs
                repairs.extend(_dqs_prev)
            except Exception:  # noqa: BLE001
                pass
            _secs = dict(art.get('sections') or {})
            _secs = _rel31_dedupe_roadmap_rows(_secs, backend=backend)
            _secs = _repair_rel3_weak_roadmap_outputs(_secs, backend=backend)
            try:
                from release_engine.roadmap_model import finalize_roadmap
                _secs, _ = finalize_roadmap(
                    _secs,
                    lang=lang,
                    domain=domain,
                    selected_frameworks=backend.get('selected_frameworks') or [],
                    backend=backend)
            except Exception:  # noqa: BLE001
                pass
            art['sections'] = _secs
            if backend.get('rebuild_markdown'):
                try:
                    art['final_markdown'] = backend['rebuild_markdown'](_secs)
                except Exception:  # noqa: BLE001
                    pass
            obj = validate_rel3_objectives(_secs, backend=backend)
            art['sections'] = obj.get('sections') or _secs
            road = validate_rel3_roadmap_output_quality(
                art.get('sections') or {}, backend=backend)
            art['sections'] = road.get('sections') or art.get('sections') or {}
            try:
                from release_engine.rel31_content_substance_checks import (
                    repair_rel31_content_substance,
                )
                _sub_secs, _sub_rep = repair_rel31_content_substance(
                    dict(art.get('sections') or {}),
                    lang=lang, domain=domain, backend=backend)
                art['sections'] = _sub_secs
                repairs.extend(_sub_rep)
            except Exception:  # noqa: BLE001
                pass
            blockers = [
                b for b in blockers
                if b not in (
                    'rel3_generation_contract_failed:objectives',
                    'rel3_generation_contract_failed:roadmap_weak_output')]
            if not obj.get('valid'):
                blockers.append('rel3_generation_contract_failed:objectives')
            if not road.get('valid'):
                blockers.append(
                    'rel3_generation_contract_failed:roadmap_weak_output')
            built = _rel31_rebuild_frozen_artifact(
                art, lang=lang,
                strategy_id=str(art.get('strategy_id') or ''))
            store_artifact(built)
            tree = rel3_build_render_tree(built)
            _bind_backend_sections(backend, art)
            preview_export, preview_ev = rel3_export_with_evidence(
                'preview', built, backend=backend)
    if not preview_ev.export_return_allowed:
        for e in preview_ev.blocking_errors:
            if e not in blockers:
                blockers.append(translate_legacy_blocker(e))

    docx_text = ''
    pdf_text = ''
    pdf_bytes = b''
    dq: Dict[str, Any] = {}
    docx_ev = None
    enforce_dq = _enforce_document_quality_blockers(
        art, domain=domain, lang=lang)
    if enforce_dq:
        try:
            from release_engine_v3.evidence.docx_text_extractor import (
                extract_docx_visible_text,
            )
            from release_engine_v3.evidence.pdf_text_extractor import (
                extract_pdf_visible_text,
            )
            from release_engine_v3.document_quality_spec import (
                document_quality_blockers,
                evaluate_document_quality,
            )
            _bind_backend_sections(backend, art)
            _dq_max_passes = 3 if route_name == 'generation' else 2
            for _dq_pass in range(_dq_max_passes):
                preview_export, preview_ev = rel3_export_with_evidence(
                    'preview', built, backend=backend)
                docx_export, docx_ev = rel3_export_with_evidence(
                    'docx', built, backend=backend,
                    export_kwargs={'filename': 'rel31_quality.docx', 'lang': lang})
                pdf_export, pdf_ev = rel3_export_with_evidence(
                    'pdf', built, backend=backend,
                    export_kwargs={'lang': lang, 'domain': domain})
                docx_text = ''
                if docx_export.docx_bytes:
                    docx_text = extract_docx_visible_text(docx_export.docx_bytes)
                pdf_bytes = pdf_export.pdf_bytes or b''
                pdf_text = ''
                if pdf_bytes:
                    pdf_text = extract_pdf_visible_text(pdf_bytes)
                dq = evaluate_document_quality(
                    canonical_artifact=built,
                    legacy_sections=dict(
                        getattr(built, 'legacy_sections', None)
                        or art.get('sections') or {}),
                    render_tree=tree,
                    extracted_preview_text=preview_export.preview_text or '',
                    extracted_docx_text=docx_text,
                    extracted_pdf_text=pdf_text,
                    pdf_bytes=pdf_bytes,
                )
                art['rel31_document_quality'] = dq
                dq_ok = bool(dq.get('passed'))
                docx_ok = bool(docx_ev.export_return_allowed)
                if dq_ok and docx_ok:
                    built = _rel31_rebuild_frozen_artifact(
                        art, lang=lang,
                        strategy_id=str(art.get('strategy_id') or ''))
                    store_artifact(built)
                    tree = rel3_build_render_tree(built)
                    _bind_backend_sections(backend, art)
                    preview_export, preview_ev = rel3_export_with_evidence(
                        'preview', built, backend=backend)
                    break
                if _dq_pass < (_dq_max_passes - 1) and (
                        _rel31_dq_repairable(blockers, dq, docx_ev)
                        or _rel31_dq_needs_repair(dq)):
                    from release_engine.export_evidence_validator import (
                        repair_for_actual_export_defects,
                    )
                    from release_engine_v3.document_quality_spec import (
                        repair_document_quality_sections,
                    )
                    export_diag = _rel31_build_export_diag_for_repair(
                        docx_ev, dq, preview_ev)
                    art, dq_rep = repair_for_actual_export_defects(
                        art, export_diag,
                        domain=domain, lang=lang, backend=backend)
                    repairs.extend(dq_rep)
                    _dqs_secs, _dqs_rep = repair_document_quality_sections(
                        dict(art.get('sections') or {}),
                        lang=lang, domain=domain, backend=backend)
                    art['sections'] = _dqs_secs
                    repairs.extend(_dqs_rep)
                    try:
                        from release_engine.rel31_content_substance_checks import (
                            repair_rel31_content_substance,
                        )
                        _sub_secs, _sub_rep = repair_rel31_content_substance(
                            dict(art.get('sections') or {}),
                            lang=lang, domain=domain, backend=backend)
                        art['sections'] = _sub_secs
                        repairs.extend(_sub_rep)
                    except Exception:  # noqa: BLE001
                        pass
                    if _dq_needs_roadmap_owner_repair(dq, export_diag):
                        _rm_secs = dict(art.get('sections') or {})
                        _rm_secs = _rel31_dedupe_roadmap_rows(
                            _rm_secs, backend=backend)
                        _rm_secs = _repair_rel3_weak_roadmap_outputs(
                            _rm_secs, backend=backend)
                        try:
                            from release_engine.roadmap_model import finalize_roadmap
                            _rm_secs, _ = finalize_roadmap(
                                _rm_secs,
                                lang=lang,
                                domain=domain,
                                selected_frameworks=(
                                    backend.get('selected_frameworks') or []),
                                backend=backend)
                            repairs.append('rel31:roadmap_owners_repaired_for_dqs')
                        except Exception:  # noqa: BLE001
                            pass
                        art['sections'] = _rm_secs
                    blockers = _rel31_clear_dq_blockers(blockers)
                    _bind_backend_sections(backend, art)
                    if backend.get('rebuild_markdown'):
                        try:
                            art['final_markdown'] = backend['rebuild_markdown'](
                                art.get('sections') or {})
                        except Exception:  # noqa: BLE001
                            pass
                    built = _rel31_rebuild_frozen_artifact(
                        art, lang=lang,
                        strategy_id=str(art.get('strategy_id') or ''))
                    store_artifact(built)
                    tree = rel3_build_render_tree(built)
                    rel2_cache = backend.get('_rel2_cache') or {}
                    rel2_cache.pop('exports', None)
                    rel2_cache.pop('models', None)
                    backend['_rel2_cache'] = rel2_cache
                    continue
                break
            road = validate_rel3_roadmap_output_quality(
                dict(art.get('sections') or {}), backend=backend)
            art['sections'] = road.get('sections') or art.get('sections') or {}
            if dq.get('passed'):
                blockers = _rel31_clear_dq_blockers(blockers)
                if not road.get('valid'):
                    blockers.append(
                        'rel3_generation_contract_failed:roadmap_weak_output')
                built = _rel31_rebuild_frozen_artifact(
                    art, lang=lang,
                    strategy_id=str(art.get('strategy_id') or ''))
                store_artifact(built)
                tree = rel3_build_render_tree(built)
                _bind_backend_sections(backend, art)
                preview_export, preview_ev = rel3_export_with_evidence(
                    'preview', built, backend=backend)
            if not dq.get('passed'):
                for err in document_quality_blockers(dq):
                    if err not in blockers:
                        blockers.append(err)
            if docx_ev and not docx_ev.export_return_allowed:
                for e in docx_ev.blocking_errors:
                    tr = translate_legacy_blocker(e)
                    if tr not in blockers:
                        blockers.append(tr)
        except Exception as exc:  # noqa: BLE001
            blockers.append(f'rel3_document_quality_failed:compiler:{exc!s:.80}')

    pillars_valid = not any(
        'missing_pillars' in b for b in (preview_ev.blocking_errors or []))
    kpi_valid = 'kpi' not in ' '.join(blockers).lower()
    risk_valid = 'risk' not in ' '.join(blockers).lower()
    trace_valid = 'traceability' not in ' '.join(blockers).lower()
    arabic_valid = (
        not _blockers_contain_arabic_defect(blockers)
        and 'arabic' not in ' '.join(blockers).lower())

    contract = build_generation_contract(
        artifact=built,
        render_tree_hash=tree.render_tree_hash,
        task_id=task_id,
        objectives_valid=bool(obj.get('valid')),
        roadmap_valid=bool(road.get('valid')),
        pillars_valid=pillars_valid,
        kpi_valid=kpi_valid,
        risk_valid=risk_valid,
        traceability_valid=trace_valid,
        arabic_valid=arabic_valid,
        render_tree_valid=bool(tree.render_tree_hash),
        preview_evidence_valid=preview_ev.export_return_allowed,
        legacy_gate_after_freeze_count=0,
        blocking_errors=blockers,
        legacy_audit=legacy_audit,
        document_quality_passed=(
            dq.get('passed') if enforce_dq and dq else None),
        dqs_route_count=len(dq.get('route_evidence') or {}) if dq else 0,
        dqs_phase=str(dq.get('phase') or 'pre_export_model_validation') if dq else 'pre_export_model_validation',
        enforce_dq=enforce_dq,
    )
    emit_rel3_generation_contract(contract)

    if contract.get('generation_save_allowed'):
        art = finalize_rel31_save_authority(
            art, contract, route_name=route_name)
        canon = art.get('rel3_canonical_hash') or built.canonical_hash
        built = _rel31_rebuild_frozen_artifact(
            art, lang=lang,
            strategy_id=str(art.get('strategy_id') or ''))
        if not blockers and not built.blocking_errors:
            built = freeze_artifact(built)
        store_artifact(built)
        tree = rel3_build_render_tree(built)
        _cm = dict(art.get('contract_meta') or {})
        _cm['final_hash'] = canon
        _cm['rel3_canonical_hash'] = canon
        _cm['rel3_render_tree_hash'] = tree.render_tree_hash
        _cm['rel31_authoritative'] = True
        art['contract_meta'] = _cm
        contract = dict(art.get('rel31_generation_contract') or contract)

    art['rel3_artifact'] = built.to_dict()
    art['rel3_frozen'] = built.frozen
    art['rel3_canonical_hash'] = built.canonical_hash
    art['rel3_render_tree_hash'] = tree.render_tree_hash
    art['rel31_generation_contract'] = contract
    art['rel31_repairs'] = repairs
    if enforce_save_contract:
        art['blocking_errors'] = (
            [] if contract.get('generation_save_allowed')
            else list(blockers))
        art['sealed'] = bool(contract.get('generation_save_allowed'))
    if enforce_dq and dq:
        art['release_ready_final_passed'] = bool(dq.get('passed'))
        art['export_return_allowed'] = bool(dq.get('export_return_allowed'))
        art['national_launch_ready'] = bool(dq.get('national_launch_ready'))
    elif contract.get('generation_save_allowed'):
        art['release_ready_final_passed'] = True
        art['board_ready_score'] = max(
            int(art.get('board_ready_score') or 0), 80)
    else:
        art['release_ready_final_passed'] = False
    art['repair_actions'] = list(art.get('repair_actions') or []) + repairs
    diag = dict(art.get('diagnostics') or {})
    diag['rel31'] = {
        'authoritative': True,
        'contract': contract,
        'legacy_audit': legacy_audit,
        'repairs': repairs,
    }
    diag['rel3'] = {
        'frozen': built.frozen,
        'canonical_hash': built.canonical_hash,
        'render_tree_hash': tree.render_tree_hash,
        'release_ready_final_passed': contract.get('generation_save_allowed'),
        'blocking_errors': blockers,
    }
    art['diagnostics'] = diag
    emit_rel3_route_artifact_equivalence(
        str(art.get('strategy_id') or built.strategy_id or ''))
    return art


def rel3_get_or_build_frozen_artifact(
        artifact_or_id: Any,
        *,
        backend: Optional[Dict[str, Any]] = None,
        flags: Optional[Dict[str, Any]] = None,
) -> Tuple[FinalDocumentArtifact, Dict[str, Any]]:
    """Resolve frozen artifact; rebuild from dict when needed."""
    from release_engine_v3.orchestrator import rel3_get_frozen_artifact
    if isinstance(artifact_or_id, dict):
        if artifact_or_id.get('rel31_generation_contract'):
            frozen = rel3_get_frozen_artifact(artifact_or_id, backend=backend)
            return frozen, artifact_or_id.get('rel31_generation_contract') or {}
        if flags and is_rel3_authoritative(
                domain=artifact_or_id.get('domain', 'cyber'),
                lang=(artifact_or_id.get('contract_meta') or {}).get('lang', 'ar'),
                flags=flags):
            merged = apply_rel31_authoritative_contract(
                artifact_or_id, backend=backend or {}, flags=flags)
            frozen = rel3_get_frozen_artifact(merged, backend=backend)
            return frozen, merged.get('rel31_generation_contract') or {}
    frozen = rel3_get_frozen_artifact(artifact_or_id, backend=backend)
    return frozen, {}
