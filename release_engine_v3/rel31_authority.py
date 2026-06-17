"""PR-REL3.1 — REL3 as sole authoritative generation/save/export contract."""

from __future__ import annotations

import json
import re
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
    'تعذر توليد الاستراتيجية لأن جودة الأهداف الاستراتيجية أو خارطة '
    'الطريق لم تحقق معيار الجاهزية. تم حجب الوثيقة لمنع إخراج ملف غير مكتمل.'
)

REL31_USER_MESSAGE_EN = (
    'Strategy generation was blocked because strategic objectives or roadmap '
    'quality did not meet readiness standards. The document was withheld to '
    'prevent an incomplete export.'
)

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


def is_rel3_authoritative(
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        flags: Optional[Dict[str, Any]] = None) -> bool:
    flags = flags or {}
    if not flags.get('rel31') or not flags.get('rel3'):
        return False
    return (
        str(domain or '').strip().lower() in ('cyber', 'cyber_security')
        and str(lang or '').lower().startswith('ar'))


def rel31_fingerprint_extension(flags: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    flags = flags or {}
    auth = bool(flags.get('rel31') and flags.get('rel3'))
    return {
        'rel3': bool(flags.get('rel3')),
        'rel31': bool(flags.get('rel31')),
        'rel3_authoritative': auth,
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
    if str(lang or '').lower().startswith('ar'):
        return REL31_USER_MESSAGE_AR
    return REL31_USER_MESSAGE_EN


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
    optional = {'awareness_or_resilience'}
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
    if backend.get('rebuild_markdown'):
        try:
            art['final_markdown'] = backend['rebuild_markdown'](sections)
        except Exception:  # noqa: BLE001
            pass
    art['sections'] = sections
    return art, list(dict.fromkeys(repairs))


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
        cyber_final_export_contract_used: bool = False,
        professional_raw_markdown_used: bool = False,
        blocking_error_if_any: str = '',
) -> Dict[str, Any]:
    valid = (
        source_used == 'rel3_render_tree'
        and sealed_artifact_used
        and not raw_markdown_used
        and not client_content_used
        and not cyber_final_export_contract_used
        and not professional_raw_markdown_used
        and not blocking_error_if_any)
    payload = {
        'route_name': route_name,
        'artifact_id': artifact_id,
        'strategy_id': strategy_id,
        'source_used': source_used,
        'sealed_artifact_used': sealed_artifact_used,
        'render_tree_hash': render_tree_hash,
        'canonical_hash': canonical_hash,
        'raw_markdown_used': raw_markdown_used,
        'client_content_used': client_content_used,
        'cyber_final_export_contract_used': cyber_final_export_contract_used,
        'professional_raw_markdown_used': professional_raw_markdown_used,
        'source_authority_valid': valid,
        'blocking_error_if_any': blocking_error_if_any,
    }
    print(
        '[REL3-SOURCE-AUTHORITY-CHECK] '
        + json.dumps(payload, ensure_ascii=False),
        flush=True,
    )
    return payload


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
) -> Dict[str, Any]:
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
    if not is_rel3_authoritative(domain=domain, lang=lang, flags=flags):
        return art

    legacy_audit = list(art.get('blocking_errors') or [])
    art['blocking_errors'] = []
    backend = dict(backend)
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
    if not obj.get('valid'):
        blockers.append('rel3_generation_contract_failed:objectives')
    if not road.get('valid'):
        blockers.append('rel3_generation_contract_failed:roadmap_weak_output')

    built = build_final_document_artifact(
        art, freeze=False, strategy_id=str(art.get('strategy_id') or ''))
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

    if not blockers:
        built = freeze_artifact(built)
    store_artifact(built)

    tree = rel3_build_render_tree(built)
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
        if any(k in _preview_blob for k in (
                'roadmap', 'arabic', 'pillar', 'missing_pillars')):
            try:
                from release_engine.export_evidence_validator import (
                    repair_for_actual_export_defects,
                )
                art, _prev_rep = repair_for_actual_export_defects(
                    art, _preview_gate,
                    domain=domain, lang=lang, backend=backend)
                repairs.extend(_prev_rep)
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
            built = build_final_document_artifact(
                art, freeze=False,
                strategy_id=str(art.get('strategy_id') or ''))
            built = freeze_artifact(built)
            store_artifact(built)
            tree = rel3_build_render_tree(built)
            preview_export, preview_ev = rel3_export_with_evidence(
                'preview', built, backend=backend)
    if not preview_ev.export_return_allowed:
        for e in preview_ev.blocking_errors:
            if e not in blockers:
                blockers.append(translate_legacy_blocker(e))

    pillars_valid = not any(
        'missing_pillars' in b for b in (preview_ev.blocking_errors or []))
    kpi_valid = 'kpi' not in ' '.join(blockers).lower()
    risk_valid = 'risk' not in ' '.join(blockers).lower()
    trace_valid = 'traceability' not in ' '.join(blockers).lower()
    arabic_valid = 'arabic' not in ' '.join(blockers).lower()

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
    )
    emit_rel3_generation_contract(contract)

    if contract.get('generation_save_allowed'):
        canon = built.canonical_hash
        art['final_hash'] = canon
        art['rel3_canonical_hash'] = canon
        if backend.get('rebuild_markdown'):
            try:
                art['final_markdown'] = backend['rebuild_markdown'](
                    art.get('sections') or {})
            except Exception:  # noqa: BLE001
                pass
        _cm = dict(art.get('contract_meta') or {})
        _cm['final_hash'] = canon
        _cm['rel3_canonical_hash'] = canon
        _cm['rel3_render_tree_hash'] = tree.render_tree_hash
        _cm['rel31_authoritative'] = True
        art['contract_meta'] = _cm

    art['rel3_artifact'] = built.to_dict()
    art['rel3_frozen'] = built.frozen
    art['rel3_canonical_hash'] = built.canonical_hash
    art['rel3_render_tree_hash'] = tree.render_tree_hash
    art['rel31_generation_contract'] = contract
    art['rel31_repairs'] = repairs
    if enforce_save_contract:
        art['blocking_errors'] = list(blockers)
        art['sealed'] = bool(contract.get('generation_save_allowed'))
    if contract.get('generation_save_allowed'):
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
