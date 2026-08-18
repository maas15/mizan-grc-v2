"""PR-REL3.3 — deterministic strategy completeness top-up (v2, surgical).

This module ensures STRATEGY documents deterministically meet their minimum
completeness thresholds *before* the post-repair quality gate and the save /
export-freeze decision run.  v2 is a document-preserving completion pass:
it patches only the incomplete section bodies and never rebuilds the whole
document from a section-order join (that rebuild dropped H2 wrappers and
broke live KPI PDF extractability / frozen export lock).

Guarantees (strategy documents only):
  * strategic objectives        >= ``STRATEGY_TOPUP_MIN_OBJECTIVES``
  * strategic pillars           >= ``STRATEGY_TOPUP_MIN_PILLARS``
  * confidence/risk table rows  >= ``STRATEGY_TOPUP_MIN_RISK_ROWS``
  * KPI main section/header     unchanged unless this module is asked to
    repair KPI (it never is)

Design constraints (hard):
  * Runs ONLY for ``document_type == 'strategy'``.  Never for ``risk`` or
    ``gap_assessment`` (ERM risk + global gap are explicitly excluded).
  * Preserves existing valid content; adds only the missing rows / pillars.
  * Never duplicates an existing pillar title or risk factor.
  * Uses domain-specific deterministic substance drawn from the REL3.3 domain
    registries (data / ai / dt / global) or the module-local cyber catalog.
    A domain never receives another domain's substance (no cross-domain
    contamination); cyber substance (CISO/SOC/SIEM/CSIRT/…) is only ever added
    to the ``cyber`` route.
  * Fails closed with ``rel33_strategy_completeness_topup_failed:<section>``
    when it cannot safely complete a section.  It NEVER fabricates placeholder
    rows and NEVER mutates a section it cannot legitimately complete, so the
    downstream strict quality gate still blocks malformed output.

The thresholds mirror the binding runtime gates in ``app.py``:
  * ``_RICHNESS_MIN_PILLARS`` (3) — the ``_final_strategy_audit`` pillar floor.
  * The post-repair assertion floor of 6 for the confidence/risk table.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

# ── Binding minimums (kept in sync with app.py runtime gates) ────────────────
STRATEGY_TOPUP_MIN_OBJECTIVES = 4
# Post-repair assertion in app.py still requires >= 6 valid SO rows.
STRATEGY_TOPUP_TARGET_OBJECTIVES = 6
STRATEGY_TOPUP_MIN_PILLARS = 3
STRATEGY_TOPUP_MIN_RISK_ROWS = 6

_KPI_PRESERVE_KEYS = (
    'kpis', 'roadmap', 'gaps', 'environment', 'governance',
    'traceability', 'kri',
)

# ── Placeholder tokens (mirror app._TS_PLACEHOLDER_TOKENS) ───────────────────
_PLACEHOLDER_TOKENS = (
    '—', '-', 'TBD', 'To be defined', 'To be determined',
    'يُحدد لاحقاً', 'يحدد لاحقا', 'يحدد لاحقاً', 'TBA',
    'placeholder', '[insert', 'add here',
)

# ── Regexes (mirror the counters used by the audit / post-repair assertions) ─
_RISK_HDR_RE = re.compile(
    r'^\|\s*#\s*\|\s*(?:Risk|المخاطر|الخطر)\s*\|', re.IGNORECASE)
_SEP_ROW_RE = re.compile(r'^\|[\s\-:|]+\|$')
_PILLAR_HEADING_RE = re.compile(
    r'^###\s+(?:Pillar\s*\d*|Strategic\s+Pillar\s*\d*|'
    r'الركيزة(?:\s+الاستراتيجية)?\s*\d*)[^\n]*',
    re.MULTILINE | re.IGNORECASE,
)
_ANY_H3_RE = re.compile(r'^###[^#\n][^\n]*$', re.MULTILINE)
_PILLAR_INIT_HDR_TOKENS = re.compile(
    r'(?:Initiative|Description|Deliverable|Output|Expected|'
    r'المبادرة|الوصف|المخرج|المتوقع)',
    re.IGNORECASE,
)
_OBJ_HDR_RE = re.compile(
    r'^\|\s*#\s*\|\s*(?:Objective|الهدف(?:\s+الاستراتيجي)?|الأهداف)\s*\|',
    re.IGNORECASE,
)
_OBJ_TF_RE = re.compile(
    r'\d{1,6}\s*(?:months?|years?|weeks?|days?'
    r'|أشهر|شهر|شهراً|سنوات|سنة|أسابيع|أسبوع|أيام|يوم)'
    r'|(?:within|خلال)\s+\d{1,6}'
    r'|(?:within|خلال)\s+(?:months?|years?|weeks?|days?'
    r'|أشهر|شهر|شهراً|سنوات|سنة|أسابيع|أسبوع|أيام|يوم)',
    re.IGNORECASE,
)
_CANONICAL_H2 = {
    'vision': 'الرؤية والأهداف الاستراتيجية',
    'pillars': 'الركائز الاستراتيجية',
    'environment': 'البيئة التنظيمية والتهديدات',
    'gaps': 'تحليل الفجوات',
    'roadmap': 'خارطة الطريق التنفيذية',
    'kpis': 'مؤشرات الأداء الرئيسية',
    'confidence': 'تقييم الثقة والمخاطر',
    'governance': 'نموذج الحوكمة والمسؤوليات',
    'traceability': 'مصفوفة تتبع الأطر المرجعية',
}

# Cyber-primary substance markers that must never leak into data/ai/dt/global
# top-up content.  Used only as a defensive self-check on ADDED content.
_CYBER_PRIMARY_MARKERS = (
    'ciso', 'soc', 'siem', 'csirt', 'iam', 'pam', 'mfa',
    'الأمن السيبراني', 'العمليات الأمنية', 'الاستجابة للحوادث',
)


# ════════════════════════════════════════════════════════════════════════════
# Deterministic cyber catalog (module-local; data/ai/dt/global reuse the
# REL3.3 domain-substance registries).  Cyber pillar / risk substance is only
# ever selected when the route domain is cyber.
# ════════════════════════════════════════════════════════════════════════════

# (pillar_title, pillar_description, ((init, description, output, owner), ...))
_CYBER_PILLARS: Tuple[Tuple[str, str, Tuple[Tuple[str, str, str, str], ...]], ...] = (
    ('المرونة السيبرانية واستمرارية الأعمال',
     'ترسي هذه الركيزة قدرة المؤسسة على الصمود والتعافي أمام الحوادث '
     'السيبرانية عبر خطط استمرارية مختبرة ونسخ احتياطي معزول واختبارات '
     'تعافٍ دورية بنتائج موثقة.',
     (('خطط الاستمرارية السيبرانية',
       'اعتماد خطط استمرارية وتعافٍ للأنظمة الحرجة واختبارها دورياً وفق NCA ECC',
       'خطط استمرارية معتمدة ومختبرة للأنظمة الحرجة',
       'رئيس الأمن السيبراني (CISO)'),
      ('النسخ الاحتياطي المعزول',
       'تطبيق نسخ احتياطي معزول وقابل للاسترجاع مع اختبارات استعادة موثقة',
       'سجل نسخ احتياطي معزول مع نتائج استعادة',
       'مدير عمليات الأمن السيبراني'),
      ('اختبارات التعافي',
       'تنفيذ تمارين محاكاة الحوادث واختبارات التعافي بشكل دوري وتوثيق الدروس',
       'تقارير تمارين تعافٍ دورية معتمدة',
       'رئيس الأمن السيبراني (CISO)'))),
    ('نضج الهوية وإدارة الضوابط',
     'ترفع هذه الركيزة نضج ضوابط الأمن السيبراني وإدارة الهوية والوصول '
     'والصلاحيات المميزة، بما يقلل سطح الهجوم ويعزز الالتزام بالضوابط '
     'الأساسية.',
     (('إدارة الهوية والوصول',
       'تطبيق إدارة الهوية والوصول والصلاحيات المميزة والمصادقة متعددة العوامل',
       'منظومة IAM/PAM تشغيلية بتغطية الأنظمة الحرجة',
       'مدير إدارة الهوية والوصول'),
      ('تصلّب الأنظمة',
       'اعتماد معايير تصلّب الأنظمة والتهيئة الآمنة ومراجعتها دورياً',
       'معايير تصلّب معتمدة مطبقة على الأصول الحرجة',
       'رئيس الأمن السيبراني (CISO)'),
      ('إدارة الثغرات',
       'تشغيل دورة إدارة الثغرات بالفحص الدوري والمعالجة ضمن مهل معتمدة',
       'لوحة إدارة ثغرات مع مؤشرات معالجة',
       'مدير عمليات الأمن السيبراني'))),
    ('الكشف والاستجابة للحوادث',
     'تعزز هذه الركيزة قدرات الكشف المبكر والاستجابة للحوادث السيبرانية عبر '
     'مركز عمليات أمنية وقدرات مراقبة مستمرة وخطط استجابة مختبرة.',
     (('المراقبة المستمرة',
       'تشغيل قدرات المراقبة المستمرة وربط الأحداث لرصد التهديدات مبكراً',
       'تغطية مراقبة مستمرة للأصول الحرجة',
       'مدير مركز العمليات الأمنية'),
      ('الاستجابة للحوادث',
       'اعتماد خطط الاستجابة للحوادث السيبرانية واختبارها وتوثيق نتائجها',
       'خطة استجابة للحوادث معتمدة ومختبرة',
       'قائد الاستجابة للحوادث'),
      ('التصعيد والإبلاغ',
       'تعريف مسارات التصعيد والإبلاغ التنظيمي ضمن مهل الالتزام المعتمدة',
       'مصفوفة تصعيد وإبلاغ معتمدة',
       'رئيس الأمن السيبراني (CISO)'))),
    ('ضمان الامتثال والحوكمة السيبرانية',
     'تضمن هذه الركيزة الالتزام بالضوابط والمتطلبات التنظيمية للأمن السيبراني '
     'عبر حوكمة واضحة ومراجعات امتثال دورية وتقارير موثقة للإدارة العليا.',
     (('حوكمة الأمن السيبراني',
       'اعتماد إطار حوكمة الأمن السيبراني والأدوار والمسؤوليات وفق NCA ECC',
       'إطار حوكمة سيبرانية معتمد مع أدوار واضحة',
       'رئيس الأمن السيبراني (CISO)'),
      ('مراجعات الامتثال',
       'تنفيذ مراجعات امتثال دورية للضوابط الأساسية ومعالجة الملاحظات الموثقة',
       'تقارير امتثال ربع سنوية معتمدة',
       'مدير الامتثال السيبراني'),
      ('تقارير المخاطر السيبرانية',
       'رفع تقارير المخاطر ومؤشرات الأداء الأمني الدورية للإدارة العليا',
       'لوحة مؤشرات مخاطر سيبرانية دورية',
       'رئيس الأمن السيبراني (CISO)'))),
)

# (risk, likelihood, impact, theme, owner, treatment)
_CYBER_RISK_ROWS: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ('تصاعد التهديدات السيبرانية المتقدمة', 'متوسط', 'عالٍ', 'incident_response',
     'رئيس الأمن السيبراني (CISO)',
     'تعزيز قدرات الكشف والمراقبة المستمرة مع خطط استجابة مختبرة ومراجعة دورية موثقة'),
    ('ضعف نضج الضوابط الأساسية', 'متوسط', 'عالٍ', 'capabilities',
     'مدير عمليات الأمن السيبراني',
     'تقييم نضج دوري وخطة رفع للضوابط الأساسية مع متابعة شهرية موثقة للتقدم'),
    ('مخاطر إدارة الهوية والصلاحيات المميزة', 'متوسط', 'عالٍ', 'data_protection',
     'مدير إدارة الهوية والوصول',
     'تطبيق أقل امتياز ومراجعة صلاحيات دورية ومصادقة متعددة العوامل للأنظمة الحرجة'),
    ('اعتماد على موردي الأمن السيبراني', 'متوسط', 'متوسط', 'third_party',
     'مدير الامتثال السيبراني',
     'تقييم موردي الأمن دورياً مع بدائل موثقة وشروط تعاقدية تحفظ متطلبات الأمن'),
    ('نقص الكفاءات السيبرانية', 'منخفض', 'متوسط', 'resource_capacity',
     'رئيس الأمن السيبراني (CISO)',
     'خطة موارد وكفاءات معتمدة لفريق الأمن مع تدريب متخصص وسد الفجوات تدريجياً'),
    ('ضعف الوعي الأمني المؤسسي', 'متوسط', 'متوسط', 'awareness',
     'مدير الامتثال السيبراني',
     'برنامج توعية أمني مستمر مع تمارين تصيّد محاكاة وقياس أثر التوعية دورياً'),
)


# ════════════════════════════════════════════════════════════════════════════
# Public entrypoints
# ════════════════════════════════════════════════════════════════════════════

def is_strategy_completeness_topup_applicable(document_type: Any) -> bool:
    """Only strategy documents receive the completeness top-up.

    ERM risk (``risk``) and global gap (``gap_assessment``) are excluded.
    """
    dt = str(document_type or '').strip().lower()
    dt = {
        'strategy document': 'strategy',
    }.get(dt, dt)
    return dt == 'strategy'


def _normalize_domain(domain: Any) -> str:
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        return normalize_domain_code(str(domain or ''), default='')
    except Exception:  # noqa: BLE001 — defensive
        return str(domain or '').strip().lower()


def _new_diag(route: str, domain: str, document_type: str, lang: str,
              stage: str) -> Dict[str, Any]:
    return {
        'diag': 'REL33-STRATEGY-COMPLETENESS-TOPUP',
        'route': route,
        'domain': domain,
        'document_type': document_type,
        'artifact_type': 'strategy',
        'language': lang,
        'generation_stage': stage,
        'objectives_before': None,
        'objectives_after': None,
        'objectives_added': 0,
        'pillars_before': None,
        'pillars_after': None,
        'pillars_added': 0,
        'confidence_risk_rows_before': None,
        'confidence_risk_rows_after': None,
        'confidence_risk_rows_added': 0,
        'sections_touched': [],
        'domain_profile': '',
        'contamination_check_passed': True,
        'quality_gate_minimums_met': False,
        'kpi_preserved': True,
        'final_quality_gate_inputs': {},
        'final_quality_gate_passed': False,
        'pdf_kpi_extractability_precheck_passed': None,
        'frozen_export_lock_ready': None,
        'topup_applied': False,
        'blocking_errors': [],
        'passed': True,
    }


def apply_strategy_completeness_topup(
        sections: Dict[str, Any],
        *,
        domain: Any,
        document_type: Any = 'strategy',
        lang: str = 'ar',
        synth_status: Optional[Dict[str, Any]] = None,
        generation_stage: str = 'post_repair',
        route: str = '',
        emit: bool = True,
) -> Dict[str, Any]:
    """Deterministically top up strategy objectives / pillars / risk rows.

    Mutates only the incomplete section bodies in ``sections``.  Never
    rebuilds the whole document.  Returns the
    ``[REL33-STRATEGY-COMPLETENESS-TOPUP]`` diagnostic dict.
    """
    dcode = _normalize_domain(domain)
    diag = _new_diag(route, dcode, str(document_type or 'strategy').lower(),
                     lang, generation_stage)
    kpi_before = sections.get('kpis', '') if isinstance(sections, dict) else ''
    preserve_before = _snapshot_preserve_sections(sections)

    if not is_strategy_completeness_topup_applicable(document_type):
        diag['generation_stage'] = 'skipped_non_strategy'
        _fill_counts(sections if isinstance(sections, dict) else {}, diag)
        _finalize_gate_inputs(diag)
        _emit(diag, emit)
        return diag

    if not isinstance(sections, dict):
        diag['blocking_errors'].append(
            'rel33_strategy_completeness_topup_failed:invalid_sections')
        diag['passed'] = False
        _finalize_gate_inputs(diag)
        _emit(diag, emit)
        return diag

    profile = _resolve_domain_profile(dcode)
    if profile is None:
        # Unknown/unsupported domain — cannot safely synthesize domain
        # substance.  Fail closed; do NOT touch the sections.
        _fill_counts(sections, diag)
        need = (
            (diag['objectives_before'] or 0) < STRATEGY_TOPUP_MIN_OBJECTIVES
            or (diag['pillars_before'] or 0) < STRATEGY_TOPUP_MIN_PILLARS
            or (diag['confidence_risk_rows_before'] or 0)
            < STRATEGY_TOPUP_MIN_RISK_ROWS)
        if need:
            diag['blocking_errors'].append(
                'rel33_strategy_completeness_topup_failed:unsupported_domain')
            diag['passed'] = False
        _finalize_gate_inputs(diag)
        _emit(diag, emit)
        return diag

    diag['domain_profile'] = profile['name']

    obj_changed = _topup_objectives(sections, profile, lang, diag)
    pillars_changed = _topup_pillars(sections, profile, lang, diag)
    conf_changed = _topup_confidence_risk(sections, profile, lang, diag)

    diag['topup_applied'] = bool(obj_changed or pillars_changed or conf_changed)

    # Contamination self-check on ADDED substance for non-cyber domains.
    if dcode != 'cyber' and diag['topup_applied']:
        diag['contamination_check_passed'] = _added_content_domain_clean(
            sections, diag)
        if not diag['contamination_check_passed']:
            diag['blocking_errors'].append(
                'rel33_strategy_completeness_topup_failed:contamination')

    pres = evaluate_kpi_preservation(
        {'kpis': kpi_before}, sections, route=route, domain=dcode,
        document_type=str(document_type or 'strategy'),
        topup_applied=diag['topup_applied'],
        sections_touched=list(diag['sections_touched']),
        diag=diag, emit=emit)
    if not pres.get('kpi_section_preserved') or not pres.get('kpi_header_preserved'):
        diag['blocking_errors'].append(
            'rel33_strategy_topup_kpi_preservation_failed')
        diag['kpi_preserved'] = False
        _restore_preserve_sections(sections, preserve_before)
    else:
        if not _unrelated_sections_preserved(preserve_before, sections,
                                             diag['sections_touched']):
            diag['blocking_errors'].append(
                'rel33_strategy_topup_unrelated_section_mutated')
            _restore_preserve_sections(sections, preserve_before)

    diag['quality_gate_minimums_met'] = (
        (diag['objectives_after'] or 0) >= STRATEGY_TOPUP_MIN_OBJECTIVES
        and (diag['pillars_after'] or 0) >= STRATEGY_TOPUP_MIN_PILLARS
        and (diag['confidence_risk_rows_after'] or 0)
        >= STRATEGY_TOPUP_MIN_RISK_ROWS
    )
    _finalize_gate_inputs(diag)
    diag['passed'] = (
        not diag['blocking_errors'] and diag['quality_gate_minimums_met'])
    diag['final_quality_gate_passed'] = diag['passed']
    diag['frozen_export_lock_ready'] = bool(
        diag['passed'] and diag.get('kpi_preserved'))

    # Clear stale synth_status markers for sections genuinely completed, so
    # the post-normalization audit does not block on an already-repaired
    # section.  The audit still independently re-validates the content.
    if (synth_status is not None and isinstance(synth_status, dict)
            and not diag['blocking_errors']):
        if ('vision' in diag['sections_touched']
                and (diag['objectives_after'] or 0)
                >= STRATEGY_TOPUP_MIN_OBJECTIVES):
            synth_status.pop('vision', None)
        if ('pillars' in diag['sections_touched']
                and (diag['pillars_after'] or 0) >= STRATEGY_TOPUP_MIN_PILLARS):
            synth_status.pop('pillars', None)
        if ('confidence' in diag['sections_touched']
                and (diag['confidence_risk_rows_after'] or 0)
                >= STRATEGY_TOPUP_MIN_RISK_ROWS):
            synth_status.pop('confidence', None)

    _emit(diag, emit)
    return diag


# ════════════════════════════════════════════════════════════════════════════
# Domain profile resolution
# ════════════════════════════════════════════════════════════════════════════

def _resolve_domain_profile(dcode: str) -> Optional[Dict[str, Any]]:
    objectives = _resolve_objective_catalog(dcode)
    if dcode == 'cyber':
        return {
            'name': 'cyber',
            'pillars': _CYBER_PILLARS,
            'risk_rows': _CYBER_RISK_ROWS,
            'objectives': objectives,
        }
    if dcode in ('data', 'ai', 'dt', 'global'):
        try:
            from release_engine_v3.rel32_registries import (
                resolve_confidence_risk_rows,
                resolve_pillar_catalog,
            )
            pillars = resolve_pillar_catalog(dcode)
            risk_rows = resolve_confidence_risk_rows(dcode)
        except Exception:  # noqa: BLE001 — registries unavailable
            return None
        if not pillars or not risk_rows:
            return None
        return {
            'name': dcode,
            'pillars': pillars,
            'risk_rows': risk_rows,
            'objectives': objectives,
        }
    return None


def _resolve_objective_catalog(dcode: str) -> Tuple[Tuple[str, str, str, str], ...]:
    try:
        from release_engine_v3.rel32_registries import (
            resolve_strategic_objective_registry,
        )
        raw = resolve_strategic_objective_registry(dcode) or {}
    except Exception:  # noqa: BLE001
        raw = {}
    out: List[Tuple[str, str, str, str]] = []
    for _fam, cells in raw.items():
        if not cells or len(cells) < 4:
            continue
        out.append((str(cells[0]), str(cells[1]), str(cells[2]), str(cells[3])))
    return tuple(out)


# ════════════════════════════════════════════════════════════════════════════
# Strategic objectives top-up
# ════════════════════════════════════════════════════════════════════════════

def _topup_objectives(sections: Dict[str, Any], profile: Dict[str, Any],
                      lang: str, diag: Dict[str, Any]) -> bool:
    text = sections.get('vision', '') or ''
    before = _count_valid_objective_rows(text)
    diag['objectives_before'] = before
    diag['objectives_after'] = before
    target = max(STRATEGY_TOPUP_MIN_OBJECTIVES, STRATEGY_TOPUP_TARGET_OBJECTIVES)
    if before >= target:
        return False

    catalog = profile.get('objectives') or ()
    existing = _existing_objective_names(text)
    to_add: List[Tuple[str, str, str, str]] = []
    for obj, metric, just, tf in catalog:
        if before + len(to_add) >= target:
            break
        if _norm_key(obj) in existing:
            continue
        if any(_is_placeholder(x) for x in (obj, metric, just, tf)):
            continue
        if not _OBJ_TF_RE.search(tf or ''):
            continue
        to_add.append((obj, metric, just, tf))

    if before + len(to_add) < STRATEGY_TOPUP_MIN_OBJECTIVES:
        diag['blocking_errors'].append(
            'rel33_strategy_completeness_topup_failed:objectives')
        return False

    if _has_objective_table(text):
        new_text = _append_objective_rows(text, to_add)
        if new_text is None:
            diag['blocking_errors'].append(
                'rel33_strategy_completeness_topup_failed:objectives_insert')
            return False
    else:
        new_text = _render_objectives_table(to_add, existing_text=text)

    sections['vision'] = new_text
    diag['objectives_added'] = len(to_add)
    diag['objectives_after'] = _count_valid_objective_rows(new_text)
    if 'vision' not in diag['sections_touched']:
        diag['sections_touched'].append('vision')
    return True


def _has_objective_table(vision_text: str) -> bool:
    if not vision_text:
        return False
    for ln in vision_text.split('\n'):
        if _OBJ_HDR_RE.match(ln.strip()):
            return True
    return False


def _existing_objective_names(vision_text: str) -> set:
    names = set()
    for cells in _iter_table_rows(vision_text, _OBJ_HDR_RE):
        if len(cells) >= 2 and cells[0].replace('.', '').isdigit():
            names.add(_norm_key(cells[1]))
    return names


def _append_objective_rows(
        vision_text: str,
        rows: List[Tuple[str, str, str, str]],
) -> Optional[str]:
    lines = vision_text.split('\n')
    hdr_idx = -1
    for i, ln in enumerate(lines):
        if _OBJ_HDR_RE.match(ln.strip()):
            hdr_idx = i
            break
    if hdr_idx < 0:
        return None
    last_data_idx = hdr_idx
    data_count = 0
    j = hdr_idx + 1
    while j < len(lines):
        s = lines[j].strip()
        if not s:
            k = j + 1
            while k < len(lines) and not lines[k].strip():
                k += 1
            if k < len(lines) and lines[k].strip().startswith('|') \
                    and lines[k].strip().endswith('|'):
                j = k
                continue
            break
        if not (s.startswith('|') and s.endswith('|')):
            break
        if _SEP_ROW_RE.match(s):
            last_data_idx = j
            j += 1
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        if cells and cells[0].replace('.', '').isdigit():
            data_count += 1
        last_data_idx = j
        j += 1
    new_row_lines = []
    for offset, (obj, metric, just, tf) in enumerate(rows, 1):
        n = data_count + offset
        new_row_lines.append(
            f'| {n} | {obj} | {metric} | {just} | {tf} |')
    out = lines[:last_data_idx + 1] + new_row_lines + lines[last_data_idx + 1:]
    return '\n'.join(out)


def _render_objectives_table(
        rows: List[Tuple[str, str, str, str]],
        *,
        existing_text: str = '',
) -> str:
    lines = [
        '### الأهداف الاستراتيجية',
        '',
        '| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |',
        '|---|---|---|---|---|',
    ]
    for i, (obj, metric, just, tf) in enumerate(rows, 1):
        lines.append(f'| {i} | {obj} | {metric} | {just} | {tf} |')
    block = '\n'.join(lines) + '\n'
    if (existing_text or '').strip():
        return existing_text.rstrip() + '\n\n' + block
    return block


def _count_valid_objective_rows(vision_text: str) -> int:
    """Mirror app.count_valid_objective_rows."""
    if not vision_text:
        return 0
    n = 0
    for cells in _iter_table_rows(vision_text, _OBJ_HDR_RE):
        if len(cells) != 5:
            continue
        if not cells[0].replace('.', '').isdigit():
            continue
        if any(_is_placeholder(cells[i]) for i in (1, 2, 3)):
            continue
        if not _OBJ_TF_RE.search(cells[4] or ''):
            continue
        if _OBJ_TF_RE.search(cells[1] or ''):
            continue
        n += 1
    return n


# ════════════════════════════════════════════════════════════════════════════
# Pillars top-up
# ════════════════════════════════════════════════════════════════════════════

def _topup_pillars(sections: Dict[str, Any], profile: Dict[str, Any],
                   lang: str, diag: Dict[str, Any]) -> bool:
    text = sections.get('pillars', '') or ''
    before = _count_substantive_pillars(text)
    diag['pillars_before'] = before
    diag['pillars_after'] = before
    if before >= STRATEGY_TOPUP_MIN_PILLARS:
        return False

    existing_titles = {
        _norm_key(t) for t, _b in _extract_pillar_blocks(text)
    }
    existing_count = len(_extract_pillar_blocks(text))
    blocks: List[str] = []
    added = 0
    idx = existing_count
    for entry in profile['pillars']:
        if before + added >= STRATEGY_TOPUP_MIN_PILLARS:
            break
        title, desc, inits = entry[0], entry[1], entry[2]
        if _norm_key(title) in existing_titles:
            continue
        idx += 1
        added += 1
        blocks.append(_render_pillar_block(idx, title, desc, inits))

    if before + added < STRATEGY_TOPUP_MIN_PILLARS:
        diag['blocking_errors'].append(
            'rel33_strategy_completeness_topup_failed:pillars')
        return False

    if text.strip():
        new_text = text.rstrip() + '\n\n' + '\n\n'.join(blocks) + '\n'
    else:
        new_text = '\n\n'.join(blocks) + '\n'
    sections['pillars'] = new_text
    diag['pillars_added'] = added
    diag['pillars_after'] = _count_substantive_pillars(new_text)
    if 'pillars' not in diag['sections_touched']:
        diag['sections_touched'].append('pillars')
    return True


def _render_pillar_block(idx: int, title: str, desc: str,
                         inits: Tuple[Tuple[str, str, str, str], ...]) -> str:
    lines = [f'### الركيزة الاستراتيجية {idx}: {title}', '', desc, '',
             '| # | المبادرة | الوصف | المخرج | المالك |',
             '|---|---|---|---|---|']
    for i, init in enumerate(inits, 1):
        init_title, description, output, owner = (
            init[0], init[1], init[2], init[3])
        lines.append(
            f'| {i} | {init_title} | {description} | {output} | {owner} |')
    return '\n'.join(lines)


# ════════════════════════════════════════════════════════════════════════════
# Confidence / risk rows top-up
# ════════════════════════════════════════════════════════════════════════════

def _topup_confidence_risk(sections: Dict[str, Any], profile: Dict[str, Any],
                           lang: str, diag: Dict[str, Any]) -> bool:
    conf = sections.get('confidence', '') or ''
    before = _count_risk_rows_with_mitigation(conf)
    diag['confidence_risk_rows_before'] = before
    diag['confidence_risk_rows_after'] = before
    if before >= STRATEGY_TOPUP_MIN_RISK_ROWS:
        return False

    # Only append into an EXISTING risk table so surrounding confidence prose
    # (Confidence Score line, CSF subsection) is preserved untouched.  If no
    # risk table exists, fail closed rather than fabricate section structure.
    if not _has_risk_table(conf):
        diag['blocking_errors'].append(
            'rel33_strategy_completeness_topup_failed:confidence_risk_no_table')
        return False

    existing_names = _existing_risk_names(conf)
    to_add: List[Tuple[str, str, str, str, str]] = []
    for row in profile['risk_rows']:
        if before + len(to_add) >= STRATEGY_TOPUP_MIN_RISK_ROWS:
            break
        risk, lik, imp, _theme, owner, treat = (
            row[0], row[1], row[2], row[3], row[4], row[5])
        if _norm_key(risk) in existing_names:
            continue
        to_add.append((risk, lik, imp, treat, owner))

    if before + len(to_add) < STRATEGY_TOPUP_MIN_RISK_ROWS:
        diag['blocking_errors'].append(
            'rel33_strategy_completeness_topup_failed:confidence_risk')
        return False

    new_conf = _append_risk_rows(conf, to_add)
    if new_conf is None:
        diag['blocking_errors'].append(
            'rel33_strategy_completeness_topup_failed:confidence_risk_insert')
        return False

    sections['confidence'] = new_conf
    diag['confidence_risk_rows_added'] = len(to_add)
    diag['confidence_risk_rows_after'] = _count_risk_rows_with_mitigation(
        new_conf)
    if 'confidence' not in diag['sections_touched']:
        diag['sections_touched'].append('confidence')
    return True


def _has_risk_table(conf_text: str) -> bool:
    if not conf_text:
        return False
    for ln in conf_text.split('\n'):
        if _RISK_HDR_RE.match(ln.strip()):
            return True
    return False


def _existing_risk_names(conf_text: str) -> set:
    names = set()
    for cells in _iter_table_rows(conf_text, _RISK_HDR_RE):
        if len(cells) >= 2 and cells[0].replace('.', '').isdigit():
            names.add(_norm_key(cells[1]))
    return names


def _append_risk_rows(conf_text: str,
                      rows: List[Tuple[str, str, str, str, str]]
                      ) -> Optional[str]:
    """Insert new ``| # | risk | lik | imp | treat | owner |`` rows directly
    after the last data row of the existing Key-Risks table.  Returns the new
    confidence text, or ``None`` when the table cannot be located safely.
    """
    lines = conf_text.split('\n')
    hdr_idx = -1
    for i, ln in enumerate(lines):
        if _RISK_HDR_RE.match(ln.strip()):
            hdr_idx = i
            break
    if hdr_idx < 0:
        return None

    # Walk the table body: separator + data rows, blank lines tolerated
    # between rows.  Track the index of the last real data row and the number
    # of existing data rows (for continuation numbering).
    last_data_idx = hdr_idx
    data_count = 0
    j = hdr_idx + 1
    while j < len(lines):
        s = lines[j].strip()
        if not s:
            # blank line: peek ahead — table continues only if the next
            # non-blank line is still a pipe row.
            k = j + 1
            while k < len(lines) and not lines[k].strip():
                k += 1
            if k < len(lines) and lines[k].strip().startswith('|') \
                    and lines[k].strip().endswith('|'):
                j = k
                continue
            break
        if not (s.startswith('|') and s.endswith('|')):
            break
        if _SEP_ROW_RE.match(s):
            last_data_idx = j
            j += 1
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        if cells and cells[0].replace('.', '').isdigit():
            data_count += 1
        last_data_idx = j
        j += 1

    new_row_lines = []
    for offset, (risk, lik, imp, treat, owner) in enumerate(rows, 1):
        n = data_count + offset
        new_row_lines.append(
            f'| {n} | {risk} | {lik} | {imp} | {treat} | {owner} |')

    out = lines[:last_data_idx + 1] + new_row_lines + lines[last_data_idx + 1:]
    return '\n'.join(out)


# ════════════════════════════════════════════════════════════════════════════
# Counters (mirror app.py gate helpers exactly)
# ════════════════════════════════════════════════════════════════════════════

def _is_placeholder(cell: Optional[str]) -> bool:
    if cell is None:
        return True
    s = (cell or '').strip().strip('*').strip()
    if not s:
        return True
    s_low = s.lower()
    for t in _PLACEHOLDER_TOKENS:
        if s == t or s_low == t.lower():
            return True
    return False


def _iter_table_rows(text: str, header_re: "re.Pattern"):
    """Yield data-row cell-lists for the table whose header matches
    ``header_re``.  Mirrors app._ts_table_rows (blank lines tolerated).
    """
    if not text:
        return
    in_tbl = False
    for ln in text.split('\n'):
        s = ln.strip()
        if not in_tbl:
            if header_re.match(s):
                in_tbl = True
            continue
        if not s.startswith('|') or not s.endswith('|'):
            if not s:
                continue
            in_tbl = False
            continue
        if _SEP_ROW_RE.match(s):
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        yield cells


def _count_risk_rows_with_mitigation(conf_text: str) -> int:
    """Mirror app._count_risk_rows_with_mitigation."""
    if not conf_text:
        return 0
    n = 0
    for cells in _iter_table_rows(conf_text, _RISK_HDR_RE):
        if len(cells) < 5:
            continue
        if not cells[0].replace('.', '').isdigit():
            continue
        if any(_is_placeholder(cells[i]) for i in (1, 2, 3, 4)):
            continue
        n += 1
    return n


def _extract_pillar_blocks(pillars_text: str) -> List[Tuple[str, str]]:
    """Return (title, body) tuples for each pillar heading.  Mirrors the
    audit's heading discovery (canonical pillar regex, widened to any ###
    heading when that finds more headings).
    """
    if not pillars_text:
        return []
    matches = list(_PILLAR_HEADING_RE.finditer(pillars_text))
    all_h3 = list(_ANY_H3_RE.finditer(pillars_text))
    if len(all_h3) > len(matches):
        matches = all_h3
    out: List[Tuple[str, str]] = []
    for i, m in enumerate(matches):
        title = re.sub(r'^###\s+', '', pillars_text[m.start():m.end()]).strip()
        bs = m.end()
        be = matches[i + 1].start() if i + 1 < len(matches) else len(
            pillars_text)
        out.append((title, pillars_text[bs:be]))
    return out


def _pillar_has_substantive_initiative(body: str) -> bool:
    """Mirror app._pillar_has_substantive_initiative."""
    if not body or not body.strip():
        return False
    in_table = False
    for ln in body.splitlines():
        s = ln.strip()
        if not (s.startswith('|') and s.endswith('|')):
            in_table = False
            continue
        if _SEP_ROW_RE.match(s):
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        hdr_hits = sum(1 for c in cells if _PILLAR_INIT_HDR_TOKENS.search(c or ''))
        if hdr_hits >= 2 and not in_table:
            in_table = True
            continue
        if not in_table:
            continue
        if len(cells) < 2:
            continue
        data = (cells[1:] if cells and cells[0].replace('.', '').isdigit()
                else cells[:])
        if data and sum(1 for c in data if c and not _is_placeholder(c)) >= 2:
            return True
    return False


def _count_substantive_pillars(pillars_text: str) -> int:
    """Mirror the audit's pillar count (substantive-initiative gate)."""
    n = 0
    for _title, body in _extract_pillar_blocks(pillars_text):
        if _pillar_has_substantive_initiative(body):
            n += 1
    return n


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

def _norm_key(s: Any) -> str:
    return re.sub(r'\s+', ' ', str(s or '')).strip().lower()


def _section_hash(text: Any) -> str:
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()


def _kpi_header_cells(text: Any) -> List[str]:
    blob = str(text or '')
    try:
        from release_engine_v3.rel32_kpi_main_schema_evidence import (
            extract_kpi_main_header_labels_from_text,
        )
        hdr = extract_kpi_main_header_labels_from_text(blob)
        if hdr:
            return list(hdr)
    except Exception:  # noqa: BLE001
        pass
    expected = ['#', 'وصف المؤشر', 'النوع', 'القيمة المستهدفة',
                'صيغة الاحتساب', 'مصدر', 'التكرار', 'المالك']
    for ln in blob.splitlines():
        s = ln.strip()
        if not (s.startswith('|') and s.endswith('|')):
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        if cells[:len(expected)] == expected:
            return cells
        if 'وصف المؤشر' in s and '#' in cells[:1]:
            return cells
    return []


def _snapshot_preserve_sections(sections: Any) -> Dict[str, str]:
    if not isinstance(sections, dict):
        return {}
    snap = {}
    for k, v in sections.items():
        if isinstance(v, str):
            snap[k] = v
    return snap


def _restore_preserve_sections(sections: Dict[str, Any],
                               snap: Dict[str, str]) -> None:
    for k, v in snap.items():
        sections[k] = v


def _unrelated_sections_preserved(
        before: Dict[str, str], after: Dict[str, Any],
        touched: List[str]) -> bool:
    touched_set = set(touched or [])
    for k, old in before.items():
        if k in touched_set:
            continue
        if (after.get(k) or '') != old:
            return False
    return True


def _fill_counts(sections: Dict[str, Any], diag: Dict[str, Any]) -> None:
    diag['objectives_before'] = _count_valid_objective_rows(
        sections.get('vision', '') or '')
    diag['objectives_after'] = diag['objectives_before']
    diag['pillars_before'] = _count_substantive_pillars(
        sections.get('pillars', '') or '')
    diag['pillars_after'] = diag['pillars_before']
    diag['confidence_risk_rows_before'] = _count_risk_rows_with_mitigation(
        sections.get('confidence', '') or '')
    diag['confidence_risk_rows_after'] = diag['confidence_risk_rows_before']


def _finalize_gate_inputs(diag: Dict[str, Any]) -> None:
    diag['final_quality_gate_inputs'] = {
        'objectives': diag.get('objectives_after'),
        'objectives_minimum': STRATEGY_TOPUP_MIN_OBJECTIVES,
        'pillars': diag.get('pillars_after'),
        'pillars_minimum': STRATEGY_TOPUP_MIN_PILLARS,
        'confidence_risk_rows': diag.get('confidence_risk_rows_after'),
        'confidence_risk_minimum': STRATEGY_TOPUP_MIN_RISK_ROWS,
    }
    try:
        from release_engine_v3.rel32_kpi_main_schema_evidence import (
            evaluate_kpi_main_schema_from_export_text,
        )
        # Precheck is informational; KPI body is not repaired here.
        diag['pdf_kpi_extractability_precheck_passed'] = None
    except Exception:  # noqa: BLE001
        diag['pdf_kpi_extractability_precheck_passed'] = None


def evaluate_kpi_preservation(
        before_sections: Dict[str, Any],
        after_sections: Dict[str, Any],
        *,
        route: str = '',
        domain: str = '',
        document_type: str = 'strategy',
        topup_applied: bool = False,
        sections_touched: Optional[List[str]] = None,
        diag: Optional[Dict[str, Any]] = None,
        emit: bool = True,
) -> Dict[str, Any]:
    kpi_before = before_sections.get('kpis', '') or ''
    kpi_after = after_sections.get('kpis', '') or ''
    hdr_before = _kpi_header_cells(kpi_before)
    hdr_after = _kpi_header_cells(kpi_after)
    hash_before = _section_hash(kpi_before)
    hash_after = _section_hash(kpi_after)
    section_preserved = hash_before == hash_after and kpi_before == kpi_after
    header_preserved = list(hdr_before) == list(hdr_after)
    blocking: List[str] = []
    if not section_preserved or not header_preserved:
        blocking.append('rel33_strategy_topup_kpi_preservation_failed')
    if diag is not None:
        diag['kpi_preserved'] = bool(section_preserved and header_preserved)
        try:
            from release_engine_v3.rel32_kpi_main_schema_evidence import (
                evaluate_kpi_main_schema_from_export_text,
            )
            pre = evaluate_kpi_main_schema_from_export_text(
                kpi_after, route_name='precheck')
            diag['pdf_kpi_extractability_precheck_passed'] = bool(
                pre.get('kpi_main_schema_passed')) if kpi_after.strip() else True
        except Exception:  # noqa: BLE001
            if kpi_after.strip() and hdr_after:
                diag['pdf_kpi_extractability_precheck_passed'] = True
    pres = {
        'diag': 'REL33-STRATEGY-TOPUP-PRESERVATION',
        'route': route,
        'domain': domain,
        'document_type': document_type,
        'topup_applied': topup_applied,
        'sections_touched': list(sections_touched or []),
        'objective_rows_before': (diag or {}).get('objectives_before'),
        'objective_rows_after': (diag or {}).get('objectives_after'),
        'pillars_before': (diag or {}).get('pillars_before'),
        'pillars_after': (diag or {}).get('pillars_after'),
        'confidence_risk_rows_before': (diag or {}).get(
            'confidence_risk_rows_before'),
        'confidence_risk_rows_after': (diag or {}).get(
            'confidence_risk_rows_after'),
        'kpi_section_hash_before': hash_before,
        'kpi_section_hash_after': hash_after,
        'kpi_section_preserved': section_preserved,
        'kpi_header_before': hdr_before,
        'kpi_header_after': hdr_after,
        'kpi_header_preserved': header_preserved,
        'frozen_lock_expected_refresh': bool(topup_applied),
        'blocking_errors': blocking,
        'passed': not blocking,
    }
    if emit:
        try:
            print('[REL33-STRATEGY-TOPUP-PRESERVATION] '
                  f"route={pres['route']!r} domain={pres['domain']!r} "
                  f"document_type={pres['document_type']!r} "
                  f"applied={pres['topup_applied']} "
                  f"touched={pres['sections_touched']} "
                  f"obj={pres['objective_rows_before']}->"
                  f"{pres['objective_rows_after']} "
                  f"pillars={pres['pillars_before']}->{pres['pillars_after']} "
                  f"risk={pres['confidence_risk_rows_before']}->"
                  f"{pres['confidence_risk_rows_after']} "
                  f"kpi_preserved={pres['kpi_section_preserved']} "
                  f"kpi_header_preserved={pres['kpi_header_preserved']} "
                  f"frozen_lock_expected_refresh="
                  f"{pres['frozen_lock_expected_refresh']} "
                  f"blockers={pres['blocking_errors']} "
                  f"passed={pres['passed']}",
                  flush=True)
        except Exception:  # noqa: BLE001
            pass
    return pres


def surgical_refresh_content(
        content: str,
        sections_before: Dict[str, Any],
        sections_after: Dict[str, Any],
        touched: List[str],
) -> str:
    """Replace only touched section bodies in ``content``. Never rebuild all."""
    out = content or ''
    for key in touched or []:
        old = sections_before.get(key) or ''
        new = sections_after.get(key) or ''
        if old == new:
            continue
        if (old or '').strip() and old in out:
            out = out.replace(old, new, 1)
            continue
        if (old or '').strip() and old.rstrip() in out:
            out = out.replace(old.rstrip(), new.rstrip(), 1)
            continue
        heading = _CANONICAL_H2.get(key)
        marker = f'## {heading}' if heading else ''
        if marker and marker in out and (new or '').strip():
            idx = out.find(marker)
            after = idx + len(marker)
            rest = out[after:]
            nxt = re.search(r'\n##\s+', rest)
            body = ('\n\n' + new.strip() + '\n') if (new or '').strip() else '\n'
            if nxt:
                out = out[:after] + body + rest[nxt.start():]
            else:
                out = out[:after] + body
            continue
        if (new or '').strip():
            suffix = (f'\n\n## {heading}\n\n{new.strip()}\n'
                      if heading else f'\n\n{new.strip()}\n')
            out = out.rstrip() + suffix
    return out


def run_strategy_topup_v2(
        sections: Dict[str, Any],
        *,
        content: str = '',
        domain: Any = '',
        document_type: Any = 'strategy',
        lang: str = 'ar',
        synth_status: Optional[Dict[str, Any]] = None,
        generation_stage: str = 'pre_completeness_gate',
        route: str = '',
        emit: bool = True,
) -> Dict[str, Any]:
    """Apply surgical top-up and refresh ``content`` without a full rebuild."""
    before = _snapshot_preserve_sections(sections)
    diag = apply_strategy_completeness_topup(
        sections,
        domain=domain,
        document_type=document_type,
        lang=lang,
        synth_status=synth_status,
        generation_stage=generation_stage,
        route=route,
        emit=emit,
    )
    fail_closed = (
        'rel33_strategy_topup_kpi_preservation_failed' in (
            diag.get('blocking_errors') or [])
    )
    new_content = content or ''
    if diag.get('topup_applied') and not fail_closed:
        new_content = surgical_refresh_content(
            content, before, sections, list(diag.get('sections_touched') or []))
    return {
        'diag': diag,
        'content': new_content,
        'fail_closed': fail_closed,
        'fail_closed_reason': (
            'rel33_strategy_topup_kpi_preservation_failed'
            if fail_closed else ''),
        'frozen_lock_expected_refresh': bool(diag.get('topup_applied')
                                             and not fail_closed),
    }


def _added_content_domain_clean(sections: Dict[str, Any],
                                diag: Dict[str, Any]) -> bool:
    """Defensive: ensure no cyber-primary markers were added to a non-cyber
    domain's topped-up sections.  Only inspects sections we touched.
    """
    for sec in diag.get('sections_touched', []):
        text = (sections.get(sec, '') or '').lower()
        for marker in _CYBER_PRIMARY_MARKERS:
            m = marker.lower()
            # word-ish boundary for latin acronyms to avoid false positives
            if m.isascii():
                if re.search(r'(?<![a-z])' + re.escape(m) + r'(?![a-z])', text):
                    return False
            elif m in text:
                return False
    return True


def _emit(diag: Dict[str, Any], emit: bool) -> None:
    if not emit:
        return
    try:
        print('[REL33-STRATEGY-COMPLETENESS-TOPUP] '
              f"route={diag.get('route')!r} domain={diag.get('domain')!r} "
              f"document_type={diag.get('document_type')!r} "
              f"objectives={diag.get('objectives_before')}->"
              f"{diag.get('objectives_after')} "
              f"(+{diag.get('objectives_added')}) "
              f"pillars={diag.get('pillars_before')}->{diag.get('pillars_after')} "
              f"(+{diag.get('pillars_added')}) "
              f"risk_rows={diag.get('confidence_risk_rows_before')}"
              f"->{diag.get('confidence_risk_rows_after')} "
              f"(+{diag.get('confidence_risk_rows_added')}) "
              f"touched={diag.get('sections_touched')} "
              f"applied={diag.get('topup_applied')} "
              f"kpi_preserved={diag.get('kpi_preserved')} "
              f"minimums_met={diag.get('quality_gate_minimums_met')} "
              f"gate_inputs={diag.get('final_quality_gate_inputs')} "
              f"gate_passed={diag.get('final_quality_gate_passed')} "
              f"pdf_kpi_precheck="
              f"{diag.get('pdf_kpi_extractability_precheck_passed')} "
              f"frozen_ready={diag.get('frozen_export_lock_ready')} "
              f"blockers={diag.get('blocking_errors')} "
              f"passed={diag.get('passed')}",
              flush=True)
    except Exception:  # noqa: BLE001 — diagnostics must never break generation
        pass
