"""PR-REL3.2 — compiler-first canonical strategy document builder."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from release_engine_v3.canonical_strategy_document import (
    CanonicalStrategyDocument,
    ConfidenceFactorRow,
    GapRow,
    GapTreatmentRow,
    GovernanceRoleRow,
    KpiFormulaRow,
    KpiRow,
    PillarInitiativeRow,
    PillarRow,
    RiskRegisterRow,
    RoadmapRow,
    StrategicObjectiveRow,
    TraceabilityInitiativeRow,
    TraceabilityGapRow,
)
from release_engine_v3.rel32_registries import (
    ARABIC_CANONICAL_REPAIR_REGISTRY,
    CONFIDENCE_FACTOR_REGISTRY,
    DEFAULT_CONFIDENCE_RATIONALE,
    DEFAULT_CONFIDENCE_SCORE,
    GAP_FAMILY_ORDER,
    GAP_FAMILY_REGISTRY,
    GOVERNANCE_ROLE_REGISTRY,
    KPI_CANONICAL_REGISTRY_FULL,
    PILLAR_INITIATIVE_REGISTRY,
    REL32_CANONICAL_HEADINGS,
    REL32_SECTION_ORDER,
    RISK_TREATMENT_REGISTRY,
    ROADMAP_FAMILY_REGISTRY,
    STRATEGIC_OBJECTIVE_REGISTRY,
    TRACEABILITY_CANONICAL_REGISTRY,
    TRACEABILITY_FAMILY_ORDER,
    resolve_kpi_canonical_registry,
    resolve_strategic_objective_registry,
)
from release_engine_v3.domain_codes import normalize_domain_code

_RAW_AI_MARKDOWN_FORBIDDEN_AS_AUTHORITY = (
    'rel32_forbidden:raw_ai_markdown_structural_authority',
)

_GAP_TABLE_MARKERS = (
    'الفجوة', 'gap', 'الأولوية', 'priority', 'دليل تطبيق', 'implementation guide',
)
_ENV_GAP_GUIDE_MARKERS = (
    'دليل تطبيق الفجوة', 'implementation guide', 'gap guide',
    '#### Gap #', '#### دليل',
)
_GAP_GAP_PREFIXES = ('ضعف ', 'غياب ', 'قصور ', 'عدم ')
_PLACEHOLDER_GAP_PATTERNS = (
    r'فجوة\s*(عامة|مؤقتة|placeholder)',
    r'generic\s*gap',
    r'\[REQUIRES_AI',
    r'TBD|tbd',
)

_MATURITY_ORDER = (
    'initial', 'developing', 'defined', 'managed', 'optimized',
)
_MATURITY_LABEL_AR = {
    'initial': 'ابتدائي',
    'developing': 'تطويري',
    'defined': 'محدد',
    'managed': 'مُدار',
    'optimized': 'محسّن',
}
_MATURITY_LABEL_EN = {
    'initial': 'Initial',
    'developing': 'Developing',
    'defined': 'Defined',
    'managed': 'Managed',
    'optimized': 'Optimized',
}


def _normalize_maturity_level(raw: str) -> str:
    m = (raw or 'initial').strip().lower()
    _map = {
        'أولي': 'initial', 'مبتدئ': 'initial',
        'قيد التطوير': 'developing', 'تطويري': 'developing',
        'intermediate': 'developing',
        'معرّف': 'defined', 'محدد': 'defined',
        'مُدار': 'managed', 'تحت الإدارة': 'managed',
        'مُحسّن': 'optimized', 'محسن': 'optimized',
        'ad-hoc': 'initial', 'ad hoc': 'initial',
    }
    m = _map.get(m, m)
    return m if m in _MATURITY_ORDER else 'initial'


def _target_maturity_level(current: str, *, horizon_months: int = 18) -> str:
    cur = _normalize_maturity_level(current)
    idx = _MATURITY_ORDER.index(cur)
    bump = 2 if horizon_months >= 19 else 1
    return _MATURITY_ORDER[min(idx + bump, len(_MATURITY_ORDER) - 1)]


def _append_maturity_trajectory_block(
        parts: List[str],
        *,
        lang: str,
        maturity_current: str,
        maturity_target: str,
        horizon_months: int,
) -> None:
    """Deterministic consulting-grade maturity trajectory (not AI-dependent)."""
    cur = _normalize_maturity_level(maturity_current)
    tgt = _normalize_maturity_level(maturity_target or _target_maturity_level(
        cur, horizon_months=horizon_months))
    months = max(12, min(24, int(horizon_months or 18)))
    if lang == 'ar':
        cur_l = _MATURITY_LABEL_AR.get(cur, cur)
        tgt_l = _MATURITY_LABEL_AR.get(tgt, tgt)
        parts.append('### مسار النضج المؤسسي')
        parts.append('')
        parts.append(f'مستوى النضج الحالي: {cur_l} ({cur})')
        parts.append(
            f'مستوى النضج المستهدف: {tgt_l} خلال {months} شهراً')
        parts.append('')
        parts.append(
            'يعكس هذا المسار أفق خارطة الطريق وعوامل الثقة التنظيمية '
            f'وقابلية التنفيذ خلال {months} شهراً.')
    else:
        cur_l = _MATURITY_LABEL_EN.get(cur, cur)
        tgt_l = _MATURITY_LABEL_EN.get(tgt, tgt)
        parts.append('### Maturity Trajectory')
        parts.append('')
        parts.append(f'Current maturity level: {cur_l} ({cur})')
        parts.append(
            f'Target maturity level: {tgt_l} within {months} months')
        parts.append('')
        parts.append(
            'This trajectory aligns with the roadmap horizon, confidence '
            f'factors, and domain implementation profile over {months} months.')
    parts.append('')


@dataclass
class CompileResult:
    document: Optional[CanonicalStrategyDocument] = None
    legacy_sections: Dict[str, str] = field(default_factory=dict)
    repairs: List[str] = field(default_factory=list)
    blocking_errors: List[str] = field(default_factory=list)
    passed: bool = False
    diagnostics: Dict[str, Any] = field(default_factory=dict)


def rel32_string_sections(sections: Dict[str, Any]) -> Dict[str, str]:
    """Return only persisted string section bodies (no internal metadata)."""
    return {
        k: v for k, v in (sections or {}).items()
        if isinstance(v, str) and v.strip() and not k.startswith('_')
    }


def is_rel32_compiler_first(
        *,
        domain: str = 'cyber',
        lang: str = 'ar',
        flags: Optional[Dict[str, Any]] = None,
        document_type: str = 'strategy') -> bool:
    """REL3.2 compiler applies to REL3.3 strategy paths (all domains, Arabic)."""
    from release_engine_v3.rel33_authority import is_rel33_compiler_first
    return is_rel33_compiler_first(
        domain=domain,
        lang=lang,
        flags=flags,
        document_type=document_type,
    )


def _heading_line(section_key: str) -> str:
    return f'## {REL32_CANONICAL_HEADINGS[section_key]}'


def _ensure_section_heading(section_key: str, body: str) -> str:
    """Prepend hardcoded REL3.2 heading; strip AI heading variants."""
    title = REL32_CANONICAL_HEADINGS.get(section_key, section_key)
    blob = (body or '').strip()
    if blob.startswith(f'## {title}'):
        return blob + ('\n' if not blob.endswith('\n') else '')
    lines = blob.splitlines()
    while lines and lines[0].strip().startswith('#'):
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)
    core = '\n'.join(lines).strip()
    if core:
        return f'## {title}\n\n{core}\n'
    return f'## {title}\n'


def _strip_markdown_tables(text: str) -> str:
    lines = (text or '').splitlines()
    kept: List[str] = []
    in_table = False
    for ln in lines:
        if ln.strip().startswith('|'):
            in_table = True
            continue
        if in_table and not ln.strip():
            in_table = False
            continue
        if not in_table:
            if ln.strip().startswith('#'):
                continue
            if any(m in ln for m in _ENV_GAP_GUIDE_MARKERS):
                continue
            kept.append(ln)
    return '\n'.join(kept).strip()


def _looks_like_gap_table(text: str) -> bool:
    blob = (text or '').lower()
    if not blob.strip().startswith('|'):
        return False
    hits = sum(1 for m in _GAP_TABLE_MARKERS if m.lower() in blob)
    return hits >= 2


def _extract_narrative_from_blob(blob: str) -> str:
    return _strip_markdown_tables(blob)


def _normalize_raw_input(
        raw_ai_output: Union[str, Dict[str, str], None],
) -> Tuple[Dict[str, str], str]:
    if isinstance(raw_ai_output, dict):
        sections = {
            k: v for k, v in raw_ai_output.items()
            if isinstance(v, str) and not str(k).startswith('_')}
        md = '\n\n'.join(
            f'## {k}\n\n{v}' for k, v in sections.items() if v.strip())
        return sections, md
    text = str(raw_ai_output or '')
    sections: Dict[str, str] = {}
    if not text.strip():
        return sections, text
    chunks = re.split(r'(?m)^##\s+', text)
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.split('\n', 1)
        heading = lines[0].strip()
        body = lines[1].strip() if len(lines) > 1 else ''
        key = _map_heading_to_key(heading)
        if key:
            sections[key] = body
    return sections, text


def _map_heading_to_key(heading: str) -> str:
    h = (heading or '').strip().lower()
    mapping = (
        ('رؤية', 'vision'), ('أهداف', 'vision'), ('vision', 'vision'),
        ('ركائز', 'pillars'), ('pillar', 'pillars'),
        ('بيئة', 'environment'), ('تهديد', 'environment'),
        ('environment', 'environment'),
        ('فجو', 'gaps'), ('gap', 'gaps'),
        ('خارطة', 'roadmap'), ('roadmap', 'roadmap'),
        ('مؤشر', 'kpis'), ('kpi', 'kpis'),
        ('ثقة', 'confidence'), ('مخاطر', 'confidence'),
        ('confidence', 'confidence'), ('risk', 'confidence'),
        ('حوكمة', 'governance'), ('governance', 'governance'),
        ('تتبع', 'traceability'), ('traceability', 'traceability'),
        ('ملحق', 'appendices'), ('append', 'appendices'),
    )
    for needle, key in mapping:
        if needle in h:
            return key
    return ''


def _relocate_misplaced_gaps(sections: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
    repairs: List[str] = []
    out = dict(sections)
    env = out.get('environment', '') or ''
    gaps = out.get('gaps', '') or ''
    if _looks_like_gap_table(env) or any(m in env for m in _ENV_GAP_GUIDE_MARKERS):
        out['environment'] = _extract_narrative_from_blob(env)
        repairs.append('rel32:removed_gap_table_from_environment')
        if not gaps.strip() or _looks_like_gap_table(env):
            out['gaps'] = env if _looks_like_gap_table(env) else gaps
            repairs.append('rel32:relocated_gap_content_from_environment')
    return out, repairs


def _build_vision_section(
        narrative: str,
        *,
        lang: str,
        backend: Dict[str, Any],
        domain: str = 'cyber',
) -> Tuple[str, Tuple[StrategicObjectiveRow, ...]]:
    rows: List[StrategicObjectiveRow] = []
    parts = [_heading_line('vision'), '']
    if narrative.strip():
        from release_engine.rendered_evidence_validator import _repair_arabic_blob
        narrative = _apply_arabic_registry_repairs(
            _repair_arabic_blob(narrative.strip()))
        parts = [_heading_line('vision'), '', narrative, '']
    parts.append(
        '| # | الهدف الاستراتيجي | المستهدف القابل للقياس | '
        'المبرر | الإطار الزمني |')
    parts.append('|---|---|---|---|---|')
    so_registry = resolve_strategic_objective_registry(domain)
    for i, fam in enumerate(so_registry, 1):
        cat = so_registry[fam]
        obj, tgt, rationale, tf = cat[0], cat[1], cat[2], cat[3]
        rows.append(StrategicObjectiveRow(
            str(i), obj, tgt, rationale, tf, family=fam))
        parts.append(f'| {i} | {obj} | {tgt} | {rationale} | {tf} |')
    return '\n'.join(parts) + '\n', tuple(rows)


def _build_pillars_section(
        narrative: str,
        *,
        lang: str,
) -> Tuple[str, Tuple[PillarRow, ...], Tuple[PillarInitiativeRow, ...]]:
    from release_engine.pillar_model import _build_canonical_pillars

    text = _build_canonical_pillars(lang)
    text = re.sub(r'^##\s+[^\n]+', _heading_line('pillars'), text, count=1, flags=re.M)
    from release_engine.pillar_model import _PILLAR_CATALOG_AR

    pillars: List[PillarRow] = []
    initiatives: List[PillarInitiativeRow] = []
    for fam, catalog_rows in PILLAR_INITIATIVE_REGISTRY.items():
        heading = ''
        for h, rows in _PILLAR_CATALOG_AR:
            if rows == catalog_rows:
                heading = h.lstrip('#').strip()
                break
        pillars.append(PillarRow(heading, family=fam))
        owner_map = {
            'فريق CSIRT': 'قائد CSIRT',
            'IAM/PAM/MFA': 'مدير IAM/PAM',
            'تصنيف البيانات': 'مدير حماية البيانات',
            'DLP': 'مدير حماية البيانات',
            'النسخ الاحتياطي': 'مدير IT',
            'التعافي من الكوارث': 'مدير BCP',
            'استمرارية الأعمال': 'مدير BCP',
        }
        for init, desc, output in catalog_rows:
            owner = owner_map.get(init, 'CISO')
            if 'SOC' in init:
                owner = 'مدير SOC'
            initiatives.append(PillarInitiativeRow(
                init, desc, output, owner, pillar_family=fam))
    if narrative.strip():
        text = _heading_line('pillars') + '\n\n' + narrative.strip() + '\n\n' + '\n'.join(
            text.split('\n')[2:])
    return text, tuple(pillars), tuple(initiatives)


def _apply_arabic_registry_repairs(text: str) -> str:
    out = text or ''
    for bad, good in ARABIC_CANONICAL_REPAIR_REGISTRY:
        out = out.replace(bad, good)
    return out


def _build_environment_section(narrative: str) -> str:
    from release_engine.rendered_evidence_validator import _repair_arabic_blob
    default = (
        'تشمل البيئة التنظيمية متطلبات NCA ECC وNCA DCC '
        'وضوابط حماية البيانات الوطنية، مع سياق تهديدات التصيد '
        'والبرمجيات الخبيثة وتسرب البيانات ومخاطر سلسلة التوريد '
        'والتشغيل على الأنظمة الحرجة.')
    body = (narrative or '').strip()
    if body:
        body = _apply_arabic_registry_repairs(_repair_arabic_blob(body))
    if not body or len(body) < 80:
        body = default if not body else f'{body}\n\n{default}'
    return f'{_heading_line("environment")}\n\n{body}\n'


def _build_gaps_section(
        ai_gaps: str,
) -> Tuple[str, Tuple[GapRow, ...], Tuple[GapTreatmentRow, ...]]:
    gap_rows: List[GapRow] = []
    treatments: List[GapTreatmentRow] = []
    parts = [_heading_line('gaps'), '']
    parts.append('| # | الفجوة | الوصف | الأولوية | الحالة |')
    parts.append('|---|---|---|---|---|')
    for i, fam in enumerate(GAP_FAMILY_ORDER, 1):
        spec = GAP_FAMILY_REGISTRY[fam]
        gap_rows.append(GapRow(
            str(i), spec['gap_label'], spec['description'],
            spec['priority'], spec['status'], family=fam,
            framework=spec['framework']))
        parts.append(
            f'| {i} | {spec["gap_label"]} | {spec["description"]} | '
            f'{spec["priority"]} | {spec["status"]} |')
        treatments.append(GapTreatmentRow(
            spec['gap_label'], '1',
            spec['treatment'], spec['owner'], '6-12 شهراً',
            f'إغلاق فجوة {spec["gap_label"]}'))
    parts.append('')
    for i, gr in enumerate(gap_rows[:5], 1):
        parts.append(f'#### دليل تطبيق الفجوة {i}: {gr.gap_label}')
        tr = treatments[i - 1]
        parts.append(
            '| الخطوة | الإجراء | المسؤول | الإطار الزمني | الناتج |')
        parts.append('|---|---|---|---|---|')
        parts.append(
            f'| {tr.step} | {tr.action} | {tr.owner} | '
            f'{tr.timeframe} | {tr.output} |')
        parts.append('')
    return '\n'.join(parts).strip() + '\n', tuple(gap_rows), tuple(treatments)


def _build_roadmap_section(
        ai_roadmap: str,
        *,
        lang: str,
        domain: str,
        backend: Dict[str, Any],
) -> Tuple[str, Tuple[RoadmapRow, ...]]:
    """Always build roadmap from registry — AI table structure is ignored."""
    _ = ai_roadmap
    from release_engine.roadmap_model import (
        ROADMAP_FAMILIES,
        _ROADMAP_CATALOG_AR,
        finalize_roadmap,
    )
    parts = [_heading_line('roadmap'), '']
    parts.append(
        '| المرحلة | الإطار الزمني | المبادرة | المالك | '
        'المخرج | الإطار |')
    parts.append('|---|---|---|---|---|---|')
    for fam in ROADMAP_FAMILIES:
        cat = tuple(
            ROADMAP_FAMILY_REGISTRY.get(fam)
            or _ROADMAP_CATALOG_AR.get(fam)
            or ())
        if len(cat) < 6:
            continue
        parts.append(
            f'| {cat[0]} | {cat[1]} | {cat[2]} | {cat[3]} | '
            f'{cat[4]} | {cat[5]} |')
    text = '\n'.join(parts) + '\n'
    sections, _ = finalize_roadmap(
        {'roadmap': text},
        lang=lang,
        domain=domain,
        selected_frameworks=backend.get('selected_frameworks') or [],
        backend=backend)
    text = _ensure_section_heading('roadmap', sections.get('roadmap', text))
    return text, tuple(_parse_roadmap_rows(text))


def _parse_roadmap_rows(text: str) -> List[RoadmapRow]:
    rows: List[RoadmapRow] = []
    for ln in (text or '').splitlines():
        if not ln.strip().startswith('|') or '---' in ln:
            continue
        cells = [c.strip() for c in ln.strip('|').split('|')]
        if len(cells) < 6:
            continue
        first = (cells[0] or '').strip()
        if first in ('المرحلة', 'Phase', 'p', '#', 'الفترة', 'Period'):
            continue
        if first.lower() in ('phase', 'period', 'initiative', 'owner'):
            continue
        rows.append(RoadmapRow(
            cells[0], cells[1], cells[2], cells[3], cells[4], cells[5]))
    return rows


def _build_kpis_section(
        ai_kpis: str,
        *,
        lang: str,
        backend: Dict[str, Any],
        domain: str = 'cyber',
) -> Tuple[str, Tuple[KpiRow, ...], Tuple[KpiFormulaRow, ...]]:
    parts = [_heading_line('kpis'), '']
    parts.append(
        '| # | وصف المؤشر | النوع | القيمة المستهدفة | '
        'صيغة الاحتساب | مصدر | التكرار | المالك |')
    parts.append('|---|---|---|---|---|---|---|---|')
    kpi_rows: List[KpiRow] = []
    formula_rows: List[KpiFormulaRow] = []
    kpi_registry = resolve_kpi_canonical_registry(domain)
    order = list(kpi_registry.keys())
    if not order:
        order = list(KPI_CANONICAL_REGISTRY_FULL.keys()) or [
            'soc_mttd', 'incident_response_mttr']
    for i, fam in enumerate(order, 1):
        reg = kpi_registry[fam]
        owner = reg.get('owner') or 'CISO'
        freq = reg.get('frequency') or 'شهري'
        if owner in ('—', '-', '—', '') or owner == freq:
            owner = 'CISO' if normalize_domain_code(domain) == 'cyber' else 'CDO'
        kpi_rows.append(KpiRow(
            str(i), reg['label_ar'], reg.get('kpi_type', 'KPI'),
            reg['target'], reg['formula'], reg['source'],
            freq, owner, family=fam))
        parts.append(
            f'| {i} | {reg["label_ar"]} | {reg.get("kpi_type", "KPI")} | '
            f'{reg["target"]} | {reg["formula"]} | {reg["source"]} | '
            f'{freq} | {owner} |')
        formula_rows.append(KpiFormulaRow(
            str(i), reg['label_ar'], reg['formula'], reg['source']))
    parts.append('')
    parts.append('### صيغة الاحتساب')
    parts.append('')
    parts.append('| # | المؤشر | صيغة الاحتساب | مصدر البيانات |')
    parts.append('|---|---|---|---|')
    for fr in formula_rows:
        parts.append(
            f'| {fr.number} | {fr.name} | {fr.formula} | {fr.source} |')
    text = '\n'.join(parts) + '\n'
    sections = {'kpis': text}
    from release_engine.kpi_model import repair_kpi_canonical_families
    sections, _ = repair_kpi_canonical_families(
        sections, lang=lang, backend=backend)
    from release_engine_v3.rel32_kpi_assessment_guides import (
        build_kpi_assessment_guides_block,
        _kpi_rows_from_section,
    )
    guide_rows = _kpi_rows_from_section(sections['kpis'])
    sections['kpis'] = (
        sections['kpis'].rstrip()
        + build_kpi_assessment_guides_block(guide_rows, lang=lang))
    return sections['kpis'], tuple(kpi_rows), tuple(formula_rows)


def _build_confidence_section(
        ai_confidence: str,
        *,
        lang: str,
        maturity_current: str = 'initial',
        maturity_target: str = '',
        horizon_months: int = 18,
) -> Tuple[str, Tuple[ConfidenceFactorRow, ...], Tuple[RiskRegisterRow, ...], str, str]:
    from release_engine.risk_treatment_model import (
        _REQUIRED_RISK_THEMES,
        specific_risk_treatment_for_blob,
    )
    score = DEFAULT_CONFIDENCE_SCORE
    rationale = DEFAULT_CONFIDENCE_RATIONALE
    m = re.search(r'(\d{1,3})\s*%', ai_confidence or '')
    if m:
        score = f'{m.group(1)}%'
    score_val = int(re.sub(r'\D', '', score) or '76')
    factor_rows: List[ConfidenceFactorRow] = []
    parts = [_heading_line('confidence'), '']
    parts.append(f'درجة الثقة: {score}')
    parts.append('')
    parts.append('مبررات التقييم:')
    parts.append(rationale)
    parts.append('')
    _append_maturity_trajectory_block(
        parts,
        lang=lang,
        maturity_current=maturity_current,
        maturity_target=maturity_target,
        horizon_months=horizon_months,
    )
    parts.append('### عوامل النجاح الحرجة')
    parts.append('')
    parts.append('| # | العامل | الوصف | الأهمية |')
    parts.append('|---|---|---|---|')
    grade = str(min(5, max(1, round(score_val / 20))))
    _factor_desc = {
        'اكتمال المدخلات': 'اكتمال مدخلات التقييم والبيانات المرجعية',
        'تغطية الأطر المرجعية': 'تغطية NCA ECC وNCA DCC والمتطلبات التنظيمية',
        'جدوى خارطة الطريق': 'قابلية تنفيذ خارطة الطريق ضمن الأفق الزمني',
        'جاهزية الموارد': 'توفر الموارد البشرية والتقنية والتمويل',
        'نضج الحوكمة': 'نضج هيكل الحوكمة والمساءلة السيبرانية',
        'جاهزية حماية البيانات': 'جاهزية ضوابط حماية البيانات والخصوصية',
    }
    for i, (fname, weight) in enumerate(CONFIDENCE_FACTOR_REGISTRY, 1):
        w_pct = int(re.sub(r'\D', '', weight) or '0')
        contrib = f'{round(w_pct * score_val / 100, 1)}%'
        desc = _factor_desc.get(fname, fname)
        importance = 'عالية' if w_pct >= 20 else 'متوسطة'
        factor_rows.append(ConfidenceFactorRow(fname, weight, grade, contrib))
        parts.append(f'| {i} | {fname} | {desc} | {importance} |')
    parts.append('')
    parts.append('### المخاطر الرئيسية')
    parts.append('')
    parts.append(
        '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة | المالك |')
    parts.append('|---|---|---|---|---|---|')
    risk_rows: List[RiskRegisterRow] = []
    risk_labels = (
        ('امتثال تنظيمي', 'متوسط', 'عالٍ', 'compliance', 'مدير الامتثال'),
        ('قدرات رصد وكشف', 'متوسط', 'عالٍ', 'capabilities', 'مدير SOC'),
        ('حماية البيانات', 'متوسط', 'عالٍ', 'data_protection', 'مدير حماية البيانات'),
        ('استجابة للحوادث', 'متوسط', 'عالٍ', 'incident_response', 'قائد CSIRT'),
        ('موارد وتمويل', 'منخفض', 'متوسط', 'resource_capacity', 'CISO'),
        ('استمرارية التشغيل', 'منخفض', 'عالٍ', 'operational_continuity',
         'مدير استمرارية الأعمال'),
    )
    for i, (risk, lik, imp, theme, owner) in enumerate(risk_labels, 1):
        treatment = RISK_TREATMENT_REGISTRY.get(
            theme, specific_risk_treatment_for_blob(risk, lang=lang))
        risk_rows.append(RiskRegisterRow(
            str(i), risk, lik, imp, treatment, owner, theme=theme))
        parts.append(f'| {i} | {risk} | {lik} | {imp} | {treatment} | {owner} |')
    return '\n'.join(parts) + '\n', tuple(factor_rows), tuple(risk_rows), score, rationale


def _build_governance_section() -> Tuple[str, Tuple[GovernanceRoleRow, ...]]:
    parts = [_heading_line('governance'), '']
    parts.append(
        '| الدور | نطاق المسؤولية | المساءلة | '
        'التقارير / التصعيد | الإطار المرتبط |')
    parts.append('|---|---|---|---|---|')
    roles: List[GovernanceRoleRow] = []
    for spec in GOVERNANCE_ROLE_REGISTRY.values():
        roles.append(GovernanceRoleRow(
            spec['role'], spec['scope'], spec['accountability'],
            spec['escalation'], spec['framework']))
        parts.append(
            f'| {spec["role"]} | {spec["scope"]} | {spec["accountability"]} | '
            f'{spec["escalation"]} | {spec["framework"]} |')
    return '\n'.join(parts) + '\n', tuple(roles)


def _build_traceability_section(
        *,
        lang: str,
) -> Tuple[str, Tuple[TraceabilityGapRow, ...], Tuple[TraceabilityInitiativeRow, ...]]:
    from release_engine.traceability_substance_model import (
        build_canonical_traceability_from_registry,
    )
    text = build_canonical_traceability_from_registry(lang=lang)
    text = re.sub(
        r'^##\s+[^\n]+', _heading_line('traceability'), text, count=1, flags=re.M)
    gap_matrix: List[TraceabilityGapRow] = []
    init_matrix: List[TraceabilityInitiativeRow] = []
    for fam in TRACEABILITY_FAMILY_ORDER:
        spec = TRACEABILITY_CANONICAL_REGISTRY[fam]
        gap_matrix.append(TraceabilityGapRow(
            spec['framework'], spec['capability'], spec['expected_gap'], fam))
        init_matrix.append(TraceabilityInitiativeRow(
            spec['framework'], spec['capability'], spec['expected_gap'],
            spec['initiative'], spec['metric'], spec['risk'], fam))
    return text, tuple(gap_matrix), tuple(init_matrix)


def _document_from_sections(
        sections: Dict[str, str],
        *,
        metadata: Dict[str, Any],
        lang: str,
        domain: str,
        backend: Dict[str, Any],
) -> CanonicalStrategyDocument:
    vision_text, objectives = _build_vision_section(
        _extract_narrative_from_blob(sections.get('vision', '')),
        lang=lang, backend=backend, domain=domain)
    pillars_text, pillars, initiatives = _build_pillars_section(
        _extract_narrative_from_blob(sections.get('pillars', '')),
        lang=lang)
    env_text = _build_environment_section(
        _extract_narrative_from_blob(sections.get('environment', '')))
    gaps_text, gaps, treatments = _build_gaps_section(sections.get('gaps', ''))
    roadmap_text, roadmap = _build_roadmap_section(
        sections.get('roadmap', ''),
        lang=lang, domain=domain, backend=backend)
    kpis_text, kpis, formulas = _build_kpis_section(
        sections.get('kpis', ''), lang=lang, backend=backend, domain=domain)
    _horizon = int(metadata.get('roadmap_horizon_months') or 18)
    _maturity_cur = str(
        metadata.get('maturity_level') or metadata.get('maturity') or 'initial')
    _maturity_tgt = str(metadata.get('maturity_target') or '')
    conf_text, factors, risks, score, rationale = _build_confidence_section(
        sections.get('confidence', ''),
        lang=lang,
        maturity_current=_maturity_cur,
        maturity_target=_maturity_tgt,
        horizon_months=_horizon,
    )
    gov_text, gov_roles = _build_governance_section()
    trace_text, trace_gaps, trace_inits = _build_traceability_section(lang=lang)
    appendices = sections.get('appendices', '') or ''

    compiled_sections = {
        'vision': vision_text,
        'pillars': pillars_text,
        'environment': env_text,
        'gaps': gaps_text,
        'roadmap': roadmap_text,
        'kpis': kpis_text,
        'confidence': conf_text,
        'governance': gov_text,
        'traceability': trace_text,
        'appendices': appendices,
    }

    doc = CanonicalStrategyDocument(
        metadata=dict(metadata),
        vision=_extract_narrative_from_blob(sections.get('vision', '')),
        strategic_objectives=objectives,
        pillars=pillars,
        pillar_initiatives=initiatives,
        environment_context=_extract_narrative_from_blob(
            sections.get('environment', '')),
        gaps=gaps,
        gap_treatments=treatments,
        roadmap=roadmap,
        kpis=kpis,
        kpi_formulas=formulas,
        risk_register=risks,
        confidence_factors=factors,
        confidence_score=score,
        confidence_rationale=rationale,
        governance_roles=gov_roles,
        traceability_gap_matrix=trace_gaps,
        traceability_initiative_matrix=trace_inits,
        appendices=appendices,
        compiler_version='rel32',
        source_authority='canonical_compiler',
    )
    doc.metadata['_compiled_sections'] = compiled_sections
    return doc


def canonical_document_to_legacy_sections(
        doc: CanonicalStrategyDocument) -> Dict[str, str]:
    cached = (doc.metadata or {}).get('_compiled_sections')
    if isinstance(cached, dict) and cached:
        return dict(cached)
    backend: Dict[str, Any] = doc.metadata or {}
    built = _document_from_sections(
        {}, metadata=doc.metadata,
        lang=backend.get('lang', 'ar'),
        domain=backend.get('domain', 'cyber'),
        backend=backend)
    return dict((built.metadata or {}).get('_compiled_sections') or {})


def _run_post_compile_repairs(
        sections: Dict[str, str],
        *,
        lang: str,
        domain: str,
        backend: Dict[str, Any],
) -> Tuple[Dict[str, str], List[str]]:
    repairs: List[str] = []
    out = dict(sections)
    try:
        from release_engine.kpi_model import repair_kpi_canonical_families
        out, kpi_diag = repair_kpi_canonical_families(
            out, lang=lang, backend=backend)
        if kpi_diag.get('action_taken') != 'no_changes':
            repairs.append('rel32:kpi_canonical_dedup')
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine.traceability_substance_model import (
            repair_traceability_canonical_families,
        )
        out, trace_diag = repair_traceability_canonical_families(
            out, lang=lang, backend=backend)
        if trace_diag.get('action_taken') != 'no_changes':
            repairs.append('rel32:traceability_canonical_repair')
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine.roadmap_model import finalize_roadmap
        out, rm_diag = finalize_roadmap(
            out, lang=lang, domain=domain,
            selected_frameworks=backend.get('selected_frameworks') or [],
            backend=backend)
        if (rm_diag.get('action_taken') or '') not in (
                '', 'no_changes', 'skipped_non_cyber'):
            repairs.append('rel32:roadmap_owners_enforced')
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine.arabic_language_gate import (
            repair_arabic_canonical_text_before_freeze,
        )
        out, ar_diag = repair_arabic_canonical_text_before_freeze(
            out, lang=lang, backend=backend)
        if ar_diag.get('sections_repaired'):
            repairs.append('rel32:arabic_canonical_repair')
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine_v3.rel32_kpi_assessment_guides import (
            repair_kpi_assessment_guides_for_sections,
        )
        out, kpi_guide_diag = repair_kpi_assessment_guides_for_sections(
            out, lang=lang, backend=backend)
        if kpi_guide_diag.get('inserted'):
            repairs.append('rel32:kpi_assessment_guides_repair')
    except Exception:  # noqa: BLE001
        pass
    for key in REL32_SECTION_ORDER:
        if key in out and key in REL32_CANONICAL_HEADINGS and out.get(key):
            out[key] = _ensure_section_heading(key, out[key])
    return out, repairs


def _has_placeholder_gaps(text: str) -> bool:
    blob = (text or '').lower()
    return any(re.search(p, blob) for p in _PLACEHOLDER_GAP_PATTERNS)


def compile_canonical_strategy_document(
        raw_ai_output: Union[str, Dict[str, str], None],
        request_context: Optional[Dict[str, Any]] = None,
) -> CompileResult:
    """Build CanonicalStrategyDocument from AI raw input + deterministic registries.

    AI output is facts-only input. Structure, headings, tables, and columns
    are always compiler-owned. Returns fail-closed CompileResult on schema/DQS block.
    """
    ctx = dict(request_context or {})
    lang = str(ctx.get('lang') or 'ar')
    domain = normalize_domain_code(str(ctx.get('domain') or 'cyber'), default='cyber')
    backend = dict(ctx.get('backend') or {})
    backend.setdefault('lang', lang)
    backend.setdefault('selected_frameworks', ctx.get('selected_frameworks') or [])

    repairs: List[str] = ['rel32:compiler_first_authority']
    ai_sections, _raw_md = _normalize_raw_input(raw_ai_output)
    ai_sections, reloc_rep = _relocate_misplaced_gaps(ai_sections)
    repairs.extend(reloc_rep)

    metadata = {
        'lang': lang,
        'domain': domain,
        'selected_frameworks': backend.get('selected_frameworks') or [],
        'compiler': 'rel32',
        'ai_input_keys': list(ai_sections.keys()),
        'maturity_level': _normalize_maturity_level(
            str(ctx.get('maturity_level') or ctx.get('maturity') or 'initial')),
        'maturity_target': _normalize_maturity_level(
            str(ctx.get('maturity_target') or ''))
        if ctx.get('maturity_target') else '',
        'roadmap_horizon_months': int(ctx.get('roadmap_horizon_months') or 18),
    }

    doc = _document_from_sections(
        ai_sections, metadata=metadata,
        lang=lang, domain=domain, backend=backend)
    legacy = canonical_document_to_legacy_sections(doc)
    legacy, post_rep = _run_post_compile_repairs(
        legacy, lang=lang, domain=domain, backend=backend)
    repairs.extend(post_rep)

    doc.metadata['_compiled_sections'] = legacy
    doc.roadmap = tuple(_parse_roadmap_rows(legacy.get('roadmap', '')))
    schema_blockers = doc.validate_schema()
    blockers: List[str] = list(schema_blockers)

    if _has_placeholder_gaps(ai_sections.get('gaps', '')):
        repairs.append('rel32:replaced_placeholder_gaps')

    for key, title in REL32_CANONICAL_HEADINGS.items():
        body = legacy.get(key, '') or ''
        if title not in body:
            blockers.append(f'rel32_heading_missing:{key}')

    try:
        from release_engine_v3.document_quality_spec import (
            evaluate_document_quality,
        )
        dqs = evaluate_document_quality(legacy_sections=legacy, domain=domain)
        if not dqs.get('passed'):
            for err in dqs.get('blocking_errors') or []:
                blockers.append(f'rel32_dqs:{err}')
    except Exception as exc:  # noqa: BLE001
        blockers.append(f'rel32_dqs_eval_failed:{exc!s:.80}')

    blockers = list(dict.fromkeys(blockers))
    passed = not blockers

    try:
        from release_engine_v3.rel32_complete_strategy_compiler import (
            evaluate_rel32_final_strategy_completeness,
        )
        from release_engine_v3.rel32_kpi_assessment_guides import (
            emit_rel32_final_strategy_completeness_diag,
            kpi_assessment_guides_present,
        )
        completeness = evaluate_rel32_final_strategy_completeness(
            legacy, lang=lang, domain=domain)
        if not kpi_assessment_guides_present(legacy.get('kpis', '')):
            blockers.append('rel32_kpi_assessment_guides_missing')
            passed = False
            completeness['blocking_errors'] = list(
                completeness.get('blocking_errors') or [])
            completeness['blocking_errors'].append(
                'rel32_kpi_assessment_guides_missing')
            completeness['saved_content_complete'] = False
            completeness['preview_complete'] = False
            completeness['docx_complete'] = False
            completeness['pdf_complete'] = False
        emit_rel32_final_strategy_completeness_diag(completeness)
        if not completeness.get('saved_content_complete'):
            for err in completeness.get('blocking_errors') or []:
                blockers.append(err)
        blockers = list(dict.fromkeys(blockers))
        passed = not blockers
    except Exception:  # noqa: BLE001
        completeness = {}

    legacy = rel32_string_sections(legacy)

    diag = {
        'repairs': repairs,
        'schema': doc.to_diag(),
        'headings_enforced': list(REL32_CANONICAL_HEADINGS.values()),
        'ai_markdown_authority': False,
        'passed': passed,
        'final_strategy_completeness': completeness,
        'compiled_sections_cache': dict(legacy),
    }
    try:
        print(
            '[REL32-COMPILER] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass

    return CompileResult(
        document=doc if passed else doc,
        legacy_sections=legacy,
        repairs=list(dict.fromkeys(repairs)),
        blocking_errors=blockers,
        passed=passed,
        diagnostics=diag,
    )


def apply_compiler_first_save_gate_sections(
        sections: Dict[str, str],
        *,
        domain: str,
        lang: str,
        flags: Optional[Dict[str, Any]] = None,
        maturity_level: str = 'initial',
        selected_frameworks: Optional[List[str]] = None,
        roadmap_horizon_months: int = 18,
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Replace AI sections with compiler-owned structure before save-gate validation."""
    if not is_rel32_compiler_first(
            domain=normalize_domain_code(domain, default='cyber'),
            lang=lang, flags=flags,
            document_type=str(
                (backend or {}).get('document_type') or 'strategy')):
        return dict(sections or {}), []
    from release_engine_v3.rel32_complete_strategy_compiler import (
        compile_complete_cyber_ar_technical_strategy,
    )
    _backend = dict(backend or {})
    _backend.setdefault('flags', dict(flags or {}))
    dcode = normalize_domain_code(domain, default='cyber')
    compiled = compile_complete_cyber_ar_technical_strategy(
        dict(sections or {}),
        request_context={
            'lang': lang,
            'domain': dcode,
            'maturity_level': maturity_level,
            'maturity': maturity_level,
            'roadmap_horizon_months': roadmap_horizon_months,
            'selected_frameworks': list(selected_frameworks or []),
            'backend': _backend,
            'flags': dict(flags or {}),
            'generation_mode': _backend.get('generation_mode') or 'drafting',
        },
    )
    repairs = list(compiled.repairs or [])
    if compiled.legacy_sections:
        repairs.insert(0, 'rel32:save_gate_compiler_first')
        out = dict(compiled.legacy_sections)
        cache = (compiled.diagnostics or {}).get('compiled_sections_cache')
        if isinstance(cache, dict) and cache:
            out['_rel32_compiled_sections'] = dict(cache)
        return out, repairs
    return dict(sections or {}), repairs


def rel32_fingerprint_extension(flags: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Alias — REL3.2 fingerprint fields are merged in rel31_fingerprint_extension."""
    from release_engine_v3.rel31_authority import rel31_fingerprint_extension
    return rel31_fingerprint_extension(flags)
