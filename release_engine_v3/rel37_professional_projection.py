"""REL37 professional-render projection.

A validated CanonicalDocument is the content authority. Layout utilities
may format these tables; they must not invent or replace values.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.rel37_apply import (
    REL37_RENDER_BLOCKED_KEY,
    load_model,
    rel37_confidence_risk_post_repair_result,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument


class Rel37RenderAuthorityError(ValueError):
    """Identity-matched REL37 content is missing or failed validation."""

    def __init__(self, blockers: Optional[List[str]] = None):
        self.blockers = list(blockers or ['rel37_render_authority_failed'])
        super().__init__(';'.join(self.blockers))


def _lang(model: CanonicalDocument) -> str:
    return 'ar' if str(model.lang or '').startswith('ar') else 'en'


def headers_for(kind: str, lang: str) -> List[str]:
    ar = {
        'so': ['#', 'الهدف', 'المستهدف', 'المبرر', 'الإطار الزمني'],
        'pillar': ['المبادرة', 'الوصف', 'المخرج المتوقع', 'المالك'],
        'gap': ['#', 'الفجوة', 'الوصف', 'الأولوية', 'الحالة'],
        'guide': ['الخطوة', 'الإجراء', 'المسؤول', 'الإطار الزمني', 'الناتج'],
        'kpi_main': [
            '#', 'وصف المؤشر', 'النوع', 'القيمة المستهدفة',
            'صيغة الاحتساب', 'مصدر', 'التكرار', 'المالك',
        ],
        'kpi_formula': ['#', 'المؤشر', 'صيغة الاحتساب', 'مصدر البيانات'],
        'roadmap': [
            'المرحلة', 'الفترة', 'المبادرة', 'المالك',
            'المخرج المتوقع', 'الإطار المرتبط',
        ],
        'confidence': ['العامل', 'الوزن', 'الدرجة', 'المساهمة'],
        'risk': ['#', 'المخاطر', 'الأثر', 'خطة المعالجة', 'المالك'],
        'governance': ['الدور', 'المسؤولية', 'التكرار', 'المالك'],
        'traceability': ['#', 'المبادرة', 'الفجوة', 'المؤشر', 'الإطار'],
    }
    en = {
        'so': ['#', 'Objective', 'Target', 'Rationale', 'Timeframe'],
        'pillar': ['Initiative', 'Description', 'Expected Deliverable', 'Owner'],
        'gap': ['#', 'Gap', 'Description', 'Priority', 'Status'],
        'guide': ['Step', 'Action', 'Owner', 'Timeframe', 'Output'],
        'kpi_main': [
            '#', 'KPI Description', 'Type', 'Target Value',
            'Calculation Formula', 'Source', 'Frequency', 'Owner',
        ],
        'kpi_formula': ['#', 'Indicator', 'Calculation Formula', 'Data Source'],
        'roadmap': [
            'Phase', 'Period', 'Initiative', 'Owner',
            'Deliverable', 'Linked Framework',
        ],
        'confidence': ['Factor', 'Weight', 'Score', 'Contribution'],
        'risk': ['#', 'Risk', 'Impact', 'Treatment Plan', 'Owner'],
        'governance': ['Role', 'Responsibility', 'Cadence', 'Owner'],
        'traceability': ['#', 'Initiative', 'Gap', 'KPI', 'Framework'],
    }
    return list((ar if lang == 'ar' else en)[kind])


def load_validated_rel37_model(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> Tuple[Optional[CanonicalDocument], List[str]]:
    """Return (model, blockers). Empty blockers means the model is authoritative."""
    if (sections or {}).get(REL37_RENDER_BLOCKED_KEY):
        raw = (sections or {}).get(REL37_RENDER_BLOCKED_KEY)
        blockers = list(raw) if isinstance(raw, list) else [str(raw)]
        return None, blockers or ['rel37_render_blocked']
    blockers = rel37_confidence_risk_post_repair_result(
        sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
        org_name=org_name,
        selected_frameworks=selected_frameworks,
    )
    if blockers is None:
        return None, []
    if blockers:
        return None, list(blockers)
    model = load_model(sections)
    if model is None:
        return None, ['rel37_model_unreadable']
    required = _required_model_content_blockers(model)
    if required:
        return None, required
    return model, []


def _required_model_content_blockers(model: CanonicalDocument) -> List[str]:
    """Missing required typed content is a validation failure, not a fill-in."""
    missing: List[str] = []
    if not model.roadmap:
        missing.append('rel37_roadmap_missing')
    if not model.kpis:
        missing.append('rel37_kpis_missing')
    if not model.confidence:
        missing.append('rel37_confidence_missing')
    if not model.traceability:
        missing.append('rel37_traceability_missing')
    if not model.gaps:
        missing.append('rel37_gaps_missing')
    if not model.governance:
        missing.append('rel37_governance_missing')
    return missing


def projection_tables(model: CanonicalDocument) -> Dict[str, Dict[str, Any]]:
    lang = _lang(model)
    return {
        'strategic_objectives': {
            'schema': 'strategic_objectives',
            'header': headers_for('so', lang),
            'rows': [list(row.cells()) for row in model.strategic_objectives],
        },
        'roadmap': {
            'schema': 'roadmap',
            'header': headers_for('roadmap', lang),
            'rows': [list(row.cells()) for row in model.roadmap],
        },
        'gap_main': {
            'schema': 'gap_main',
            'header': headers_for('gap', lang),
            'rows': [list(row.cells()) for row in model.gaps],
        },
        'kpi_main': {
            'schema': 'kpi_main',
            'header': headers_for('kpi_main', lang),
            'rows': [list(row.cells()) for row in model.kpis],
        },
        'kpi_formula': {
            'schema': 'kpi_formula',
            'header': headers_for('kpi_formula', lang),
            'rows': [list(row.cells()) for row in model.kpi_formula_source],
        },
        'confidence': {
            'schema': 'conf_factor',
            'header': headers_for('confidence', lang),
            'rows': [list(row.cells()) for row in model.confidence],
        },
        'risk': {
            'schema': 'risk_register',
            'header': headers_for('risk', lang),
            'rows': [
                [str(idx), row.risk, row.impact, row.mitigation, row.owner]
                for idx, row in enumerate(model.risks, 1)
            ],
        },
        'governance': {
            'schema': 'governance',
            'header': headers_for('governance', lang),
            'rows': [list(row.cells()) for row in model.governance],
        },
        'traceability': {
            'schema': 'traceability',
            'header': headers_for('traceability', lang),
            'rows': [list(row.cells()) for row in model.traceability],
        },
    }


def _display_heading(value: str) -> str:
    """Schema-defined heading text without leftover markdown hashes."""
    return re.sub(r'^#{1,6}\s*', '', str(value or '')).strip()


def _guide_tables(model: CanonicalDocument, kind: str) -> List[Dict[str, Any]]:
    lang = _lang(model)
    guides = model.gap_guides if kind == 'gap' else model.kpi_guides
    tables: List[Dict[str, Any]] = []
    for guide in guides:
        tables.append({
            'schema': 'gap_action' if kind == 'gap' else 'kpi_guide',
            'title': _display_heading(guide.heading),
            'header': headers_for('guide', lang),
            'rows': [list(step.cells()) for step in guide.steps],
            'family': guide.family,
            'number': guide.number,
        })
    return tables


def apply_rel37_projection_to_blocks(
        blocks: Dict[str, Any],
        model: CanonicalDocument,
) -> Dict[str, Any]:
    """Replace content-bearing professional tables with validated model values."""
    out = dict(blocks or {})
    lang = _lang(model)
    tables = projection_tables(model)
    gap_guides = _guide_tables(model, 'gap')
    kpi_guides = _guide_tables(model, 'kpi')

    vis = dict(out.get('vision_objectives') or {})
    vis['tables'] = [tables['strategic_objectives']] if tables['strategic_objectives']['rows'] else []
    out['vision_objectives'] = vis

    pil = dict(out.get('strategic_pillars') or {})
    pillar_blocks: List[Dict[str, Any]] = []
    for pillar in model.pillars:
        inits = [
            list(row.cells()) for row in model.pillar_initiatives
            if row.pillar_number == pillar.number
        ]
        init_tbl = {
            'schema': 'pillar_initiatives',
            'header': headers_for('pillar', lang),
            'rows': inits,
        } if inits else None
        pillar_blocks.append({
            'title': pillar.title,
            'description': pillar.description,
            'owner': pillar.owner,
            'number': pillar.number,
            'table': init_tbl,
            'tables': [init_tbl] if init_tbl else [],
        })
    pil['pillar_blocks'] = pillar_blocks
    out['strategic_pillars'] = pil

    gaps = dict(out.get('gap_analysis') or {})
    gaps['tables'] = [tables['gap_main']] + gap_guides
    out['gap_analysis'] = gaps

    road = dict(out.get('roadmap') or {})
    road['tables'] = [tables['roadmap']]
    road['content'] = ''
    road['paragraphs'] = [
        p for p in (road.get('paragraphs') or [])
        if str(p).strip() and not str(p).lstrip().startswith('#')
        and '|' not in str(p)
    ]
    out['roadmap'] = road

    kpi = dict(out.get('kpi_kri_framework') or {})
    # One main KPI table + separate formula/source table. Guides keep their
    # model row associations in the appendix, not as extra KPI-section tables.
    kpi['tables'] = [tables['kpi_main'], tables['kpi_formula']]
    kpi['paragraphs'] = [
        p for p in (kpi.get('paragraphs') or [])
        if str(p).strip() and not str(p).lstrip().startswith('#')
        and '|' not in str(p)
    ]
    out['kpi_kri_framework'] = kpi

    conf = dict(out.get('confidence_risk_register') or {})
    score = str(model.confidence_score or '').strip() or '—'
    just = str(model.confidence_justification or '').strip()
    conf['confidence_score'] = score
    if lang == 'ar':
        paras = [f'درجة الثقة: {score}']
    else:
        paras = [f'Confidence score: {score}']
    if just:
        paras.append(just)
    conf['paragraphs'] = paras
    conf['tables'] = [tables['confidence'], tables['risk']]
    out['confidence_risk_register'] = conf

    gov = dict(out.get('governance_ownership') or {})
    gov['schema'] = 'governance'
    gov['header'] = tables['governance']['header']
    gov['rows'] = tables['governance']['rows']
    gov['tables'] = [tables['governance']]
    out['governance_ownership'] = gov

    trace = dict(out.get('traceability_matrix') or {})
    trace['schema'] = 'traceability'
    trace['header'] = tables['traceability']['header']
    trace['rows'] = tables['traceability']['rows']
    trace['tables'] = [tables['traceability']]
    # Do not keep catalog-synthesized split mappings.
    trace['split_tables'] = []
    out['traceability_matrix'] = trace

    appx = dict(out.get('appendices') or {})
    # Both guide families use the same step-table layout already rendered
    # by the appendix writer. Keep gap and KPI guides associated by title.
    appx['gap_action_tables'] = list(gap_guides) + list(kpi_guides)
    appx['kpi_guide_tables'] = list(kpi_guides)
    appx['tables'] = list(gap_guides) + list(kpi_guides)
    out['appendices'] = appx
    return out


def rel37_preserve_compiler_content(
        sections: Optional[Dict[str, Any]],
        *,
        domain: str = '',
        lang: str = '',
        document_type: str = 'strategy',
        org_name: str = '',
        selected_frameworks: Optional[List[str]] = None,
) -> bool:
    model, blockers = load_validated_rel37_model(
        sections,
        domain=domain,
        lang=lang,
        document_type=document_type,
        org_name=org_name,
        selected_frameworks=selected_frameworks,
    )
    return model is not None and not blockers
