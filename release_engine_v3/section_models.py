"""PR-REL3 — typed canonical section models (structured data, not pipe tables)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.contracts import CanonicalSection, TableRow


@dataclass
class StrategyDocument:
    executive_summary: CanonicalSection
    vision_objectives: CanonicalSection
    strategic_pillars: CanonicalSection
    environment_threats: CanonicalSection
    gap_analysis: CanonicalSection
    roadmap: CanonicalSection
    kpi_kri: CanonicalSection
    confidence_risk: CanonicalSection
    governance_ownership: CanonicalSection
    traceability: CanonicalSection
    appendices: CanonicalSection

    def as_dict(self) -> Dict[str, CanonicalSection]:
        return {
            'executive_summary': self.executive_summary,
            'vision_objectives': self.vision_objectives,
            'pillars': self.strategic_pillars,
            'environment': self.environment_threats,
            'gap_analysis': self.gap_analysis,
            'roadmap': self.roadmap,
            'kpi_kri': self.kpi_kri,
            'confidence_risk': self.confidence_risk,
            'governance': self.governance_ownership,
            'traceability': self.traceability,
            'appendices': self.appendices,
        }


ExecutiveSummary = CanonicalSection
VisionObjectivesSection = CanonicalSection
StrategicPillarsSection = CanonicalSection
EnvironmentThreatsSection = CanonicalSection
GapAnalysisSection = CanonicalSection
RoadmapSection = CanonicalSection
KpiKriSection = CanonicalSection
ConfidenceRiskSection = CanonicalSection
GovernanceOwnershipSection = CanonicalSection
TraceabilitySection = CanonicalSection
AppendicesSection = CanonicalSection


_SECTION_TITLES_AR = {
    'executive_summary': 'الملخص التنفيذي',
    'vision_objectives': 'الرؤية والأهداف الاستراتيجية',
    'pillars': 'الركائز الاستراتيجية',
    'environment': 'البيئة والتهديدات',
    'gap_analysis': 'تحليل الفجوات',
    'roadmap': 'خارطة الطريق',
    'kpi_kri': 'مؤشرات الأداء والمخاطر',
    'confidence_risk': 'تقييم الثقة والمخاطر',
    'governance': 'الحوكمة والملكية',
    'traceability': 'مصفوفة التتبع',
    'appendices': 'الملاحق',
}

_LEGACY_KEY_MAP = {
    'vision': 'vision_objectives',
    'pillars': 'pillars',
    'environment': 'environment',
    'gaps': 'gap_analysis',
    'roadmap': 'roadmap',
    'kpis': 'kpi_kri',
    'confidence': 'confidence_risk',
    'governance': 'governance',
    'traceability': 'traceability',
    'executive_summary': 'executive_summary',
    'appendices': 'appendices',
}


def _parse_table_rows(text: str) -> Tuple[str, Tuple[TableRow, ...]]:
    """Split narrative from pipe-table rows."""
    lines = (text or '').splitlines()
    narrative_lines: List[str] = []
    table_lines: List[str] = []
    in_table = False
    for ln in lines:
        if ln.strip().startswith('|'):
            in_table = True
            table_lines.append(ln)
        elif in_table and not ln.strip():
            in_table = False
            narrative_lines.append(ln)
        elif not in_table:
            narrative_lines.append(ln)
    rows: List[TableRow] = []
    header_seen = False
    for ln in table_lines:
        if '---' in ln:
            header_seen = True
            continue
        if not ln.strip().startswith('|'):
            continue
        cells = tuple(c.strip() for c in ln.strip('|').split('|'))
        if not cells or all(not c for c in cells):
            continue
        if not header_seen and ('وصف' in ln or 'Metric' in ln or 'المبادرة' in ln):
            continue
        rows.append(TableRow(cells=cells))
    narrative = '\n'.join(narrative_lines).strip()
    return narrative, tuple(rows)


def _empty_section(key: str) -> CanonicalSection:
    return CanonicalSection(
        key=key,
        title=_SECTION_TITLES_AR.get(key, key),
        narrative='',
        table_rows=(),
    )


def build_strategy_document(
        legacy_sections: Optional[Dict[str, str]]) -> StrategyDocument:
    """Build typed StrategyDocument from legacy section dict."""
    canon: Dict[str, CanonicalSection] = {}
    src = dict(legacy_sections or {})
    for leg_key, body in src.items():
        if not isinstance(body, str) or str(leg_key).startswith('_'):
            continue
        ck = _LEGACY_KEY_MAP.get(str(leg_key).strip().lower())
        if not ck:
            continue
        narrative, rows = _parse_table_rows(body)
        canon[ck] = CanonicalSection(
            key=ck,
            title=_SECTION_TITLES_AR.get(ck, ck),
            narrative=narrative,
            table_rows=rows,
        )
    for key in _SECTION_TITLES_AR:
        if key not in canon:
            canon[key] = _empty_section(key)
    return StrategyDocument(
        executive_summary=canon['executive_summary'],
        vision_objectives=canon['vision_objectives'],
        strategic_pillars=canon['pillars'],
        environment_threats=canon['environment'],
        gap_analysis=canon['gap_analysis'],
        roadmap=canon['roadmap'],
        kpi_kri=canon['kpi_kri'],
        confidence_risk=canon['confidence_risk'],
        governance_ownership=canon['governance'],
        traceability=canon['traceability'],
        appendices=canon['appendices'],
    )


def _strip_embedded_section_headings(narrative: str, section_key: str) -> str:
    """Drop legacy ## headings embedded in narrative — title is rendered separately."""
    if not (narrative or '').strip():
        return ''
    drop_if = {
        'kpi_kri': ('مؤشر', 'kpi', 'kri', 'صيغ'),
        'vision_objectives': ('رؤية', 'أهداف', 'vision'),
        'pillars': ('ركائز', 'pillar'),
        'roadmap': ('خارطة', 'roadmap'),
        'traceability': ('تتبع', 'traceability'),
    }
    needles = drop_if.get(section_key, ())
    kept: List[str] = []
    for ln in narrative.splitlines():
        stripped = ln.strip()
        if stripped.startswith('#'):
            low = stripped.lower()
            if any(n in stripped or n in low for n in needles):
                continue
        kept.append(ln)
    return '\n'.join(kept).strip()


def canonical_legacy_sections_for_parity(
        canonical_sections: Dict[str, CanonicalSection]) -> Dict[str, str]:
    """Map typed canonical sections to legacy parity keys for preview drift checks."""
    canon_to_legacy = {
        'vision_objectives': 'vision',
        'pillars': 'pillars',
        'roadmap': 'roadmap',
        'kpi_kri': 'kpis',
        'traceability': 'traceability',
    }
    out: Dict[str, str] = {}
    for ck, lk in canon_to_legacy.items():
        sec = (canonical_sections or {}).get(ck)
        if not sec:
            continue
        rendered = section_to_markdown(sec)
        if rendered.strip():
            out[lk] = rendered
    return out


def section_to_markdown(section: CanonicalSection) -> str:
    """Render one canonical section to markdown (view only, not source of truth)."""
    parts: List[str] = []
    if section.title:
        parts.append(f'## {section.title}')
    narrative = _strip_embedded_section_headings(
        section.narrative or '', section.key)
    if narrative:
        parts.append(narrative)
    if section.table_rows:
        # infer header from first row width
        width = max(len(r.cells) for r in section.table_rows)
        if section.key == 'kpi_kri':
            header = ['#', 'وصف المؤشر', 'القيمة المستهدفة',
                      'صيغة الاحتساب', 'مصدر', 'تواتر']
        elif section.key == 'roadmap':
            header = ['المرحلة', 'الإطار الزمني', 'المبادرة',
                      'المالك', 'المخرج', 'الإطار']
        elif section.key == 'confidence_risk':
            header = ['المخاطرة', 'الاحتمال', 'الأثر', 'خطة المعالجة', 'المالك']
        elif section.key == 'traceability':
            header = ['المتطلب', 'الفجوة', 'المبادرة المرتبطة']
        else:
            header = [f'col{i+1}' for i in range(width)]
        header = header[:width]
        parts.append('| ' + ' | '.join(header) + ' |')
        parts.append('| ' + ' | '.join(['---'] * len(header)) + ' |')
        for row in section.table_rows:
            cells = list(row.cells)
            while len(cells) < len(header):
                cells.append('')
            parts.append('| ' + ' | '.join(cells[:len(header)]) + ' |')
    return '\n\n'.join(p for p in parts if p)


def strategy_document_to_markdown(doc: StrategyDocument) -> str:
    sections = doc.as_dict()
    order = (
        'executive_summary', 'vision_objectives', 'pillars', 'environment',
        'gap_analysis', 'roadmap', 'kpi_kri', 'confidence_risk',
        'governance', 'traceability', 'appendices',
    )
    return '\n\n'.join(
        section_to_markdown(sections[k])
        for k in order
        if sections.get(k) and (
            sections[k].narrative or sections[k].table_rows))


def rows_from_kpi_parser(text: str) -> Tuple[TableRow, ...]:
    from release_engine.kpi_model import _parse_kpi_rows
    _, rows = _parse_kpi_rows(text)
    return tuple(TableRow(cells=tuple(cells)) for cells in rows)


def enrich_kpi_section(section: CanonicalSection, raw_text: str) -> CanonicalSection:
    rows = rows_from_kpi_parser(raw_text)
    if rows:
        return CanonicalSection(
            key=section.key,
            title=section.title,
            narrative=section.narrative,
            table_rows=rows,
        )
    return section
