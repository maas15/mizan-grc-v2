"""PR-REL3.2 — typed CanonicalStrategyDocument (compiler authority, not AI Markdown)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from release_engine_v3.rel32_registries import (
    REL32_CANONICAL_HEADINGS,
    REL32_SECTION_ORDER,
)


@dataclass(frozen=True)
class StrategicObjectiveRow:
    number: str
    objective: str
    target: str
    rationale: str
    timeframe: str
    family: str = ''


@dataclass(frozen=True)
class PillarRow:
    heading: str
    family: str = ''


@dataclass(frozen=True)
class PillarInitiativeRow:
    initiative: str
    description: str
    output: str
    owner: str
    pillar_family: str = ''


@dataclass(frozen=True)
class GapRow:
    number: str
    gap_label: str
    description: str
    priority: str
    status: str
    family: str = ''
    framework: str = ''


@dataclass(frozen=True)
class GapTreatmentRow:
    gap_label: str
    step: str
    action: str
    owner: str
    timeframe: str
    output: str


@dataclass(frozen=True)
class RoadmapRow:
    phase: str
    period: str
    initiative: str
    owner: str
    output: str
    framework: str
    family: str = ''


@dataclass(frozen=True)
class KpiRow:
    number: str
    name: str
    kpi_type: str
    target: str
    formula: str
    source: str
    frequency: str
    owner: str = ''
    family: str = ''


@dataclass(frozen=True)
class KpiFormulaRow:
    number: str
    name: str
    formula: str
    source: str


@dataclass(frozen=True)
class RiskRegisterRow:
    number: str
    risk: str
    likelihood: str
    impact: str
    treatment: str
    owner: str
    theme: str = ''


@dataclass(frozen=True)
class ConfidenceFactorRow:
    factor: str
    weight: str
    grade: str
    contribution: str


@dataclass(frozen=True)
class GovernanceRoleRow:
    role: str
    scope: str
    accountability: str
    escalation: str
    framework: str


@dataclass(frozen=True)
class TraceabilityGapRow:
    framework: str
    capability: str
    gap: str
    family: str = ''


@dataclass(frozen=True)
class TraceabilityInitiativeRow:
    framework: str
    capability: str
    gap: str
    initiative: str
    metric: str
    risk: str
    family: str = ''


@dataclass
class CanonicalStrategyDocument:
    """Typed canonical model — sole structural authority for final output."""

    metadata: Dict[str, Any] = field(default_factory=dict)
    vision: str = ''
    strategic_objectives: Tuple[StrategicObjectiveRow, ...] = ()
    pillars: Tuple[PillarRow, ...] = ()
    pillar_initiatives: Tuple[PillarInitiativeRow, ...] = ()
    environment_context: str = ''
    gaps: Tuple[GapRow, ...] = ()
    gap_treatments: Tuple[GapTreatmentRow, ...] = ()
    roadmap: Tuple[RoadmapRow, ...] = ()
    kpis: Tuple[KpiRow, ...] = ()
    kpi_formulas: Tuple[KpiFormulaRow, ...] = ()
    risk_register: Tuple[RiskRegisterRow, ...] = ()
    confidence_factors: Tuple[ConfidenceFactorRow, ...] = ()
    confidence_score: str = ''
    confidence_rationale: str = ''
    governance_roles: Tuple[GovernanceRoleRow, ...] = ()
    traceability_gap_matrix: Tuple[TraceabilityGapRow, ...] = ()
    traceability_initiative_matrix: Tuple[TraceabilityInitiativeRow, ...] = ()
    appendices: str = ''
    compiler_version: str = 'rel32'
    source_authority: str = 'canonical_compiler'

    def canonical_headings(self) -> Dict[str, str]:
        return dict(REL32_CANONICAL_HEADINGS)

    def validate_schema(self) -> List[str]:
        """Return schema blockers (empty list = valid)."""
        blockers: List[str] = []
        if len(self.strategic_objectives) < 6:
            blockers.append('rel32_schema:insufficient_objectives')
        if len(self.pillar_initiatives) < 8:
            blockers.append('rel32_schema:insufficient_pillar_initiatives')
        if len(self.gaps) < 5:
            blockers.append('rel32_schema:insufficient_gaps')
        if len(self.roadmap) < 10:
            blockers.append('rel32_schema:insufficient_roadmap_rows')
        if len(self.kpis) < 5:
            blockers.append('rel32_schema:insufficient_kpis')
        if not self.confidence_score:
            blockers.append('rel32_schema:missing_confidence_score')
        if not self.confidence_rationale:
            blockers.append('rel32_schema:missing_confidence_rationale')
        if len(self.governance_roles) < 5:
            blockers.append('rel32_schema:insufficient_governance_roles')
        if len(self.traceability_initiative_matrix) < 8:
            blockers.append('rel32_schema:insufficient_traceability')
        for key, title in REL32_CANONICAL_HEADINGS.items():
            if not title:
                blockers.append(f'rel32_schema:missing_heading:{key}')
        return blockers

    def to_diag(self) -> Dict[str, Any]:
        return {
            'compiler_version': self.compiler_version,
            'source_authority': self.source_authority,
            'objectives': len(self.strategic_objectives),
            'pillar_initiatives': len(self.pillar_initiatives),
            'gaps': len(self.gaps),
            'roadmap_rows': len(self.roadmap),
            'kpis': len(self.kpis),
            'risk_register': len(self.risk_register),
            'confidence_factors': len(self.confidence_factors),
            'governance_roles': len(self.governance_roles),
            'traceability_rows': len(self.traceability_initiative_matrix),
        }


def rel32_heading_for(section_key: str) -> str:
    return REL32_CANONICAL_HEADINGS.get(section_key, section_key)


def rel32_section_order() -> Tuple[str, ...]:
    return REL32_SECTION_ORDER
