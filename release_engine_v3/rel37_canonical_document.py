"""REL37 CanonicalDocument — typed source of truth for Data / AI / DT strategy."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from release_engine_v3.rel37_schema_registry import (
    APPROVED_ACRONYMS,
    COVERAGE_REGISTRY_VERSION,
    FORMULA_BLOCK,
    GAP_GUIDE_HEADING,
    KPI_FORMULA_HEADERS,
    KPI_GUIDE_HEADING,
    KPI_GUIDES_BLOCK,
    KPI_MAIN_HEADERS,
    SCHEMA_VERSION,
    SO_HEADERS,
    header_line,
    leakage_terms,
)

# Derived / runtime fields that must never enter model_hash input.
HASH_EXCLUDED_FIELDS = frozenset({
    'model_hash',
    'prose_hash',
    'source_hash',
    'preview_hash',
    'docx_hash',
    'pdf_hash',
    'evidence',
    'evidence_hashes',
    'validation_passed',
    'blockers',
    'missing_families',
    'task_id',
    'runtime_diagnostics',
    'sector',
    'validation_timestamps',
    'generated_timestamps',
    'export_debug',
    'last_render_hash',
})

_AR_LETTER = re.compile(r'[\u0600-\u06FF]')
_SPLIT_BENEFICIARY = re.compile(r'المست\s+فيد')


def _stable_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class SORow:
    number: int
    objective: str
    target: str
    rationale: str
    timeframe: str
    family: str
    framework: str = ''

    def cells(self) -> Tuple[str, ...]:
        return (
            str(self.number), self.objective, self.target,
            self.rationale, self.timeframe,
        )


@dataclass(frozen=True)
class PillarRow:
    number: int
    title: str
    description: str
    family: str
    owner: str


@dataclass(frozen=True)
class PillarInitiativeRow:
    pillar_number: int
    initiative: str
    description: str
    output: str
    owner: str
    pillar_family: str

    def cells(self) -> Tuple[str, ...]:
        return (self.initiative, self.description, self.output, self.owner)


@dataclass(frozen=True)
class GapRow:
    number: int
    gap_label: str
    description: str
    priority: str
    status: str
    family: str
    framework: str = ''

    def cells(self) -> Tuple[str, ...]:
        return (
            str(self.number), self.gap_label, self.description,
            self.priority, self.status,
        )


@dataclass(frozen=True)
class GuideStep:
    step: int
    action: str
    owner: str
    timeline: str
    output: str

    def cells(self) -> Tuple[str, ...]:
        return (str(self.step), self.action, self.owner, self.timeline, self.output)


@dataclass(frozen=True)
class GapGuide:
    number: int
    family: str
    heading: str
    steps: Tuple[GuideStep, ...]


@dataclass(frozen=True)
class KpiRow:
    number: int
    description: str
    type: str
    target: str
    formula: str
    source: str
    frequency: str
    owner: str
    family: str
    framework: str = ''

    def cells(self) -> Tuple[str, ...]:
        return (
            str(self.number), self.description, self.type, self.target,
            self.formula, self.source, self.frequency, self.owner,
        )


@dataclass(frozen=True)
class KpiFormulaRow:
    number: int
    kpi: str
    formula: str
    data_source: str
    family: str = ''

    def cells(self) -> Tuple[str, ...]:
        return (str(self.number), self.kpi, self.formula, self.data_source)


@dataclass(frozen=True)
class KpiGuide:
    number: int
    family: str
    heading: str
    steps: Tuple[GuideStep, ...]


@dataclass(frozen=True)
class RoadmapRow:
    phase: str
    period: str
    initiative: str
    owner: str
    deliverable: str
    framework: str
    family: str

    def cells(self) -> Tuple[str, ...]:
        return (
            self.phase, self.period, self.initiative,
            self.owner, self.deliverable, self.framework,
        )


@dataclass(frozen=True)
class ConfidenceRow:
    factor: str
    weight: str
    score: str
    rationale: str

    def cells(self) -> Tuple[str, ...]:
        return (self.factor, self.weight, self.score, self.rationale)


@dataclass(frozen=True)
class RiskRow:
    risk: str
    impact: str
    mitigation: str
    owner: str

    def cells(self) -> Tuple[str, ...]:
        return (self.risk, self.impact, self.mitigation, self.owner)


@dataclass(frozen=True)
class TraceabilityRow:
    number: int
    initiative: str
    gap: str
    kpi: str
    framework: str
    family: str = ''

    def cells(self) -> Tuple[str, ...]:
        return (
            str(self.number), self.initiative, self.gap,
            self.kpi, self.framework,
        )


@dataclass(frozen=True)
class GovernanceRow:
    role: str
    responsibility: str
    cadence: str
    owner: str

    def cells(self) -> Tuple[str, ...]:
        return (self.role, self.responsibility, self.cadence, self.owner)


@dataclass
class CanonicalDocument:
    schema_version: str = SCHEMA_VERSION
    document_type: str = 'strategy'
    domain: str = ''
    lang: str = 'ar'
    selected_frameworks: Tuple[str, ...] = ()
    org_name: str = ''
    sector: str = ''
    task_id: str = ''
    vision: str = ''
    environment_narrative: str = ''
    strategic_objectives: Tuple[SORow, ...] = ()
    pillars: Tuple[PillarRow, ...] = ()
    pillar_initiatives: Tuple[PillarInitiativeRow, ...] = ()
    gaps: Tuple[GapRow, ...] = ()
    gap_guides: Tuple[GapGuide, ...] = ()
    kpis: Tuple[KpiRow, ...] = ()
    kpi_formula_source: Tuple[KpiFormulaRow, ...] = ()
    kpi_guides: Tuple[KpiGuide, ...] = ()
    roadmap: Tuple[RoadmapRow, ...] = ()
    confidence: Tuple[ConfidenceRow, ...] = ()
    risks: Tuple[RiskRow, ...] = ()
    confidence_score: str = '78%'
    confidence_justification: str = ''
    governance: Tuple[GovernanceRow, ...] = ()
    traceability: Tuple[TraceabilityRow, ...] = ()
    required_families: Tuple[str, ...] = ()
    satisfied_families: Tuple[str, ...] = ()
    model_hash: str = ''
    prose_hash: str = ''
    validation_passed: bool = False
    blockers: Tuple[str, ...] = ()
    runtime_diagnostics: Dict[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> Dict[str, Any]:
        """Persistence projection. Includes task_id; excludes derived hashes."""
        return {
            'schema_version': self.schema_version,
            'coverage_registry_version': COVERAGE_REGISTRY_VERSION,
            'document_type': self.document_type,
            'domain': self.domain,
            'lang': self.lang,
            'selected_frameworks': list(self.selected_frameworks),
            'org_name': self.org_name,
            'sector': self.sector,
            'task_id': self.task_id,
            'vision': self.vision,
            'environment_narrative': self.environment_narrative,
            'strategic_objectives': [asdict(row) for row in self.strategic_objectives],
            'pillars': [asdict(row) for row in self.pillars],
            'pillar_initiatives': [asdict(row) for row in self.pillar_initiatives],
            'gaps': [asdict(row) for row in self.gaps],
            'gap_guides': [asdict(row) for row in self.gap_guides],
            'kpis': [asdict(row) for row in self.kpis],
            'kpi_formula_source': [asdict(row) for row in self.kpi_formula_source],
            'kpi_guides': [asdict(row) for row in self.kpi_guides],
            'roadmap': [asdict(row) for row in self.roadmap],
            'confidence': [asdict(row) for row in self.confidence],
            'risks': [asdict(row) for row in self.risks],
            'confidence_score': self.confidence_score,
            'confidence_justification': self.confidence_justification,
            'governance': [asdict(row) for row in self.governance],
            'traceability': [asdict(row) for row in self.traceability],
            'required_families': list(self.required_families),
            'satisfied_families': list(self.satisfied_families),
        }

    def canonical_hash_payload(self) -> Dict[str, Any]:
        """Stable model-authority payload. Never includes derived hash fields."""
        persist = self.canonical_payload()
        payload = {
            key: value
            for key, value in persist.items()
            if key not in HASH_EXCLUDED_FIELDS
        }
        payload['selected_frameworks'] = sorted(
            str(item).strip().lower() for item in payload.get('selected_frameworks') or []
            if str(item).strip()
        )
        payload['required_families'] = list(self.required_families)
        payload['satisfied_families'] = list(self.satisfied_families)
        payload['coverage_registry_version'] = COVERAGE_REGISTRY_VERSION
        payload['schema_version'] = self.schema_version
        payload['org_name'] = self.org_name
        return payload

    def compute_model_hash(self) -> str:
        return sha256_text(_stable_json(self.canonical_hash_payload()))

    def compute_hashes(self) -> 'CanonicalDocument':
        prose = {
            'vision': self.vision,
            'environment_narrative': self.environment_narrative,
            'confidence_justification': self.confidence_justification,
            'org_name': self.org_name,
        }
        self.model_hash = self.compute_model_hash()
        self.prose_hash = sha256_text(_stable_json(prose))
        return self

    def missing_families(self) -> Tuple[str, ...]:
        have = set(self.satisfied_families)
        return tuple(fam for fam in self.required_families if fam not in have)

    def generated_text_blob(self) -> str:
        parts: List[str] = [
            self.vision, self.environment_narrative,
            self.confidence_justification, self.confidence_score,
        ]
        for row in self.strategic_objectives:
            parts.extend(row.cells())
        for row in self.pillars:
            parts.extend((row.title, row.description, row.owner))
        for row in self.pillar_initiatives:
            parts.extend(row.cells())
        for row in self.gaps:
            parts.extend(row.cells())
        for guide in self.gap_guides:
            parts.append(guide.heading)
            for step in guide.steps:
                parts.extend(step.cells())
        for row in self.kpis:
            parts.extend(row.cells())
        for row in self.kpi_formula_source:
            parts.extend(row.cells())
        for guide in self.kpi_guides:
            parts.append(guide.heading)
            for step in guide.steps:
                parts.extend(step.cells())
        for row in self.roadmap:
            parts.extend(row.cells())
        for row in self.confidence:
            parts.extend(row.cells())
        for row in self.risks:
            parts.extend(row.cells())
        for row in self.governance:
            parts.extend(row.cells())
        for row in self.traceability:
            parts.extend(row.cells())
        return '\n'.join(parts)

    def guide_association_blockers(self) -> List[str]:
        """1:1 guide-to-row numbers and required non-empty steps."""
        blockers: List[str] = []

        def _assoc(rows, guides, kind: str) -> None:
            row_ids = [int(row.number) for row in rows]
            guide_ids = [int(guide.number) for guide in guides]
            if len(guide_ids) != len(set(guide_ids)):
                blockers.append(f'{kind}_guide_duplicate_association')
            extra = set(guide_ids) - set(row_ids)
            missing = set(row_ids) - set(guide_ids)
            if extra:
                blockers.append(f'{kind}_guide_orphan_association')
            if missing:
                blockers.append(f'{kind}_guide_missing_row_association')
            wrong = [
                gid for gid, row_id in zip(guide_ids, row_ids)
                if gid != row_id
            ]
            if wrong and not extra and not missing and len(guide_ids) == len(row_ids):
                blockers.append(f'{kind}_guide_wrong_row_association')
            for guide in guides:
                if not guide.steps:
                    blockers.append(f'{kind}_guide_steps_missing:{guide.number}')
                    continue
                for step in guide.steps:
                    if (
                        not str(step.action or '').strip()
                        or not str(step.output or '').strip()
                    ):
                        blockers.append(
                            f'{kind}_guide_step_incomplete:'
                            f'{guide.number}:{step.step}'
                        )

        _assoc(self.gaps, self.gap_guides, 'gap')
        _assoc(self.kpis, self.kpi_guides, 'kpi')
        return blockers

    def validate(self) -> List[str]:
        blockers: List[str] = []
        if self.schema_version != SCHEMA_VERSION:
            blockers.append(f'schema_version_invalid:{self.schema_version}')
        if self.document_type != 'strategy':
            blockers.append(f'document_type_invalid:{self.document_type}')
        if self.domain not in ('data', 'ai', 'dt'):
            blockers.append(f'domain_not_phase1:{self.domain}')
        if self.lang not in ('ar', 'en'):
            blockers.append(f'lang_invalid:{self.lang}')
        if not self.kpis:
            blockers.append('kpi_main_missing')
        if len(self.kpi_formula_source) not in (0, len(self.kpis)) and self.kpi_formula_source:
            if len(self.kpi_formula_source) > len(self.kpis) and not self.kpis:
                blockers.append('kpi_formula_without_main')
        if self.kpi_formula_source and not self.kpis:
            blockers.append('kpi_formula_without_main')
        if len(self.kpi_guides) != len(self.kpis):
            blockers.append(
                f'kpi_guide_count_mismatch:{len(self.kpi_guides)}:{len(self.kpis)}')
        if len(self.gap_guides) != len(self.gaps):
            blockers.append(
                f'gap_guide_count_mismatch:{len(self.gap_guides)}:{len(self.gaps)}')
        blockers.extend(self.guide_association_blockers())
        missing = self.missing_families()
        if missing:
            blockers.append('coverage_missing:' + ','.join(missing))
        roadmap_families = [row.family for row in self.roadmap if row.family]
        if len(roadmap_families) != len(set(roadmap_families)):
            blockers.append('roadmap_duplicate_families')
        seen: set = set()
        restarted = False
        for fam in roadmap_families:
            if fam in seen:
                restarted = True
            seen.add(fam)
        # restart = family appears after a later distinct family then again
        last_index: Dict[str, int] = {}
        for idx, fam in enumerate(roadmap_families):
            prev = last_index.get(fam)
            if prev is not None and idx - prev > 1:
                gap_fams = set(roadmap_families[prev + 1:idx])
                if gap_fams - {fam}:
                    restarted = True
            last_index[fam] = idx
        if restarted:
            blockers.append('roadmap_family_restarted')
        required_road = set(self.required_families)
        if required_road - set(roadmap_families):
            blockers.append(
                'roadmap_family_coverage_missing:'
                + ','.join(sorted(required_road - set(roadmap_families))))
        so_header = header_line('so', self.lang)
        kpi_header = header_line('kpi_main', self.lang)
        if so_header != '| ' + ' | '.join(SO_HEADERS[self.lang]) + ' |':
            blockers.append('so_header_schema_mismatch')
        if kpi_header != '| ' + ' | '.join(KPI_MAIN_HEADERS[self.lang]) + ' |':
            blockers.append('kpi_header_schema_mismatch')
        blob = self.generated_text_blob()
        if _SPLIT_BENEFICIARY.search(blob):
            blockers.append('dt_beneficiary_token_split')
        deny = leakage_terms(self.domain)
        hits = detect_leakage(blob, deny, org_name=self.org_name)
        if hits:
            blockers.append('cross_domain_leakage:' + ','.join(hits))
        if self.lang == 'en':
            stripped = blob.replace(self.org_name or '', '')
            if _AR_LETTER.search(stripped):
                blockers.append('english_contains_arabic_generated_text')
        expected_so = header_line('so', self.lang)
        expected_kpi = header_line('kpi_main', self.lang)
        expected_formula = header_line('kpi_formula', self.lang)
        expected_guide = header_line('guide', self.lang)
        expected_road = header_line('roadmap', self.lang)
        for label, expected in (
                ('so', expected_so),
                ('kpi_main', expected_kpi),
                ('kpi_formula', expected_formula),
                ('guide', expected_guide),
                ('roadmap', expected_road)):
            if not expected.startswith('| '):
                blockers.append(f'header_invalid:{label}')
        if self.lang == 'ar':
            if 'الهدف الاستراتيجي' not in expected_so:
                blockers.append('arabic_so_header_missing')
            if 'المصدر' not in expected_kpi:
                blockers.append('arabic_kpi_source_header_missing')
        else:
            if 'Strategic Objective' not in expected_so:
                blockers.append('english_so_header_missing')
            if 'KPI Description' not in expected_kpi:
                blockers.append('english_kpi_header_missing')
        if KPI_FORMULA_HEADERS[self.lang][1] == KPI_MAIN_HEADERS[self.lang][1]:
            blockers.append('formula_header_collides_with_kpi_main')
        self.blockers = tuple(blockers)
        self.validation_passed = not blockers
        return blockers

    def to_dict(self) -> Dict[str, Any]:
        payload = self.canonical_payload()
        payload['model_hash'] = self.model_hash
        payload['prose_hash'] = self.prose_hash
        payload['validation_passed'] = self.validation_passed
        payload['blockers'] = list(self.blockers)
        payload['missing_families'] = list(self.missing_families())
        return payload

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> 'CanonicalDocument':
        data = dict(payload or {})
        doc = cls(
            schema_version=str(data.get('schema_version') or SCHEMA_VERSION),
            document_type=str(data.get('document_type') or 'strategy'),
            domain=str(data.get('domain') or ''),
            lang=str(data.get('lang') or 'ar'),
            selected_frameworks=tuple(data.get('selected_frameworks') or ()),
            org_name=str(data.get('org_name') or ''),
            sector=str(data.get('sector') or ''),
            task_id=str(data.get('task_id') or ''),
            vision=str(data.get('vision') or ''),
            environment_narrative=str(data.get('environment_narrative') or ''),
            strategic_objectives=tuple(SORow(**row) for row in data.get('strategic_objectives') or ()),
            pillars=tuple(PillarRow(**row) for row in data.get('pillars') or ()),
            pillar_initiatives=tuple(
                PillarInitiativeRow(**row) for row in data.get('pillar_initiatives') or ()),
            gaps=tuple(GapRow(**row) for row in data.get('gaps') or ()),
            gap_guides=tuple(
                GapGuide(
                    number=int(g['number']),
                    family=str(g.get('family') or ''),
                    heading=str(g.get('heading') or ''),
                    steps=tuple(GuideStep(**s) for s in g.get('steps') or ()),
                )
                for g in data.get('gap_guides') or ()
            ),
            kpis=tuple(KpiRow(**row) for row in data.get('kpis') or ()),
            kpi_formula_source=tuple(
                KpiFormulaRow(**row) for row in data.get('kpi_formula_source') or ()),
            kpi_guides=tuple(
                KpiGuide(
                    number=int(g['number']),
                    family=str(g.get('family') or ''),
                    heading=str(g.get('heading') or ''),
                    steps=tuple(GuideStep(**s) for s in g.get('steps') or ()),
                )
                for g in data.get('kpi_guides') or ()
            ),
            roadmap=tuple(RoadmapRow(**row) for row in data.get('roadmap') or ()),
            confidence=tuple(ConfidenceRow(**row) for row in data.get('confidence') or ()),
            risks=tuple(RiskRow(**row) for row in data.get('risks') or ()),
            confidence_score=str(data.get('confidence_score') or '78%'),
            confidence_justification=str(data.get('confidence_justification') or ''),
            governance=tuple(GovernanceRow(**row) for row in data.get('governance') or ()),
            traceability=tuple(
                TraceabilityRow(**row) for row in data.get('traceability') or ()),
            required_families=tuple(data.get('required_families') or ()),
            satisfied_families=tuple(data.get('satisfied_families') or ()),
            model_hash=str(data.get('model_hash') or ''),
            prose_hash=str(data.get('prose_hash') or ''),
            validation_passed=bool(data.get('validation_passed')),
            blockers=tuple(data.get('blockers') or ()),
            runtime_diagnostics=dict(data.get('runtime_diagnostics') or {}),
        )
        return doc


def detect_leakage(
        text: str,
        terms: Sequence[str],
        *,
        org_name: str = '',
) -> Tuple[str, ...]:
    blob = (text or '').replace(org_name or '', '')
    hits: List[str] = []
    for term in terms:
        token = str(term or '').strip()
        if not token:
            continue
        if re.search(r'[\u0600-\u06FF]', token):
            if token in blob:
                hits.append(token)
            continue
        if re.search(r'(?<![A-Za-z])' + re.escape(token) + r'(?![A-Za-z])', blob):
            hits.append(token)
    return tuple(dict.fromkeys(hits))


def default_guide_heading(kind: str, lang: str, number: int) -> str:
    if kind == 'gap':
        return GAP_GUIDE_HEADING[lang].format(n=number)
    return KPI_GUIDE_HEADING[lang].format(n=number)


def formula_block_title(lang: str) -> str:
    return FORMULA_BLOCK[lang]


def kpi_guides_block_title(lang: str) -> str:
    return KPI_GUIDES_BLOCK[lang]
