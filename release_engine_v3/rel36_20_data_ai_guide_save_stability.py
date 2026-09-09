"""REL36.20 — Data/AI save-gate + guide-completeness stabilization.

Staging bilingual validation on REL36.19.1 (``94936cc``) held language
parity for Cyber / Arabic Data / Arabic AI, but English Data / English
AI and Arabic AI SDAIA 5-attempt failed the unchanged save / synth
gates:

* ``data_roadmap_balance_missing:privacy_governance`` — REL36.7 never
  inserts that family; REL36.10 / REL36.15 registry repair is
  Arabic-only, so English NDMO+PDPL roadmaps miss detector-visible
  ``privacy governance``.
* ``synth_failed:vision`` / ``synth_failed:pillars`` — REL36.16 / 17
  are Cyber-only; English Data/AI rely on AI-first synthesizers that
  fail-close after one cycle.
* ``Gap Implementation Guides`` / ``KPI Assessment Guidelines`` —
  ``count_gap_guides`` / ``synthesize_kpi_depth`` require exact
  ``#### Gap #N Implementation Guide`` (or Arabic
  ``#### دليل تنفيذ الفجوة رقم N``) plus one
  ``### KPI Assessment Guidelines`` / ``### أدلة تقييم مؤشرات الأداء``
  heading and one per-row ``#### KPI #N Assessment Guide``. Data/AI
  have no deterministic completer.

This module repairs before the unchanged save / synth gates. It does
not mark gates passed and does not apply to Cyber.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    _splice_rows,
    detect_balance_families,
    missing_balance_families,
    required_balance_families,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    _DATA_FAMILY_ROWS_AR,
    official_data_missing_families,
    official_data_required_families,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_20_DATA_EN_ROADMAP_GUIDE_STABILITY_TAG = (
    '[REL36.20-DATA-EN-ROADMAP-GUIDE-STABILITY]')
REL36_20_EN_DATA_AI_CORE_SYNTH_STABILITY_TAG = (
    '[REL36.20-EN-DATA-AI-CORE-SYNTH-STABILITY]')
REL36_20_DATA_AI_GUIDE_COMPLETENESS_TAG = (
    '[REL36.20-DATA-AI-GUIDE-COMPLETENESS]')

_MIN_SO = 4
_MIN_PILLARS = 3
_MIN_INITIATIVES = 3

_SO_HEADER_EN = (
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |')
_SO_SEP = '|---|---|---|---|---|'
_PILLAR_HEADER_EN = (
    '| # | Initiative | Description | Expected Deliverable | Owner |')
_PILLAR_SEP = '|---|---|---|---|---|'

_GAP_GUIDE_HEADING_EN = re.compile(
    r'^####\s*Gap\s*#?\d+\s*Implementation Guide\b',
    re.IGNORECASE | re.MULTILINE,
)
_GAP_GUIDE_HEADING_AR = re.compile(
    r'^####\s*دليل تنفيذ الفجوة\s*(?:رقم|#)?\s*\d+',
    re.MULTILINE,
)
_KPI_GUIDES_HEADING_EN = re.compile(
    r'^###\s*KPI Assessment Guidelines\s*$',
    re.IGNORECASE | re.MULTILINE,
)
_KPI_GUIDES_HEADING_AR = re.compile(
    r'^###\s*أدلة تقييم مؤشرات الأداء\s*$',
    re.MULTILINE,
)
_PER_KPI_GUIDE_EN = re.compile(
    r'^####\s*KPI\s*#\s*\d+\s*Assessment Guide\s*$',
    re.IGNORECASE | re.MULTILINE,
)
_PER_KPI_GUIDE_AR = re.compile(
    r'^####\s*دليل تقييم المؤشر رقم\s*\d+\s*$',
    re.MULTILINE,
)
_ARABIC_CHAR_RE = re.compile(r'[\u0600-\u06FF]')
_ARABIC_HEADER_RE = re.compile(
    r'(?m)^#{1,4}\s*.*[\u0600-\u06FF]')
_LEAK_TERMS = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
_ALLOWED_ACRONYMS = frozenset({
    'NDMO', 'PDPL', 'SDAIA', 'MLOps', 'KPI', 'AI', 'DGA',
})

_DATA_FAMILY_ROWS_EN = {
    'data_quality': (
        '| Phase 1: Establish | 1-6 months | '
        'Launch the data quality management program | Data Quality Manager | '
        'Approved data quality metrics and data quality management dashboard | '
        'NDMO |'),
    'data_catalog': (
        '| Phase 1: Establish | 1-6 months | '
        'Establish the enterprise data catalog | Data Catalog Owner | '
        'Approved data catalog covering critical data assets | NDMO |'),
    'data_lifecycle': (
        '| Phase 1: Establish | 1-6 months | '
        'Formalize the data lifecycle operating model | Data Steward | '
        'Approved data lifecycle policy covering create, store, use, '
        'share, archive, and destroy | NDMO |'),
    'privacy_governance': (
        '| Phase 1: Establish | 1-6 months | '
        'Establish privacy governance operating model for personal data '
        'protection | Data Protection Officer | '
        'Approved privacy governance charter, roles, and personal data '
        'protection escalation model | PDPL |'),
    'personal_data_classification': (
        '| Phase 1: Establish | 1-6 months | '
        'Classify personal data by sensitivity | Data Protection Officer | '
        'Approved personal data classification register | PDPL |'),
    'consent_management': (
        '| Phase 2: Enable | 6-12 months | '
        'Deploy the consent management operating model | '
        'Data Protection Officer | '
        'Live consent management register with withdrawal evidence | PDPL |'),
    'data_subject_rights': (
        '| Phase 2: Enable | 6-12 months | '
        'Operationalize data subject rights fulfillment | '
        'Data Protection Officer | '
        'Data subject rights fulfillment SLA with evidence pack | PDPL |'),
    'breach_notification': (
        '| Phase 2: Enable | 6-12 months | '
        'Operationalize personal data breach notification | '
        'Data Protection Officer | '
        'Personal data breach notification runbook with 72-hour evidence | '
        'PDPL |'),
}

_DATA_OWNERS_EN = (
    'Data Governance Manager',
    'Data Quality Manager',
    'Data Protection Officer',
    'Data Catalog Owner',
    'Data Steward',
)
_AI_OWNERS_EN = (
    'AI Governance Manager',
    'Model Owner',
    'Model Risk Manager',
    'Data Scientist',
    'MLOps Lead',
    'Compliance Officer',
)
_DATA_OWNERS_AR = (
    'مدير حوكمة البيانات',
    'مدير جودة البيانات',
    'مسؤول حماية البيانات',
    'مالك كتالوج البيانات',
    'أمين البيانات',
)
_AI_OWNERS_AR = (
    'مدير حوكمة الذكاء الاصطناعي',
    'مالك نموذج الذكاء الاصطناعي',
    'مدير مخاطر النماذج',
    'مسؤول الامتثال',
    'قائد MLOps',
)

_DATA_SO_ROWS = (
    ('Publish the enterprise data catalog covering critical assets',
     '100% of critical data assets cataloged',
     'NDMO requires a governed catalog as the system of record',
     '12 months'),
    ('Operationalize personal data protection and privacy governance',
     'Approved privacy governance charter and DPO operating model',
     'PDPL requires a named privacy governance owner',
     '9 months'),
    ('Classify personal data and enforce consent management',
     'All personal-data processing activities classified and consented',
     'PDPL consent and classification controls must be evidenced',
     '12 months'),
    ('Fulfill data subject rights within published SLAs',
     '95% of data-subject requests closed within the SLA',
     'PDPL data-subject rights require a measurable fulfillment path',
     '12 months'),
)

_AI_SO_ROWS = (
    ('Establish SDAIA-aligned AI governance operating model',
     'Approved AI governance charter and model inventory',
     'SDAIA requires accountable AI ownership before scale',
     '9 months'),
    ('Operationalize model risk management for production models',
     '100% of production models have a named Model Risk Manager',
     'SDAIA model-risk controls must be evidenced per model',
     '12 months'),
    ('Publish AI ethics and human-oversight procedures',
     'Human-oversight procedure approved for high-risk AI use cases',
     'SDAIA ethics and oversight expectations require written controls',
     '12 months'),
    ('Stand up MLOps change-control for model promotion',
     'All production promotions pass MLOps change-control evidence',
     'SDAIA operational excellence requires controlled model release',
     '12 months'),
)

_DATA_PILLARS = (
    ('Data Catalog and Lifecycle',
     (
         ('Stand up the enterprise data catalog',
          'Register critical data assets with owners and quality rules',
          'Approved data catalog covering critical assets',
          'Data Catalog Owner'),
         ('Formalize data lifecycle controls',
          'Define create, store, use, share, archive, and destroy steps',
          'Approved data lifecycle operating model',
          'Data Steward'),
         ('Assign data stewards per domain',
          'Name stewards for finance, customer, and operations data',
          'Signed data-steward RACI',
          'Data Governance Manager'),
     )),
    ('Privacy Governance and PDPL Controls',
     (
         ('Establish privacy governance operating model',
          'Name the Data Protection Officer and escalation path',
          'Approved privacy governance charter',
          'Data Protection Officer'),
         ('Classify personal data by sensitivity',
          'Tag personal-data processing with PDPL sensitivity labels',
          'Personal data classification register',
          'Data Protection Officer'),
         ('Deploy consent management',
          'Capture, evidence, and withdraw consent for personal data',
          'Live consent management register',
          'Data Protection Officer'),
     )),
    ('Data Subject Rights and Quality',
     (
         ('Fulfill data subject rights',
          'Process access, correction, and erasure requests to SLA',
          'Data subject rights fulfillment evidence pack',
          'Data Protection Officer'),
         ('Notify personal-data breaches',
          'Run the 72-hour personal-data breach notification path',
          'Breach notification runbook with evidence',
          'Data Protection Officer'),
         ('Measure data quality for cataloged assets',
          'Track completeness and accuracy for critical data assets',
          'Monthly data-quality scorecard',
          'Data Quality Manager'),
     )),
)

_AI_PILLARS = (
    ('AI Governance and Accountability',
     (
         ('Publish the AI governance charter',
          'Define SDAIA-aligned roles, inventory, and decision rights',
          'Approved AI governance charter',
          'AI Governance Manager'),
         ('Inventory production and high-risk models',
          'Register each model with owner, purpose, and risk tier',
          'Complete AI model inventory',
          'Model Owner'),
         ('Assign model accountability',
          'Name a Model Owner and Model Risk Manager per production model',
          'Signed model-accountability RACI',
          'AI Governance Manager'),
     )),
    ('Model Risk and Ethics',
     (
         ('Operationalize model risk reviews',
          'Review bias, drift, and residual risk before promotion',
          'Model-risk review pack per production model',
          'Model Risk Manager'),
         ('Publish AI ethics procedures',
          'Document fairness, transparency, and prohibited-use rules',
          'Approved AI ethics procedure',
          'Compliance Officer'),
         ('Enforce human oversight',
          'Require human review for high-risk AI decisions',
          'Human-oversight evidence log',
          'Compliance Officer'),
     )),
    ('MLOps and Model Operations',
     (
         ('Stand up MLOps change-control',
          'Gate model promotion through tested change-control',
          'MLOps change-control evidence pack',
          'MLOps Lead'),
         ('Monitor production model quality',
          'Track drift, performance, and incident response',
          'Monthly model-quality dashboard',
          'Data Scientist'),
         ('Retire or retrain underperforming models',
          'Apply SDAIA-aligned retirement and retraining criteria',
          'Model retirement / retraining record',
          'Model Owner'),
     )),
)


def _domain_code(domain: Optional[str]) -> str:
    return _normalize_rel31_domain_code(domain or '')


def _is_strategy(document_type: Optional[str]) -> bool:
    return str(document_type or 'strategy').strip().lower() in {
        'strategy', 'tech_strategy', 'technical_strategy', ''}


def _frameworks_text(selected_frameworks: Optional[Iterable[Any]]) -> str:
    return ' '.join(_selected_list(selected_frameworks)).upper()


def _has_ndmo_or_pdpl(selected_frameworks: Optional[Iterable[Any]]) -> bool:
    blob = _frameworks_text(selected_frameworks)
    return 'NDMO' in blob or 'PDPL' in blob


def _leakage_terms(text: str) -> List[str]:
    hits: List[str] = []
    for term in _LEAK_TERMS:
        if re.search(rf'(?i)\b{re.escape(term)}\b', text or ''):
            hits.append(term)
    return hits


def _arabic_prose_hits(text: str, *, keep_org: str = '') -> List[str]:
    hits: List[str] = []
    for line in (text or '').splitlines():
        stripped = line.strip()
        if keep_org and keep_org in stripped:
            remainder = stripped.replace(keep_org, '')
            if not _ARABIC_CHAR_RE.search(remainder):
                continue
        if _ARABIC_CHAR_RE.search(stripped):
            hits.append(stripped[:80])
    return hits


def _count_valid_so_rows(text: str) -> int:
    try:
        from app import count_valid_objective_rows
        return int(count_valid_objective_rows(text or '') or 0)
    except Exception:
        return 0


def _count_pillar_init_rows(text: str) -> int:
    rows = 0
    in_table = False
    for raw in (text or '').splitlines():
        line = raw.strip()
        if re.match(
                r'^\|\s*#\s*\|\s*(?:Initiative|المبادرة)\s*\|',
                line, re.IGNORECASE):
            in_table = True
            continue
        if in_table and re.match(r'^\|[\s:\-|]+\|\s*$', line):
            continue
        if in_table and line.startswith('|'):
            cells = [c.strip() for c in line.strip('|').split('|')]
            if len(cells) >= 4 and cells[0] not in {'#', ''}:
                rows += 1
            continue
        if in_table and line and not line.startswith('|'):
            in_table = False
    return rows


def _count_pillars(text: str) -> int:
    try:
        from app import _count_substantive_pillars
        return int(_count_substantive_pillars(text or '') or 0)
    except Exception:
        headings = re.findall(
            r'(?im)^#{2,4}\s+.+\b(?:pillar|ركيزة)\b', text or '')
        return max(len(headings), 1 if _count_pillar_init_rows(text) else 0)


def _count_gap_rows(text: str) -> int:
    try:
        from app import count_substantive_gaps
        return int(count_substantive_gaps(text or '') or 0)
    except Exception:
        return 0


def _count_kpi_rows(text: str) -> int:
    try:
        from app import count_substantive_kpis
        return int(count_substantive_kpis(text or '') or 0)
    except Exception:
        return 0


def _count_gap_guides(text: str) -> int:
    try:
        from app import count_gap_guides
        return int(count_gap_guides(text or '') or 0)
    except Exception:
        return (
            len(_GAP_GUIDE_HEADING_EN.findall(text or ''))
            + len(_GAP_GUIDE_HEADING_AR.findall(text or ''))
        )


def _count_kpi_guide_headings(text: str, lang: str) -> int:
    if lang.startswith('ar'):
        return len(_KPI_GUIDES_HEADING_AR.findall(text or ''))
    return len(_KPI_GUIDES_HEADING_EN.findall(text or ''))


def _count_per_kpi_guides(text: str, lang: str) -> int:
    if lang.startswith('ar'):
        return len(_PER_KPI_GUIDE_AR.findall(text or ''))
    return len(_PER_KPI_GUIDE_EN.findall(text or ''))


def _save_blockers_of(
        sections: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        selected_frameworks: Optional[Iterable[Any]],
        document_type: str = 'strategy',
) -> List[str]:
    try:
        from app import _audit_doc_quality
        result = _audit_doc_quality(
            {k: str(v or '') for k, v in (sections or {}).items()},
            domain=domain,
            lang=lang,
            selected_frameworks=list(_selected_list(selected_frameworks)),
            document_type=document_type,
        ) or {}
        blockers = list(result.get('blockers') or result.get('errors') or [])
        return [str(b) for b in blockers]
    except Exception:
        return []


def _synth_blockers(kind: str, text: str, *, lang: str, domain: str) -> List[str]:
    try:
        import app as app_mod
        fn = {
            'vision': getattr(app_mod, 'synthesize_objectives_depth', None),
            'pillars': getattr(app_mod, 'synthesize_pillars_depth', None),
        }.get(kind)
        if fn is None:
            return []
        # Dry inspect via the same counters the synthesizer uses.
        if kind == 'vision':
            rows = _count_valid_so_rows(text)
            return [] if rows >= _MIN_SO else [f'synth_failed:{kind}']
        if kind == 'pillars':
            pillars = _count_pillars(text)
            inits = _count_pillar_init_rows(text)
            if pillars >= _MIN_PILLARS and inits >= _MIN_PILLARS * _MIN_INITIATIVES:
                return []
            return [f'synth_failed:{kind}']
    except Exception:
        pass
    return []


def _owners(domain: str, lang: str) -> Sequence[str]:
    if domain == 'ai':
        return _AI_OWNERS_AR if lang.startswith('ar') else _AI_OWNERS_EN
    return _DATA_OWNERS_AR if lang.startswith('ar') else _DATA_OWNERS_EN


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = [
        '| ' + ' | '.join(headers) + ' |',
        '|' + '|'.join(['---'] * len(headers)) + '|',
    ]
    for row in rows:
        lines.append('| ' + ' | '.join(str(c) for c in row) + ' |')
    return '\n'.join(lines)


def _first_md_table(text: str) -> str:
    match = re.search(
        r'(^[ \t]*\|.+\|[ \t]*\n[ \t]*\|[\s:\-|]+\|[ \t]*\n'
        r'(?:[ \t]*\|.+\|[ \t]*\n?)*)',
        text or '',
        re.MULTILINE,
    )
    return match.group(1) if match else ''


def _guide_table(lang: str, owner: str, action: str, output: str) -> str:
    if lang.startswith('ar'):
        return _md_table(
            ['الخطوة', 'الإجراء', 'المسؤول', 'الإطار الزمني', 'الناتج'],
            [
                ['1', action, owner, '30 يوماً', output],
                ['2', 'توثيق الأدلة ومراجعة الامتثال', owner, '60 يوماً',
                 'حزمة أدلة معتمدة'],
                ['3', 'إغلاق الفجوة وتحديث السجل', owner, '90 يوماً',
                 'سجل محدث ومعتمد'],
            ],
        )
    return _md_table(
        ['Step', 'Action', 'Owner', 'Timeline', 'Output'],
        [
            ['1', action, owner, '30 days', output],
            ['2', 'Document evidence and complete compliance review', owner,
             '60 days', 'Approved evidence pack'],
            ['3', 'Close the item and update the controlled register', owner,
             '90 days', 'Updated approved register'],
        ],
    )


def _so_block(domain: str) -> str:
    rows = _AI_SO_ROWS if domain == 'ai' else _DATA_SO_ROWS
    body = [_SO_HEADER_EN, _SO_SEP]
    for idx, (obj, target, rationale, timeframe) in enumerate(rows, start=1):
        body.append(
            f'| {idx} | {obj} | {target} | {rationale} | {timeframe} |')
    heading = (
        '## Strategic Objectives'
        if domain == 'ai'
        else '## Strategic Objectives'
    )
    return heading + '\n\n' + '\n'.join(body) + '\n'


def _pillars_block(domain: str) -> str:
    pillars = _AI_PILLARS if domain == 'ai' else _DATA_PILLARS
    parts = ['## Strategic Pillars\n']
    for idx, (title, initiatives) in enumerate(pillars, start=1):
        parts.append(f'### Pillar {idx}: {title}\n')
        body = [_PILLAR_HEADER_EN, _PILLAR_SEP]
        for j, (init, desc, deliverable, owner) in enumerate(
                initiatives, start=1):
            body.append(
                f'| {j} | {init} | {desc} | {deliverable} | {owner} |')
        parts.append('\n'.join(body) + '\n')
    return '\n'.join(parts)


def _replace_or_set_section(
        sections: Dict[str, str],
        keys: Sequence[str],
        replacement: str,
) -> None:
    for key in keys:
        if key in sections and str(sections.get(key) or '').strip():
            current = str(sections[key])
            table = _first_md_table(current)
            if table:
                sections[key] = current.replace(table, replacement, 1)
            else:
                sections[key] = current.rstrip() + '\n\n' + replacement
            return
    sections[keys[0]] = replacement


def _canonical_text(sections: Dict[str, str], aliases: Sequence[str]) -> str:
    for key in aliases:
        if str(sections.get(key) or '').strip():
            return str(sections[key])
    return ''


def _ensure_canonical_key(
        sections: Dict[str, str],
        canonical: str,
        aliases: Sequence[str],
) -> None:
    if str(sections.get(canonical) or '').strip():
        return
    for key in aliases:
        if key != canonical and str(sections.get(key) or '').strip():
            sections[canonical] = str(sections[key])
            return


def _ensure_english_core(
        sections: Dict[str, str],
        *,
        domain: str,
) -> Dict[str, int]:
    vision_aliases = (
        'vision', 'strategic_objectives', 'vision_mission_objectives',
        'objectives',
    )
    pillar_aliases = ('pillars', 'strategic_pillars', 'initiatives')
    _ensure_canonical_key(sections, 'vision', vision_aliases)
    _ensure_canonical_key(sections, 'pillars', pillar_aliases)
    vision_text = str(sections.get('vision') or '')
    pillar_text = str(sections.get('pillars') or '')
    so_before = _count_valid_so_rows(vision_text)
    pillars_before = _count_pillar_init_rows(pillar_text)
    if so_before < _MIN_SO:
        _replace_or_set_section(sections, vision_aliases, _so_block(domain))
        sections['vision'] = str(sections.get('vision') or _so_block(domain))
    if (
            _count_pillars(pillar_text) < _MIN_PILLARS
            or pillars_before < _MIN_PILLARS * _MIN_INITIATIVES
    ):
        _replace_or_set_section(sections, pillar_aliases, _pillars_block(domain))
        sections['pillars'] = str(
            sections.get('pillars') or _pillars_block(domain))
    vision_after = str(sections.get('vision') or '')
    pillar_after = str(sections.get('pillars') or '')
    return {
        'so_rows_before': so_before,
        'so_rows_after': _count_valid_so_rows(vision_after),
        'pillars_rows_before': pillars_before,
        'pillars_rows_after': _count_pillar_init_rows(pillar_after),
    }


def _gap_guides_markdown(
        n: int, *, domain: str, lang: str,
) -> str:
    owners = _owners(domain, lang)
    parts: List[str] = []
    for i in range(1, n + 1):
        owner = owners[(i - 1) % len(owners)]
        if lang.startswith('ar'):
            heading = f'#### دليل تنفيذ الفجوة رقم {i}'
            action = (
                'إغلاق فجوة الحوكمة المحددة وتوثيق التحكم التشغيلي'
                if domain == 'data'
                else 'إغلاق فجوة حوكمة النموذج وتوثيق التحكم التشغيلي'
            )
            output = 'دليل تنفيذ معتمد مع أدلة الإغلاق'
        else:
            heading = f'#### Gap #{i} Implementation Guide'
            action = (
                'Close the counted data-governance gap and evidence the control'
                if domain == 'data'
                else 'Close the counted AI-governance gap and evidence the control'
            )
            output = 'Approved implementation guide with closure evidence'
        parts.append(heading)
        parts.append('')
        parts.append(_guide_table(lang, owner, action, output))
        parts.append('')
    return '\n'.join(parts).rstrip() + '\n'


def _kpi_guides_markdown(
        n: int, *, domain: str, lang: str,
) -> str:
    owners = _owners(domain, lang)
    if lang.startswith('ar'):
        parts = ['### أدلة تقييم مؤشرات الأداء', '']
    else:
        parts = ['### KPI Assessment Guidelines', '']
    for i in range(1, n + 1):
        owner = owners[(i - 1) % len(owners)]
        if lang.startswith('ar'):
            heading = f'#### دليل تقييم المؤشر رقم {i}'
            action = 'قياس المؤشر من المصدر المعتمد وتوثيق الانحراف'
            output = 'تقرير تقييم مؤشر معتمد'
        else:
            heading = f'#### KPI #{i} Assessment Guide'
            action = 'Measure the KPI from the approved source and document variance'
            output = 'Approved KPI assessment report'
        parts.append(heading)
        parts.append('')
        parts.append(_guide_table(lang, owner, action, output))
        parts.append('')
    return '\n'.join(parts).rstrip() + '\n'


_GAP_GUIDE_BLOCK_RE = re.compile(
    r'(?:^####\s*(?:Gap\s*#?\d+\s*Implementation Guide|'
    r'دليل تنفيذ الفجوة\s*(?:رقم|#)?\s*\d+)[^\n]*\n'
    r'(?:^(?!####\s*(?:Gap\s*#?\d+\s*Implementation Guide|'
    r'دليل تنفيذ الفجوة)|#{1,3}\s).*\n?)*)',
    re.MULTILINE | re.IGNORECASE,
)
_KPI_GUIDES_BLOCK_RE = re.compile(
    r'(?:^###\s*(?:KPI Assessment Guidelines|أدلة تقييم مؤشرات الأداء)\s*\n'
    r'(?:^(?!#{1,3}\s(?!#)).*\n?)*)',
    re.MULTILINE | re.IGNORECASE,
)


def _strip_duplicate_guide_blocks(text: str, pattern: re.Pattern) -> str:
    matches = list(pattern.finditer(text or ''))
    if len(matches) <= 1:
        return text
    keep = matches[0]
    out = text
    for match in reversed(matches[1:]):
        out = out[:match.start()] + out[match.end():]
    return out


def _replace_first_or_append_guides(
        text: str,
        *,
        existing_re: re.Pattern,
        replacement: str,
        append_if_missing: bool,
) -> str:
    current = text or ''
    match = existing_re.search(current)
    if match:
        return current[:match.start()] + replacement + current[match.end():]
    if append_if_missing:
        return current.rstrip() + '\n\n' + replacement
    return current


def _gap_table(domain: str, lang: str) -> str:
    if lang.startswith('ar'):
        if domain == 'ai':
            rows = [
                ['1', 'سجل نماذج الذكاء الاصطناعي غير مكتمل',
                 'النماذج الإنتاجية بلا جرد مالك معتمد وفق سدايا',
                 'عالية', 'مفتوحة'],
                ['2', 'إدارة مخاطر النماذج غير مفعلة',
                 'النماذج عالية المخاطر بلا مدير مخاطر ومراجعة معتمدة',
                 'عالية', 'مفتوحة'],
            ]
        else:
            rows = [
                ['1', 'كتالوج البيانات غير مكتمل',
                 'الأصول الحرجة غير مسجلة في كتالوج بيانات محكوم',
                 'عالية', 'مفتوحة'],
                ['2', 'حوكمة الخصوصية غير مفعلة',
                 'حوكمة الخصوصية وحماية البيانات الشخصية غير تشغيلية',
                 'عالية', 'مفتوحة'],
            ]
        return _md_table(
            ['#', 'الفجوة', 'الوصف', 'الأولوية', 'الحالة'], rows)
    if domain == 'ai':
        rows = [
            ['1', 'AI model inventory is incomplete',
             'Production models lack a SDAIA-aligned inventory and owner',
             'High', 'Open'],
            ['2', 'Model risk management is informal',
             'High-risk models lack a named Model Risk Manager and review pack',
             'High', 'Open'],
        ]
    else:
        rows = [
            ['1', 'Enterprise data catalog is incomplete',
             'Critical data assets are not in a governed data catalog',
             'High', 'Open'],
            ['2', 'Privacy governance operating model is missing',
             'PDPL privacy governance and personal data protection are not operational',
             'High', 'Open'],
        ]
    return _md_table(
        ['#', 'Gap', 'Description', 'Priority', 'Status'], rows)


def _kpi_table(domain: str, lang: str) -> str:
    if lang.startswith('ar'):
        if domain == 'ai':
            rows = [
                ['1', 'تغطية سجل النماذج', 'لاحق', '100%',
                 'النماذج المسجلة ÷ النماذج الإنتاجية', 'سجل النماذج',
                 'ربع سنوي', 'مالك نموذج الذكاء الاصطناعي'],
                ['2', 'اكتمال الإشراف البشري', 'قائد', '100%',
                 'النماذج عالية المخاطر المشمولة بالإشراف ÷ النماذج عالية المخاطر',
                 'سجل الإشراف', 'ربع سنوي', 'مدير حوكمة الذكاء الاصطناعي'],
                ['3', 'تغطية خط MLOps', 'لاحق', '100%',
                 'النماذج في MLOps ÷ النماذج الإنتاجية', 'منصة MLOps',
                 'ربع سنوي', 'قائد MLOps'],
                ['4', 'اكتمال بطاقة النموذج', 'لاحق', '100%',
                 'النماذج ببطاقة معتمدة ÷ النماذج عالية المخاطر',
                 'بطاقات النماذج', 'ربع سنوي', 'مسؤول الامتثال'],
            ]
        else:
            rows = [
                ['1', 'اكتمال كتالوج البيانات', 'لاحق', '100%',
                 'الأصول المفهرسة ÷ الأصول الحرجة', 'كتالوج البيانات',
                 'ربع سنوي', 'مالك كتالوج البيانات'],
                ['2', 'درجة جودة البيانات', 'لاحق', '90%',
                 'السجلات الصحيحة ÷ إجمالي السجلات', 'منصة الجودة',
                 'شهري', 'مدير جودة البيانات'],
                ['3', 'تغطية موافقات PDPL', 'لاحق', '100%',
                 'المعالجات بموافقة ÷ معالجات البيانات الشخصية',
                 'سجل الموافقات', 'ربع سنوي', 'مسؤول حماية البيانات'],
                ['4', 'SLA حقوق أصحاب البيانات', 'لاحق', '95%',
                 'الطلبات المغلقة في المهلة ÷ الطلبات المستلمة',
                 'سجل الطلبات', 'شهري', 'مسؤول حماية البيانات'],
            ]
        return _md_table(
            ['#', 'وصف المؤشر', 'النوع', 'القيمة المستهدفة',
             'صيغة الاحتساب', 'مصدر', 'التكرار', 'المالك'],
            rows)
    if domain == 'ai':
        rows = [
            ['1', 'Model register coverage', 'Lagging', '100%',
             'registered models / production models', 'Model register',
             'Quarterly', 'Model Owner'],
            ['2', 'Human oversight completion', 'Leading', '100%',
             'overseen high-risk models / high-risk models',
             'Oversight log', 'Quarterly', 'AI Governance Manager'],
            ['3', 'MLOps pipeline coverage', 'Lagging', '100%',
             'models in MLOps / production models', 'MLOps platform',
             'Quarterly', 'MLOps Lead'],
            ['4', 'Model-card coverage', 'Lagging', '100%',
             'models with cards / high-risk models', 'Model cards',
             'Quarterly', 'Compliance Officer'],
        ]
    else:
        rows = [
            ['1', 'Catalog completeness', 'Lagging', '100%',
             'cataloged assets / critical assets', 'Data catalog',
             'Quarterly', 'Data Catalog Owner'],
            ['2', 'Data quality score', 'Lagging', '90%',
             'valid records / total records', 'Quality platform',
             'Monthly', 'Data Quality Manager'],
            ['3', 'PDPL consent coverage', 'Lagging', '100%',
             'consented processing / personal-data processing',
             'Consent register', 'Quarterly', 'Data Protection Officer'],
            ['4', 'DSR SLA', 'Lagging', '95%',
             'DSR closed on time / DSR received', 'DSR ticket log',
             'Monthly', 'Data Protection Officer'],
        ]
    return _md_table(
        ['#', 'KPI Description', 'Type', 'Target Value',
         'Calculation Formula', 'Source', 'Frequency', 'Owner'],
        rows)


def _ensure_guides(
        sections: Dict[str, str],
        *,
        domain: str,
        lang: str,
) -> Dict[str, Any]:
    gap_aliases = ('gaps', 'gap_analysis', 'current_state_gaps')
    kpi_aliases = ('kpis', 'kpi', 'performance_kpis')
    _ensure_canonical_key(sections, 'gaps', gap_aliases)
    _ensure_canonical_key(sections, 'kpis', kpi_aliases)
    gap_text = str(sections.get('gaps') or '')
    kpi_text = str(sections.get('kpis') or '')
    counted_gaps = _count_gap_rows(gap_text)
    counted_kpis = _count_kpi_rows(kpi_text)
    gap_guides_before = _count_gap_guides(gap_text)
    kpi_guides_before = _count_per_kpi_guides(kpi_text, lang)
    missing_gap_before = max(0, counted_gaps - gap_guides_before)
    missing_kpi_before = max(0, counted_kpis - kpi_guides_before)

    if counted_gaps < 2:
        seed = _gap_table(domain, lang)
        # Table only — never append a numbered ``## N.`` section heading.
        gap_text = seed if not gap_text.strip() else (
            gap_text.rstrip() + '\n\n' + seed)
        sections['gaps'] = gap_text
        counted_gaps = _count_gap_rows(gap_text)
        gap_guides_before = _count_gap_guides(gap_text)
        missing_gap_before = max(0, counted_gaps - gap_guides_before)
    if counted_gaps > 0 and gap_guides_before < counted_gaps:
        rebuilt = _GAP_GUIDE_BLOCK_RE.sub('', str(sections.get('gaps') or ''))
        rebuilt = rebuilt.rstrip() + '\n\n' + _gap_guides_markdown(
            counted_gaps, domain=domain, lang=lang)
        sections['gaps'] = rebuilt

    if counted_kpis < 4:
        seed = _kpi_table(domain, lang)
        kpi_text = seed if not kpi_text.strip() else (
            kpi_text.rstrip() + '\n\n' + seed)
        sections['kpis'] = kpi_text
        counted_kpis = _count_kpi_rows(kpi_text)
        kpi_guides_before = _count_per_kpi_guides(kpi_text, lang)
        missing_kpi_before = max(0, counted_kpis - kpi_guides_before)
    heading_count = _count_kpi_guide_headings(
        str(sections.get('kpis') or ''), lang)
    if counted_kpis > 0 and (
            heading_count != 1 or kpi_guides_before != counted_kpis):
        stripped = _KPI_GUIDES_BLOCK_RE.sub(
            '', str(sections.get('kpis') or ''))
        leftover = (
            _PER_KPI_GUIDE_AR if lang.startswith('ar') else _PER_KPI_GUIDE_EN
        )
        stripped = leftover.sub('', stripped)
        sections['kpis'] = (
            stripped.rstrip() + '\n\n'
            + _kpi_guides_markdown(counted_kpis, domain=domain, lang=lang)
        )

    gap_after = str(sections.get('gaps') or '')
    kpi_after = _strip_duplicate_guide_blocks(
        str(sections.get('kpis') or ''), _KPI_GUIDES_BLOCK_RE)
    sections['gaps'] = gap_after
    sections['kpis'] = kpi_after
    counted_gaps = _count_gap_rows(gap_after)
    counted_kpis = _count_kpi_rows(kpi_after)

    gap_guides_after = _count_gap_guides(gap_after)
    kpi_guides_after = _count_per_kpi_guides(kpi_after, lang)
    heading_after = _count_kpi_guide_headings(kpi_after, lang)
    headers_valid = True
    if lang.startswith('ar'):
        headers_valid = (
            (counted_gaps == 0 or bool(_GAP_GUIDE_HEADING_AR.search(gap_after)))
            and (counted_kpis == 0 or heading_after == 1)
            and not _GAP_GUIDE_HEADING_EN.search(gap_after)
            and not _KPI_GUIDES_HEADING_EN.search(kpi_after)
        )
    else:
        headers_valid = (
            (counted_gaps == 0 or bool(_GAP_GUIDE_HEADING_EN.search(gap_after)))
            and (counted_kpis == 0 or heading_after == 1)
            and not _GAP_GUIDE_HEADING_AR.search(gap_after)
            and not _KPI_GUIDES_HEADING_AR.search(kpi_after)
        )
    duplicate = (
        heading_after > 1
        or len(_KPI_GUIDES_HEADING_EN.findall(kpi_after)
               + _KPI_GUIDES_HEADING_AR.findall(kpi_after)) > 1
    )
    return {
        'counted_gap_rows': counted_gaps,
        'gap_guides_before': gap_guides_before,
        'gap_guides_after': gap_guides_after,
        'missing_gap_guides_before': list(range(gap_guides_before + 1, counted_gaps + 1))
        if missing_gap_before else [],
        'missing_gap_guides_after': (
            list(range(gap_guides_after + 1, counted_gaps + 1))
            if gap_guides_after < counted_gaps else []
        ),
        'counted_kpi_rows': counted_kpis,
        'kpi_guides_before': kpi_guides_before,
        'kpi_guides_after': kpi_guides_after,
        'missing_kpi_guides_before': (
            list(range(kpi_guides_before + 1, counted_kpis + 1))
            if missing_kpi_before else []
        ),
        'missing_kpi_guides_after': (
            list(range(kpi_guides_after + 1, counted_kpis + 1))
            if kpi_guides_after < counted_kpis else []
        ),
        'guide_headers_language_valid': headers_valid,
        'duplicate_guides_after': duplicate,
    }


def _required_data_families(
        selected_frameworks: Optional[Iterable[Any]],
) -> List[str]:
    try:
        required = official_data_required_families(selected_frameworks)
        if required:
            return list(required)
    except Exception:
        pass
    return required_balance_families(selected_frameworks)


def _official_missing_data_families(
        text: str,
        selected_frameworks: Optional[Iterable[Any]],
        lang: str,
) -> List[str]:
    try:
        import app as app_mod
        return list(
            app_mod._compute_missing_data_roadmap_balance_topics(
                text or '', selected_frameworks, lang=lang) or [])
    except Exception:
        try:
            return official_data_missing_families(text, selected_frameworks)
        except Exception:
            return missing_balance_families(text, selected_frameworks)


def _splice_data_rows(text: str, new_rows: Sequence[str], lang: str) -> str:
    if not new_rows:
        return text or ''
    if lang.startswith('ar'):
        return _splice_rows(text or '', new_rows)
    current = text or ''
    lines = current.split('\n')
    sep_re = re.compile(r'^\|[\s\-:|]+\|$')
    last_tbl_idx = -1
    for idx, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('|') and s.endswith('|') and not sep_re.match(s):
            last_tbl_idx = idx
    if last_tbl_idx < 0:
        header = (
            '| Phase | Timeline | Initiative | Owner | Output | Framework |')
        sep = '|---|---|---|---|---|---|'
        block = '\n'.join([header, sep, *new_rows])
        return current.rstrip() + ('\n\n' if current.strip() else '') + block + '\n'
    return '\n'.join(
        lines[:last_tbl_idx + 1] + list(new_rows) + lines[last_tbl_idx + 1:])


def _repair_data_roadmap(
        sections: Dict[str, str],
        *,
        lang: str,
        selected_frameworks: Optional[Iterable[Any]],
) -> Dict[str, Any]:
    _ensure_canonical_key(
        sections, 'roadmap',
        ('roadmap', 'implementation_roadmap', 'implementation_plan'))
    required = _required_data_families(selected_frameworks)
    text = str(sections.get('roadmap') or '')
    detected_before = detect_balance_families(text)
    missing_before = _official_missing_data_families(
        text, selected_frameworks, lang)
    inserted: List[str] = []
    rows_by_family = (
        _DATA_FAMILY_ROWS_AR if lang.startswith('ar') else _DATA_FAMILY_ROWS_EN
    )
    if missing_before:
        rows = [rows_by_family[f] for f in missing_before if f in rows_by_family]
        inserted = [f for f in missing_before if f in rows_by_family]
        if rows:
            sections['roadmap'] = _splice_data_rows(text, rows, lang)
    after = str(sections.get('roadmap') or '')
    still = _official_missing_data_families(after, selected_frameworks, lang)
    if still:
        extra = [rows_by_family[f] for f in still if f in rows_by_family]
        extra_fams = [f for f in still if f in rows_by_family]
        if extra:
            sections['roadmap'] = _splice_data_rows(after, extra, lang)
            inserted.extend(extra_fams)
            after = str(sections.get('roadmap') or '')
    detected_after = detect_balance_families(after)
    missing_after = _official_missing_data_families(
        after, selected_frameworks, lang)
    return {
        'required_families': required,
        'detected_families_before': sorted(detected_before),
        'missing_families_before': missing_before,
        'inserted_families': list(dict.fromkeys(inserted)),
        'detected_families_after': sorted(detected_after),
        'missing_families_after': missing_after,
        'privacy_governance_present_after': (
            'privacy_governance' in detected_after
            or 'privacy_governance' not in missing_after
        ),
        'leakage_terms_after': _leakage_terms(after),
    }


def rel36_20_should_apply(
        *,
        domain: Optional[str],
        lang: Optional[str],
        document_type: Optional[str],
        selected_frameworks: Optional[Iterable[Any]] = None,
        roadmap_only: bool = False,
) -> bool:
    dcode = _domain_code(domain)
    if dcode == 'cyber':
        return False
    if not _is_strategy(document_type):
        return False
    if dcode not in {'data', 'ai'}:
        return False
    if roadmap_only:
        return dcode == 'data' and _has_ndmo_or_pdpl(selected_frameworks)
    return True


def apply_rel36_20_data_ai_guide_save_stability(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Optional[str] = None,
        org_name: Optional[str] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Repair Data/AI roadmap, English core synth, and guide completeness."""
    out = {str(k): str(v or '') for k, v in (sections or {}).items()}
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    doc_type = str(document_type or 'strategy')
    fw = list(_selected_list(selected_frameworks))
    diagnostics: Dict[str, Any] = {
        'domain': dcode,
        'lang': nlang,
        'task_id': task_id or '',
        'selected_frameworks': fw,
        'applied': False,
        'passed': False,
    }
    if not rel36_20_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type,
            selected_frameworks=fw):
        diagnostics['skipped'] = True
        return out, diagnostics

    blockers_before = _save_blockers_of(
        out, domain=dcode, lang=nlang, selected_frameworks=fw,
        document_type=doc_type)
    roadmap_diag: Dict[str, Any] = {}
    core_diag: Dict[str, Any] = {}
    guide_diag: Dict[str, Any] = {}

    if dcode == 'data' and _has_ndmo_or_pdpl(fw):
        roadmap_diag = _repair_data_roadmap(
            out, lang=nlang, selected_frameworks=fw)
        roadmap_diag.update({
            'domain': dcode,
            'lang': nlang,
            'selected_frameworks': fw,
            'save_blockers_before': [
                b for b in blockers_before
                if 'privacy_governance' in b or 'roadmap' in b.lower()
            ],
        })

    if nlang.startswith('en') and dcode in {'data', 'ai'}:
        so_text_before = ''
        for key in ('strategic_objectives', 'vision_mission_objectives',
                    'vision', 'objectives'):
            if out.get(key):
                so_text_before = out[key]
                break
        pillar_text_before = ''
        for key in ('strategic_pillars', 'pillars', 'initiatives'):
            if out.get(key):
                pillar_text_before = out[key]
                break
        synth_v_before = _synth_blockers(
            'vision', so_text_before, lang=nlang, domain=dcode)
        synth_p_before = _synth_blockers(
            'pillars', pillar_text_before, lang=nlang, domain=dcode)
        core_counts = _ensure_english_core(out, domain=dcode)
        so_after = ''
        for key in ('strategic_objectives', 'vision_mission_objectives',
                    'vision', 'objectives'):
            if out.get(key):
                so_after = out[key]
                break
        pillar_after = ''
        for key in ('strategic_pillars', 'pillars', 'initiatives'):
            if out.get(key):
                pillar_after = out[key]
                break
        core_diag = {
            'domain': dcode,
            'lang': nlang,
            'task_id': task_id or '',
            **core_counts,
            'synth_vision_blockers_before': synth_v_before,
            'synth_vision_blockers_after': _synth_blockers(
                'vision', so_after, lang=nlang, domain=dcode),
            'synth_pillars_blockers_before': synth_p_before,
            'synth_pillars_blockers_after': _synth_blockers(
                'pillars', pillar_after, lang=nlang, domain=dcode),
            'arabic_header_hits_after': _ARABIC_HEADER_RE.findall(
                so_after + '\n' + pillar_after),
            'arabic_prose_hits_after': _arabic_prose_hits(
                so_after + '\n' + pillar_after, keep_org=org_name or ''),
            'leakage_terms_after': _leakage_terms(
                so_after + '\n' + pillar_after),
            'save_blockers_before': [
                b for b in blockers_before
                if 'synth_failed' in b or 'vision' in b or 'pillar' in b
            ],
        }

    if dcode in {'data', 'ai'}:
        roadmap_before_guides = str(out.get('roadmap') or '')
        guide_diag = _ensure_guides(out, domain=dcode, lang=nlang)
        # Guide completion writes gaps/kpis only. Never mutate roadmap rows.
        if str(out.get('roadmap') or '') != roadmap_before_guides:
            out['roadmap'] = roadmap_before_guides
        guide_diag['roadmap_mutated'] = False
        joined = '\n'.join(out.values())
        guide_diag.update({
            'domain': dcode,
            'lang': nlang,
            'task_id': task_id or '',
            'leakage_terms_after': _leakage_terms(joined),
            'save_blockers_before': [
                b for b in blockers_before
                if 'guide' in b.lower() or 'Guideline' in b
                or 'Gap Implementation' in b or 'KPI Assessment' in b
            ],
        })

    blockers_after = _save_blockers_of(
        out, domain=dcode, lang=nlang, selected_frameworks=fw,
        document_type=doc_type)
    if roadmap_diag:
        roadmap_diag['save_blockers_after'] = [
            b for b in blockers_after
            if 'privacy_governance' in b or 'roadmap' in b.lower()
        ]
        roadmap_diag['passed'] = (
            roadmap_diag.get('privacy_governance_present_after') is True
            and roadmap_diag.get('missing_families_after') == []
            and roadmap_diag.get('leakage_terms_after') == []
            and roadmap_diag.get('save_blockers_after') == []
        )
        print(
            REL36_20_DATA_EN_ROADMAP_GUIDE_STABILITY_TAG + ' '
            + json.dumps(roadmap_diag, ensure_ascii=False),
            flush=True,
        )
    if core_diag:
        core_diag['save_blockers_after'] = [
            b for b in blockers_after
            if 'synth_failed' in b or 'vision' in b or 'pillar' in b
        ]
        core_diag['passed'] = (
            core_diag.get('synth_vision_blockers_after') == []
            and core_diag.get('synth_pillars_blockers_after') == []
            and core_diag.get('arabic_header_hits_after') == []
            and core_diag.get('arabic_prose_hits_after') == []
            and core_diag.get('leakage_terms_after') == []
            and core_diag.get('save_blockers_after') == []
        )
        print(
            REL36_20_EN_DATA_AI_CORE_SYNTH_STABILITY_TAG + ' '
            + json.dumps(core_diag, ensure_ascii=False),
            flush=True,
        )
    if guide_diag:
        guide_diag['save_blockers_after'] = [
            b for b in blockers_after
            if 'guide' in b.lower() or 'Guideline' in b
            or 'Gap Implementation' in b or 'KPI Assessment' in b
        ]
        guide_diag['passed'] = (
            guide_diag.get('missing_gap_guides_after') == []
            and guide_diag.get('missing_kpi_guides_after') == []
            and guide_diag.get('guide_headers_language_valid') is True
            and guide_diag.get('duplicate_guides_after') is False
            and guide_diag.get('leakage_terms_after') == []
            and guide_diag.get('save_blockers_after') == []
        )
        print(
            REL36_20_DATA_AI_GUIDE_COMPLETENESS_TAG + ' '
            + json.dumps(guide_diag, ensure_ascii=False),
            flush=True,
        )

    passed = True
    if roadmap_diag:
        passed = passed and bool(roadmap_diag.get('passed'))
    if core_diag:
        passed = passed and bool(core_diag.get('passed'))
    if guide_diag:
        passed = passed and bool(guide_diag.get('passed'))
    family_diag: Dict[str, Any] = {}
    if dcode == 'data':
        from release_engine_v3.rel36_20_1_data_roadmap_family_integrity import (
            apply_rel36_20_1_data_roadmap_family_integrity,
        )
        out, family_diag = apply_rel36_20_1_data_roadmap_family_integrity(
            out, domain=dcode, lang=nlang, document_type=doc_type,
            selected_frameworks=fw, task_id=task_id)
        if family_diag.get('passed') is False:
            passed = False
        blockers_after = _save_blockers_of(
            out, domain=dcode, lang=nlang, selected_frameworks=fw,
            document_type=doc_type)

    diagnostics.update({
        'applied': True,
        'passed': passed,
        'save_blockers_before': blockers_before,
        'save_blockers_after': blockers_after,
        'roadmap': roadmap_diag,
        'core': core_diag,
        'guides': guide_diag,
        'family_integrity': family_diag,
    })
    return out, diagnostics
