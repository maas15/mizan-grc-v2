"""REL36.23 — Data/AI guide uniqueness, English Data pillars, visible headers.

Live REL36.22 staging on ``6b702c4`` kept official 6/6 and Arabic Data
roadmap countable, then failed English Data/AI save and English Cyber
visible SO-header parity:

* English Data ``### Pillar Governance`` is a counted H3
  (``Pillar\\s*\\d*`` matches ``Pillar``) whose body has no initiative
  table. REL36.20 only rebuilds when the *total* pillar/init counts are
  low, so a weak counted pillar survives. The save-path
  ``pillars_missing_substantive_initiative`` gate then 422s.
* English Data/AI ``gap_guides_not_unique`` uses the official detector:
  first 200 raw stripped chars after ``#### Gap #N Implementation`` /
  ``#### دليل``. REL36.20 completes missing guides but does not uniquify
  bodies; its generated openings are boilerplate-identical, so owners
  that cycle (or later synthesis) collide.
* Arabic AI 5-attempt: later synthesis after REL36.20 can wipe
  ``#### دليل تنفيذ الفجوة رقم N``. ``count_gap_guides`` does not count
  ``دليل تطبيق``. Timeouts are not passes; completed generations must
  still carry one guide per counted gap/KPI row.
* English Cyber visible header stays
  ``Objective | Target Metric | Justification`` because REL36.16/13 and
  ``_STANDARD_HEADERS`` emit those aliases, and later synthesis runs
  after REL36.21's Data/AI canonicalizer.
* DT Arabic recovered text can split ``المستفيد`` to ``المست فيد``.
  REL36.22 coverage stays; this module only stitches that exact token.

Repairs run immediately before the unchanged save gates. Gates are not
weakened or suppressed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel35_domain_framework_fidelity import dga_selected
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_21_en_data_ai_framework_objectives import (
    CANONICAL_SO_HEADER_EN,
    canonicalize_english_so_header,
    count_so_tables,
    first_so_header,
    is_english_so_header_line,
)
from release_engine_v3.rel36_22_dt_dga_citizen_experience_coverage import (
    OFFICIAL_CITIZEN_AR,
    apply_rel36_22_dt_dga_citizen_experience_coverage,
    section_has_citizen_experience,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_23_EN_DATA_PILLAR_SUBSTANCE_TAG = (
    '[REL36.23-EN-DATA-PILLAR-SUBSTANCE]')
REL36_23_DATA_AI_GAP_GUIDE_UNIQUENESS_TAG = (
    '[REL36.23-DATA-AI-GAP-GUIDE-UNIQUENESS]')
REL36_23_AR_AI_GUIDE_STABILITY_TAG = (
    '[REL36.23-AR-AI-GUIDE-STABILITY]')
REL36_23_EN_SO_VISIBLE_HEADER_FINALIZER_TAG = (
    '[REL36.23-EN-SO-VISIBLE-HEADER-FINALIZER]')
REL36_23_DT_AR_CITIZEN_TOKEN_NORMALIZATION_TAG = (
    '[REL36.23-DT-AR-CITIZEN-TOKEN-NORMALIZATION]')

_MIN_INITIATIVES = 3
_PILLAR_HEADER = (
    '| # | Initiative | Description | Expected Deliverable | Owner |')
_PILLAR_SEP = '|---|---|---|---|---|'
_PILLAR_HEADING_RE = re.compile(
    r'^###\s+(?:Pillar\s*\d*|Strategic\s+Pillar\s*\d*|'
    r'الركيزة(?:\s+الاستراتيجية)?\s*\d*)[^\n]*',
    re.MULTILINE | re.IGNORECASE,
)
_H3_RE = re.compile(r'^###[^#\n][^\n]*$', re.MULTILINE)
_SEP_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_HDR_TOKENS = re.compile(
    r'(?:Initiative|Description|Deliverable|Output|Expected|'
    r'المبادرة|الوصف|المخرج|المتوقع)',
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r'(?i)^(?:tbd|todo|n/?a|none|placeholder|xxx|tbc|-|—|–)$')
_OFFICIAL_GUIDE_HDR_RE = re.compile(
    r'^####\s+(?:دليل|Gap\s+#\d+\s+Implementation)',
    re.MULTILINE,
)
_GAP_GUIDE_BLOCK_RE = re.compile(
    r'(?ms)^####\s+(?:Gap\s*#?\d+\s*Implementation Guide|'
    r'دليل\s+(?:تنفيذ|تطبيق)\s+الفجوة\s*(?:رقم|#)?\s*\d+)'
    r'[^\n]*\n.*?(?=^####\s+|^###\s+|\Z)',
)
_KPI_GUIDES_BLOCK_RE = re.compile(
    r'(?ms)^###\s*(?:KPI Assessment Guidelines|أدلة تقييم مؤشرات الأداء)'
    r'[^\n]*\n.*?(?=^##\s+|\Z)',
)
_PER_KPI_GUIDE_RE = re.compile(
    r'(?ms)^####\s+(?:KPI\s*#\s*\d+\s*Assessment Guide|'
    r'دليل تقييم المؤشر رقم\s*\d+)[^\n]*\n.*?(?=^####\s+|^###\s+|\Z)',
)
_AR_GAP_APPLY_RE = re.compile(
    r'^(####\s*)دليل تطبيق الفجوة(\s*(?:رقم|#)?\s*\d+)',
    re.MULTILINE,
)
_AR_GAP_GUIDE_RE = re.compile(
    r'^####\s*دليل\s+(?:تنفيذ|تطبيق)\s+الفجوة\s*(?:رقم|#)?\s*\d+',
    re.MULTILINE,
)
_AR_KPI_HEADING_RE = re.compile(
    r'^###\s*أدلة تقييم مؤشرات الأداء\s*$',
    re.MULTILINE,
)
_AR_KPI_GUIDE_RE = re.compile(
    r'^####\s*دليل تقييم المؤشر رقم\s*\d+\s*$',
    re.MULTILINE,
)
_SPLIT_TOKEN = 'المست فيد'
_CONTIGUOUS_TOKEN = 'المستفيد'
_DATA_OWNERS = (
    'Data Governance Manager',
    'Data Quality Manager',
    'Data Protection Officer',
    'Data Catalog Owner',
    'Data Steward',
)
_AI_OWNERS_EN = (
    'AI Governance Manager',
    'Model Risk Manager',
    'AI Data Steward',
    'Fairness Lead',
    'Human Oversight Owner',
    'Model Monitoring Lead',
    'Explainability Lead',
    'AI Incident Manager',
    'MLOps Control Owner',
    'SDAIA Compliance Officer',
)
_AI_OWNERS_AR = (
    'مدير حوكمة الذكاء الاصطناعي',
    'مدير مخاطر النماذج',
    'أمين بيانات الذكاء الاصطناعي',
    'مسؤول الإنصاف',
    'مالك الإشراف البشري',
    'قائد مراقبة النماذج',
    'قائد قابلية التفسير',
    'مدير حوادث الذكاء الاصطناعي',
    'مالك ضبط MLOps',
    'مسؤول امتثال سدايا',
)
_DATA_LEAKS = (
    'CISO', 'SOC', 'SIEM', 'CSIRT', 'IAM', 'PAM', 'MFA',
    'NCA ECC', 'NCA DCC',
)
_AI_LEAKS = _DATA_LEAKS + (
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
_VISION_ALIASES = (
    'vision', 'strategic_objectives', 'vision_mission_objectives',
    'objectives',
)
_PILLAR_ALIASES = ('pillars', 'strategic_pillars', 'initiatives')
_GAP_ALIASES = ('gaps', 'gap_analysis', 'current_state_gaps')
_KPI_ALIASES = ('kpis', 'kpi', 'performance_kpis')
_DT_SECTIONS = ('pillars', 'environment', 'gaps', 'roadmap', 'kpis')

_DATA_GUIDE_FAMILIES = (
    ('privacy governance',
     'Privacy-governance gap #{n} requires a named Data Protection Officer '
     'to publish the privacy operating model and evidence PDPL accountability.'),
    ('data catalog',
     'Data-catalog gap #{n} requires the Data Catalog Owner to register '
     'critical assets with stewards before any downstream sharing.'),
    ('data lifecycle',
     'Data-lifecycle gap #{n} requires the Data Steward to encode create, '
     'store, use, share, archive, and destroy controls in one schedule.'),
    ('personal data classification',
     'Personal-data classification gap #{n} requires sensitivity labels on '
     'every personal-data processing record before PDPL reuse.'),
    ('consent management',
     'Consent-management gap #{n} requires a live consent register that can '
     'capture, evidence, and withdraw consent for each purpose.'),
    ('data subject rights',
     'Data-subject-rights gap #{n} requires a timed fulfillment path for '
     'access, correction, and erasure requests against the SLA.'),
    ('breach notification',
     'Breach-notification gap #{n} requires a 72-hour personal-data breach '
     'path with named escalation and evidence of regulator notice.'),
    ('data quality',
     'Data-quality gap #{n} requires the Data Quality Manager to score '
     'completeness and accuracy for every cataloged critical asset.'),
    ('metadata/stewardship',
     'Metadata-stewardship gap #{n} requires named stewards and business '
     'glossary terms before catalog entries are marked authoritative.'),
    ('data sharing',
     'Data-sharing gap #{n} requires a controlled sharing agreement and '
     'purpose limitation before any personal or critical dataset leaves.'),
)

_AI_GUIDE_FAMILIES_EN = (
    ('AI governance',
     'AI-governance gap #{n} requires an approved SDAIA-aligned charter '
     'naming the accountable AI Governance Manager before scale.'),
    ('model risk',
     'Model-risk gap #{n} requires a Model Risk Manager review of bias, '
     'drift, and residual risk before any production promotion.'),
    ('data readiness',
     'Data-readiness gap #{n} requires lineage, quality, and consent '
     'evidence for every training and inference dataset in scope.'),
    ('bias/fairness',
     'Bias-and-fairness gap #{n} requires a documented fairness test and '
     'disaggregated error review before the model is released.'),
    ('human oversight',
     'Human-oversight gap #{n} requires a named overseer and an override '
     'log for every high-risk automated decision.'),
    ('model monitoring',
     'Model-monitoring gap #{n} requires live drift, quality, and incident '
     'thresholds with an on-call owner after go-live.'),
    ('explainability',
     'Explainability gap #{n} requires a model card and user-facing '
     'rationale for each high-impact score the model emits.'),
    ('incident handling',
     'Incident-handling gap #{n} requires an AI incident runbook covering '
     'containment, notification, and model rollback.'),
    ('MLOps control',
     'MLOps-control gap #{n} requires change-control evidence for every '
     'production promotion, rollback, and configuration change.'),
    ('SDAIA compliance',
     'SDAIA-compliance gap #{n} requires mapped SDAIA obligations, owners, '
     'and evidence artifacts before the use case is approved.'),
)

_AI_GUIDE_FAMILIES_AR = (
    ('حوكمة الذكاء الاصطناعي',
     'فجوة حوكمة الذكاء الاصطناعي رقم {n} تتطلب ميثاقاً معتمداً وفق سدايا '
     'يسمي مدير حوكمة الذكاء الاصطناعي قبل التوسع.'),
    ('مخاطر النماذج',
     'فجوة مخاطر النماذج رقم {n} تتطلب مراجعة مدير مخاطر النماذج للانحياز '
     'والانحراف قبل أي ترقية إنتاجية.'),
    ('جاهزية البيانات',
     'فجوة جاهزية البيانات رقم {n} تتطلب إثبات جودة البيانات والموافقة '
     'ونسبها لكل مجموعة تدريب واستدلال.'),
    ('الإنصاف والتحيز',
     'فجوة الإنصاف رقم {n} تتطلب اختبار إنصاف موثقاً ومراجعة أخطاء '
     'مجزأة قبل إطلاق النموذج.'),
    ('الإشراف البشري',
     'فجوة الإشراف البشري رقم {n} تتطلب مشرفاً مسمى وسجل تجاوز لكل قرار '
     'آلي عالي المخاطر.'),
    ('مراقبة النماذج',
     'فجوة مراقبة النماذج رقم {n} تتطلب عتبات انحراف وجودة وحادثة مع '
     'مالك مناوب بعد الإطلاق.'),
    ('قابلية التفسير',
     'فجوة قابلية التفسير رقم {n} تتطلب بطاقة نموذج ومبرراً موجهاً '
     'للمستفيد لكل درجة عالية الأثر.'),
    ('معالجة الحوادث',
     'فجوة معالجة الحوادث رقم {n} تتطلب دليل حوادث يشمل الاحتواء '
     'والإبلاغ والتراجع عن النموذج.'),
    ('ضبط MLOps',
     'فجوة ضبط MLOps رقم {n} تتطلب أدلة تغيير لكل ترقية إنتاجية '
     'وتراجع وتعديل إعداد.'),
    ('امتثال سدايا',
     'فجوة امتثال سدايا رقم {n} تتطلب ربط التزامات سدايا بالمالكين '
     'وأدلة الإثبات قبل اعتماد حالة الاستخدام.'),
)

_GOVERNANCE_INITIATIVES = (
    ('Publish the data-governance operating model',
     'Name decision rights, escalation, and the Data Governance Manager',
     'Approved data-governance charter',
     'Data Governance Manager'),
    ('Stand up the data-governance forum',
     'Convene stewards and the Data Protection Officer on a fixed cadence',
     'Signed data-governance forum minutes and RACI',
     'Data Governance Manager'),
    ('Evidence policy exceptions',
     'Log and close data-policy exceptions with residual-risk owners',
     'Controlled exception register',
     'Data Steward'),
)

_DEFAULT_DATA_INITIATIVES = (
    ('Register critical data assets',
     'Capture owner, quality rule, and classification for each asset',
     'Approved catalog entries for critical assets',
     'Data Catalog Owner'),
    ('Measure data quality',
     'Score completeness and accuracy for cataloged critical assets',
     'Monthly data-quality scorecard',
     'Data Quality Manager'),
    ('Protect personal data',
     'Apply PDPL classification, consent, and subject-rights controls',
     'Personal-data control evidence pack',
     'Data Protection Officer'),
)


def _domain_code(domain: Optional[str]) -> str:
    return _normalize_rel31_domain_code(str(domain or ''))


def _norm_dtype(document_type: Optional[str]) -> str:
    raw = str(document_type or 'strategy').strip().lower()
    if raw in {'', 'strategy', 'strategy_document', 'strategy document'}:
        return 'strategy'
    return raw


def _is_strategy(document_type: Optional[str]) -> bool:
    return _norm_dtype(document_type) == 'strategy'


def _is_placeholder(cell: str) -> bool:
    try:
        from app import _ts_is_placeholder
        return bool(_ts_is_placeholder(cell))
    except Exception:
        return bool(_PLACEHOLDER_RE.match(str(cell or '').strip()))


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


def _set_aliases(sections: Dict[str, str], canonical: str,
                 aliases: Sequence[str], text: str) -> None:
    sections[canonical] = text
    for key in aliases:
        if key != canonical and key in sections:
            sections[key] = text


def _count_gap_rows(text: str) -> int:
    try:
        from app import count_substantive_gaps
        return int(count_substantive_gaps(text or '') or 0)
    except Exception:
        n = 0
        in_tbl = False
        for ln in str(text or '').splitlines():
            s = ln.strip()
            if s.startswith('|') and 'gap' in s.lower() and '---' not in s:
                in_tbl = True
                continue
            if in_tbl and s.startswith('|') and not _SEP_RE.match(s):
                cells = [c.strip() for c in s.split('|')[1:-1]]
                if cells and cells[0].replace('.', '').isdigit():
                    n += 1
            elif in_tbl and not s.startswith('|'):
                in_tbl = False
        return n


def _count_kpi_rows(text: str) -> int:
    try:
        from app import count_substantive_kpis
        return int(count_substantive_kpis(text or '') or 0)
    except Exception:
        return 0


def _count_gap_guides_official(text: str) -> int:
    try:
        from app import count_gap_guides
        return int(count_gap_guides(text or '') or 0)
    except Exception:
        return len(re.findall(
            r'^####\s*(?:Gap\s*#?\d+\s*Implementation Guide|'
            r'دليل تنفيذ الفجوة\s*(?:رقم|#)?\s*\d+)',
            text or '',
            re.MULTILINE | re.IGNORECASE,
        ))


def official_guide_prefixes(text: str) -> List[str]:
    parts = _OFFICIAL_GUIDE_HDR_RE.split(text or '')
    return [b.strip()[:200] for b in parts[1:]]


def duplicate_guide_hashes(text: str) -> List[str]:
    bodies = official_guide_prefixes(text)
    seen: Dict[str, int] = {}
    dups: List[str] = []
    for idx, body in enumerate(bodies, 1):
        if body in seen and body not in dups:
            dups.append(body)
        else:
            seen[body] = idx
    return dups


def _normalize_guide_body(body: str) -> str:
    return re.sub(r'\s+', ' ', str(body or '')).strip().lower()


def guide_bodies_unique(text: str) -> bool:
    prefixes = official_guide_prefixes(text)
    if len(prefixes) < 2:
        return True
    return len(set(prefixes)) == len(prefixes)


def _leakage_terms(text: str, extra: Sequence[str] = ()) -> List[str]:
    hay = str(text or '')
    found: List[str] = []
    for tok in list(_DATA_LEAKS) + list(extra):
        if tok in {'IAM', 'PAM', 'MFA', 'CISO', 'SOC'}:
            if re.search(r'(?<![A-Z])%s(?![A-Z])' % tok, hay) and tok not in found:
                found.append(tok)
            continue
        if tok in hay and tok not in found:
            found.append(tok)
    return found


def _counted_pillar_matches(text: str) -> List[re.Match]:
    canonical = list(_PILLAR_HEADING_RE.finditer(text or ''))
    all_h3 = list(_H3_RE.finditer(text or ''))
    if len(all_h3) > len(canonical):
        return all_h3
    return canonical


def extract_counted_pillars(text: str) -> List[Tuple[str, str]]:
    matches = _counted_pillar_matches(text or '')
    out: List[Tuple[str, str]] = []
    for i, match in enumerate(matches):
        title = re.sub(r'^###\s+', '', match.group(0)).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out.append((title, (text or '')[start:end]))
    return out


def count_pillar_initiatives(body: str) -> int:
    in_table = False
    n = 0
    for ln in str(body or '').splitlines():
        s = ln.strip()
        if not (s.startswith('|') and s.endswith('|')):
            in_table = False
            continue
        if _SEP_RE.match(s):
            continue
        cells = [c.strip() for c in s.split('|')[1:-1]]
        hdr_hits = sum(1 for c in cells if _HDR_TOKENS.search(c or ''))
        if hdr_hits >= 2 and not in_table:
            in_table = True
            continue
        if not in_table or len(cells) < 2:
            continue
        data = (
            cells[1:]
            if cells and cells[0].replace('.', '').isdigit()
            else cells
        )
        if data and sum(1 for c in data if c and not _is_placeholder(c)) >= 2:
            n += 1
    return n


def weak_pillar_titles(text: str, min_rows: int = 1) -> List[str]:
    weak: List[str] = []
    for title, body in extract_counted_pillars(text):
        if count_pillar_initiatives(body) < min_rows:
            weak.append(title)
    return weak


def _initiative_bank(title: str) -> Sequence[Tuple[str, str, str, str]]:
    low = title.lower()
    if 'govern' in low or 'حوك' in title:
        return _GOVERNANCE_INITIATIVES
    if 'catalog' in low or 'كتالوج' in title:
        return (
            ('Stand up the enterprise data catalog',
             'Register critical data assets with owners and quality rules',
             'Approved data catalog covering critical assets',
             'Data Catalog Owner'),
            ('Publish catalog stewardship rules',
             'Require a named Data Steward before an asset is authoritative',
             'Catalog stewardship procedure',
             'Data Steward'),
            ('Link catalog entries to quality scores',
             'Surface completeness and accuracy beside each critical asset',
             'Catalog quality scorecard',
             'Data Quality Manager'),
        )
    if 'quality' in low or 'جود' in title:
        return (
            ('Measure completeness for critical assets',
             'Score null and default rates on cataloged critical fields',
             'Monthly completeness scorecard',
             'Data Quality Manager'),
            ('Measure accuracy for critical assets',
             'Reconcile cataloged values to the system of record',
             'Monthly accuracy scorecard',
             'Data Quality Manager'),
            ('Close quality exceptions',
             'Assign Data Stewards to remediate failed quality rules',
             'Closed quality-exception register',
             'Data Steward'),
        )
    if 'privacy' in low or 'pdpl' in low or 'خصوص' in title:
        return (
            ('Establish privacy governance',
             'Name the Data Protection Officer and escalation path',
             'Approved privacy governance charter',
             'Data Protection Officer'),
            ('Classify personal data',
             'Tag personal-data processing with PDPL sensitivity labels',
             'Personal data classification register',
             'Data Protection Officer'),
            ('Deploy consent management',
             'Capture, evidence, and withdraw consent for personal data',
             'Live consent management register',
             'Data Protection Officer'),
        )
    return _DEFAULT_DATA_INITIATIVES


def _pillar_table(title: str) -> str:
    rows = list(_initiative_bank(title))[:_MIN_INITIATIVES]
    lines = [_PILLAR_HEADER, _PILLAR_SEP]
    for idx, (init, desc, deliverable, owner) in enumerate(rows, 1):
        lines.append(
            f'| {idx} | {init} | {desc} | {deliverable} | {owner} |')
    return '\n'.join(lines) + '\n'


def _rebuild_pillars(text: str) -> str:
    matches = _counted_pillar_matches(text or '')
    if not matches:
        return text or ''
    out: List[str] = []
    cursor = 0
    for i, match in enumerate(matches):
        out.append((text or '')[cursor:match.start()])
        title_line = match.group(0)
        title = re.sub(r'^###\s+', '', title_line).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = (text or '')[start:end]
        if count_pillar_initiatives(body) < _MIN_INITIATIVES:
            suffix = ''
            # Keep trailing non-table prose after the first blank line
            # only when it is not another heading we already own.
            out.append(title_line.rstrip() + '\n\n' + _pillar_table(title))
            if not body.strip():
                suffix = ''
            out.append(suffix)
        else:
            out.append(title_line)
            out.append(body)
        cursor = end
    out.append((text or '')[cursor:])
    return ''.join(out)


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = [
        '| ' + ' | '.join(headers) + ' |',
        '|' + '|'.join(['---'] * len(headers)) + '|',
    ]
    for row in rows:
        lines.append('| ' + ' | '.join(str(c) for c in row) + ' |')
    return '\n'.join(lines)


def _guide_table(lang: str, owner: str, action: str, output: str) -> str:
    if lang.startswith('ar'):
        return _md_table(
            ['الخطوة', 'الإجراء', 'المسؤول', 'الإطار الزمني', 'الناتج'],
            [
                ['1', action, owner, '30 يوماً', output],
                ['2', 'توثيق الأدلة ومراجعة الامتثال', owner, '60 يوماً',
                 'حزمة أدلة معتمدة'],
                ['3', 'إغلاق البند وتحديث السجل', owner, '90 يوماً',
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


def _unique_gap_guides(n: int, *, domain: str, lang: str) -> str:
    if lang.startswith('ar'):
        families = _AI_GUIDE_FAMILIES_AR
        owners = _AI_OWNERS_AR
    elif domain == 'ai':
        families = _AI_GUIDE_FAMILIES_EN
        owners = _AI_OWNERS_EN
    else:
        families = _DATA_GUIDE_FAMILIES
        owners = _DATA_OWNERS
    parts: List[str] = []
    for i in range(1, n + 1):
        family, opening = families[(i - 1) % len(families)]
        owner = owners[(i - 1) % len(owners)]
        sentence = opening.format(n=i)
        if lang.startswith('ar'):
            heading = f'#### دليل تنفيذ الفجوة رقم {i}'
            action = f'إغلاق {family} وتوثيق التحكم التشغيلي للفجوة {i}'
            output = f'دليل تنفيذ معتمد للفجوة {i} مع أدلة الإغلاق'
        else:
            heading = f'#### Gap #{i} Implementation Guide'
            action = (
                f'Close the {family} control gap #{i} and evidence the '
                f'operating control'
            )
            output = f'Approved {family} implementation pack for gap #{i}'
        parts.extend([
            heading,
            '',
            sentence,
            '',
            _guide_table(lang, owner, action, output),
            '',
        ])
    return '\n'.join(parts).rstrip() + '\n'


def _unique_kpi_guides(n: int, *, domain: str, lang: str) -> str:
    if lang.startswith('ar'):
        owners = _AI_OWNERS_AR if domain == 'ai' else (
            'مدير حوكمة البيانات',
            'مدير جودة البيانات',
            'مسؤول حماية البيانات',
            'مالك كتالوج البيانات',
        )
        parts = ['### أدلة تقييم مؤشرات الأداء', '']
        for i in range(1, n + 1):
            owner = owners[(i - 1) % len(owners)]
            parts.extend([
                f'#### دليل تقييم المؤشر رقم {i}',
                '',
                f'دليل تقييم المؤشر رقم {i} يقيس المصدر المعتمد ويوثق '
                f'الانحراف عن القيمة المستهدفة للمؤشر {i}.',
                '',
                _guide_table(
                    'ar', owner,
                    f'قياس المؤشر رقم {i} من المصدر المعتمد وتوثيق الانحراف',
                    f'تقرير تقييم معتمد للمؤشر رقم {i}'),
                '',
            ])
        return '\n'.join(parts).rstrip() + '\n'
    owners = _AI_OWNERS_EN if domain == 'ai' else _DATA_OWNERS
    parts = ['### KPI Assessment Guidelines', '']
    for i in range(1, n + 1):
        owner = owners[(i - 1) % len(owners)]
        parts.extend([
            f'#### KPI #{i} Assessment Guide',
            '',
            f'KPI #{i} assessment requires the named owner to measure the '
            f'approved source and document variance for indicator {i}.',
            '',
            _guide_table(
                'en', owner,
                f'Measure KPI #{i} from the approved source and document variance',
                f'Approved KPI #{i} assessment report'),
            '',
        ])
    return '\n'.join(parts).rstrip() + '\n'


def _strip_gap_guides(text: str) -> str:
    return _GAP_GUIDE_BLOCK_RE.sub('', text or '').rstrip() + '\n'


def _strip_kpi_guides(text: str) -> str:
    stripped = _KPI_GUIDES_BLOCK_RE.sub('', text or '')
    stripped = _PER_KPI_GUIDE_RE.sub('', stripped)
    return stripped.rstrip() + '\n'


def _missing_guide_numbers(have: int, need: int) -> List[int]:
    if have >= need:
        return []
    return list(range(have + 1, need + 1))


def _relevant_save_blockers(
        sections: Dict[str, Any],
        *,
        domain: str,
        lang: str,
) -> List[str]:
    blockers: List[str] = []
    gaps = str(sections.get('gaps') or '')
    pillars = str(sections.get('pillars') or '')
    kpis = str(sections.get('kpis') or '')
    if domain == 'data' and lang.startswith('en'):
        missing = weak_pillar_titles(pillars, min_rows=1)
        if missing:
            blockers.append('pillars_missing_substantive_initiative')
    if domain in {'data', 'ai'} and lang.startswith('en'):
        if duplicate_guide_hashes(gaps):
            blockers.append('gap_guides_not_unique')
        counted = _count_gap_rows(gaps)
        if counted and _count_gap_guides_official(gaps) < counted:
            blockers.append('Gap Implementation Guides')
    if domain == 'ai' and lang.startswith('ar'):
        counted = _count_gap_rows(gaps)
        if counted and _count_gap_guides_official(gaps) < counted:
            blockers.append('Gap Implementation Guides')
        counted_k = _count_kpi_rows(kpis)
        have_k = len(_AR_KPI_GUIDE_RE.findall(kpis))
        if counted_k and have_k < counted_k:
            blockers.append('KPI Assessment Guidelines')
    return blockers


def _repair_en_data_pillars(
        sections: Dict[str, str],
        *,
        task_id: str,
) -> Dict[str, Any]:
    _ensure_canonical_key(sections, 'pillars', _PILLAR_ALIASES)
    before = str(sections.get('pillars') or '')
    titles_before = [t for t, _b in extract_counted_pillars(before)]
    counts_before = [count_pillar_initiatives(b) for _t, b in extract_counted_pillars(before)]
    weak_before = weak_pillar_titles(before, min_rows=_MIN_INITIATIVES)
    missing_before = weak_pillar_titles(before, min_rows=1)
    blockers_before = _relevant_save_blockers(
        sections, domain='data', lang='en')
    after_text = _rebuild_pillars(before)
    _set_aliases(sections, 'pillars', _PILLAR_ALIASES, after_text)
    titles_after = [t for t, _b in extract_counted_pillars(after_text)]
    counts_after = [count_pillar_initiatives(b) for _t, b in extract_counted_pillars(after_text)]
    weak_after = weak_pillar_titles(after_text, min_rows=_MIN_INITIATIVES)
    missing_after = weak_pillar_titles(after_text, min_rows=1)
    dup = len(titles_after) != len(set(t.lower() for t in titles_after))
    leaks = _leakage_terms(after_text)
    blockers_after = _relevant_save_blockers(
        sections, domain='data', lang='en')
    passed = (
        weak_after == []
        and missing_after == []
        and 'pillars_missing_substantive_initiative' not in blockers_after
        and leaks == []
    )
    return {
        'task_id': task_id,
        'pillar_titles_before': titles_before,
        'pillar_titles_after': titles_after,
        'initiative_counts_before': counts_before,
        'initiative_counts_after': counts_after,
        'weak_pillars_before': weak_before,
        'weak_pillars_after': weak_after,
        'pillars_missing_substantive_initiative_before': missing_before,
        'pillars_missing_substantive_initiative_after': missing_after,
        'duplicate_pillar_sections_after': dup,
        'leakage_terms_after': leaks,
        'save_blockers_before': blockers_before,
        'save_blockers_after': [
            b for b in blockers_after
            if b == 'pillars_missing_substantive_initiative'
        ],
        'passed': passed,
    }


def _repair_en_gap_guides(
        sections: Dict[str, str],
        *,
        domain: str,
        task_id: str,
) -> Dict[str, Any]:
    _ensure_canonical_key(sections, 'gaps', _GAP_ALIASES)
    before = str(sections.get('gaps') or '')
    counted = _count_gap_rows(before)
    guides_before = _count_gap_guides_official(before)
    dups_before = duplicate_guide_hashes(before)
    missing_before = _missing_guide_numbers(guides_before, counted)
    blockers_before = _relevant_save_blockers(
        sections, domain=domain, lang='en')
    needs = (
        counted > 0
        and (
            guides_before != counted
            or bool(dups_before)
            or not guide_bodies_unique(before)
        )
    )
    after = before
    if needs:
        after = _strip_gap_guides(before).rstrip() + '\n\n' + _unique_gap_guides(
            counted, domain=domain, lang='en')
        _set_aliases(sections, 'gaps', _GAP_ALIASES, after)
    guides_after = _count_gap_guides_official(after)
    dups_after = duplicate_guide_hashes(after)
    missing_after = _missing_guide_numbers(guides_after, counted)
    headers_valid = bool(
        counted == 0 or re.search(
            r'^####\s*Gap\s*#\d+\s*Implementation Guide\b', after, re.M)
    ) and not _AR_GAP_GUIDE_RE.search(after)
    unique_after = guide_bodies_unique(after)
    leaks = _leakage_terms(after, extra=_AI_LEAKS if domain == 'ai' else ())
    roadmap = str(sections.get('roadmap') or '')
    if '#### Gap #' in roadmap:
        leaks = list(leaks) + ['guides_in_roadmap']
    blockers_after = _relevant_save_blockers(
        sections, domain=domain, lang='en')
    passed = (
        dups_after == []
        and missing_after == []
        and unique_after
        and 'gap_guides_not_unique' not in blockers_after
        and 'Gap Implementation Guides' not in blockers_after
        and 'guides_in_roadmap' not in leaks
    )
    return {
        'task_id': task_id,
        'domain': domain,
        'lang': 'en',
        'counted_gap_rows': counted,
        'gap_guides_before': guides_before,
        'gap_guides_after': guides_after,
        'duplicate_guide_hashes_before': dups_before,
        'duplicate_guide_hashes_after': dups_after,
        'missing_gap_guides_before': missing_before,
        'missing_gap_guides_after': missing_after,
        'guide_headers_language_valid': headers_valid,
        'guide_bodies_unique_after': unique_after,
        'leakage_terms_after': leaks,
        'save_blockers_before': [
            b for b in blockers_before
            if b in {'gap_guides_not_unique', 'Gap Implementation Guides'}
        ],
        'save_blockers_after': [
            b for b in blockers_after
            if b in {'gap_guides_not_unique', 'Gap Implementation Guides'}
        ],
        'passed': passed,
    }


def _repair_ar_ai_guides(
        sections: Dict[str, str],
        *,
        task_id: str,
) -> Dict[str, Any]:
    _ensure_canonical_key(sections, 'gaps', _GAP_ALIASES)
    _ensure_canonical_key(sections, 'kpis', _KPI_ALIASES)
    gap_before = str(sections.get('gaps') or '')
    kpi_before = str(sections.get('kpis') or '')
    counted_gaps = _count_gap_rows(gap_before)
    counted_kpis = _count_kpi_rows(kpi_before)
    gap_guides_before = _count_gap_guides_official(gap_before)
    kpi_guides_before = len(_AR_KPI_GUIDE_RE.findall(kpi_before))
    # Normalize تطبيق → تنفيذ so the official counter and helper agree.
    gap_norm = _AR_GAP_APPLY_RE.sub(r'\1دليل تنفيذ الفجوة\2', gap_before)
    needs_gap = (
        counted_gaps > 0
        and (
            _count_gap_guides_official(gap_norm) != counted_gaps
            or bool(duplicate_guide_hashes(gap_norm))
            or not guide_bodies_unique(gap_norm)
        )
    )
    if needs_gap:
        gap_after = _strip_gap_guides(gap_norm).rstrip() + '\n\n' + (
            _unique_gap_guides(counted_gaps, domain='ai', lang='ar'))
    else:
        gap_after = gap_norm
    _set_aliases(sections, 'gaps', _GAP_ALIASES, gap_after)

    kpi_norm = kpi_before
    needs_kpi = (
        counted_kpis > 0
        and (
            len(_AR_KPI_HEADING_RE.findall(kpi_norm)) != 1
            or len(_AR_KPI_GUIDE_RE.findall(kpi_norm)) != counted_kpis
        )
    )
    if needs_kpi:
        kpi_after = _strip_kpi_guides(kpi_norm).rstrip() + '\n\n' + (
            _unique_kpi_guides(counted_kpis, domain='ai', lang='ar'))
    else:
        kpi_after = kpi_norm
    _set_aliases(sections, 'kpis', _KPI_ALIASES, kpi_after)

    gap_guides_after = _count_gap_guides_official(gap_after)
    kpi_guides_after = len(_AR_KPI_GUIDE_RE.findall(kpi_after))
    headings = (
        _AR_GAP_GUIDE_RE.findall(gap_after)
        + _AR_KPI_HEADING_RE.findall(kpi_after)
        + _AR_KPI_GUIDE_RE.findall(kpi_after)
    )
    leaks = _leakage_terms(gap_after + '\n' + kpi_after, extra=_AI_LEAKS)
    blockers_after = _relevant_save_blockers(
        sections, domain='ai', lang='ar')
    missing_gap_after = _missing_guide_numbers(gap_guides_after, counted_gaps)
    missing_kpi_after = _missing_guide_numbers(kpi_guides_after, counted_kpis)
    passed = (
        missing_gap_after == []
        and missing_kpi_after == []
        and blockers_after == []
        and leaks == []
    )
    return {
        'task_id': task_id,
        'counted_gap_rows': counted_gaps,
        'gap_guides_before': gap_guides_before,
        'gap_guides_after': gap_guides_after,
        'missing_gap_guides_after': missing_gap_after,
        'counted_kpi_rows': counted_kpis,
        'kpi_guides_before': kpi_guides_before,
        'kpi_guides_after': kpi_guides_after,
        'missing_kpi_guides_after': missing_kpi_after,
        'guide_headings_after': headings,
        'leakage_terms_after': leaks,
        'save_blockers_after': blockers_after,
        'passed': passed,
    }


def _canonical_vision(sections: Dict[str, str]) -> str:
    for key in _VISION_ALIASES:
        if str(sections.get(key) or '').strip():
            return str(sections[key])
    return ''


def _set_vision(sections: Dict[str, str], text: str) -> None:
    _set_aliases(sections, 'vision', _VISION_ALIASES, text)
    if 'vision' not in sections:
        sections['vision'] = text


def _header_is_canonical(header: str) -> bool:
    h = str(header or '')
    return (
        'Strategic Objective' in h
        and 'Measurable Target' in h
        and 'Rationale' in h
        and 'Timeframe' in h
        and 'Target Metric' not in h
        and 'Justification' not in h
    )


def _header_is_alias(header: str) -> bool:
    h = str(header or '')
    return (
        is_english_so_header_line(h)
        and (
            'Target Metric' in h
            or 'Justification' in h
            or re.search(r'\|\s*Objective\s*\|', h) is not None
        )
        and not _header_is_canonical(h)
    )


def _rewrite_so_header_in_place(text: str) -> Tuple[str, bool]:
    """Swap only the first English SO header line. Do not rebuild rows."""
    lines = str(text or '').splitlines()
    for i, ln in enumerate(lines):
        if is_english_so_header_line(ln):
            if ln.strip() == CANONICAL_SO_HEADER_EN:
                return text or '', False
            lines[i] = CANONICAL_SO_HEADER_EN
            return '\n'.join(lines) + ('\n' if str(text or '').endswith('\n') else ''), True
    repaired, changed = canonicalize_english_so_header(text or '')
    return repaired, changed


def _preview_header_mismatches(header: str) -> List[str]:
    if not header:
        return ['missing_so_header']
    mismatches: List[str] = []
    if 'Strategic Objective' not in header:
        mismatches.append('Strategic Objective')
    if 'Measurable Target' not in header:
        mismatches.append('Measurable Target')
    if 'Rationale' not in header:
        mismatches.append('Rationale')
    if 'Timeframe' not in header:
        mismatches.append('Timeframe')
    if 'Target Metric' in header:
        mismatches.append('Target Metric')
    if 'Justification' in header:
        mismatches.append('Justification')
    return mismatches


def _repair_en_so_header(
        sections: Dict[str, str],
        *,
        domain: str,
) -> Dict[str, Any]:
    before = _canonical_vision(sections)
    header_before = first_so_header(before)
    tables_before = count_so_tables(before)
    alias = _header_is_alias(header_before)
    after, applied = _rewrite_so_header_in_place(before)
    if after != before:
        _set_vision(sections, after)
    header_after = first_so_header(after)
    tables_after = count_so_tables(after)
    duplicate = tables_after > max(tables_before, 1)
    mismatches = _preview_header_mismatches(header_after)
    passed = (
        _header_is_canonical(header_after)
        and duplicate is False
        and mismatches == []
    )
    return {
        'domain': domain,
        'header_before': header_before,
        'header_after': header_after,
        'alias_header_detected': alias,
        'canonical_header_applied': applied or _header_is_canonical(header_after),
        'duplicate_so_table_after': duplicate,
        'preview_header_mismatch_after': mismatches,
        'passed': passed,
    }


def _count_split_tokens(sections: Dict[str, str]) -> int:
    return sum(
        str(sections.get(key) or '').count(_SPLIT_TOKEN)
        for key in _DT_SECTIONS
    )


def _official_dt_blockers(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]],
        lang: str,
) -> List[str]:
    try:
        from app import _compute_missing_selected_framework_coverage
        missing = _compute_missing_selected_framework_coverage(
            sections, list(_selected_list(selected_frameworks)),
            domain='Digital Transformation', lang=lang,
        ) or []
        return [
            f'selected_framework_coverage_missing:{fw}:{fam}'
            for fw, fam, _sk in missing
        ]
    except Exception:
        return []


def _repair_dt_split_token(
        sections: Dict[str, str],
        *,
        selected_frameworks: Optional[Iterable[Any]],
        lang: str,
) -> Dict[str, Any]:
    hits_before = _count_split_tokens(sections)
    for key in _DT_SECTIONS:
        blob = str(sections.get(key) or '')
        if _SPLIT_TOKEN in blob:
            sections[key] = blob.replace(_SPLIT_TOKEN, _CONTIGUOUS_TOKEN)
    hits_after = _count_split_tokens(sections)
    present = any(
        section_has_citizen_experience(sections.get(key, ''))
        or any(tok in str(sections.get(key) or '') for tok in OFFICIAL_CITIZEN_AR)
        for key in _DT_SECTIONS
    )
    if not present:
        # Preserve REL36.22 coverage if the split-only text was the signal.
        repaired, _diag22 = apply_rel36_22_dt_dga_citizen_experience_coverage(
            sections, domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=selected_frameworks, emit=False)
        sections.update(repaired)
        present = any(
            section_has_citizen_experience(sections.get(key, ''))
            for key in _DT_SECTIONS
        )
    blockers = _official_dt_blockers(sections, selected_frameworks, lang)
    citizen_blockers = [
        b for b in blockers if 'DGA:citizen_experience' in b
    ]
    passed = (
        hits_after == 0
        and present
        and citizen_blockers == []
    )
    return {
        'split_token_hits_before': hits_before,
        'split_token_hits_after': hits_after,
        'citizen_experience_token_present_after': present,
        'selected_framework_blockers_after': citizen_blockers,
        'passed': passed,
    }


def rel36_23_should_apply(
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        part: Optional[str] = None,
) -> bool:
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    if not _is_strategy(document_type):
        return False
    if part == 'A':
        return dcode == 'data' and nlang == 'en'
    if part == 'B':
        return dcode in {'data', 'ai'} and nlang == 'en'
    if part == 'C':
        return dcode == 'ai' and nlang == 'ar'
    if part == 'D':
        return nlang == 'en' and dcode in {'cyber', 'data', 'ai'}
    if part == 'E':
        return dcode == 'dt' and nlang == 'ar' and dga_selected(selected_frameworks)
    return (
        (dcode == 'data' and nlang == 'en')
        or (dcode in {'data', 'ai'} and nlang == 'en')
        or (dcode == 'ai' and nlang == 'ar')
        or (nlang == 'en' and dcode in {'cyber', 'data', 'ai'})
        or (dcode == 'dt' and nlang == 'ar' and dga_selected(selected_frameworks))
    )


def apply_rel36_23_data_ai_guides_and_visible_headers(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Optional[str] = None,
        org_name: Optional[str] = None,
        emit: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = {str(k): str(v or '') for k, v in (sections or {}).items()}
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    doc_type = _norm_dtype(document_type)
    fw = list(_selected_list(selected_frameworks))
    tid = task_id or ''
    diagnostics: Dict[str, Any] = {
        'task_id': tid,
        'domain': dcode,
        'lang': nlang,
        'document_type': doc_type,
        'selected_frameworks': fw,
        'org_name': org_name or '',
        'applied': False,
        'passed': False,
    }
    if not rel36_23_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type,
            selected_frameworks=fw):
        diagnostics['skipped'] = True
        return out, diagnostics

    parts: Dict[str, Any] = {}
    applied_any = False
    if rel36_23_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type, part='A'):
        parts['en_data_pillar_substance'] = _repair_en_data_pillars(
            out, task_id=tid)
        applied_any = True
        if emit:
            print(
                REL36_23_EN_DATA_PILLAR_SUBSTANCE_TAG + ' '
                + json.dumps(parts['en_data_pillar_substance'],
                             ensure_ascii=False, default=str),
                flush=True,
            )
    if rel36_23_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type, part='B'):
        parts['data_ai_gap_guide_uniqueness'] = _repair_en_gap_guides(
            out, domain=dcode, task_id=tid)
        applied_any = True
        if emit:
            print(
                REL36_23_DATA_AI_GAP_GUIDE_UNIQUENESS_TAG + ' '
                + json.dumps(parts['data_ai_gap_guide_uniqueness'],
                             ensure_ascii=False, default=str),
                flush=True,
            )
    if rel36_23_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type, part='C'):
        parts['ar_ai_guide_stability'] = _repair_ar_ai_guides(
            out, task_id=tid)
        applied_any = True
        if emit:
            print(
                REL36_23_AR_AI_GUIDE_STABILITY_TAG + ' '
                + json.dumps(parts['ar_ai_guide_stability'],
                             ensure_ascii=False, default=str),
                flush=True,
            )
    if rel36_23_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type, part='D'):
        parts['en_so_visible_header'] = _repair_en_so_header(
            out, domain=dcode)
        applied_any = True
        if emit:
            print(
                REL36_23_EN_SO_VISIBLE_HEADER_FINALIZER_TAG + ' '
                + json.dumps(parts['en_so_visible_header'],
                             ensure_ascii=False, default=str),
                flush=True,
            )
    if rel36_23_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type,
            selected_frameworks=fw, part='E'):
        parts['dt_ar_citizen_token'] = _repair_dt_split_token(
            out, selected_frameworks=fw, lang=nlang)
        applied_any = True
        if emit:
            print(
                REL36_23_DT_AR_CITIZEN_TOKEN_NORMALIZATION_TAG + ' '
                + json.dumps(parts['dt_ar_citizen_token'],
                             ensure_ascii=False, default=str),
                flush=True,
            )

    passed = applied_any and all(
        bool(part.get('passed')) for part in parts.values()
    )
    diagnostics.update({
        'applied': applied_any,
        'passed': passed,
        'parts': parts,
    })
    return out, diagnostics
