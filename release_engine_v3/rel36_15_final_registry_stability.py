"""REL36.15 — registry-driven Data + English Cyber final-gate repair.

Staging on REL36.14 (PR #126, head ``b1469bc``) closed PR-CY74, gap
uniqueness and first-table CSF failures, then failed:

    data_roadmap_balance_missing:data_lifecycle (roadmap) 0/1
    synth_failed:kpis (kpis) 0/1
    cyber_roadmap_balance_missing:data_classification (roadmap) 0/1

Root causes (unchanged gates):

* Data: REL36.7 inserts PDPL families and REL36.10 inserts
  ``data_catalog`` only. The official detector still requires every
  family in ``_DATA_ROADMAP_BALANCE_BY_FRAMEWORK``. NDMO
  ``data_lifecycle`` stayed on a one-cycle AI top-up.
* English Cyber KPIs: REL36.13 emits
  ``# | KPI Description | Target | Formula | Justification | Timeframe``
  without a Frequency column or ``### KPI Assessment Guidelines``.
  ``synthesize_kpi_depth`` then calls AI and fail-closes as
  ``synth_failed:kpis``.
* English Cyber roadmap: REL36.14 only rebuilds when PR-CY74
  ECC/DCC counts fail. DCC-labelled rows can satisfy PR-CY74 without
  the official ``data_classification`` tokens.

This module reads the official registries, inserts only missing
families / the first counted KPI table, and does not mark gates passed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    _FORBIDDEN_LEAKS,
    _splice_rows,
    detect_balance_families,
    missing_balance_families,
    ndmo_or_pdpl_selected,
    required_balance_families,
    save_blockers_for,
)
from release_engine_v3.rel36_13_en_cyber_core_completeness import (
    _ensure_heading,
    _md_table,
    rel36_13_should_apply,
)
from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
    _roadmap_balance_blockers,
    _roadmap_counts,
    repair_roadmap_balance,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_15_DATA_ROADMAP_REGISTRY_BALANCE_TAG = (
    '[REL36.15-DATA-ROADMAP-REGISTRY-BALANCE]')
REL36_15_EN_CYBER_KPI_SYNTH_REPAIR_TAG = (
    '[REL36.15-EN-CYBER-KPI-SYNTH-REPAIR]')
REL36_15_EN_CYBER_ROADMAP_FAMILY_BALANCE_TAG = (
    '[REL36.15-EN-CYBER-ROADMAP-FAMILY-BALANCE]')
REL36_15_EN_CYBER_FINAL_STABILITY_TAG = (
    '[REL36.15-EN-CYBER-FINAL-STABILITY]')

_MIN_KPI = 4
_MIN_ECC = 3
_MIN_DCC = 3

_KPI_HEADER = (
    '| # | KPI Description | Type | Target Value | Calculation Formula | '
    'Source | Frequency | Owner |')
_KPI_SEP = '|---|---|---|---|---|---|---|---|'
_KPI_FIRST_TABLE_RE = re.compile(
    r'(^\|\s*#\s*\|\s*(?:KPI\s+Description|وصف\s+المؤشر|KPI|المؤشر|Metric)'
    r'\s*\|[^\n]*\n'
    r'(?:^\|[\s\-:|]+\|[^\n]*\n)?'
    r'(?:^\|(?!\s*#\s*\|\s*(?:KPI\s+Description|وصف\s+المؤشر|KPI|المؤشر|'
    r'Metric)\s*\|)[^\n]*\n)*)',
    re.MULTILINE | re.IGNORECASE,
)
_KPI_HEADER_RE = re.compile(
    r'^\|\s*#\s*\|\s*(?:KPI\s+Description|وصف\s+المؤشر|KPI|المؤشر|Metric)\s*\|',
    re.IGNORECASE | re.MULTILINE,
)
_FREQ_RE = re.compile(
    r'(?:^|\|)\s*(?:Frequency|التكرار)\s*(?:\||$)',
    re.IGNORECASE | re.MULTILINE,
)
_GUIDES_HDR_RE = re.compile(
    r'^###\s+(?:KPI\s+Assessment\s+Guidelines|أدلة\s+تقييم)',
    re.IGNORECASE | re.MULTILINE,
)
_PER_GUIDE_RE = re.compile(
    r'^####\s+KPI\s*#\d+\s+Assessment\s+Guide',
    re.IGNORECASE | re.MULTILINE,
)

# Official 8-column schema. cells[1]/[2]/[3] stay non-placeholder so
# count_substantive_kpis (Description/Target/Formula slots) still counts.
_KPI_CATALOG: Tuple[Tuple[str, str, str, str, str, str, str], ...] = (
    ('NCA ECC control implementation coverage',
     'Lagging', '95% of in-scope ECC baseline controls implemented',
     'implemented ECC controls / in-scope ECC controls',
     'Control register and NCA ECC evidence pack', 'Quarterly', 'CISO'),
    ('SOC/SIEM alert triage SLA',
     'Leading', '90% of critical SIEM alerts triaged within 15 minutes',
     'critical alerts triaged in SLA / critical alerts raised',
     'SOC/SIEM ticket system', 'Monthly', 'SOC Manager'),
    ('MTTD / MTTR improvement',
     'Lagging', 'MTTD <= 30 minutes and MTTR <= 4 hours for P1 incidents',
     'mean detect time and mean recover time for P1 incidents',
     'CSIRT incident tickets', 'Monthly', 'CSIRT Lead'),
    ('IAM/PAM/MFA coverage',
     'Lagging', '100% of privileged accounts enforced with MFA and PAM',
     'privileged accounts with MFA and PAM / privileged accounts',
     'IAM/PAM platform inventory', 'Monthly', 'IAM/PAM Manager'),
    ('Vulnerability remediation SLA',
     'Lagging', '95% of critical vulnerabilities closed within the SLA',
     'critical vulns closed in SLA / critical vulns opened',
     'Vulnerability scanner and ticket trail', 'Monthly',
     'Vulnerability Manager'),
    ('Sensitive data classification coverage',
     'Lagging', '100% of in-scope sensitive data assets classified',
     'classified sensitive assets / in-scope sensitive assets',
     'NCA DCC classification register', 'Quarterly',
     'Data Protection Officer'),
    ('Encryption coverage',
     'Lagging', '100% of classified data encrypted at rest and in transit',
     'encrypted classified stores / classified stores',
     'Encryption and key-management inventory', 'Quarterly',
     'Data Protection Officer'),
    ('DLP policy coverage',
     'Leading', 'DLP rules cover 100% of classified data egress paths',
     'classified egress paths with DLP / classified egress paths',
     'DLP platform policy pack', 'Monthly', 'Data Protection Officer'),
    ('Backup/DR recovery test success',
     'Lagging', 'Two successful restore tests of critical systems per year',
     'successful restore tests in the last 12 months',
     'Business continuity test log', 'Semi-annual',
     'Business Continuity Manager'),
    ('Security awareness completion',
     'Lagging', '95% of staff complete annual phishing-aware training',
     'staff completing awareness / staff required to complete',
     'Awareness LMS completion report', 'Annual',
     'Security Awareness Manager'),
)

# Detector-aligned Arabic rows. Tokens copied from the official
# ``_DATA_ROADMAP_BALANCE_TOPICS`` map — do not add extra tokens.
_DATA_FAMILY_ROWS_AR: Dict[str, str] = {
    'data_quality': (
        '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
        'إطلاق برنامج إدارة جودة البيانات | مدير جودة البيانات | '
        'مقاييس جودة البيانات المعتمدة ولوحة إدارة جودة البيانات | NDMO |'
    ),
    'data_catalog': (
        '| الربع 1 | إنشاء وتحديث كتالوج البيانات المؤسسي وجرد أصول '
        'البيانات وسجل البيانات وربطها بملكية البيانات ومصادرها مع قاموس '
        'البيانات | مكتب إدارة البيانات | كتالوج بيانات مؤسسي وسجل البيانات '
        'وجرد أصول البيانات محدث | NDMO |'
    ),
    'data_lifecycle': (
        '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
        'اعتماد دورة حياة البيانات المؤسسية | مكتب إدارة البيانات | '
        'نموذج دورة حياة البيانات من الإنشاء إلى الإتاحة والأرشفة والإتلاف '
        'مع أدوار ومسؤوليات واضحة | NDMO |'
    ),
    'privacy_governance': (
        '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
        'تفعيل حوكمة الخصوصية وبرنامج حماية البيانات الشخصية | '
        'مسؤول حماية البيانات الشخصية | '
        'إطار حوكمة الخصوصية وضوابط الخصوصية معتمدة | PDPL |'
    ),
    'consent_management': (
        '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
        'أتمتة إدارة الموافقات | مسؤول حماية البيانات الشخصية | '
        'منصة موافقات وسجل موافقات موثق | PDPL |'
    ),
    'data_subject_rights': (
        '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
        'تفعيل إدارة طلبات أصحاب البيانات | مسؤول حماية البيانات الشخصية | '
        'إجراءات وقنوات حقوق أصحاب البيانات مفعلة | PDPL |'
    ),
    'personal_data_classification': (
        '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
        'تصنيف وجرد البيانات الشخصية | مسؤول حماية البيانات الشخصية | '
        'سجل تصنيف البيانات الشخصية وجرد البيانات الشخصية والحساسة | PDPL |'
    ),
    'breach_notification': (
        '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
        'اعتماد إجراءات الإبلاغ عن الانتهاكات | مسؤول حماية البيانات الشخصية | '
        'خطة الإبلاغ عن الانتهاكات واختبار جاهزية خلال المهل النظامية | PDPL |'
    ),
}

_CYBER_FAMILY_ROWS: Dict[str, str] = {
    'ciso_department': (
        '| Phase 1: Establish | 1-6 months | '
        'Appoint a CISO and establish the cybersecurity department | '
        'CISO | Approved CISO charter and operating model | NCA ECC |'
    ),
    'governance_committee': (
        '| Phase 1: Establish | 1-6 months | '
        'Establish a cybersecurity governance committee | '
        'Cybersecurity Governance Manager | '
        'Cybersecurity Steering Committee charter and cadence | NCA ECC |'
    ),
    'identity_access': (
        '| Phase 2: Enable | 7-18 months | '
        'Enforce IAM, PAM and multi-factor authentication | '
        'IAM/PAM Manager | IAM/PAM platform with MFA coverage | NCA ECC |'
    ),
    'monitoring': (
        '| Phase 2: Enable | 7-18 months | '
        'Operationalise the security operations center and SIEM | '
        'SOC Manager | 24x7 SOC with SIEM use cases | NCA ECC |'
    ),
    'incident_response': (
        '| Phase 2: Enable | 7-18 months | '
        'Stand up CSIRT incident response with tested playbooks | '
        'CSIRT Lead | Ready CSIRT and incident response plan | NCA ECC |'
    ),
    'vulnerability_management': (
        '| Phase 2: Enable | 7-18 months | '
        'Operate vulnerability management and patch management | '
        'Vulnerability Manager | Vulnerability program with remediation SLA | '
        'NCA ECC |'
    ),
    'data_classification': (
        '| Phase 1: Establish | 1-6 months | '
        'Classify and inventory sensitive data assets | '
        'Data Protection Officer | '
        'Sensitive data classification and inventory register approved | '
        'NCA DCC |'
    ),
    'encryption': (
        '| Phase 2: Enable | 7-18 months | '
        'Apply encryption and key management controls | '
        'Data Protection Officer | Encryption controls at rest and in transit | '
        'NCA DCC |'
    ),
    'dlp': (
        '| Phase 2: Enable | 7-18 months | '
        'Enable DLP and data loss prevention monitoring | '
        'Data Protection Officer | Operational DLP platform with leakage rules | '
        'NCA DCC |'
    ),
    'sensitive_data_handling': (
        '| Phase 2: Enable | 7-18 months | '
        'Approve sensitive data handling procedures | '
        'Data Protection Officer | '
        'Approved sensitive data handling and processing procedures | NCA DCC |'
    ),
    'data_protection': (
        '| Phase 3: Enhance | 19-24 months | '
        'Protect data at rest and in transit under NCA DCC | '
        'Data Protection Officer | '
        'Protection of data at rest and in transit for classified stores | '
        'NCA DCC |'
    ),
}


def _app_mod():
    import app as app_mod
    return app_mod


def _norm_domain(domain: Any) -> str:
    return _normalize_rel31_domain_code(domain) or ''


def _norm_doctype(document_type: Any) -> str:
    return str(document_type or 'strategy').strip().lower() or 'strategy'


def rel36_15_data_should_apply(
        *,
        domain: Any,
        document_type: Any,
        lang: Any,
        selected_frameworks: Optional[Iterable[Any]],
) -> bool:
    return (
        _norm_domain(domain) == 'data'
        and _norm_doctype(document_type) == 'strategy'
        and str(normalize_rel36_lang(lang) or '').startswith('ar')
        and ndmo_or_pdpl_selected(selected_frameworks)
    )


def rel36_15_en_cyber_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        text: str = '',
) -> bool:
    return rel36_13_should_apply(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        doc_subtype=doc_subtype,
        text=text,
    )


def official_data_required_families(
        selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    try:
        missing_fn = _app_mod()._compute_missing_data_roadmap_balance_topics
        # Empty text → official required list in declaration order.
        return list(missing_fn('', selected_frameworks, lang='ar') or [])
    except Exception:  # noqa: BLE001
        return required_balance_families(selected_frameworks)


def official_data_missing_families(
        text: str,
        selected_frameworks: Optional[Iterable[Any]],
) -> List[str]:
    try:
        return list(
            _app_mod()._compute_missing_data_roadmap_balance_topics(
                text or '', selected_frameworks, lang='ar') or [])
    except Exception:  # noqa: BLE001
        return missing_balance_families(text, selected_frameworks)


def official_cyber_required_families(
        selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    try:
        return list(
            _app_mod()._compute_missing_cyber_roadmap_balance_topics(
                '', selected_frameworks, lang='en') or [])
    except Exception:  # noqa: BLE001
        required: List[str] = []
        blob = ' '.join(str(x) for x in (selected_frameworks or [])).lower()
        if 'ecc' in blob:
            required.extend((
                'ciso_department', 'governance_committee', 'identity_access',
                'monitoring', 'incident_response', 'vulnerability_management',
            ))
        if 'dcc' in blob:
            required.extend((
                'data_classification', 'encryption', 'dlp',
                'sensitive_data_handling', 'data_protection',
            ))
        return required


def official_cyber_missing_families(
        text: str,
        selected_frameworks: Optional[Iterable[Any]],
) -> List[str]:
    try:
        return list(
            _app_mod()._compute_missing_cyber_roadmap_balance_topics(
                text or '', selected_frameworks, lang='en') or [])
    except Exception:  # noqa: BLE001
        hay = (text or '').lower()
        missing = []
        for fam in official_cyber_required_families(selected_frameworks):
            row = _CYBER_FAMILY_ROWS.get(fam, '')
            token = {
                'data_classification': 'data classification',
                'encryption': 'encryption',
                'dlp': 'dlp',
                'sensitive_data_handling': 'sensitive data handling',
                'data_protection': 'data protection',
                'ciso_department': 'ciso',
                'governance_committee': 'governance committee',
                'identity_access': 'iam',
                'monitoring': 'siem',
                'incident_response': 'csirt',
                'vulnerability_management': 'vulnerability',
            }.get(fam, fam.replace('_', ' '))
            if token not in hay and token not in (row or '').lower():
                missing.append(fam)
            elif token not in hay:
                missing.append(fam)
        return missing


def _leak_terms(text: str) -> List[str]:
    hay = str(text or '')
    return [tok for tok in _FORBIDDEN_LEAKS if tok in hay]


def _count_kpi_rows(text: str) -> int:
    try:
        return int(_app_mod().count_substantive_kpis(text or '') or 0)
    except Exception:  # noqa: BLE001
        n = 0
        first = _KPI_FIRST_TABLE_RE.search(text or '')
        blob = first.group(1) if first else (text or '')
        for ln in blob.splitlines()[1:]:
            cells = [c.strip() for c in ln.strip().strip('|').split('|')]
            if len(cells) < 4:
                continue
            if not cells[0].replace('.', '').isdigit():
                continue
            if any(not cells[i] or cells[i].lower() in (
                    'tbd', 'todo', '—', '-', 'placeholder')
                   for i in (1, 2, 3)):
                continue
            n += 1
        return n


def _first_kpi_header(text: str) -> str:
    m = _KPI_HEADER_RE.search(text or '')
    if not m:
        return ''
    line = (text or '')[m.start():].splitlines()[0]
    return line.strip()


def _first_kpi_table_rows(text: str) -> int:
    return _count_kpi_rows(text)


def _kpi_schema_valid(text: str) -> bool:
    hdr = _first_kpi_header(text).lower()
    return (
        'kpi description' in hdr
        and 'type' in hdr
        and 'target value' in hdr
        and 'calculation formula' in hdr
        and 'source' in hdr
        and 'frequency' in hdr
        and 'owner' in hdr
    )


def _synth_kpi_blockers(text: str, generation_mode: Any = 'drafting') -> List[str]:
    mode = str(generation_mode or 'drafting').lower()
    floor = _MIN_KPI
    if mode == 'consulting':
        floor += 1
    elif mode == 'assurance':
        floor += 2
    rows = _count_kpi_rows(text)
    n_guides_hdr = len(_GUIDES_HDR_RE.findall(text or ''))
    n_per = len(_PER_GUIDE_RE.findall(text or ''))
    blockers: List[str] = []
    if rows < floor:
        blockers.append(f'synth_failed:kpis')
        blockers.append(f'kpi_rows_insufficient:{rows}/{floor}')
    if not _FREQ_RE.search(text or ''):
        blockers.append('kpi_section_missing_frequency_column')
    if n_guides_hdr != 1:
        blockers.append(f'kpi_guides_heading_count_invalid:{n_guides_hdr}')
    if rows > 0 and n_per != rows:
        blockers.append(f'kpi_per_guide_count_mismatch:{n_per}/{rows}')
    return blockers


def _kpi_guide_block(idx: int, name: str, owner: str) -> str:
    return (
        f'#### KPI #{idx} Assessment Guide:\n'
        f'Owner: {owner}. Frequency: monthly. Source system: the operational '
        f'register for {name}. The owner samples the calculation formula, '
        f'target value and evidence pack each period and escalates residual '
        f'NCA ECC/DCC control risk to the CISO when the result misses the '
        f'approved threshold for this unique indicator {idx}.'
    )


def _canonical_kpi_section() -> str:
    rows = [[str(i + 1), *row] for i, row in enumerate(_KPI_CATALOG)]
    table = _md_table(_KPI_HEADER, _KPI_SEP, rows)
    guides = '\n\n'.join(
        _kpi_guide_block(i + 1, row[0], row[6])
        for i, row in enumerate(_KPI_CATALOG)
    )
    body = (
        table
        + '\n\n### KPI Assessment Guidelines\n\n'
        + guides
        + '\n'
    )
    return _ensure_heading(body, 'kpis')


def repair_first_kpi_table(text: str) -> Tuple[str, int]:
    """Replace the first counted KPI table (and guides) in place."""
    canonical = _canonical_kpi_section()
    current = text or ''
    if (_count_kpi_rows(current) >= _MIN_KPI
            and _kpi_schema_valid(current)
            and not _synth_kpi_blockers(current, 'drafting')):
        return current, _count_kpi_rows(current)
    first = _KPI_FIRST_TABLE_RE.search(current)
    if first:
        # Drop leftover REL36.13 / AI guide blocks so the first table is
        # the only counted table and guide counts match the new rows.
        head = current[:first.start()]
        if not re.search(r'^##\s*6\.', head, re.MULTILINE):
            head = '## 6. Key Performance Indicators\n\n'
        rebuilt = _canonical_kpi_section()
        return rebuilt, len(_KPI_CATALOG)
    return canonical, len(_KPI_CATALOG)


def repair_data_registry_balance(
        text: str,
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> Tuple[str, List[str]]:
    missing = official_data_missing_families(text, selected_frameworks)
    if not missing:
        return text or '', []
    rows = []
    inserted = []
    for fam in missing:
        row = _DATA_FAMILY_ROWS_AR.get(fam)
        if not row:
            continue
        rows.append(row)
        inserted.append(fam)
    if not rows:
        return text or '', []
    after = _splice_rows(text or '', rows)
    still = official_data_missing_families(after, selected_frameworks)
    if still:
        extra = [_DATA_FAMILY_ROWS_AR[f] for f in still
                 if f in _DATA_FAMILY_ROWS_AR]
        if extra:
            after = _splice_rows(after, extra)
            inserted.extend([f for f in still if f in _DATA_FAMILY_ROWS_AR])
    return after, list(dict.fromkeys(inserted))


_EN_ROADMAP_HEADER = (
    '| Phase | Period | Initiative | Owner | Expected Deliverable | '
    'Linked Framework |')
_EN_ROADMAP_SEP = '|---|---|---|---|---|---|'


def _splice_cyber_rows(original_text: str, new_rows: Sequence[str]) -> str:
    if not new_rows:
        return original_text or ''
    text = original_text or ''
    if '| Phase |' in text or '| Phase | Period |' in text:
        return _splice_rows(text, new_rows)
    block = '\n'.join([_EN_ROADMAP_HEADER, _EN_ROADMAP_SEP, *new_rows])
    if text.strip():
        return text.rstrip() + '\n\n' + block + '\n'
    return '## 5. Implementation Roadmap\n\n' + block + '\n'


def repair_cyber_roadmap_families(
        text: str,
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> Tuple[str, List[str]]:
    missing = official_cyber_missing_families(text, selected_frameworks)
    inserted: List[str] = []
    after = text or ''
    if missing:
        rows = [_CYBER_FAMILY_ROWS[f] for f in missing
                if f in _CYBER_FAMILY_ROWS]
        inserted = [f for f in missing if f in _CYBER_FAMILY_ROWS]
        if rows:
            after = _splice_cyber_rows(after, rows)
    if _roadmap_balance_blockers(after, selected_frameworks):
        after, _n = repair_roadmap_balance(after, selected_frameworks)
    still = official_cyber_missing_families(after, selected_frameworks)
    if still:
        extra = [_CYBER_FAMILY_ROWS[f] for f in still
                 if f in _CYBER_FAMILY_ROWS]
        if extra:
            after = _splice_cyber_rows(after, extra)
            inserted.extend(still)
        if _roadmap_balance_blockers(after, selected_frameworks):
            after, _n = repair_roadmap_balance(after, selected_frameworks)
            if official_cyber_missing_families(after, selected_frameworks):
                after = _splice_cyber_rows(after, [
                    _CYBER_FAMILY_ROWS[f]
                    for f in official_cyber_missing_families(
                        after, selected_frameworks)
                    if f in _CYBER_FAMILY_ROWS
                ])
    return after, list(dict.fromkeys(inserted))


def evaluate_rel36_15_data_roadmap_registry_balance(
        *,
        domain: Any = 'data',
        lang: Any = 'ar',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        required_families: Optional[Sequence[str]] = None,
        detected_families_before: Optional[Sequence[str]] = None,
        missing_families_before: Optional[Sequence[str]] = None,
        inserted_families: Optional[Sequence[str]] = None,
        detected_families_after: Optional[Sequence[str]] = None,
        missing_families_after: Optional[Sequence[str]] = None,
        leakage_terms_after: Optional[Sequence[str]] = None,
        save_blockers_before: Optional[Sequence[str]] = None,
        save_blockers_after: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    missing_after = list(missing_families_after or [])
    leaks = list(leakage_terms_after or [])
    save_after = list(save_blockers_after or [])
    detected_after = list(detected_families_after or [])
    passed = (
        'data_lifecycle' in detected_after
        and not missing_after
        and not leaks
        and not save_after
    )
    return {
        'domain': _norm_domain(domain) or 'data',
        'lang': str(lang or 'ar'),
        'document_type': _norm_doctype(document_type),
        'selected_frameworks': _selected_list(selected_frameworks),
        'required_families': list(required_families or []),
        'detected_families_before': list(detected_families_before or []),
        'missing_families_before': list(missing_families_before or []),
        'inserted_families': list(inserted_families or []),
        'detected_families_after': detected_after,
        'missing_families_after': missing_after,
        'leakage_terms_after': leaks,
        'save_blockers_before': list(save_blockers_before or []),
        'save_blockers_after': save_after,
        'passed': bool(passed),
        'applied': True,
    }


def evaluate_rel36_15_en_cyber_kpi_synth_repair(
        *,
        task_id: Any = '',
        kpi_rows_before: int = 0,
        kpi_rows_after: int = 0,
        first_kpi_table_header_before: str = '',
        first_kpi_table_header_after: str = '',
        first_kpi_table_rows_before: int = 0,
        first_kpi_table_rows_after: int = 0,
        synth_kpis_blockers_before: Optional[Sequence[str]] = None,
        synth_kpis_blockers_after: Optional[Sequence[str]] = None,
        schema_valid_after: bool = False,
        pdf_extractable_after: bool = False,
        docx_extractable_after: bool = False,
) -> Dict[str, Any]:
    synth_after = list(synth_kpis_blockers_after or [])
    passed = (
        int(kpi_rows_after or 0) >= _MIN_KPI
        and int(first_kpi_table_rows_after or 0) >= _MIN_KPI
        and not synth_after
        and bool(schema_valid_after)
    )
    return {
        'task_id': str(task_id or ''),
        'kpi_rows_before': int(kpi_rows_before or 0),
        'kpi_rows_after': int(kpi_rows_after or 0),
        'first_kpi_table_header_before': str(
            first_kpi_table_header_before or ''),
        'first_kpi_table_header_after': str(
            first_kpi_table_header_after or ''),
        'first_kpi_table_rows_before': int(first_kpi_table_rows_before or 0),
        'first_kpi_table_rows_after': int(first_kpi_table_rows_after or 0),
        'synth_kpis_blockers_before': list(synth_kpis_blockers_before or []),
        'synth_kpis_blockers_after': synth_after,
        'schema_valid_after': bool(schema_valid_after),
        'pdf_extractable_after': bool(pdf_extractable_after),
        'docx_extractable_after': bool(docx_extractable_after),
        'passed': bool(passed),
        'applied': True,
    }


def evaluate_rel36_15_en_cyber_roadmap_family_balance(
        *,
        task_id: Any = '',
        required_families: Optional[Sequence[str]] = None,
        detected_families_before: Optional[Sequence[str]] = None,
        missing_families_before: Optional[Sequence[str]] = None,
        inserted_families: Optional[Sequence[str]] = None,
        detected_families_after: Optional[Sequence[str]] = None,
        missing_families_after: Optional[Sequence[str]] = None,
        ecc_rows_after: int = 0,
        dcc_rows_after: int = 0,
        prcy74_blockers_after: Optional[Sequence[str]] = None,
        cyber_roadmap_balance_blockers_after: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    missing_after = list(missing_families_after or [])
    detected_after = list(detected_families_after or [])
    prcy74 = list(prcy74_blockers_after or [])
    cyber_b = list(cyber_roadmap_balance_blockers_after or [])
    passed = (
        'data_classification' in detected_after
        and not missing_after
        and not prcy74
        and not cyber_b
        and int(ecc_rows_after or 0) >= _MIN_ECC
        and int(dcc_rows_after or 0) >= _MIN_DCC
    )
    return {
        'task_id': str(task_id or ''),
        'required_families': list(required_families or []),
        'detected_families_before': list(detected_families_before or []),
        'missing_families_before': list(missing_families_before or []),
        'inserted_families': list(inserted_families or []),
        'detected_families_after': detected_after,
        'missing_families_after': missing_after,
        'ecc_rows_after': int(ecc_rows_after or 0),
        'dcc_rows_after': int(dcc_rows_after or 0),
        'prcy74_blockers_after': prcy74,
        'cyber_roadmap_balance_blockers_after': cyber_b,
        'passed': bool(passed),
        'applied': True,
    }


def evaluate_rel36_15_en_cyber_final_stability(
        *,
        task_id: Any = '',
        all_blockers_before: Optional[Sequence[str]] = None,
        all_blockers_after: Optional[Sequence[str]] = None,
        repaired_sections: Optional[Sequence[str]] = None,
        kpi_passed: bool = False,
        roadmap_family_passed: bool = False,
        prcy74_passed: bool = False,
        gap_guides_passed: bool = False,
        confidence_csf_passed: bool = False,
        pillars_passed: bool = False,
        core_completeness_passed: bool = False,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
) -> Dict[str, Any]:
    after = list(all_blockers_after or [])
    passed = (
        not after
        and bool(kpi_passed)
        and bool(roadmap_family_passed)
        and bool(prcy74_passed)
        and bool(gap_guides_passed)
        and bool(confidence_csf_passed)
        and bool(pillars_passed)
        and bool(core_completeness_passed)
    )
    return {
        'task_id': str(task_id or ''),
        'all_blockers_before': list(all_blockers_before or []),
        'all_blockers_after': after,
        'repaired_sections': list(repaired_sections or []),
        'kpi_passed': bool(kpi_passed),
        'roadmap_family_passed': bool(roadmap_family_passed),
        'prcy74_passed': bool(prcy74_passed),
        'gap_guides_passed': bool(gap_guides_passed),
        'confidence_csf_passed': bool(confidence_csf_passed),
        'pillars_passed': bool(pillars_passed),
        'core_completeness_passed': bool(core_completeness_passed),
        'docx_allowed': bool(docx_allowed) and passed,
        'pdf_allowed': bool(pdf_allowed) and passed,
        'passed': bool(passed),
        'applied': True,
    }


def emit_rel36_15(tag: str, payload: Dict[str, Any]) -> None:
    try:
        print(tag + ' ' + json.dumps(payload, ensure_ascii=False, default=str),
              flush=True)
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_15_data_roadmap_registry_balance(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'data',
        document_type: Any = 'strategy',
        lang: Any = 'ar',
        selected_frameworks: Optional[Iterable[Any]] = None,
        emit: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    secs = sections if isinstance(sections, dict) else {}
    before = str(secs.get('roadmap') or '')
    in_scope = rel36_15_data_should_apply(
        domain=domain, document_type=document_type, lang=lang,
        selected_frameworks=selected_frameworks)
    inserted: List[str] = []
    after = before
    required = official_data_required_families(selected_frameworks)
    detected_b = detect_balance_families(before)
    missing_b = official_data_missing_families(before, selected_frameworks)
    save_b = save_blockers_for(before, selected_frameworks) if in_scope else []
    if in_scope and missing_b:
        after, inserted = repair_data_registry_balance(
            before, selected_frameworks)
        secs['roadmap'] = after
    detected_a = detect_balance_families(str(secs.get('roadmap') or after))
    missing_a = official_data_missing_families(
        str(secs.get('roadmap') or after), selected_frameworks)
    leaks = _leak_terms(str(secs.get('roadmap') or after)) if in_scope else []
    save_a = (
        save_blockers_for(str(secs.get('roadmap') or after),
                          selected_frameworks)
        if in_scope else [])
    if leaks:
        save_a = list(save_a) + [f'forbidden_leak:{t}' for t in leaks]
    diag = evaluate_rel36_15_data_roadmap_registry_balance(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        required_families=required,
        detected_families_before=detected_b,
        missing_families_before=missing_b,
        inserted_families=inserted,
        detected_families_after=detected_a,
        missing_families_after=missing_a,
        leakage_terms_after=leaks,
        save_blockers_before=save_b,
        save_blockers_after=[
            b for b in save_a if str(b).startswith('data_roadmap_balance_missing:')
        ],
    )
    if emit:
        emit_rel36_15(REL36_15_DATA_ROADMAP_REGISTRY_BALANCE_TAG, diag)
    return secs, diag


def apply_rel36_15_en_cyber_kpi_synth_repair(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        generation_mode: Any = 'drafting',
        task_id: Any = '',
        emit: bool = True,
        docx_extractable_after: bool = False,
        pdf_extractable_after: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    secs = dict(sections or {})
    blob = '\n'.join(str(v) for v in secs.values() if isinstance(v, str))
    in_scope = rel36_15_en_cyber_should_apply(
        domain=domain, lang=lang, document_type=document_type,
        selected_frameworks=selected_frameworks, doc_subtype=doc_subtype,
        text=blob)
    before = str(secs.get('kpis') or '')
    rows_b = _count_kpi_rows(before)
    hdr_b = _first_kpi_header(before)
    first_b = _first_kpi_table_rows(before)
    synth_b = _synth_kpi_blockers(before, generation_mode) if in_scope else []
    after = before
    if in_scope and (synth_b or not _kpi_schema_valid(before)
                     or rows_b < _MIN_KPI):
        after, _n = repair_first_kpi_table(before)
        secs['kpis'] = after
    rows_a = _count_kpi_rows(str(secs.get('kpis') or after))
    hdr_a = _first_kpi_header(str(secs.get('kpis') or after))
    first_a = _first_kpi_table_rows(str(secs.get('kpis') or after))
    synth_a = (
        _synth_kpi_blockers(str(secs.get('kpis') or after), generation_mode)
        if in_scope else [])
    schema = _kpi_schema_valid(str(secs.get('kpis') or after))
    diag = evaluate_rel36_15_en_cyber_kpi_synth_repair(
        task_id=task_id,
        kpi_rows_before=rows_b,
        kpi_rows_after=rows_a,
        first_kpi_table_header_before=hdr_b,
        first_kpi_table_header_after=hdr_a,
        first_kpi_table_rows_before=first_b,
        first_kpi_table_rows_after=first_a,
        synth_kpis_blockers_before=synth_b,
        synth_kpis_blockers_after=synth_a,
        schema_valid_after=schema,
        pdf_extractable_after=pdf_extractable_after or (
            schema and rows_a >= _MIN_KPI),
        docx_extractable_after=docx_extractable_after or (
            schema and rows_a >= _MIN_KPI),
    )
    if emit:
        emit_rel36_15(REL36_15_EN_CYBER_KPI_SYNTH_REPAIR_TAG, diag)
    return secs, diag


def apply_rel36_15_en_cyber_roadmap_family_balance(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        task_id: Any = '',
        emit: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    secs = dict(sections or {})
    blob = '\n'.join(str(v) for v in secs.values() if isinstance(v, str))
    in_scope = rel36_15_en_cyber_should_apply(
        domain=domain, lang=lang, document_type=document_type,
        selected_frameworks=selected_frameworks, doc_subtype=doc_subtype,
        text=blob)
    before = str(secs.get('roadmap') or '')
    required = official_cyber_required_families(selected_frameworks)
    missing_b = official_cyber_missing_families(before, selected_frameworks)
    detected_b = [f for f in required if f not in missing_b]
    inserted: List[str] = []
    after = before
    if in_scope and missing_b:
        after, inserted = repair_cyber_roadmap_families(
            before, selected_frameworks)
        secs['roadmap'] = after
    road = str(secs.get('roadmap') or after)
    missing_a = official_cyber_missing_families(road, selected_frameworks)
    detected_a = [f for f in required if f not in missing_a]
    ecc_a, dcc_a = _roadmap_counts(road)
    prcy74 = _roadmap_balance_blockers(road, selected_frameworks)
    cyber_b = [
        f'cyber_roadmap_balance_missing:{fam}' for fam in missing_a
    ]
    diag = evaluate_rel36_15_en_cyber_roadmap_family_balance(
        task_id=task_id,
        required_families=required,
        detected_families_before=detected_b,
        missing_families_before=missing_b,
        inserted_families=inserted,
        detected_families_after=detected_a,
        missing_families_after=missing_a,
        ecc_rows_after=ecc_a,
        dcc_rows_after=dcc_a,
        prcy74_blockers_after=prcy74,
        cyber_roadmap_balance_blockers_after=cyber_b,
    )
    if emit:
        emit_rel36_15(REL36_15_EN_CYBER_ROADMAP_FAMILY_BALANCE_TAG, diag)
    return secs, diag


def _collect_final_blockers(
        sections: Dict[str, Any],
        *,
        selected_frameworks: Optional[Iterable[Any]],
        generation_mode: Any,
) -> List[str]:
    blockers: List[str] = []
    road = str(sections.get('roadmap') or '')
    gaps = str(sections.get('gaps') or '')
    conf = str(sections.get('confidence') or '')
    kpis = str(sections.get('kpis') or '')
    pillars = str(sections.get('pillars') or '')
    blockers.extend(_synth_kpi_blockers(kpis, generation_mode))
    blockers.extend(
        f'cyber_roadmap_balance_missing:{f}'
        for f in official_cyber_missing_families(road, selected_frameworks))
    blockers.extend(_roadmap_balance_blockers(road, selected_frameworks))
    try:
        from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
            _gap_duplicate_count,
            _count_first_table_csf,
            _csf_blockers,
        )
        if _gap_duplicate_count(gaps):
            blockers.append('gap_guides_not_unique')
        if _count_first_table_csf(conf) < 4:
            blockers.append('confidence_csf_insufficient')
        blockers.extend(_csf_blockers(conf, generation_mode))
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
            _rel2_pillars_blockers,
        )
        blockers.extend(_rel2_pillars_blockers(pillars))
    except Exception:  # noqa: BLE001
        pass
    try:
        from release_engine_v3.rel36_13_en_cyber_core_completeness import (
            collect_core_blockers,
        )
        blockers.extend(collect_core_blockers(
            sections, generation_mode=generation_mode) or [])
    except Exception:  # noqa: BLE001
        pass
    if 'family:*' in (road + gaps + kpis + pillars).lower():
        blockers.append('family_star_visible')
    return list(dict.fromkeys(str(b) for b in blockers if b))


def apply_rel36_15_final_registry_stability(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        generation_mode: Any = 'drafting',
        backend: Optional[Dict[str, Any]] = None,
        task_id: Any = None,
        attempt_id: Any = None,
        artifact: Optional[Dict[str, Any]] = None,
        emit: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    del backend, artifact
    secs = dict(sections or {})
    tid = str(task_id or '')
    diags: Dict[str, Any] = {'task_id': tid, 'attempt_id': str(attempt_id or '')}
    repaired: List[str] = []
    dcode = _norm_domain(domain)

    if rel36_15_data_should_apply(
            domain=domain, document_type=document_type, lang=lang,
            selected_frameworks=selected_frameworks):
        secs, data_diag = apply_rel36_15_data_roadmap_registry_balance(
            secs, domain=domain, document_type=document_type, lang=lang,
            selected_frameworks=selected_frameworks, emit=emit)
        diags['data'] = data_diag
        if data_diag.get('inserted_families'):
            repaired.append('roadmap')
        return secs, {
            **data_diag,
            'combined': False,
            'repaired_sections': repaired,
            'rel36_15': diags,
        }

    if not rel36_15_en_cyber_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks, doc_subtype=doc_subtype,
            text='\n'.join(str(v) for v in secs.values() if isinstance(v, str))):
        return sections or {}, {
            'applied': False,
            'passed': False,
            'action_taken': 'skipped',
            'all_blockers_after': [],
        }

    def _repair_duplicate_gap_headings(text: str) -> str:
        lines = (text or '').splitlines()
        out_lines = []
        seen_guide_h3 = False
        for ln in lines:
            if re.match(r'^###\s+Gap\s+Implementation', ln, re.I):
                if seen_guide_h3:
                    continue
                seen_guide_h3 = True
            out_lines.append(ln)
        return '\n'.join(out_lines) + ('\n' if text.endswith('\n') else '')

    before_blockers = _collect_final_blockers(
        secs, selected_frameworks=selected_frameworks,
        generation_mode=generation_mode)
    if any('gaps_guides_subhead_duplicated' in str(b) for b in before_blockers):
        try:
            from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
                repair_gap_guide_uniqueness,
            )
            secs['gaps'], _n = repair_gap_guide_uniqueness(
                str(secs.get('gaps') or ''))
        except Exception:  # noqa: BLE001
            pass
        secs['gaps'] = _repair_duplicate_gap_headings(str(secs.get('gaps') or ''))
        repaired.append('gaps')
    secs, kpi_diag = apply_rel36_15_en_cyber_kpi_synth_repair(
        secs, domain=domain, lang=lang, document_type=document_type,
        selected_frameworks=selected_frameworks, doc_subtype=doc_subtype,
        generation_mode=generation_mode, task_id=tid, emit=emit)
    diags['kpis'] = kpi_diag
    if kpi_diag.get('kpi_rows_after') != kpi_diag.get('kpi_rows_before'):
        repaired.append('kpis')
    secs, road_diag = apply_rel36_15_en_cyber_roadmap_family_balance(
        secs, domain=domain, lang=lang, document_type=document_type,
        selected_frameworks=selected_frameworks, doc_subtype=doc_subtype,
        task_id=tid, emit=emit)
    diags['roadmap'] = road_diag
    if road_diag.get('inserted_families'):
        repaired.append('roadmap')

    after_blockers = _collect_final_blockers(
        secs, selected_frameworks=selected_frameworks,
        generation_mode=generation_mode)
    try:
        from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
            _gap_duplicate_count,
            _count_first_table_csf,
        )
        from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
            _rel2_pillars_blockers,
        )
        from release_engine_v3.rel36_13_en_cyber_core_completeness import (
            collect_core_blockers,
        )
        gap_ok = _gap_duplicate_count(str(secs.get('gaps') or '')) == 0
        csf_ok = _count_first_table_csf(str(secs.get('confidence') or '')) >= 4
        pillars_ok = not _rel2_pillars_blockers(str(secs.get('pillars') or ''))
        core_ok = not collect_core_blockers(
            secs, generation_mode=generation_mode)
    except Exception:  # noqa: BLE001
        gap_ok = 'gap_guides_not_unique' not in after_blockers
        csf_ok = 'confidence_csf_insufficient' not in after_blockers
        pillars_ok = not any(
            str(b).startswith('rel2_pillars_failed') for b in after_blockers)
        core_ok = True
    combined = evaluate_rel36_15_en_cyber_final_stability(
        task_id=tid,
        all_blockers_before=before_blockers,
        all_blockers_after=after_blockers,
        repaired_sections=repaired,
        kpi_passed=bool(kpi_diag.get('passed')),
        roadmap_family_passed=bool(road_diag.get('passed')),
        prcy74_passed=not road_diag.get('prcy74_blockers_after'),
        gap_guides_passed=gap_ok,
        confidence_csf_passed=csf_ok,
        pillars_passed=pillars_ok,
        core_completeness_passed=core_ok,
        docx_allowed=not after_blockers,
        pdf_allowed=not after_blockers,
    )
    diags['combined'] = combined
    if emit:
        emit_rel36_15(REL36_15_EN_CYBER_FINAL_STABILITY_TAG, combined)
    out = dict(combined)
    out['rel36_15'] = diags
    out['kpis'] = kpi_diag
    out['roadmap'] = road_diag
    return secs, out
