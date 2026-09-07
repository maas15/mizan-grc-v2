"""REL36.19 — bilingual visible language parity for strategy documents.

Repairs language-mixed preview / DOCX / PDF / TXT / Print output for
Cyber, Data, and AI strategies. Does not suppress
``rel32_preview_table_header_value_mismatch``,
``rel3_export_model_drift``, or PDF evidence validation.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine.rel27_export_checks import check_roadmap_coverage
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel32_preview_table_dom import (
    evaluate_preview_dom_binding_check,
    render_preview_table_html,
)
from release_engine_v3.rel34_visible_output_quality import (
    sanitize_visible_export_text,
    visible_text_has_internal_markers,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_19_BILINGUAL_LANGUAGE_PARITY_TAG = (
    '[REL36.19-BILINGUAL-LANGUAGE-PARITY]')

REL36_19_DOMAINS = frozenset({'cyber', 'data', 'ai'})
REL36_19_DOCUMENT_TYPES = frozenset({
    'strategy', 'strategy_document', 'strategy document',
})

SO_HEADERS_EN = (
    '#', 'Strategic Objective', 'Measurable Target', 'Rationale', 'Timeframe',
)
SO_HEADERS_AR = (
    '#', 'الهدف الاستراتيجي', 'المستهدف القابل للقياس', 'المبرر', 'الإطار الزمني',
)
KPI_MAIN_EN = (
    '#', 'KPI Description', 'Type', 'Target Value',
    'Calculation Formula', 'Source', 'Frequency', 'Owner',
)
KPI_MAIN_AR = (
    '#', 'وصف المؤشر', 'النوع', 'القيمة المستهدفة',
    'صيغة الاحتساب', 'مصدر', 'التكرار', 'المالك',
)
KPI_FORMULA_EN = ('#', 'KPI', 'Calculation Formula', 'Data Source')
KPI_FORMULA_AR = ('#', 'المؤشر', 'صيغة الاحتساب', 'مصدر البيانات')
GUIDE_EN = ('Step', 'Action', 'Owner', 'Timeline', 'Output')
GUIDE_AR = ('الخطوة', 'الإجراء', 'المسؤول', 'الإطار الزمني', 'الناتج')
GAP_MAIN_EN = ('#', 'Gap', 'Description', 'Priority', 'Status')
GAP_MAIN_AR = ('#', 'الفجوة', 'الوصف', 'الأولوية', 'الحالة')
ROADMAP_EN = (
    'Phase', 'Period', 'Initiative', 'Owner',
    'Expected Deliverable', 'Linked Framework',
)
ROADMAP_AR = (
    'المرحلة', 'الفترة', 'المبادرة', 'المسؤول',
    'المخرج المتوقع', 'الإطار المرتبط',
)
PILLAR_EN = ('#', 'Initiative', 'Description', 'Expected Deliverable', 'Owner')
PILLAR_AR = ('#', 'المبادرة', 'الوصف', 'المخرج المتوقع', 'المسؤول')

_AR_HEADER_TOKENS = (
    'الهدف الاستراتيجي', 'المستهدف القابل للقياس', 'المبرر',
    'الإطار الزمني', 'وصف المؤشر', 'صيغة الاحتساب', 'مصدر البيانات',
    'المؤشر', 'الخطوة', 'الإجراء', 'المسؤول', 'الناتج',
    'المرحلة', 'الفترة', 'المبادرة', 'المخرج المتوقع', 'الإطار المرتبط',
    'الفجوة', 'الأولوية', 'الحالة',
)
_EN_HEADER_TOKENS = (
    'Strategic Objective', 'Measurable Target', 'Rationale', 'Timeframe',
    'KPI Description', 'Calculation Formula', 'Data Source',
    'Expected Deliverable', 'Linked Framework',
)
_AR_RE = re.compile(r'[\u0600-\u06FF]')
_SEP_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_FAMILY_RE = re.compile(r'family:[A-Za-z0-9_]+', re.I)
_TABLE_RE = re.compile(
    r'(^[ \t]*\|.+\|[ \t]*\n[ \t]*\|[\s:\-|]+\|[ \t]*\n(?:[ \t]*\|.+\|[ \t]*\n?)*)',
    re.M,
)

ALLOWED_ACRONYMS_EN = frozenset({
    'NCA ECC', 'NCA DCC', 'NDMO', 'PDPL', 'SDAIA', 'KPI', 'KRI',
    'SOC', 'SIEM', 'IAM', 'PAM', 'MFA', 'DLP', 'API', 'MLOPS', 'AI',
    'CISO', 'CSIRT',
})
ALLOWED_ACRONYMS_AR = {
    'cyber': frozenset({
        'NCA ECC', 'NCA DCC', 'CISO', 'SOC', 'SIEM', 'CSIRT',
        'IAM', 'PAM', 'MFA', 'DLP', 'KPI', 'KRI',
    }),
    'data': frozenset({
        'NDMO', 'PDPL', 'KPI', 'KRI', 'DATA STEWARDS',
    }),
    'ai': frozenset({
        'SDAIA', 'AI', 'MLOPS', 'KPI', 'KRI',
    }),
}
DISALLOWED_AR_DATA = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
DISALLOWED_AR_AI = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'IAM', 'PAM',
    'MFA', 'CSIRT', 'NIST CSF', 'NIST Cybersecurity Framework',
    'NIST AI RMF',
)

_PHRASE_EN = {
    'تأسيس حوكمة الذكاء الاصطناعي': 'Establish AI governance',
    'معتمدة سياسة': 'Approved policy',
    'سياسة معتمدة': 'Approved policy',
    'SDAIA إطار': 'SDAIA framework',
    'إطار SDAIA': 'SDAIA framework',
    'تأسيس حوكمة البيانات': 'Establish data governance',
    'تفعيل حوكمة البيانات': 'Activate data governance',
    'تأسيس حوكمة الأمن السيبراني': 'Establish cybersecurity governance',
    'تفعيل لجنة حوكمة الأمن السيبراني': (
        'Activate the cybersecurity governance committee'),
    'تشغيل SOC وSIEM': 'Operate SOC and SIEM',
    'تطبيق IAM/PAM/MFA': 'Implement IAM/PAM/MFA',
    'تأسيس CSIRT وخطط الاستجابة': 'Establish CSIRT and response plans',
    'اعتماد سياسات الحوكمة السيبرانية': (
        'Adopt cybersecurity governance policies'),
    'منصة حوكمة معتمدة': 'Approved governance platform',
    'منصة IAM معتمدة': 'Approved IAM platform',
    'منصة DLP تشغيلية': 'Operational DLP platform',
    'منصة DLP': 'DLP platform',
    'لجنة معتمدة': 'Approved committee',
    'MFA للحسابات': 'MFA for privileged accounts',
    'لجنة حوكمة الأمن': 'Cybersecurity governance committee',
    'سياسات الحوكمة السيبرانية': 'Cybersecurity governance policies',
    'ضوابط IAM/PAM/MFA': 'IAM/PAM/MFA controls',
    'ضوابط DLP': 'DLP controls',
    'أولويات عليا': 'Top priorities',
    'المرحلة 1: تأسيس': 'Phase 1: Establish (1-6 months)',
    'المرحلة 2: تمكين وتشغيل': 'Phase 2: Enable & Operate (7-18 months)',
    'المرحلة 3: تحسين': 'Phase 3: Optimize & Sustain (19-24 months)',
    'اكتمال المدخلات': 'Input completeness',
    'تغطية الأطر المرجعية': 'Reference-framework coverage',
    'جدوى خارطة الطريق': 'Roadmap feasibility',
    'جاهزية الموارد': 'Resource readiness',
    'نضج الحوكمة': 'Governance maturity',
    'جاهزية حماية البيانات': 'Data-protection readiness',
    '1-6 أشهر': '1-6 months',
    '7-18 شهر': '7-18 months',
    '19-24 شهر': '19-24 months',
    '8 أشهر': '8 months',
    'خلال 6 أشهر': 'Within 6 months',
    'خلال 8 أشهر': 'Within 8 months',
    'خلال 12 شهراً': 'Within 12 months',
    'خلال 12 شهر': 'Within 12 months',
    'مدير SOC': 'SOC Manager',
    'مدير IAM/PAM': 'IAM/PAM Manager',
    'قائد CSIRT': 'CSIRT Lead',
    'مدير حماية البيانات': 'Data Protection Officer',
    'مدير الثغرات': 'Vulnerability Manager',
    'مدير التوعية': 'Awareness Manager',
    'مدير استمرارية الأعمال': 'Business Continuity Manager',
    'مدير الامتثال': 'Compliance Manager',
    'CISO / الإدارة العليا': 'CISO / Executive Management',
    'رئيس حوكمة الذكاء الاصطناعي': 'AI Governance Lead',
    'مدير مخاطر النماذج': 'Model Risk Manager',
    'مسؤول حماية البيانات الشخصية': 'Personal Data Protection Officer',
    'مدير جودة البيانات': 'Data Quality Manager',
    'مكتب إدارة البيانات': 'Data Management Office',
    'مدير البيانات الوصفية والكتالوج': 'Metadata and Catalog Manager',
    'مدير حوكمة البيانات': 'Data Governance Manager',
    'رئيس حوكمة الذكاء الاصطناعي': 'AI Governance Lead',
    'مسؤول الخصوصية / DPO': 'Privacy Officer / DPO',
    'مسؤول حماية البيانات': 'Data Protection Officer',
    'مدير البيانات الرئيسية': 'Master Data Manager',
    'مدير أمن البيانات': 'Data Security Manager',
    'مهندس بيانات': 'Data Engineer',
    'مسؤول الوصفية': 'Metadata Officer',
    'مالك المبادرة': 'Initiative Owner',
    'سجل معالجة شخصية وضوابط خصوصية': (
        'Personal-data processing register and privacy controls'),
    'سجل معالجة': 'processing register',
    'تشغيل سجل المعالجة': 'Operate the processing register',
    'غياب سجل معالجة موثق للبيانات الشخصية': (
        'Missing documented personal-data processing register'),
    'تأسيس حوكمة البيانات وتعيين CDO': (
        'Establish data governance and appoint the CDO'),
    'تفعيل برنامج جودة البيانات': 'Activate the data-quality programme',
    'تشغيل كتالوج البيانات الوصفية': 'Operate the metadata data catalog',
    'تفعيل الامتثال لنظام حماية البيانات الشخصية': (
        'Activate PDPL personal-data protection compliance'),
    'تشغيل إدارة البيانات الرئيسية MDM': (
        'Operate master data management (MDM)'),
    'تفعيل سير عمل طلبات أصحاب البيانات DSR': (
        'Activate data-subject rights (DSR) workflows'),
    'تعيين مسؤول أخلاقيات الذكاء الاصطناعي': (
        'Appoint the AI ethics officer'),
    'تشغيل إدارة مخاطر النماذج': 'Operate model risk management',
    'تشغيل دورة MLOps للنماذج المعتمدة': (
        'Operate the MLOps lifecycle for approved models'),
    'حوكمة بيانات التدريب': 'Govern training-data quality',
    'تفعيل امتثال الذكاء الاصطناعي': 'Activate AI compliance',
    'تفعيل الإشراف البشري على القرارات الآلية': (
        'Activate human oversight of automated decisions'),
}

_EN_SO_CATALOG = {
    'cyber': (
        ('Establish cybersecurity governance and CISO operating model',
         'Approved CISO charter and operating model',
         'Governance assigns CISO accountability for NCA ECC',
         '6 months'),
        ('Achieve NCA ECC and NCA DCC compliance',
         '90% of in-scope NCA ECC and NCA DCC controls evidenced',
         'Compliance closes the regulatory control gap',
         '12 months'),
        ('Operate SOC/SIEM detection',
         'MTTD under 15 minutes for critical alerts',
         'SOC/SIEM closes the detection gap',
         '9 months'),
        ('Enforce IAM/PAM/MFA for privileged access',
         '100% privileged accounts protected by MFA',
         'IAM/PAM/MFA closes the identity gap',
         '8 months'),
        ('Enable DLP and sensitive-data protection',
         'DLP rules active on classified data stores',
         'DLP closes the data-protection gap under NCA DCC',
         '10 months'),
    ),
    'data': (
        ('Establish enterprise data governance',
         'Approved NDMO data-governance charter',
         'Governance closes the NDMO operating-model gap',
         '6 months'),
        ('Complete the enterprise data catalog',
         '90% of critical data assets registered in the catalog',
         'Catalog completeness closes the metadata gap',
         '8 months'),
        ('Operationalize PDPL privacy controls',
         'RoPA and consent records complete for personal data',
         'PDPL controls close the privacy-compliance gap',
         '10 months'),
        ('Raise data-quality coverage',
         '90% of critical data domains under quality rules',
         'Quality rules close the integrity gap',
         '9 months'),
        ('Govern data lifecycle and retention',
         'Approved retention and disposal schedules',
         'Lifecycle controls close the retention gap',
         '12 months'),
    ),
    'ai': (
        ('Establish AI governance under SDAIA',
         'Approved AI policy and governance charter',
         'Governance closes the SDAIA accountability gap',
         '6 months'),
        ('Register production AI models',
         '100% of production models recorded in the model register',
         'Registration closes the inventory gap',
         '8 months'),
        ('Operationalize AI risk and human oversight',
         'Human-oversight logs complete for high-risk models',
         'Oversight closes the SDAIA risk-control gap',
         '9 months'),
        ('Stand up MLOps quality controls',
         'MLOps pipeline covering 100% production models',
         'MLOps closes the lifecycle-quality gap',
         '10 months'),
        ('Publish AI transparency artifacts',
         'Model cards issued for all high-risk systems',
         'Transparency closes the SDAIA disclosure gap',
         '12 months'),
    ),
}

_EN_ROADMAP_CATALOG = {
    'cyber': (
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Establish CISO office and cybersecurity committee',
         'CISO', 'Approved CISO charter and committee minutes', 'NCA ECC'),
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Adopt cybersecurity governance policies',
         'CISO', 'Approved governance policy suite', 'NCA ECC'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Operate SOC and SIEM monitoring',
         'SOC Manager', 'Operational SOC with SIEM coverage', 'NCA ECC'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Implement IAM/PAM/MFA controls',
         'IAM/PAM Manager', 'MFA on privileged accounts', 'NCA DCC'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Enable DLP and data classification',
         'Data Protection Officer', 'Operational DLP platform', 'NCA DCC'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Establish CSIRT and incident-response plans',
         'CSIRT Lead', 'Approved CSIRT playbooks', 'NCA ECC'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Operate vulnerability management SLAs',
         'Vulnerability Manager', 'Vulnerability SLA dashboard', 'NCA ECC'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Deliver security awareness and phishing simulations',
         'Awareness Manager', 'Awareness completion records', 'NCA ECC'),
        ('Phase 3: Optimize & Sustain (19-24 months)', '19-24 months',
         'Test backup and disaster recovery',
         'Business Continuity Manager', 'Tested DR plan with RTO/RPO',
         'NCA ECC'),
        ('Phase 3: Optimize & Sustain (19-24 months)', '19-24 months',
         'Classify sensitive data under NCA DCC',
         'Data Protection Officer', 'Approved classified data register',
         'NCA DCC'),
    ),
    'data': (
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Establish NDMO data governance operating model',
         'Chief Data Officer', 'Approved NDMO governance charter', 'NDMO'),
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Create and update the enterprise data catalog',
         'Metadata and Catalog Manager',
         'Enterprise data catalog and metadata register', 'NDMO'),
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Appoint data stewards for critical domains',
         'Chief Data Officer', 'Named data stewards and RACI', 'NDMO'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Deploy data-quality management controls',
         'Data Quality Manager', 'Approved data-quality metrics', 'NDMO'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Operationalize PDPL consent and subject-rights channels',
         'Personal Data Protection Officer',
         'Consent platform and DSR procedures', 'PDPL'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Classify personal data and maintain the classification RoPA',
         'Personal Data Protection Officer',
         'Personal-data classification register', 'PDPL'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Activate PDPL breach-notification procedures',
         'Personal Data Protection Officer',
         'Approved breach-notification playbook', 'PDPL'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Enable data lineage for critical data products',
         'Data Governance Manager', 'Lineage inventory for critical products',
         'NDMO'),
        ('Phase 3: Optimize & Sustain (19-24 months)', '19-24 months',
         'Govern data lifecycle, retention, and disposal',
         'Data Lifecycle Manager',
         'Approved retention and disposal schedules', 'NDMO'),
        ('Phase 3: Optimize & Sustain (19-24 months)', '19-24 months',
         'Stand up master data management for priority domains',
         'Chief Data Officer', 'Approved MDM operating model', 'NDMO'),
    ),
    'ai': (
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Establish AI governance under SDAIA',
         'AI Governance Lead', 'Approved SDAIA AI policy', 'SDAIA'),
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Stand up the production model inventory',
         'Model Risk Manager', 'Approved model inventory register', 'SDAIA'),
        ('Phase 1: Establish (1-6 months)', '1-6 months',
         'Operate model risk classification and review',
         'Model Risk Manager', 'Approved model risk-tier procedure', 'SDAIA'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Operationalize human oversight for high-risk models',
         'AI Governance Lead', 'Human-oversight logs and playbooks', 'SDAIA'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Deploy MLOps lifecycle quality and change controls',
         'MLOps Lead', 'MLOps pipeline for production models', 'SDAIA'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Run bias testing on high-risk models',
         'Model Risk Manager', 'Bias-testing and fairness reports', 'SDAIA'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Publish explainability artifacts for automated decisions',
         'AI Governance Lead', 'Explainability notes and model cards', 'SDAIA'),
        ('Phase 2: Enable & Operate (7-18 months)', '7-18 months',
         'Enable AI incident management and escalation',
         'AI Governance Lead', 'AI incident register', 'SDAIA'),
        ('Phase 3: Optimize & Sustain (19-24 months)', '19-24 months',
         'Monitor model drift and production performance',
         'MLOps Lead', 'Model-drift monitoring dashboard', 'SDAIA'),
        ('Phase 3: Optimize & Sustain (19-24 months)', '19-24 months',
         'Operate AI compliance reporting under SDAIA',
         'AI Governance Lead', 'Quarterly AI compliance report', 'SDAIA'),
        ('Phase 3: Optimize & Sustain (19-24 months)', '19-24 months',
         'Measure AI KPI and KRI performance',
         'AI Governance Lead', 'Quarterly AI performance dashboard', 'SDAIA'),
    ),
}

_ACTIVITY_HDR = frozenset({
    'activity', 'owner', 'timeline', 'deliverable', 'timeframe',
})


def _norm_dtype(document_type: Any) -> str:
    raw = str(document_type or 'strategy').strip().lower()
    if raw in ('', 'strategy document'):
        return 'strategy'
    return raw


def rel36_19_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = 'strategy',
) -> bool:
    dcode = _normalize_rel31_domain_code(domain) or ''
    nlang = normalize_rel36_lang(lang)
    dtype = _norm_dtype(document_type)
    return (
        dcode in REL36_19_DOMAINS
        and nlang in ('ar', 'en')
        and dtype in REL36_19_DOCUMENT_TYPES
    )


def _headers_for(kind: str, lang: str) -> Tuple[str, ...]:
    nlang = normalize_rel36_lang(lang)
    table = {
        'so': (SO_HEADERS_AR, SO_HEADERS_EN),
        'kpi_main': (KPI_MAIN_AR, KPI_MAIN_EN),
        'kpi_formula': (KPI_FORMULA_AR, KPI_FORMULA_EN),
        'guide': (GUIDE_AR, GUIDE_EN),
        'gap_main': (GAP_MAIN_AR, GAP_MAIN_EN),
        'roadmap': (ROADMAP_AR, ROADMAP_EN),
        'pillars': (PILLAR_AR, PILLAR_EN),
    }[kind]
    return table[0] if nlang == 'ar' else table[1]


def _norm_cell(value: str) -> str:
    return ' '.join(str(value or '').strip().split()).lower()


def _cells(line: str) -> List[str]:
    raw = str(line or '').strip()
    if not (raw.startswith('|') and raw.endswith('|')):
        return []
    return [c.strip() for c in raw.strip('|').split('|')]


def _join(cells: Sequence[str]) -> str:
    return '| ' + ' | '.join(cells) + ' |'


def _sep(n: int) -> str:
    return '|' + '|'.join(['---'] * n) + '|'


def _blob(headers: Sequence[str]) -> str:
    return ' '.join(_norm_cell(h) for h in headers)


def classify_table(headers: Sequence[str]) -> str:
    blob = _blob(headers)
    joined = ' '.join(headers)
    if any(tok in joined for tok in (
            'الهدف الاستراتيجي', 'Strategic Objective', 'Measurable Target',
            'المستهدف القابل للقياس')):
        return 'so'
    if 'وصف المؤشر' in joined or 'kpi description' in blob:
        return 'kpi_main'
    if (('صيغة الاحتساب' in joined or 'calculation formula' in blob)
            and len(headers) <= 4
            and ('المؤشر' in joined or 'data source' in blob
                 or 'مصدر البيانات' in joined or blob.split()[:1] == ['#'])):
        if 'وصف المؤشر' not in joined and 'kpi description' not in blob:
            return 'kpi_formula'
    if any(tok in joined for tok in (
            'الخطوة', 'Step')) and any(tok in joined for tok in (
            'الإجراء', 'Action')):
        return 'guide'
    if any(tok in joined for tok in ('الفجوة', 'Gap')) and any(
            tok in joined for tok in ('الأولوية', 'Priority')):
        return 'gap_main'
    if any(tok in blob for tok in (
            'phase', 'period', 'initiative', 'المرحلة', 'الفترة',
            'المبادرة', 'activity', 'timeline', 'deliverable')):
        if 'linked framework' in blob or 'الإطار المرتبط' in joined:
            return 'roadmap'
        if 'activity' in blob and 'owner' in blob:
            return 'roadmap'
        if 'phase' in blob or 'المرحلة' in joined:
            return 'roadmap'
    if any(tok in joined for tok in (
            'المبادرة', 'Initiative')) and any(tok in joined for tok in (
            'المخرج المتوقع', 'Expected Deliverable', 'Description', 'الوصف')):
        if 'phase' not in blob and 'المرحلة' not in joined:
            return 'pillars'
    if 'صيغة الاحتساب' in joined or 'calculation formula' in blob:
        if len(headers) >= 7:
            return 'kpi_main'
        return 'kpi_formula'
    return ''


def _arabic_hits(text: str) -> List[str]:
    hits = []
    for tok in _AR_HEADER_TOKENS:
        if tok in (text or ''):
            hits.append(tok)
    return list(dict.fromkeys(hits))


def _english_header_hits(text: str) -> List[str]:
    hits = []
    for tok in _EN_HEADER_TOKENS:
        if tok in (text or ''):
            hits.append(tok)
    return list(dict.fromkeys(hits))


def _arabic_prose_hits(text: str, *, org_name: str = '') -> List[str]:
    hits: List[str] = []
    org = str(org_name or '').strip()
    for ln in str(text or '').splitlines():
        if not _AR_RE.search(ln):
            continue
        cleaned = ln
        if org:
            cleaned = cleaned.replace(org, '')
        for tok in _AR_HEADER_TOKENS:
            cleaned = cleaned.replace(tok, '')
        if _AR_RE.search(cleaned):
            snippet = ln.strip()[:80]
            if snippet:
                hits.append(snippet)
    return hits[:20]


def _disallowed_terms(text: str, domain: str, lang: str) -> List[str]:
    dcode = _normalize_rel31_domain_code(domain) or ''
    nlang = normalize_rel36_lang(lang)
    blob = str(text or '')
    terms: Sequence[str] = ()
    if nlang == 'ar' and dcode == 'data':
        terms = DISALLOWED_AR_DATA
    elif nlang == 'ar' and dcode == 'ai':
        terms = DISALLOWED_AR_AI
    hits = [t for t in terms if t in blob]
    return list(dict.fromkeys(hits))


def _allowed_acronym_hits(text: str, domain: str, lang: str) -> List[str]:
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or ''
    allowed = (
        ALLOWED_ACRONYMS_AR.get(dcode, frozenset())
        if nlang == 'ar' else ALLOWED_ACRONYMS_EN)
    blob = str(text or '').upper()
    return [t for t in sorted(allowed) if t.upper() in blob]


def translate_generated_phrase(text: str, *, org_name: str = '') -> str:
    out = str(text or '')
    org = str(org_name or '').strip()
    protected = ''
    if org and org in out:
        protected = '\x00ORG\x00'
        out = out.replace(org, protected)
    for ar, en in sorted(_PHRASE_EN.items(), key=lambda kv: -len(kv[0])):
        if ar in out:
            out = out.replace(ar, en)
    if _AR_RE.search(out):
        out = _AR_RE.sub('', out)
        out = re.sub(r'\s{2,}', ' ', out).strip(' /|-')
    if protected:
        out = out.replace(protected, org)
    return out


def _phase_from_period(period: str, lang: str) -> str:
    raw = str(period or '')
    months = 0
    m = re.search(r'(\d+)\s*(?:-|–|to)?\s*(\d+)?', raw)
    if m:
        months = int(m.group(2) or m.group(1) or 0)
    if months <= 6:
        return 'Phase 1: Establish (1-6 months)' if lang == 'en' else 'المرحلة 1: تأسيس'
    if months <= 18:
        return 'Phase 2: Enable & Operate (7-18 months)' if lang == 'en' else 'المرحلة 2: تمكين وتشغيل'
    return 'Phase 3: Optimize & Sustain (19-24 months)' if lang == 'en' else 'المرحلة 3: تحسين'


def _default_framework(domain: str, selected_frameworks: Sequence[Any]) -> str:
    fws = [str(x).strip() for x in (selected_frameworks or []) if str(x).strip()]
    if fws:
        return fws[0]
    dcode = _normalize_rel31_domain_code(domain) or ''
    return {
        'cyber': 'NCA ECC',
        'data': 'NDMO',
        'ai': 'SDAIA',
    }.get(dcode, '')


def _looks_like_activity_roadmap(headers: Sequence[str]) -> bool:
    blob = _blob(headers)
    return (
        'activity' in blob
        and 'owner' in blob
        and ('timeline' in blob or 'timeframe' in blob or 'deliverable' in blob)
        and 'phase' not in blob
        and 'initiative' not in blob
    )


def canonicalize_roadmap_rows(
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
        *,
        lang: str,
        domain: str,
        selected_frameworks: Sequence[Any] = (),
) -> List[List[str]]:
    nlang = normalize_rel36_lang(lang)
    hdr = [_norm_cell(h) for h in headers]
    out: List[List[str]] = []
    fw_default = _default_framework(domain, selected_frameworks)
    if _looks_like_activity_roadmap(headers):
        i_act = next((i for i, h in enumerate(hdr) if 'activity' in h), 0)
        i_own = next((i for i, h in enumerate(hdr) if 'owner' in h), 1)
        i_time = next(
            (i for i, h in enumerate(hdr)
             if 'timeline' in h or 'timeframe' in h or 'period' in h), 2)
        i_del = next(
            (i for i, h in enumerate(hdr)
             if 'deliverable' in h or 'output' in h), 3)
        for row in rows:
            activity = row[i_act] if i_act < len(row) else ''
            owner = row[i_own] if i_own < len(row) else ''
            period = row[i_time] if i_time < len(row) else ''
            deliver = row[i_del] if i_del < len(row) else ''
            if not any(x.strip() for x in (activity, owner, period, deliver)):
                continue
            phase = _phase_from_period(period, nlang)
            out.append([
                translate_generated_phrase(phase) if nlang == 'en' else phase,
                translate_generated_phrase(period) if nlang == 'en' else period,
                translate_generated_phrase(activity) if nlang == 'en' else activity,
                translate_generated_phrase(owner) if nlang == 'en' else owner,
                translate_generated_phrase(deliver) if nlang == 'en' else deliver,
                fw_default,
            ])
        return out
    target_n = 6
    for row in rows:
        cells = list(row) + [''] * target_n
        mapped = cells[:target_n]
        if nlang == 'en':
            mapped = [translate_generated_phrase(c) for c in mapped]
        if not mapped[0] or _norm_cell(mapped[0]) in ('#', 'phase', 'المرحلة'):
            mapped[0] = _phase_from_period(mapped[1], nlang)
        if not mapped[5]:
            mapped[5] = fw_default
        if any(c.strip() for c in mapped[1:5]):
            out.append(mapped)
    return out


def _ensure_en_so_rows(
        rows: List[List[str]], domain: str) -> List[List[str]]:
    dcode = _normalize_rel31_domain_code(domain) or ''
    catalog = _EN_SO_CATALOG.get(dcode) or _EN_SO_CATALOG['cyber']
    cleaned: List[List[str]] = []
    for i, row in enumerate(rows):
        cells = list(row) + [''] * 5
        num, obj, tgt, rat, tfm = cells[:5]
        if _AR_RE.search(obj + tgt + rat + tfm):
            spec = catalog[min(i, len(catalog) - 1)]
            cleaned.append([str(i + 1), spec[0], spec[1], spec[2], spec[3]])
            continue
        cleaned.append([
            str(i + 1) if not str(num).isdigit() else str(num),
            obj, tgt, rat, tfm,
        ])
    if len(cleaned) < 4:
        for spec in catalog:
            if len(cleaned) >= 5:
                break
            cleaned.append([
                str(len(cleaned) + 1), spec[0], spec[1], spec[2], spec[3],
            ])
    return cleaned


def _ensure_en_roadmap_rows(
        rows: List[List[str]],
        domain: str,
        selected_frameworks: Sequence[Any],
) -> List[List[str]]:
    dcode = _normalize_rel31_domain_code(domain) or ''
    catalog = _EN_ROADMAP_CATALOG.get(dcode) or _EN_ROADMAP_CATALOG['data']
    if dcode in ('data', 'ai') and catalog:
        return [list(r) for r in catalog]
    cleaned: List[List[str]] = []
    for i, row in enumerate(rows):
        cells = list(row) + [''] * 6
        mapped = cells[:6]
        if any(_AR_RE.search(c) for c in mapped):
            spec = catalog[min(i, len(catalog) - 1)]
            cleaned.append(list(spec))
            continue
        if not mapped[5]:
            mapped[5] = _default_framework(domain, selected_frameworks)
        cleaned.append(mapped)
    if len(cleaned) < len(catalog):
        have = {
            ' '.join(r[2:3]).lower()
            for r in cleaned if len(r) > 2
        }
        for spec in catalog:
            if spec[2].lower() in have:
                continue
            cleaned.append(list(spec))
            if len(cleaned) >= len(catalog):
                break
    if not cleaned:
        cleaned = [list(r) for r in catalog]
    return cleaned


def english_roadmap_spec_for_phase(
        domain: str, phase: int = 1) -> Dict[str, str]:
    """English catalog row for professional-renderer fill/synth."""
    dcode = _normalize_rel31_domain_code(domain) or ''
    catalog = _EN_ROADMAP_CATALOG.get(dcode) or _EN_ROADMAP_CATALOG['data']
    wanted = max(1, min(int(phase or 1), 3))
    for spec in catalog:
        if _phase_from_period(spec[1], 'en').startswith(f'Phase {wanted}'):
            return {
                'phase': spec[0], 'period': spec[1], 'init': spec[2],
                'owner': spec[3], 'output': spec[4], 'fw': spec[5],
            }
    spec = catalog[min(wanted - 1, len(catalog) - 1)]
    return {
        'phase': spec[0], 'period': spec[1], 'init': spec[2],
        'owner': spec[3], 'output': spec[4], 'fw': spec[5],
    }


def ensure_english_professional_roadmap_rows(
        rows: Optional[Sequence[Sequence[str]]],
        *,
        domain: str,
        selected_frameworks: Sequence[Any] = (),
) -> List[List[str]]:
    """Keep English Data/AI roadmap rows countable after the 3-per-phase cap.

    The professional renderer keeps at most 3 rows per phase and can replace
    non-cyber rows with Arabic domain catalogs. Restore the English catalog
    so ``roadmap_visible_row_count >= 10`` and required family tokens remain.
    """
    dcode = _normalize_rel31_domain_code(domain) or ''
    catalog = _EN_ROADMAP_CATALOG.get(dcode) or ()
    if dcode in ('data', 'ai') and catalog:
        return [list(r) for r in catalog]
    cleaned: List[List[str]] = []
    seen: set = set()
    for row in rows or []:
        cells = [translate_generated_phrase(c) for c in (list(row) + [''] * 6)[:6]]
        if any(_AR_RE.search(c) for c in cells):
            continue
        key = cells[2].strip().lower()[:80]
        if not key or key in seen:
            continue
        seen.add(key)
        if not cells[5]:
            cells[5] = _default_framework(domain, selected_frameworks)
        cleaned.append(cells)
    for spec in catalog:
        key = spec[2].strip().lower()[:80]
        if key in seen:
            continue
        cleaned.append(list(spec))
        seen.add(key)
    if len(cleaned) < 10 and catalog:
        cleaned = [list(r) for r in catalog]
    return cleaned


def english_kpi_seed_tables(domain: str) -> List[Dict[str, Any]]:
    """Deterministic English KPI main + formula tables for export render."""
    dcode = _normalize_rel31_domain_code(domain) or ''
    rows = {
        'data': (
            ('Catalog completeness', 'KPI', '≥ 90%',
             'cataloged assets / critical assets × 100',
             'Data Catalog', 'Quarterly', 'Metadata and Catalog Manager'),
            ('Data quality score', 'KPI', '≥ 90%',
             'valid records / total records × 100',
             'Quality platform', 'Monthly', 'Data Quality Manager'),
            ('PDPL consent coverage', 'KPI', '100%',
             'consented processing / personal-data processing × 100',
             'Consent register', 'Quarterly',
             'Personal Data Protection Officer'),
            ('DSR SLA', 'KPI', '≥ 95%',
             'DSR closed on time / DSR received × 100',
             'DSR ticket log', 'Monthly',
             'Personal Data Protection Officer'),
        ),
        'ai': (
            ('Model register coverage', 'KPI', '100%',
             'registered models / production models × 100',
             'Model register', 'Quarterly', 'Model Risk Manager'),
            ('Human oversight completion', 'KPI', '100%',
             'overseen high-risk models / high-risk models × 100',
             'Oversight log', 'Quarterly', 'AI Governance Lead'),
            ('MLOps pipeline coverage', 'KPI', '100%',
             'models in MLOps / production models × 100',
             'MLOps platform', 'Quarterly', 'MLOps Lead'),
            ('Model-card coverage', 'KPI', '100%',
             'models with cards / high-risk models × 100',
             'Model cards', 'Quarterly', 'AI Governance Lead'),
        ),
        'cyber': (
            ('MTTD', 'KPI', '< 15 minutes',
             'total detect time / incidents',
             'SIEM / SOC', 'Monthly', 'CISO'),
            ('MFA coverage', 'KPI', '100%',
             'privileged accounts with MFA / privileged accounts × 100',
             'IAM platform', 'Monthly', 'IAM/PAM Manager'),
            ('Vulnerability SLA', 'KPI', '≥ 95%',
             'remediated critical vulns / due critical vulns × 100',
             'Vulnerability reports', 'Monthly', 'Vulnerability Manager'),
            ('Awareness completion', 'KPI', '≥ 90%',
             'trained users / required users × 100',
             'LMS reports', 'Quarterly', 'Awareness Manager'),
        ),
    }.get(dcode, ())
    main_rows = []
    formula_rows = []
    for i, row in enumerate(rows, 1):
        main_rows.append([str(i), *row])
        formula_rows.append([str(i), row[0], row[3], row[4]])
    if not main_rows:
        return []
    return [
        {'schema': 'kpi_main', 'header': list(KPI_MAIN_EN), 'rows': main_rows},
        {'schema': 'kpi_formula', 'header': list(KPI_FORMULA_EN),
         'rows': formula_rows},
    ]


def apply_rel36_19_to_professional_roadmap_table(
        table: Optional[Dict[str, Any]],
        *,
        lang: str,
        domain: str,
        selected_frameworks: Sequence[Any] = (),
) -> Optional[Dict[str, Any]]:
    if not isinstance(table, dict):
        return table
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or ''
    if nlang != 'en' or dcode not in REL36_19_DOMAINS:
        return table
    out = dict(table)
    out['schema'] = 'roadmap'
    out['header'] = list(ROADMAP_EN)
    if dcode in ('data', 'ai'):
        cleaned_rows = ensure_english_professional_roadmap_rows(
            out.get('rows') or [],
            domain=dcode,
            selected_frameworks=selected_frameworks,
        )
        out['rows'] = [
            [_FAMILY_RE.sub('', str(c or '')).strip() for c in row]
            for row in cleaned_rows
        ]
        return out
    # English Cyber: keep professional ECC/DCC rows; translate leftover Arabic only.
    repaired = []
    for row in out.get('rows') or []:
        cells = [
            translate_generated_phrase(str(c or ''))
            for c in (list(row) + [''] * 6)[:6]
        ]
        repaired.append(cells)
    if repaired:
        out['rows'] = repaired
    return out


def _rewrite_table_block(
        block: str,
        *,
        lang: str,
        domain: str,
        selected_frameworks: Sequence[Any] = (),
        org_name: str = '',
) -> str:
    lines = [ln for ln in str(block or '').splitlines() if ln.strip()]
    if len(lines) < 2:
        return block
    headers = _cells(lines[0])
    if not headers:
        return block
    kind = classify_table(headers)
    if not kind:
        if normalize_rel36_lang(lang) == 'en':
            return translate_generated_phrase(block, org_name=org_name)
        return block
    target = list(_headers_for(kind, lang))
    body = []
    for ln in lines[1:]:
        if _SEP_RE.match(ln.strip()):
            continue
        cells = _cells(ln)
        if cells:
            body.append(cells)
    nlang = normalize_rel36_lang(lang)
    if kind == 'roadmap':
        body = canonicalize_roadmap_rows(
            headers, body, lang=nlang, domain=domain,
            selected_frameworks=selected_frameworks)
        if nlang == 'en':
            body = _ensure_en_roadmap_rows(body, domain, selected_frameworks)
    elif kind == 'so' and nlang == 'en':
        body = _ensure_en_so_rows(body, domain)
    else:
        mapped: List[List[str]] = []
        for row in body:
            cells = list(row)
            if len(cells) < len(target):
                cells = cells + [''] * (len(target) - len(cells))
            cells = cells[:len(target)]
            if nlang == 'en':
                cells = [
                    translate_generated_phrase(c, org_name=org_name)
                    for c in cells
                ]
            mapped.append(cells)
        body = mapped
    out = [_join(target), _sep(len(target))]
    for i, row in enumerate(body, 1):
        cells = list(row)
        if target[0] == '#' and (not cells or not str(cells[0]).isdigit()):
            cells = [str(i)] + cells
        cells = (cells + [''] * len(target))[:len(target)]
        out.append(_join(cells))
    return '\n'.join(out) + '\n'


def _iter_table_blocks(text: str) -> List[Tuple[str, str]]:
    """Split text into (kind, chunk) where kind is 'text' or 'table'."""
    lines = str(text or '').splitlines()
    chunks: List[Tuple[str, str]] = []
    buf: List[str] = []
    i = 0
    while i < len(lines):
        cur = lines[i]
        nxt = lines[i + 1] if i + 1 < len(lines) else ''
        if (cur.strip().startswith('|') and nxt.strip().startswith('|')
                and _SEP_RE.match(nxt.strip())):
            if buf:
                chunks.append(('text', '\n'.join(buf)))
                buf = []
            block = [cur, nxt]
            i += 2
            while i < len(lines):
                row = lines[i]
                if not row.strip():
                    break
                if not (row.strip().startswith('|') and row.strip().endswith('|')):
                    break
                if _SEP_RE.match(row.strip()):
                    # A second separator means a new table is starting.
                    break
                peek = lines[i + 1] if i + 1 < len(lines) else ''
                if peek.strip().startswith('|') and _SEP_RE.match(peek.strip()):
                    break
                block.append(row)
                i += 1
            chunks.append(('table', '\n'.join(block) + '\n'))
            continue
        buf.append(cur)
        i += 1
    if buf:
        chunks.append(('text', '\n'.join(buf)))
    return chunks


def normalize_visible_table_headers(
        text: str,
        *,
        lang: str,
        domain: str = '',
        selected_frameworks: Sequence[Any] = (),
        org_name: str = '',
) -> str:
    nlang = normalize_rel36_lang(lang)
    src = str(text or '')
    if not src.strip():
        return src
    parts: List[str] = []
    for kind, chunk in _iter_table_blocks(src):
        if kind == 'table':
            parts.append(_rewrite_table_block(
                chunk, lang=nlang, domain=domain,
                selected_frameworks=selected_frameworks,
                org_name=org_name,
            ).rstrip('\n'))
        else:
            body = chunk
            if nlang == 'en':
                body = translate_generated_phrase(body, org_name=org_name)
            parts.append(body)
    out = '\n\n'.join(str(p).strip('\n') for p in parts if str(p).strip())
    if nlang == 'en':
        out = translate_generated_phrase(out, org_name=org_name)
        out = out.replace('ل معالجة', 'treatment')
        out = out.replace('لل معالجة', 'treatment')
        out = out.replace('ال معالجة', 'treatment')
    return sanitize_visible_language_text(out, nlang)


def sanitize_visible_language_text(text: str, lang: str = 'ar') -> str:
    """Shared preview / TXT / Print / export visible-language sanitizer.

    Newline-safe: does not collapse ``\\n`` or strip leading table pipes.
    """
    nlang = normalize_rel36_lang(lang)
    cleaned = _FAMILY_RE.sub(' ', str(text or ''))
    try:
        from release_engine_v3.rel34_visible_output_quality import (
            FAMILY_MARKER_RE,
            INTERNAL_SNAKE_MARKER_RE,
            KNOWN_INTERNAL_FAMILY_IDS,
        )
        cleaned = FAMILY_MARKER_RE.sub(' ', cleaned)

        def _snake(m: re.Match[str]) -> str:
            tok = m.group(0)
            low = tok.lower()
            if low in KNOWN_INTERNAL_FAMILY_IDS:
                return ' '
            if low.endswith('_management') or low.endswith('_governance'):
                return ' '
            if low.startswith('family'):
                return ' '
            return tok

        cleaned = INTERNAL_SNAKE_MARKER_RE.sub(_snake, cleaned)
    except Exception:
        pass
    if nlang == 'en':
        cleaned = translate_generated_phrase(cleaned)
        cleaned = cleaned.replace('سجل\u00a0معالجة', 'processing register')
        cleaned = cleaned.replace('سجل معالجة', 'processing register')
        cleaned = cleaned.replace('لل\u00a0معالجة', 'treatment')
        cleaned = cleaned.replace('ال\u00a0معالجة', 'treatment')
        cleaned = cleaned.replace('ل\u00a0معالجة', 'treatment')
        cleaned = cleaned.replace('لل معالجة', 'treatment')
        cleaned = cleaned.replace('ال معالجة', 'treatment')
        cleaned = cleaned.replace('ل معالجة', 'treatment')
    cleaned = re.sub(r'[ \t]{2,}', ' ', cleaned)
    return cleaned


def sanitize_preview_txt_print(
        text: str,
        *,
        lang: str,
        domain: str = '',
        selected_frameworks: Sequence[Any] = (),
        org_name: str = '',
) -> str:
    return normalize_visible_table_headers(
        text, lang=lang, domain=domain,
        selected_frameworks=selected_frameworks, org_name=org_name)


def repair_sections_language_parity(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str,
        domain: str,
        selected_frameworks: Sequence[Any] = (),
        org_name: str = '',
) -> Dict[str, Any]:
    secs = dict(sections or {})
    for key, value in list(secs.items()):
        if str(key).startswith('_') or not isinstance(value, str):
            continue
        secs[key] = _demote_inner_h2(normalize_visible_table_headers(
            value, lang=lang, domain=domain,
            selected_frameworks=selected_frameworks, org_name=org_name))
    road = str(secs.get('roadmap') or '')
    if road.strip():
        nlang = normalize_rel36_lang(lang)
        heading = (
            '### Implementation Roadmap' if nlang == 'en'
            else '### خارطة الطريق التنفيذية')
        if 'خارطة الطريق' not in road and 'roadmap' not in road.lower():
            secs['roadmap'] = heading + '\n\n' + road.lstrip()
        elif not any(
                ln.strip().startswith('#') and (
                    'roadmap' in ln.lower() or 'خارطة الطريق' in ln)
                for ln in road.splitlines()):
            secs['roadmap'] = heading + '\n\n' + road.lstrip()
    nlang = normalize_rel36_lang(lang)
    if nlang == 'en':
        kpis = str(secs.get('kpis') or '')
        if 'KPI Description' not in kpis:
            seeds = english_kpi_seed_tables(domain)
            if seeds:
                main = seeds[0]
                lines = [_join(main['header']), _sep(len(main['header']))]
                for row in main.get('rows') or []:
                    lines.append(_join(row))
                secs['kpis'] = (
                    (kpis + '\n\n' if kpis.strip() else '')
                    + '### Key Performance Indicators\n\n'
                    + '\n'.join(lines) + '\n')
    return secs


def _demote_inner_h2(text: str) -> str:
    """Demote leftover inner H2s so rebuild/split cannot steal tables.

    Keep the first H2 in each section. Joined-document roadmap coverage
    stops at the next H2; demoting every title to H3 made KPI/guide tables
    look like extra roadmap rows (weak owner/output) on Arabic AI/Data.
    """
    out: List[str] = []
    seen_h2 = False
    for ln in str(text or '').splitlines():
        raw = ln.lstrip()
        if raw.startswith('## ') and not raw.startswith('###'):
            if seen_h2:
                out.append('#' + raw)
            else:
                out.append(ln)
                seen_h2 = True
        else:
            out.append(ln)
    return '\n'.join(out)


def _first_table_headers(text: str, kind: str) -> List[str]:
    for match in _TABLE_RE.finditer(str(text or '')):
        headers = _cells(match.group(1).splitlines()[0])
        if classify_table(headers) == kind:
            return headers
    return []


def _first_markdown_table(text: str) -> Tuple[List[str], List[List[str]]]:
    match = _TABLE_RE.search(str(text or ''))
    if not match:
        return [], []
    lines = [ln for ln in match.group(1).splitlines() if ln.strip()]
    if not lines:
        return [], []
    headers = _cells(lines[0])
    rows: List[List[str]] = []
    for ln in lines[1:]:
        if _SEP_RE.match(ln.strip()):
            continue
        cells = _cells(ln)
        if cells:
            rows.append(cells)
    return headers, rows


def _preview_mismatch(
        text: str, schema_id: str, lang: str) -> List[str]:
    headers, rows = _first_markdown_table(text or '')
    if not headers:
        return []
    html = render_preview_table_html(
        headers, rows or [[''] * len(headers)],
        schema_id=schema_id, is_rtl=(lang == 'ar'), lang=lang)
    check = evaluate_preview_dom_binding_check(html, schema_id, lang=lang)
    return list(check.get('blocking_errors') or []) + list(
        check.get('mismatched_headers') or [])


def roadmap_visible_row_count(text: str, domain: str) -> int:
    dcode = _normalize_rel31_domain_code(domain) or domain or 'cyber'
    try:
        cov = check_roadmap_coverage(text or '', domain=dcode)
        return int(cov.get('visible_row_count') or 0)
    except Exception:  # noqa: BLE001
        return 0


def bind_latest_preview_payload(
        payload: Optional[Dict[str, Any]],
        *,
        expected_domain: str = '',
        expected_lang: str = '',
        expected_document_type: str = 'strategy',
) -> Dict[str, Any]:
    """Fail closed when latest artifact lang/domain/type do not match."""
    src = dict(payload or {})
    got_lang = normalize_rel36_lang(
        src.get('language') or src.get('lang') or '')
    got_domain = _normalize_rel31_domain_code(
        src.get('domain') or '') or str(src.get('domain') or '')
    got_dtype = _norm_dtype(src.get('document_type') or 'strategy')
    exp_lang = normalize_rel36_lang(expected_lang) if expected_lang else ''
    exp_domain = (
        _normalize_rel31_domain_code(expected_domain) or expected_domain
        if expected_domain else '')
    exp_dtype = _norm_dtype(expected_document_type)
    blockers: List[str] = []
    if exp_lang and got_lang and exp_lang != got_lang:
        blockers.append(f'rel36_19_latest_lang_mismatch:{got_lang}:{exp_lang}')
    if exp_domain and got_domain and exp_domain != got_domain:
        blockers.append(
            f'rel36_19_latest_domain_mismatch:{got_domain}:{exp_domain}')
    if exp_dtype and got_dtype and exp_dtype != got_dtype:
        blockers.append(
            f'rel36_19_latest_document_type_mismatch:{got_dtype}:{exp_dtype}')
    return {
        'success': not blockers,
        'language': got_lang,
        'domain': got_domain,
        'document_type': got_dtype,
        'blocking_errors': blockers,
        'preview_bound': not blockers,
    }


def evaluate_rel36_19_bilingual_language_parity(
        *,
        task_id: Any = '',
        strategy_id: Any = '',
        domain: Any = '',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        output_type: Any = 'preview',
        section: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        static_version: Any = '',
        headers_before: Optional[Sequence[str]] = None,
        headers_after: Optional[Sequence[str]] = None,
        arabic_header_hits_in_en_before: Optional[Sequence[str]] = None,
        arabic_header_hits_in_en_after: Optional[Sequence[str]] = None,
        arabic_prose_hits_in_en_before: Optional[Sequence[str]] = None,
        arabic_prose_hits_in_en_after: Optional[Sequence[str]] = None,
        english_header_hits_in_ar_before: Optional[Sequence[str]] = None,
        english_header_hits_in_ar_after: Optional[Sequence[str]] = None,
        disallowed_domain_terms_before: Optional[Sequence[str]] = None,
        disallowed_domain_terms_after: Optional[Sequence[str]] = None,
        allowed_acronym_hits: Optional[Sequence[str]] = None,
        preview_header_mismatch_before: Optional[Sequence[str]] = None,
        preview_header_mismatch_after: Optional[Sequence[str]] = None,
        roadmap_visible_row_count_before: int = 0,
        roadmap_visible_row_count_after: int = 0,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
        pdf_evidence_blockers_after: Optional[Sequence[str]] = None,
        blockers_before: Optional[Sequence[str]] = None,
        blockers_after: Optional[Sequence[str]] = None,
        text_after: str = '',
) -> Dict[str, Any]:
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or str(domain or '')
    ar_hdr_after = list(arabic_header_hits_in_en_after or [])
    ar_prose_after = list(arabic_prose_hits_in_en_after or [])
    en_hdr_after = list(english_header_hits_in_ar_after or [])
    disallowed_after = list(disallowed_domain_terms_after or [])
    mismatch_after = [
        x for x in (preview_header_mismatch_after or [])
        if str(x).startswith('rel32_preview_table_header_value_mismatch')
        or str(x).startswith('header:')
    ]
    blockers_a = list(blockers_after or [])
    pdf_blockers = list(pdf_evidence_blockers_after or [])
    contamination = False
    if nlang == 'en':
        contamination = bool(ar_hdr_after or ar_prose_after)
    else:
        contamination = bool(en_hdr_after or disallowed_after)
    if visible_text_has_internal_markers(text_after):
        blockers_a.append('internal_marker_leak')
    passed = (
        rel36_19_should_apply(
            domain=domain, lang=nlang, document_type=document_type)
        and not contamination
        and not mismatch_after
        and not blockers_a
        and bool(docx_allowed)
        and bool(pdf_allowed)
        and not pdf_blockers
        and (
            nlang != 'en'
            or int(roadmap_visible_row_count_after or 0) > 0
            or 'roadmap' not in str(section or output_type or '')
        )
    )
    if nlang == 'en' and str(output_type) in ('docx', 'pdf', 'preview'):
        if 'roadmap' in str(text_after or '').lower() or str(section) == 'roadmap':
            passed = passed and int(roadmap_visible_row_count_after or 0) > 0
    return {
        'tag': REL36_19_BILINGUAL_LANGUAGE_PARITY_TAG.strip('[]'),
        'task_id': task_id,
        'strategy_id': strategy_id,
        'domain': dcode,
        'lang': nlang,
        'document_type': _norm_dtype(document_type),
        'output_type': output_type,
        'section': section,
        'selected_frameworks': [
            str(x) for x in (selected_frameworks or []) if str(x).strip()],
        'static_version': static_version,
        'headers_before': list(headers_before or []),
        'headers_after': list(headers_after or []),
        'arabic_header_hits_in_en_before': list(
            arabic_header_hits_in_en_before or []),
        'arabic_header_hits_in_en_after': ar_hdr_after,
        'arabic_prose_hits_in_en_before': list(
            arabic_prose_hits_in_en_before or []),
        'arabic_prose_hits_in_en_after': ar_prose_after,
        'english_header_hits_in_ar_before': list(
            english_header_hits_in_ar_before or []),
        'english_header_hits_in_ar_after': en_hdr_after,
        'disallowed_domain_terms_before': list(
            disallowed_domain_terms_before or []),
        'disallowed_domain_terms_after': disallowed_after,
        'allowed_acronym_hits': list(allowed_acronym_hits or []),
        'preview_header_mismatch_before': list(
            preview_header_mismatch_before or []),
        'preview_header_mismatch_after': mismatch_after,
        'roadmap_visible_row_count_before': int(
            roadmap_visible_row_count_before or 0),
        'roadmap_visible_row_count_after': int(
            roadmap_visible_row_count_after or 0),
        'docx_allowed': bool(docx_allowed),
        'pdf_allowed': bool(pdf_allowed),
        'pdf_evidence_blockers_after': pdf_blockers,
        'blockers_before': list(blockers_before or []),
        'blockers_after': blockers_a,
        'passed': bool(passed),
    }


def emit_rel36_19(diag: Dict[str, Any]) -> None:
    try:
        print(
            REL36_19_BILINGUAL_LANGUAGE_PARITY_TAG + ' '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        print(REL36_19_BILINGUAL_LANGUAGE_PARITY_TAG + ' emit_failed', flush=True)


def apply_rel36_19_bilingual_language_parity(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = '',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Any = '',
        strategy_id: Any = '',
        output_type: Any = 'preview',
        static_version: Any = '',
        org_name: Any = '',
        emit: bool = True,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
        pdf_evidence_blockers_after: Optional[Sequence[str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    secs = dict(sections or {})
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or ''
    fws = list(selected_frameworks or [])
    before_blob = '\n'.join(
        str(v) for v in secs.values() if isinstance(v, str))
    headers_before = (
        _first_table_headers(str(secs.get('vision') or ''), 'so')
        or _first_table_headers(str(secs.get('kpis') or ''), 'kpi_main')
    )
    road_b = roadmap_visible_row_count(
        str(secs.get('roadmap') or before_blob), dcode or 'cyber')
    mismatch_b: List[str] = []
    try:
        mismatch_b = _preview_mismatch(
            str(secs.get('kpis') or ''), 'kpi_main', nlang)
    except Exception:  # noqa: BLE001
        mismatch_b = []
    if not rel36_19_should_apply(
            domain=domain, lang=nlang, document_type=document_type):
        diag = evaluate_rel36_19_bilingual_language_parity(
            task_id=task_id, strategy_id=strategy_id, domain=dcode,
            lang=nlang, document_type=document_type, output_type=output_type,
            selected_frameworks=fws, static_version=static_version,
            headers_before=headers_before, headers_after=headers_before,
            roadmap_visible_row_count_before=road_b,
            roadmap_visible_row_count_after=road_b,
            docx_allowed=docx_allowed, pdf_allowed=pdf_allowed,
            blockers_after=['skipped'],
        )
        diag['passed'] = False
        diag['skipped_reason'] = 'out_of_scope'
        if emit:
            emit_rel36_19(diag)
        return secs, diag

    repaired = repair_sections_language_parity(
        secs, lang=nlang, domain=dcode, selected_frameworks=fws,
        org_name=str(org_name or ''))
    after_blob = '\n'.join(
        str(v) for v in repaired.values() if isinstance(v, str))
    headers_after = (
        _first_table_headers(str(repaired.get('vision') or ''), 'so')
        or _first_table_headers(str(repaired.get('kpis') or ''), 'kpi_main')
    )
    road_a = roadmap_visible_row_count(
        str(repaired.get('roadmap') or after_blob), dcode or 'cyber')
    mismatch_a: List[str] = []
    try:
        mismatch_a = _preview_mismatch(
            str(repaired.get('kpis') or ''), 'kpi_main', nlang)
    except Exception:  # noqa: BLE001
        mismatch_a = []
    drift = []
    if road_a <= 0 and (repaired.get('roadmap') or ''):
        drift.append('rel3_export_model_drift:roadmap_visible_row_count:0')
    ar_hdr_b = _arabic_hits(before_blob) if nlang == 'en' else []
    ar_hdr_a = _arabic_hits(after_blob) if nlang == 'en' else []
    ar_prose_b = _arabic_prose_hits(
        before_blob, org_name=str(org_name or '')) if nlang == 'en' else []
    ar_prose_a = _arabic_prose_hits(
        after_blob, org_name=str(org_name or '')) if nlang == 'en' else []
    en_hdr_b = _english_header_hits(before_blob) if nlang == 'ar' else []
    en_hdr_a = _english_header_hits(after_blob) if nlang == 'ar' else []
    dis_b = _disallowed_terms(before_blob, dcode, nlang)
    dis_a = _disallowed_terms(after_blob, dcode, nlang)
    diag = evaluate_rel36_19_bilingual_language_parity(
        task_id=task_id,
        strategy_id=strategy_id,
        domain=dcode,
        lang=nlang,
        document_type=document_type,
        output_type=output_type,
        section='all',
        selected_frameworks=fws,
        static_version=static_version,
        headers_before=headers_before,
        headers_after=headers_after,
        arabic_header_hits_in_en_before=ar_hdr_b,
        arabic_header_hits_in_en_after=ar_hdr_a,
        arabic_prose_hits_in_en_before=ar_prose_b,
        arabic_prose_hits_in_en_after=ar_prose_a,
        english_header_hits_in_ar_before=en_hdr_b,
        english_header_hits_in_ar_after=en_hdr_a,
        disallowed_domain_terms_before=dis_b,
        disallowed_domain_terms_after=dis_a,
        allowed_acronym_hits=_allowed_acronym_hits(after_blob, dcode, nlang),
        preview_header_mismatch_before=mismatch_b,
        preview_header_mismatch_after=mismatch_a,
        roadmap_visible_row_count_before=road_b,
        roadmap_visible_row_count_after=road_a,
        docx_allowed=docx_allowed or not drift,
        pdf_allowed=pdf_allowed or not drift,
        pdf_evidence_blockers_after=pdf_evidence_blockers_after,
        blockers_before=['language_mix'] if (ar_hdr_b or ar_prose_b or en_hdr_b) else [],
        blockers_after=drift + dis_a,
        text_after=after_blob,
    )
    if emit:
        emit_rel36_19(diag)
    if isinstance(sections, dict):
        sections.clear()
        sections.update(repaired)
        return sections, diag
    return repaired, diag
