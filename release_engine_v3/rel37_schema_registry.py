"""REL37 versioned schemas for Data / AI / DT strategy (AR + EN)."""
from __future__ import annotations

import os
from typing import Dict, Tuple

SCHEMA_VERSION = 'rel37.strategy.v1'
PHASE1_DOMAINS = ('data', 'ai', 'dt')
PHASE1_LANGS = ('ar', 'en')
DOMAIN_DEFAULT_FRAMEWORKS: Dict[str, Tuple[str, ...]] = {
    'data': ('ndmo', 'pdpl'),
    'ai': ('sdaia',),
    'dt': ('dga',),
}

SO_HEADERS = {
    'en': ('#', 'Strategic Objective', 'Measurable Target', 'Rationale', 'Timeframe'),
    'ar': ('#', 'الهدف الاستراتيجي', 'المستهدف القابل للقياس', 'المبرر', 'الإطار الزمني'),
}
KPI_MAIN_HEADERS = {
    'en': ('#', 'KPI Description', 'Type', 'Target Value',
           'Calculation Formula', 'Source', 'Frequency', 'Owner'),
    'ar': ('#', 'وصف المؤشر', 'النوع', 'القيمة المستهدفة',
           'صيغة الاحتساب', 'المصدر', 'التكرار', 'المالك'),
}
KPI_FORMULA_HEADERS = {
    'en': ('#', 'KPI', 'Calculation Formula', 'Data Source'),
    'ar': ('#', 'المؤشر', 'صيغة الاحتساب', 'مصدر البيانات'),
}
GUIDE_HEADERS = {
    'en': ('Step', 'Action', 'Owner', 'Timeline', 'Output'),
    'ar': ('الخطوة', 'الإجراء', 'المسؤول', 'الإطار الزمني', 'الناتج'),
}
ROADMAP_HEADERS = {
    'en': ('Phase', 'Period', 'Initiative', 'Owner',
           'Expected Deliverable', 'Linked Framework'),
    'ar': ('المرحلة', 'الفترة', 'المبادرة', 'المسؤول',
           'المخرج المتوقع', 'الإطار المرتبط'),
}
PILLAR_INIT_HEADERS = {
    'en': ('Initiative', 'Description', 'Expected Deliverable', 'Owner'),
    'ar': ('المبادرة', 'الوصف', 'المخرج المتوقع', 'المسؤول'),
}
GAP_HEADERS = {
    'en': ('#', 'Gap', 'Description', 'Priority', 'Status'),
    'ar': ('#', 'الفجوة', 'الوصف', 'الأولوية', 'الحالة'),
}
TRACE_HEADERS = {
    'en': ('#', 'Initiative', 'Gap', 'KPI', 'Framework'),
    'ar': ('#', 'المبادرة', 'الفجوة', 'المؤشر', 'الإطار'),
}
CONF_CSF_HEADERS = {
    'en': ('Factor', 'Weight', 'Score', 'Rationale'),
    'ar': ('العامل', 'الوزن', 'التقييم', 'المبرر'),
}
CONF_RISK_HEADERS = {
    'en': ('Risk', 'Impact', 'Mitigation', 'Owner'),
    'ar': ('المخاطرة', 'الأثر', 'المعالجة', 'المالك'),
}

SECTION_TITLES = {
    'en': {
        'vision': '1. Strategic Vision and Objectives',
        'pillars': '2. Strategic Pillars',
        'environment': '3. Environment and Drivers',
        'gaps': '4. Gap Assessment',
        'roadmap': '5. Implementation Roadmap',
        'kpis': '6. Key Performance Indicators',
        'confidence': '7. Confidence and Risk',
        'traceability': '8. Traceability',
    },
    'ar': {
        'vision': '1. الرؤية والأهداف الاستراتيجية',
        'pillars': '2. الركائز الاستراتيجية',
        'environment': '3. البيئة والمحركات',
        'gaps': '4. تقييم الفجوات',
        'roadmap': '5. خارطة الطريق',
        'kpis': '6. مؤشرات الأداء الرئيسية',
        'confidence': '7. الثقة والمخاطر',
        'traceability': '8. مصفوفة التتبع',
    },
}

GAP_GUIDE_HEADING = {
    'en': '#### Gap #{n} Implementation Guide',
    'ar': '#### دليل تنفيذ الفجوة رقم {n}',
}
KPI_GUIDE_HEADING = {
    'en': '#### KPI #{n} Assessment Guide',
    'ar': '#### دليل تقييم المؤشر رقم {n}',
}
KPI_GUIDES_BLOCK = {
    'en': '### KPI Assessment Guidelines',
    'ar': '### أدلة تقييم مؤشرات الأداء',
}
FORMULA_BLOCK = {
    'en': '### Calculation Formula and Data Source',
    'ar': '### صيغة الاحتساب ومصدر البيانات',
}

OWNERS = {
    'data': {
        'en': 'Data Governance Manager',
        'ar': 'مدير حوكمة البيانات',
    },
    'ai': {
        'en': 'AI Governance Lead',
        'ar': 'رئيس حوكمة الذكاء الاصطناعي',
    },
    'dt': {
        'en': 'Digital Transformation Lead',
        'ar': 'مدير التحول الرقمي',
    },
}

LEAKAGE: Dict[str, Tuple[str, ...]] = {
    'data': (
        'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
        'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
    ),
    'ai': (
        'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
        'IAM', 'PAM', 'MFA',
        'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
    ),
    'dt': (
        'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
        'NIST CSF', 'NIST Cybersecurity Framework',
    ),
}

APPROVED_ACRONYMS = (
    'NDMO', 'PDPL', 'SDAIA', 'DGA', 'API', 'APIs', 'MLOps', 'KPI', 'KPIs',
    'ISO', 'CSF', 'CDO', 'DPO', 'CX',
)

REL32_AR_HEADINGS = {
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


def header_line(kind: str, lang: str) -> str:
    tables = {
        'so': SO_HEADERS,
        'kpi_main': KPI_MAIN_HEADERS,
        'kpi_formula': KPI_FORMULA_HEADERS,
        'guide': GUIDE_HEADERS,
        'roadmap': ROADMAP_HEADERS,
        'pillar': PILLAR_INIT_HEADERS,
        'gap': GAP_HEADERS,
        'trace': TRACE_HEADERS,
        'csf': CONF_CSF_HEADERS,
        'risk': CONF_RISK_HEADERS,
    }
    cols = tables[kind][lang if lang in ('ar', 'en') else 'en']
    return '| ' + ' | '.join(cols) + ' |'


def separator_line(kind: str, lang: str) -> str:
    n = header_line(kind, lang).count('|') - 1
    return '|' + '|'.join(['---'] * n) + '|'


def leakage_terms(domain: str) -> Tuple[str, ...]:
    extras = {
        'data': ('NCA', 'NIST'),
        'ai': ('NCA', 'NIST'),
        'dt': ('NCA', 'NIST'),
    }
    base = LEAKAGE.get(domain, ())
    return tuple(dict.fromkeys(base + extras.get(domain, ())))


def rel37_compiler_flag_enabled() -> bool:
    raw = str(os.environ.get('REL37_DATA_AI_DT_COMPILER', '1')).strip().lower()
    return raw not in ('0', 'false', 'off', 'no')
