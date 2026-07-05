"""PR-REL3.2 — deterministic registries for compiler-first strategy documents."""

from __future__ import annotations

from typing import Any, Dict, Tuple

from cyber_board_ready_prcy88 import (
    PRCY88_ARABIC_FIXES,
    PRCY88_KPI_CATALOG_AR,
    PRCY88_KPI_FAMILIES,
    PRCY88_ROADMAP_CATALOG_AR,
    PRCY88_ROADMAP_FAMILIES,
    PRCY88_SO_CATALOG_AR,
    PRCY88_SO_FAMILIES,
)
from release_engine.kpi_model import KPI_CANONICAL_REGISTRY
from release_engine.pillar_model import CYBER_PILLAR_FAMILIES, _PILLAR_CATALOG_AR
from release_engine.roadmap_model import ROADMAP_FAMILIES, _ROADMAP_CATALOG_AR
from release_engine.risk_treatment_model import _RISK_TREATMENTS_AR
from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY,
    _DCC_REGISTRY_ORDER,
    _ECC_REGISTRY_ORDER,
)

# ── Hardcoded REL3.2 canonical section headings (never from AI) ─────────────
REL32_CANONICAL_HEADINGS: Dict[str, str] = {
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

REL32_SECTION_ORDER: Tuple[str, ...] = (
    'vision', 'pillars', 'environment', 'gaps', 'roadmap',
    'kpis', 'confidence', 'governance', 'traceability', 'appendices',
)

# ── Gap families derived from traceability canonical registry ───────────────
GAP_FAMILY_REGISTRY: Dict[str, Dict[str, str]] = {}
for _fam, _spec in TRACE_CANONICAL_REGISTRY.items():
    _gap = _spec['expected_gap']
    GAP_FAMILY_REGISTRY[_fam] = {
        'gap_label': _gap,
        'description': _spec['initiative'],
        'priority': 'عالية' if 'غياب' in _gap else 'متوسطة',
        'status': 'مفتوحة',
        'framework': _spec['framework'],
        'treatment': _spec['initiative'],
        'owner': (
            'مدير حماية البيانات' if _spec['framework'] == 'NCA DCC'
            else 'CISO'),
    }

GAP_FAMILY_ORDER: Tuple[str, ...] = _DCC_REGISTRY_ORDER + _ECC_REGISTRY_ORDER

# ── Roadmap family registry ─────────────────────────────────────────────────
ROADMAP_FAMILY_REGISTRY: Dict[str, Tuple[str, ...]] = {
    fam: tuple(PRCY88_ROADMAP_CATALOG_AR.get(fam) or _ROADMAP_CATALOG_AR.get(fam) or ())
    for fam in ROADMAP_FAMILIES
}

# ── KPI canonical registry (REL3 + PRCY88 merged) ───────────────────────────
KPI_CANONICAL_REGISTRY_FULL: Dict[str, Dict[str, str]] = dict(
    KPI_CANONICAL_REGISTRY)
for _kf in PRCY88_KPI_FAMILIES:
    if _kf in PRCY88_KPI_CATALOG_AR:
        _cells = PRCY88_KPI_CATALOG_AR[_kf]
        # PRCY88 catalog order: … | source | owner | frequency |
        KPI_CANONICAL_REGISTRY_FULL[_kf] = {
            'label_ar': _cells[1],
            'kpi_type': _cells[2],
            'target': _cells[3],
            'formula': _cells[4],
            'source': _cells[5],
            'owner': _cells[6] if len(_cells) > 6 else 'CISO',
            'frequency': _cells[7] if len(_cells) > 7 else 'شهري',
        }

# ── Traceability canonical registry ─────────────────────────────────────────
TRACEABILITY_CANONICAL_REGISTRY = TRACE_CANONICAL_REGISTRY
TRACEABILITY_FAMILY_ORDER: Tuple[str, ...] = GAP_FAMILY_ORDER

# ── Pillar initiative registry ──────────────────────────────────────────────
PILLAR_INITIATIVE_REGISTRY: Dict[str, Tuple[Tuple[str, str, str], ...]] = {}
for _pi, _fam in enumerate(CYBER_PILLAR_FAMILIES):
    if _pi < len(_PILLAR_CATALOG_AR):
        PILLAR_INITIATIVE_REGISTRY[_fam] = _PILLAR_CATALOG_AR[_pi][1]

# ── Strategic objective registry ────────────────────────────────────────────
STRATEGIC_OBJECTIVE_REGISTRY: Dict[str, Tuple[str, ...]] = {
    fam: PRCY88_SO_CATALOG_AR[fam]
    for fam in PRCY88_SO_FAMILIES
    if fam in PRCY88_SO_CATALOG_AR
}

# ── Domain-specific strategic objectives (REL3.3 non-cyber) ───────────────────
DATA_STRATEGIC_OBJECTIVE_REGISTRY: Dict[str, Tuple[str, ...]] = {
    'data_governance': (
        'تأسيس حوكمة البيانات المؤسسية',
        'اعتماد إطار حوكمة NDMO',
        'إطار حوكمة معتمد',
        '6 أشهر',
    ),
    'data_quality': (
        'رفع جودة البيانات التشغيلية',
        '≥ 95% اكتمال البيانات الحرجة',
        'تحسين قرارات الأعمال',
        '12 شهراً',
    ),
    'metadata_catalog': (
        'تفعيل كتالوج البيانات والبيانات الوصفية',
        '100% فهرسة الأصول الحرجة',
        'اكتشاف وإدارة البيانات',
        '12 شهراً',
    ),
    'data_stewardship': (
        'تغطية أمناء البيانات لجميع المجالات',
        '100% مجالات بمالك بيانات',
        'مساءلة واضحة',
        '9 أشهر',
    ),
    'privacy_pdpl': (
        'الامتثال لنظام حماية البيانات الشخصية',
        '100% عمليات معالجة موثقة',
        'حماية الخصوصية',
        '12 شهراً',
    ),
    'data_security': (
        'تطبيق ضوابط أمن البيانات',
        '≥ 98% البيانات الحساسة محمية',
        'تقليل مخاطر التسرب',
        '12 شهراً',
    ),
    'data_sharing': (
        'حوكمة مشاركة البيانات بين الجهات',
        '100% اتفاقيات مشاركة معتمدة',
        'تمكين التكامل الآمن',
        '18 شهراً',
    ),
    'lifecycle_management': (
        'إدارة دورة حياة البيانات',
        '100% فئات بسياسات احتفاظ',
        'امتثال NDMO',
        '12 شهراً',
    ),
}

AI_STRATEGIC_OBJECTIVE_REGISTRY: Dict[str, Tuple[str, ...]] = {
    'ai_governance': (
        'تأسيس حوكمة الذكاء الاصطناعي',
        'سياسة AI معتمدة',
        'إطار NIST AI RMF',
        '6 أشهر',
    ),
    'model_inventory': (
        'جرد شامل لنماذج الذكاء الاصطناعي',
        '100% نماذج إنتاجية مسجلة',
        'رؤية المخاطر',
        '9 أشهر',
    ),
    'model_risk': (
        'إدارة مخاطر النماذج',
        '100% نماذج عالية الخطورة مقيمة',
        'تخفيف مخاطر AI',
        '12 شهراً',
    ),
    'bias_fairness': (
        'مراقبة الانحياز والعدالة',
        '≥ 95% نماذج حرجة مختبرة',
        'عدالة القرارات',
        '12 شهراً',
    ),
    'explainability': (
        'قابلية تفسير قرارات AI',
        '100% حالات حرجة قابلة للتفسير',
        'ثقة أصحاب المصلحة',
        '12 شهراً',
    ),
    'data_lineage': (
        'تتبع سلسلة بيانات التدريب',
        '100% مجموعات تدريب موثقة',
        'امتثال ومساءلة',
        '12 شهراً',
    ),
    'human_oversight': (
        'إشراف بشري على قرارات AI',
        '100% حالات حرجة بمراجعة بشرية',
        'حوكمة قرارات آلية',
        '9 أشهر',
    ),
    'ai_security': (
        'أمن أنظمة الذكاء الاصطناعي',
        'صفر ثغرات حرجة مفتوحة',
        'حماية النماذج والبيانات',
        '12 شهراً',
    ),
}

DT_STRATEGIC_OBJECTIVE_REGISTRY: Dict[str, Tuple[str, ...]] = {
    'digital_strategy': (
        'تحديد استراتيجية التحول الرقمي',
        'خارطة DGA معتمدة',
        'مواءمة رؤية المؤسسة',
        '6 أشهر',
    ),
    'service_digitization': (
        'رقمنة الخدمات الأساسية',
        '≥ 80% خدمات إلكترونية',
        'تحسين تجربة المستفيد',
        '18 شهراً',
    ),
    'platform_modernization': (
        'تحديث المنصات التقنية',
        '100% أنظمة حرجة على منصات حديثة',
        'مرونة تشغيلية',
        '24 شهراً',
    ),
    'cloud_adoption': (
        'تبني الحوسبة السحابية',
        '≥ 70% أعباء حرجة على السحابة',
        'كفاءة وتوسع',
        '18 شهراً',
    ),
    'api_integration': (
        'تكامل الأنظمة عبر واجهات API',
        '100% أنظمة حرجة متكاملة',
        'تدفق بيانات موحد',
        '12 شهراً',
    ),
    'customer_experience': (
        'تحسين تجربة العملاء الرقمية',
        '≥ 85% رضا المستفيدين',
        'ولاء واستخدام',
        '12 شهراً',
    ),
    'agile_delivery': (
        'تبني التسليم الرشيق',
        '100% فرق منتج بسprints',
        'سرعة إطلاق',
        '9 أشهر',
    ),
    'digital_governance': (
        'حوكمة التحول الرقمي',
        'لجنة تحول رقمي فعالة',
        'إشراف ومتابعة',
        '6 أشهر',
    ),
}

# ── Domain-specific KPI registries (8-column canonical) ─────────────────────
# Tuple order: label_ar, kpi_type, target, formula, source, owner, frequency
_DATA_KPI_ROWS: Tuple[Tuple[str, ...], ...] = (
    ('data_governance', 'نسبة تغطية حوكمة البيانات', 'KPI', '≥ 95%',
     'عدد مجالات مغطاة ÷ إجمالي المجالات × 100',
     'منصة حوكمة البيانات', 'CDO', 'ربع سنوي'),
    ('data_quality', 'نسبة اكتمال البيانات الحرجة', 'KPI', '≥ 95%',
     'حقول مكتملة ÷ حقول مطلوبة × 100',
     'أداة جودة البيانات', 'مدير جودة البيانات', 'شهري'),
    ('metadata_catalog', 'نسبة فهرسة الأصول في الكتالوج', 'KPI', '≥ 90%',
     'أصول مفهرسة ÷ أصول حرجة × 100',
     'كتالوج البيانات', 'مدير البيانات الوصفية', 'ربع سنوي'),
    ('data_stewardship', 'نسبة تغطية أمناء البيانات', 'KPI', '100%',
     'مجالات بأمين ÷ إجمالي المجالات × 100',
     'سجل أمناء البيانات', 'مدير حوكمة البيانات', 'ربع سنوي'),
    ('privacy_pdpl', 'نسبة عمليات المعالجة الموثقة', 'KPI', '100%',
     'عمليات موثقة ÷ عمليات نشطة × 100',
     'سجل RoPA', 'مسؤول حماية البيانات', 'ربع سنوي'),
    ('data_security', 'نسبة البيانات الحساسة المشفرة', 'KPI', '≥ 98%',
     'سجلات مشفرة ÷ سجلات حساسة × 100',
     'SIEM / DLP', 'مدير أمن البيانات', 'شهري'),
    ('data_sharing', 'نسبة اتفاقيات المشاركة المعتمدة', 'KPI', '100%',
     'اتفاقيات معتمدة ÷ تدفقات مشاركة × 100',
     'سجل المشاركة', 'CDO', 'ربع سنوي'),
    ('lifecycle_retention', 'نسبة فئات البيانات بسياسة احتفاظ', 'KPI', '100%',
     'فئات بسياسة ÷ فئات معرفة × 100',
     'سجل دورة الحياة', 'مدير حوكمة البيانات', 'ربع سنوي'),
    ('consent_management', 'نسبة الموافقات المدارة إلكترونياً', 'KPI', '≥ 95%',
     'موافقات إلكترونية ÷ إجمالي الموافقات × 100',
     'منصة الموافقات', 'مسؤول حماية البيانات', 'شهري'),
    ('dsr_response', 'متوسط زمن الاستجابة لطلبات DSR', 'KPI', '≤ 15 يوم',
     'مجموع أيام الاستجابة ÷ عدد الطلبات',
     'نظام DSR', 'مسؤول حماية البيانات', 'شهري'),
    ('breach_notification', 'متوسط زمن الإبلاغ عن الانتهاكات', 'KPI', '≤ 72 ساعة',
     'مجموع ساعات الإبلاغ ÷ عدد الحوادث',
     'سجل الحوادث', 'مدير أمن البيانات', 'حسب الحادثة'),
    ('ndmo_compliance', 'نسبة الامتثال لضوابط NDMO', 'KPI', '≥ 90%',
     'ضوابط مطبقة ÷ ضوابط مطلوبة × 100',
     'تقييم الامتثال', 'CDO', 'ربع سنوي'),
)

_AI_KPI_ROWS: Tuple[Tuple[str, ...], ...] = (
    ('ai_governance', 'نسبة نماذج AI ضمن سياسة الحوكمة', 'KPI', '100%',
     'نماذج مسجلة ÷ نماذج إنتاج × 100',
     'سجل النماذج', 'مدير حوكمة AI', 'ربع سنوي'),
    ('model_inventory', 'نسبة اكتمال جرد النماذج', 'KPI', '100%',
     'نماذج موثقة ÷ نماذج نشطة × 100',
     'مخزون النماذج', 'مدير مخاطر النماذج', 'شهري'),
    ('model_risk', 'نسبة نماذج عالية الخطورة المقيّمة', 'KPI', '100%',
     'نماذج مقيمة ÷ نماذج عالية الخطورة × 100',
     'منصة MRM', 'مدير مخاطر النماذج', 'ربع سنوي'),
    ('bias_fairness', 'نسبة نماذج حرجة مختبرة للانحياز', 'KPI', '≥ 95%',
     'نماذج مختبرة ÷ نماذج حرجة × 100',
     'أدوات Fairness', 'محلل AI', 'ربع سنوي'),
    ('explainability', 'نسبة قرارات AI قابلة للتفسير', 'KPI', '≥ 90%',
     'قرارات مفسرة ÷ قرارات حرجة × 100',
     'منصة XAI', 'مدير حوكمة AI', 'شهري'),
    ('data_lineage', 'نسبة مجموعات التدريب بسلسلة بيانات', 'KPI', '100%',
     'مجموعات موثقة ÷ مجموعات نشطة × 100',
     'سجل Lineage', 'مهندس بيانات AI', 'ربع سنوي'),
    ('human_oversight', 'نسبة حالات AI الحرجة بمراجعة بشرية', 'KPI', '100%',
     'حالات مراجعة ÷ حالات حرجة × 100',
     'سجل الإشراف', 'مدير حوكمة AI', 'شهري'),
    ('ai_incidents', 'عدد حوادث AI غير المعالجة', 'KRI', '0',
     'عدد حوادث مفتوحة',
     'سجل الحوادث', 'مدير AI Ops', 'شهري'),
    ('model_drift', 'نسبة نماذج بانحراف مقبول', 'KPI', '≥ 95%',
     'نماذج ضمن حدود ÷ نماذج مراقبة × 100',
     'MLOps Monitor', 'مهندس MLOps', 'شهري'),
    ('ai_training', 'نسبة فرق AI المدربة على الحوكمة', 'KPI', '100%',
     'أفراد مدربون ÷ أفراد AI × 100',
     'LMS', 'مدير التوعية', 'ربع سنوي'),
    ('vendor_ai', 'نسبة موردي AI المقيّمين', 'KPI', '100%',
     'موردون مقيمون ÷ موردون نشطون × 100',
     'سجل الموردين', 'مدير المشتريات', 'ربع سنوي'),
    ('ai_compliance', 'نسبة الامتثال لـ NIST AI RMF', 'KPI', '≥ 90%',
     'ضوابط مطبقة ÷ ضوابط مطلوبة × 100',
     'تقييم الامتثال', 'مدير حوكمة AI', 'ربع سنوي'),
)

_DT_KPI_ROWS: Tuple[Tuple[str, ...], ...] = (
    ('service_digitization', 'نسبة الخدمات الرقمية', 'KPI', '≥ 80%',
     'خدمات إلكترونية ÷ إجمالي الخدمات × 100',
     'بوابة الخدمات', 'مدير التحول الرقمي', 'ربع سنوي'),
    ('platform_uptime', 'توفر المنصات الحرجة', 'KPI', '≥ 99.5%',
     'وقت التشغيل ÷ وقت Planned × 100',
     'APM', 'مدير العمليات', 'شهري'),
    ('cloud_adoption', 'نسبة الأعباء على السحابة', 'KPI', '≥ 70%',
     'أعباء سحابية ÷ أعباء حرجة × 100',
     'Cloud Dashboard', 'مهندس سحابة', 'ربع سنوي'),
    ('api_coverage', 'نسبة تكامل الأنظمة عبر API', 'KPI', '100%',
     'أنظمة متكاملة ÷ أنظمة حرجة × 100',
     'API Gateway', 'مهندس تكامل', 'ربع سنوي'),
    ('cx_satisfaction', 'رضا المستفيدين الرقمي', 'KPI', '≥ 85%',
     'متوسط درجات الرضا',
     'استطلاعات CX', 'مدير تجربة العملاء', 'ربع سنوي'),
    ('agile_velocity', 'سرعة فرق المنتج', 'KPI', '≥ 85%',
     'Story points مكتملة ÷ مخططة × 100',
     'Jira', 'مدير Agile', 'شهري'),
    ('legacy_retirement', 'نسبة أنظمة Legacy المتقاعدة', 'KPI', '≥ 60%',
     'أنظمة متقاعدة ÷ أنظمة Legacy × 100',
     'سجل التقاعد', 'مدير التحول الرقمي', 'ربع سنوي'),
    ('digital_skills', 'نسبة الموظفين بمهارات رقمية', 'KPI', '≥ 80%',
     'موظفون مدربون ÷ موظفون مستهدفون × 100',
     'LMS', 'مدير التدريب', 'ربع سنوي'),
    ('automation_rate', 'نسبة العمليات المؤتمتة', 'KPI', '≥ 50%',
     'عمليات مؤتمتة ÷ عمليات مؤهلة × 100',
     'RPA Dashboard', 'مدير الأتمتة', 'ربع سنوي'),
    ('dga_compliance', 'نسبة الامتثال لـ DGA', 'KPI', '≥ 90%',
     'ضوابط مطبقة ÷ ضوابط DGA × 100',
     'تقييم DGA', 'مدير التحول الرقمي', 'ربع سنوي'),
    ('project_delivery', 'نسبة مشاريع التحول في الموعد', 'KPI', '≥ 85%',
     'مشاريع في الموعد ÷ مشاريع نشطة × 100',
     'PMO', 'مدير PMO', 'شهري'),
    ('digital_security', 'نسبة خدمات رقمية باختبار أمني', 'KPI', '100%',
     'خدمات مختبرة ÷ خدمات جديدة × 100',
     'DevSecOps', 'CISO', 'شهري'),
)


def _rows_to_kpi_registry(
        rows: Tuple[Tuple[str, ...], ...],
) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for row in rows:
        fam = row[0]
        out[fam] = {
            'label_ar': row[1],
            'kpi_type': row[2],
            'target': row[3],
            'formula': row[4],
            'source': row[5],
            'owner': row[6],
            'frequency': row[7],
        }
    return out


DATA_KPI_CANONICAL_REGISTRY = _rows_to_kpi_registry(_DATA_KPI_ROWS)
AI_KPI_CANONICAL_REGISTRY = _rows_to_kpi_registry(_AI_KPI_ROWS)
DT_KPI_CANONICAL_REGISTRY = _rows_to_kpi_registry(_DT_KPI_ROWS)


def resolve_strategic_objective_registry(domain: str) -> Dict[str, Tuple[str, ...]]:
    from release_engine_v3.domain_codes import normalize_domain_code
    d = normalize_domain_code(domain or 'cyber', default='cyber')
    if d == 'data':
        return DATA_STRATEGIC_OBJECTIVE_REGISTRY
    if d == 'ai':
        return AI_STRATEGIC_OBJECTIVE_REGISTRY
    if d == 'dt':
        return DT_STRATEGIC_OBJECTIVE_REGISTRY
    return STRATEGIC_OBJECTIVE_REGISTRY


def resolve_kpi_canonical_registry(domain: str) -> Dict[str, Dict[str, str]]:
    from release_engine_v3.domain_codes import normalize_domain_code
    d = normalize_domain_code(domain or 'cyber', default='cyber')
    if d == 'data':
        return DATA_KPI_CANONICAL_REGISTRY
    if d == 'ai':
        return AI_KPI_CANONICAL_REGISTRY
    if d == 'dt':
        return DT_KPI_CANONICAL_REGISTRY
    return KPI_CANONICAL_REGISTRY_FULL

# ── Governance role registry (cyber) ────────────────────────────────────────
GOVERNANCE_ROLE_REGISTRY: Dict[str, Dict[str, str]] = {
    'ciso': {
        'role': 'CISO / رئيس الأمن السيبراني',
        'scope': 'قيادة برنامج الأمن السيبراني والحوكمة والامتثال',
        'accountability': 'الإدارة العليا ومجلس الإدارة',
        'escalation': 'تقرير ربع سنوي للجنة الحوكمة',
        'framework': 'NCA ECC',
    },
    'soc_manager': {
        'role': 'مدير SOC',
        'scope': 'تشغيل مركز العمليات الأمنية وSIEM والكشف',
        'accountability': 'CISO',
        'escalation': 'تصعيد الحوادث الحرجة لقائد CSIRT',
        'framework': 'NCA ECC',
    },
    'csirt_lead': {
        'role': 'قائد CSIRT',
        'scope': 'الاستجابة للحوادث وخطط الاحتواء والتعافي',
        'accountability': 'CISO',
        'escalation': 'تصعيد للإدارة العليا خلال SLA',
        'framework': 'NCA ECC',
    },
    'iam_manager': {
        'role': 'مدير IAM/PAM',
        'scope': 'إدارة الهوية والوصول والصلاحيات المميزة وMFA',
        'accountability': 'CISO',
        'escalation': 'تقرير شهري لجنة الحوكمة',
        'framework': 'NCA ECC',
    },
    'dpo': {
        'role': 'مدير حماية البيانات',
        'scope': 'تصنيف البيانات والتشفير وDLP وحماية البيانات الحساسة',
        'accountability': 'CISO',
        'escalation': 'تقرير ربع سنوي لجنة الحوكمة',
        'framework': 'NCA DCC',
    },
    'compliance_manager': {
        'role': 'مدير الامتثال',
        'scope': 'متابعة امتثال NCA ECC وNCA DCC والمراجعات',
        'accountability': 'CISO',
        'escalation': 'تقرير امتثال ربع سنوي',
        'framework': 'NCA ECC / DCC',
    },
    'bcp_manager': {
        'role': 'مدير استمرارية الأعمال',
        'scope': 'النسخ الاحتياطي والتعافي من الكوارث وخطط BCP',
        'accountability': 'CISO',
        'escalation': 'تقرير اختبارات DR سنوياً',
        'framework': 'NCA ECC',
    },
}

# ── Risk treatment registry ─────────────────────────────────────────────────
RISK_TREATMENT_REGISTRY: Dict[str, str] = dict(_RISK_TREATMENTS_AR)

# ── Arabic canonical repair registry ──────────────────────────────────────────
ARABIC_CANONICAL_REPAIR_REGISTRY: Tuple[Tuple[str, str], ...] = tuple(
    PRCY88_ARABIC_FIXES)

# ── Confidence factors (weights must sum to 100%) ───────────────────────────
CONFIDENCE_FACTOR_REGISTRY: Tuple[Tuple[str, str], ...] = (
    ('اكتمال المدخلات', '20%'),
    ('تغطية الأطر المرجعية', '20%'),
    ('جدوى خارطة الطريق', '20%'),
    ('جاهزية الموارد', '15%'),
    ('نضج الحوكمة', '15%'),
    ('جاهزية حماية البيانات', '10%'),
)

DEFAULT_CONFIDENCE_SCORE = '76%'
DEFAULT_CONFIDENCE_RATIONALE = (
    'تقييم مبني على اكتمال المدخلات وتغطية الأطر المرجعية '
    'وجدوى خارطة الطريق وجاهزية الموارد ونضج الحوكمة '
    'وجاهزية حماية البيانات.')


def registry_schema_version() -> str:
    return 'rel32.0'


def emit_rel32_registry_diag() -> Dict[str, Any]:
    return {
        'schema': registry_schema_version(),
        'gap_families': len(GAP_FAMILY_REGISTRY),
        'roadmap_families': len(ROADMAP_FAMILY_REGISTRY),
        'kpi_families': len(KPI_CANONICAL_REGISTRY_FULL),
        'trace_families': len(TRACEABILITY_CANONICAL_REGISTRY),
        'pillar_families': len(PILLAR_INITIATIVE_REGISTRY),
        'governance_roles': len(GOVERNANCE_ROLE_REGISTRY),
        'risk_themes': len(RISK_TREATMENT_REGISTRY),
    }
