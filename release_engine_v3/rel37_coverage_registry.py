"""REL37 coverage families for Data, AI, and DT strategy compilers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Tuple

from release_engine_v3.rel37_schema_registry import DOMAIN_DEFAULT_FRAMEWORKS, leakage_terms


@dataclass(frozen=True)
class FamilySpec:
    family_id: str
    frameworks: FrozenSet[str]
    so_ar: Tuple[str, str, str, str]
    so_en: Tuple[str, str, str, str]
    gap_ar: Tuple[str, str, str, str]
    gap_en: Tuple[str, str, str, str]
    kpi_ar: Tuple[str, str, str, str, str, str, str]
    kpi_en: Tuple[str, str, str, str, str, str, str]
    roadmap_ar: Tuple[str, str, str, str, str]
    roadmap_en: Tuple[str, str, str, str, str]


def _f(*codes: str) -> FrozenSet[str]:
    return frozenset(c.lower() for c in codes)


DATA_FAMILIES: Tuple[FamilySpec, ...] = (
    FamilySpec(
        "NDMO",
        _f("ndmo", "ndmo_dga", "national_data_management_office"),
        ("تفعيل حوكمة NDMO الوطنية للبيانات", "اكتمال سياسة NDMO بنسبة 100%", "الامتثال لإطار إدارة البيانات الوطني", "12 شهراً"),
        ("Activate national NDMO data governance", "100% NDMO policy completeness", "National data-management compliance", "12 months"),
        ("فجوة سياسة NDMO التشغيلية", "مرتفعة", "غياب سياسة بيانات وطنية معتمدة", "اعتماد سياسة NDMO خلال ربع"),
        ("NDMO operating-policy gap", "High", "No approved national data policy", "Approve NDMO policy within one quarter"),
        ("اكتمال سياسات NDMO المعتمدة", "نسبة", "100%", "السياسات المعتمدة / السياسات المطلوبة × 100", "سجل سياسات البيانات", "ربع سنوي", "CDO"),
        ("Approved NDMO policy completeness", "Percent", "100%", "approved policies / required policies × 100", "Data policy register", "Quarterly", "CDO"),
        ("المرحلة 1", "Q1-Q2", "برنامج حوكمة NDMO", "CDO", "سياسة NDMO معتمدة", "NDMO"),
        ("Phase 1", "Q1-Q2", "NDMO governance program", "CDO", "Approved NDMO policy", "NDMO"),
    ),
    FamilySpec(
        "PDPL",
        _f("pdpl", "personal_data_protection_law"),
        ("امتثال PDPL لحماية البيانات الشخصية", "تغطية ضوابط PDPL بنسبة 100%", "حماية البيانات الشخصية وفق النظام", "12 شهراً"),
        ("Achieve PDPL personal-data compliance", "100% PDPL control coverage", "Statutory personal-data protection", "12 months"),
        ("فجوة ضوابط PDPL", "مرتفعة", "ضوابط PDPL غير مكتملة", "إغلاق فجوات PDPL خلال ربع"),
        ("PDPL control gap", "High", "Incomplete PDPL controls", "Close PDPL gaps within one quarter"),
        ("تغطية ضوابط PDPL", "نسبة", "100%", "الضوابط المغلقة / الضوابط المطلوبة × 100", "سجل امتثال PDPL", "ربع سنوي", "DPO"),
        ("PDPL control coverage", "Percent", "100%", "closed controls / required controls × 100", "PDPL compliance register", "Quarterly", "DPO"),
        ("المرحلة 1", "Q1-Q2", "برنامج امتثال PDPL", "DPO", "ملف امتثال PDPL", "PDPL"),
        ("Phase 1", "Q1-Q2", "PDPL compliance program", "DPO", "PDPL compliance file", "PDPL"),
    ),
    FamilySpec(
        "data_catalog",
        _f("data_catalog", "ndmo", "metadata"),
        ("تشغيل كتالوج بيانات مؤسسي", "تغطية الكتالوج بنسبة 95%", "اكتشاف الأصول البيانية", "9 أشهر"),
        ("Operate an enterprise data catalog", "95% catalog coverage", "Discoverable data assets", "9 months"),
        ("فجوة كتالوج البيانات", "متوسطة", "أصول غير مكتشفة في الكتالوج", "رفع تغطية الكتالوج"),
        ("Data-catalog gap", "Medium", "Undiscovered assets outside the catalog", "Raise catalog coverage"),
        ("تغطية كتالوج البيانات", "نسبة", "95%", "الأصول المفهرسة / الأصول المعروفة × 100", "منصة الكتالوج", "شهري", "Data Steward"),
        ("Data catalog coverage", "Percent", "95%", "indexed assets / known assets × 100", "Catalog platform", "Monthly", "Data Steward"),
        ("المرحلة 2", "Q2-Q3", "مبادرة كتالوج البيانات", "Data Steward", "كتالوج تشغيلي", "data_catalog"),
        ("Phase 2", "Q2-Q3", "Data catalog initiative", "Data Steward", "Operating catalog", "data_catalog"),
    ),
    FamilySpec(
        "data_lifecycle",
        _f("data_lifecycle", "ndmo"),
        ("ضبط دورة حياة البيانات", "سياسات احتفاظ مطبقة بنسبة 100%", "إدارة الاحتفاظ والإتلاف", "12 شهراً"),
        ("Control the data lifecycle", "100% retention-policy application", "Retention and disposal control", "12 months"),
        ("فجوة دورة حياة البيانات", "متوسطة", "احتفاظ غير منضبط", "تطبيق جداول الاحتفاظ"),
        ("Data-lifecycle gap", "Medium", "Uncontrolled retention", "Apply retention schedules"),
        ("تطبيق سياسات الاحتفاظ", "نسبة", "100%", "الأصول الخاضعة للسياسة / الأصول الخاضعة × 100", "سجل الاحتفاظ", "ربع سنوي", "Records Officer"),
        ("Retention-policy application", "Percent", "100%", "assets under policy / in-scope assets × 100", "Retention register", "Quarterly", "Records Officer"),
        ("المرحلة 2", "Q2-Q3", "مبادرة دورة حياة البيانات", "Records Officer", "جدول احتفاظ معتمد", "data_lifecycle"),
        ("Phase 2", "Q2-Q3", "Data lifecycle initiative", "Records Officer", "Approved retention schedule", "data_lifecycle"),
    ),
    FamilySpec(
        "privacy_governance",
        _f("privacy_governance", "pdpl"),
        ("إرساء حوكمة الخصوصية", "لجنة خصوصية عاملة بنسبة 100%", "رقابة الخصوصية المؤسسية", "6 أشهر"),
        ("Establish privacy governance", "100% operating privacy committee", "Institutional privacy oversight", "6 months"),
        ("فجوة حوكمة الخصوصية", "مرتفعة", "غياب لجنة خصوصية", "تفعيل لجنة الخصوصية"),
        ("Privacy-governance gap", "High", "No privacy committee", "Activate the privacy committee"),
        ("فاعلية لجنة الخصوصية", "نسبة", "100%", "الاجتماعات المنعقدة / المخططة × 100", "محاضر اللجنة", "ربع سنوي", "DPO"),
        ("Privacy committee effectiveness", "Percent", "100%", "held meetings / planned meetings × 100", "Committee minutes", "Quarterly", "DPO"),
        ("المرحلة 1", "Q1-Q2", "مبادرة حوكمة الخصوصية", "DPO", "ميثاق لجنة الخصوصية", "privacy_governance"),
        ("Phase 1", "Q1-Q2", "Privacy governance initiative", "DPO", "Privacy committee charter", "privacy_governance"),
    ),
    FamilySpec(
        "personal_data_classification",
        _f("personal_data_classification", "pdpl", "ndmo"),
        ("تصنيف البيانات الشخصية", "تصنيف 100% من مجموعات البيانات الشخصية", "حماية متناسبة مع الحساسية", "9 أشهر"),
        ("Classify personal data", "100% personal datasets classified", "Sensitivity-aligned protection", "9 months"),
        ("فجوة تصنيف البيانات الشخصية", "مرتفعة", "مجموعات غير مصنفة", "إكمال تصنيف البيانات الشخصية"),
        ("Personal-data classification gap", "High", "Unclassified datasets", "Complete personal-data classification"),
        ("اكتمال تصنيف البيانات الشخصية", "نسبة", "100%", "المجموعات المصنفة / المجموعات الشخصية × 100", "سجل التصنيف", "ربع سنوي", "Data Steward"),
        ("Personal-data classification completeness", "Percent", "100%", "classified sets / personal sets × 100", "Classification register", "Quarterly", "Data Steward"),
        ("المرحلة 2", "Q2-Q3", "مبادرة تصنيف البيانات الشخصية", "Data Steward", "سجل تصنيف معتمد", "personal_data_classification"),
        ("Phase 2", "Q2-Q3", "Personal-data classification initiative", "Data Steward", "Approved classification register", "personal_data_classification"),
    ),
    FamilySpec(
        "consent_management",
        _f("consent_management", "pdpl"),
        ("إدارة موافقات معالجة البيانات", "تسجيل 100% من الموافقات المطلوبة", "أساس نظامي للمعالجة", "9 أشهر"),
        ("Manage processing consent", "100% required consents recorded", "Lawful processing basis", "9 months"),
        ("فجوة إدارة الموافقات", "مرتفعة", "موافقات غير مسجلة", "تشغيل سجل الموافقات"),
        ("Consent-management gap", "High", "Unrecorded consents", "Operate the consent register"),
        ("اكتمال سجل الموافقات", "نسبة", "100%", "الموافقات المسجلة / المطلوبة × 100", "منصة الموافقات", "شهري", "DPO"),
        ("Consent-register completeness", "Percent", "100%", "recorded consents / required consents × 100", "Consent platform", "Monthly", "DPO"),
        ("المرحلة 2", "Q2-Q3", "مبادرة إدارة الموافقات", "DPO", "منصة موافقات تشغيلية", "consent_management"),
        ("Phase 2", "Q2-Q3", "Consent-management initiative", "DPO", "Operating consent platform", "consent_management"),
    ),
    FamilySpec(
        "data_subject_rights",
        _f("data_subject_rights", "pdpl"),
        ("تمكين حقوق أصحاب البيانات", "إغلاق 100% من الطلبات ضمن المهلة", "الاستجابة النظامية للحقوق", "6 أشهر"),
        ("Enable data-subject rights", "100% requests closed on time", "Statutory rights response", "6 months"),
        ("فجوة حقوق أصحاب البيانات", "مرتفعة", "مسار طلبات غير مكتمل", "تشغيل مكتب حقوق أصحاب البيانات"),
        ("Data-subject-rights gap", "High", "Incomplete request path", "Operate the rights desk"),
        ("إغلاق طلبات أصحاب البيانات في المهلة", "نسبة", "100%", "الطلبات المغلقة في المهلة / إجمالي الطلبات × 100", "مكتب الحقوق", "شهري", "DPO"),
        ("On-time data-subject request closure", "Percent", "100%", "on-time closures / total requests × 100", "Rights desk", "Monthly", "DPO"),
        ("المرحلة 1", "Q1-Q2", "مبادرة حقوق أصحاب البيانات", "DPO", "إجراء حقوق تشغيلي", "data_subject_rights"),
        ("Phase 1", "Q1-Q2", "Data-subject-rights initiative", "DPO", "Operating rights procedure", "data_subject_rights"),
    ),
    FamilySpec(
        "breach_notification",
        _f("breach_notification", "pdpl"),
        ("إخطار حوادث البيانات وفق PDPL", "إخطار 100% من الحوادث المؤهلة في المهلة", "الالتزام النظامي بالإبلاغ", "6 أشهر"),
        ("Notify data incidents under PDPL", "100% eligible incidents notified on time", "Statutory notification duty", "6 months"),
        ("فجوة إخطار حوادث البيانات", "مرتفعة", "مسار إخطار غير مجرب", "تجريب مسار الإخطار"),
        ("Breach-notification gap", "High", "Unexercised notification path", "Exercise the notification path"),
        ("إخطار الحوادث المؤهلة في المهلة", "نسبة", "100%", "الإخطارات في المهلة / الحوادث المؤهلة × 100", "سجل الحوادث", "ربع سنوي", "DPO"),
        ("On-time eligible-incident notification", "Percent", "100%", "on-time notices / eligible incidents × 100", "Incident register", "Quarterly", "DPO"),
        ("المرحلة 1", "Q1-Q2", "مبادرة إخطار الحوادث", "DPO", "إجراء إخطار معتمد", "breach_notification"),
        ("Phase 1", "Q1-Q2", "Breach-notification initiative", "DPO", "Approved notification procedure", "breach_notification"),
    ),
    FamilySpec(
        "data_quality",
        _f("data_quality", "ndmo"),
        ("رفع جودة البيانات التشغيلية", "درجة جودة لا تقل عن 95%", "موثوقية القرارات المعتمدة على البيانات", "12 شهراً"),
        ("Raise operational data quality", "Quality score of at least 95%", "Reliable data-driven decisions", "12 months"),
        ("فجوة جودة البيانات", "متوسطة", "قواعد جودة غير مفعلة", "تفعيل قواعد الجودة"),
        ("Data-quality gap", "Medium", "Inactive quality rules", "Activate quality rules"),
        ("درجة جودة البيانات", "نسبة", "95%", "السجلات السليمة / السجلات المختبرة × 100", "محرك الجودة", "شهري", "Data Quality Lead"),
        ("Data quality score", "Percent", "95%", "clean records / tested records × 100", "Quality engine", "Monthly", "Data Quality Lead"),
        ("المرحلة 3", "Q3-Q4", "مبادرة جودة البيانات", "Data Quality Lead", "لوحة جودة تشغيلية", "data_quality"),
        ("Phase 3", "Q3-Q4", "Data-quality initiative", "Data Quality Lead", "Operating quality dashboard", "data_quality"),
    ),
    FamilySpec(
        "metadata_stewardship",
        _f("metadata", "stewardship", "ndmo", "data_catalog"),
        ("حوكمة البيانات الوصفية والملكية", "تعيين مالك لكل أصل بنسبة 100%", "مساءلة واضحة على الأصول", "9 أشهر"),
        ("Govern metadata and stewardship", "100% assets have an owner", "Clear asset accountability", "9 months"),
        ("فجوة الملكية والبيانات الوصفية", "متوسطة", "أصول بلا مالك", "تعيين ملاك الأصول"),
        ("Metadata-stewardship gap", "Medium", "Ownerless assets", "Assign asset owners"),
        ("تعيين ملاك الأصول", "نسبة", "100%", "الأصول بمالك / الأصول المسجلة × 100", "سجل الملكية", "ربع سنوي", "CDO"),
        ("Asset-owner assignment", "Percent", "100%", "owned assets / registered assets × 100", "Ownership register", "Quarterly", "CDO"),
        ("المرحلة 2", "Q2-Q3", "مبادرة الملكية والبيانات الوصفية", "CDO", "سجل ملكية مكتمل", "metadata_stewardship"),
        ("Phase 2", "Q2-Q3", "Metadata-stewardship initiative", "CDO", "Complete ownership register", "metadata_stewardship"),
    ),
    FamilySpec(
        "data_sharing",
        _f("data_sharing", "ndmo"),
        ("ضبط مشاركة البيانات", "100% من اتفاقيات المشاركة موثقة", "مشاركة منضبطة وآمنة", "9 أشهر"),
        ("Control data sharing", "100% sharing agreements documented", "Controlled and safe sharing", "9 months"),
        ("فجوة اتفاقيات مشاركة البيانات", "متوسطة", "مشاركات بلا اتفاقية", "توثيق اتفاقيات المشاركة"),
        ("Data-sharing gap", "Medium", "Sharing without agreements", "Document sharing agreements"),
        ("توثيق اتفاقيات المشاركة", "نسبة", "100%", "الاتفاقيات الموثقة / المشاركات النشطة × 100", "سجل المشاركة", "ربع سنوي", "CDO"),
        ("Sharing-agreement documentation", "Percent", "100%", "documented agreements / active shares × 100", "Sharing register", "Quarterly", "CDO"),
        ("المرحلة 3", "Q3-Q4", "مبادرة مشاركة البيانات", "CDO", "اتفاقيات مشاركة معتمدة", "data_sharing"),
        ("Phase 3", "Q3-Q4", "Data-sharing initiative", "CDO", "Approved sharing agreements", "data_sharing"),
    ),
)


AI_FAMILIES: Tuple[FamilySpec, ...] = (
    FamilySpec(
        "SDAIA",
        _f("sdaia", "sdaia_ai_ethics", "national_ai_authority"),
        ("امتثال إطار SDAIA الوطني للذكاء الاصطناعي", "تغطية ضوابط SDAIA بنسبة 100%", "الالتزام بالإطار الوطني", "12 شهراً"),
        ("Comply with the national SDAIA AI framework", "100% SDAIA control coverage", "National AI-framework alignment", "12 months"),
        ("فجوة ضوابط SDAIA", "مرتفعة", "ضوابط SDAIA غير مكتملة", "إغلاق فجوات SDAIA"),
        ("SDAIA control gap", "High", "Incomplete SDAIA controls", "Close SDAIA gaps"),
        ("تغطية ضوابط SDAIA", "نسبة", "100%", "الضوابط المغلقة / المطلوبة × 100", "سجل امتثال SDAIA", "ربع سنوي", "AI Governance Lead"),
        ("SDAIA control coverage", "Percent", "100%", "closed controls / required controls × 100", "SDAIA compliance register", "Quarterly", "AI Governance Lead"),
        ("المرحلة 1", "Q1-Q2", "برنامج امتثال SDAIA", "AI Governance Lead", "ملف امتثال SDAIA", "SDAIA"),
        ("Phase 1", "Q1-Q2", "SDAIA compliance program", "AI Governance Lead", "SDAIA compliance file", "SDAIA"),
    ),
    FamilySpec(
        "responsible_ai_governance",
        _f("responsible_ai", "responsible_ai_governance", "sdaia"),
        ("تشغيل حوكمة الذكاء الاصطناعي المسؤول", "سياسة ذكاء اصطناعي مسؤولة معتمدة بنسبة 100%", "رقابة أخلاقية وتشغيلية", "9 أشهر"),
        ("Operate responsible AI governance", "100% approved responsible-AI policy", "Ethical and operating oversight", "9 months"),
        ("فجوة الحوكمة المسؤولة", "مرتفعة", "غياب سياسة ذكاء اصطناعي مسؤول", "اعتماد السياسة"),
        ("Responsible-AI governance gap", "High", "No responsible-AI policy", "Approve the policy"),
        ("اعتماد سياسة الذكاء الاصطناعي المسؤول", "نسبة", "100%", "بنود السياسة المعتمدة / المطلوبة × 100", "سجل السياسات", "ربع سنوي", "AI Governance Lead"),
        ("Responsible-AI policy approval", "Percent", "100%", "approved clauses / required clauses × 100", "Policy register", "Quarterly", "AI Governance Lead"),
        ("المرحلة 1", "Q1-Q2", "مبادرة الحوكمة المسؤولة", "AI Governance Lead", "سياسة معتمدة", "responsible_ai_governance"),
        ("Phase 1", "Q1-Q2", "Responsible-AI governance initiative", "AI Governance Lead", "Approved policy", "responsible_ai_governance"),
    ),
    FamilySpec(
        "ai_model_registry",
        _f("ai_model_registry", "model_inventory", "sdaia"),
        ("تشغيل سجل نماذج الذكاء الاصطناعي", "تسجيل 100% من النماذج الإنتاجية", "جرد نماذج قابل للتدقيق", "6 أشهر"),
        ("Operate an AI model registry", "100% production models registered", "Auditable model inventory", "6 months"),
        ("فجوة سجل النماذج", "مرتفعة", "نماذج إنتاجية غير مسجلة", "إكمال السجل"),
        ("Model-registry gap", "High", "Unregistered production models", "Complete the registry"),
        ("اكتمال سجل النماذج", "نسبة", "100%", "النماذج المسجلة / نماذج الإنتاج × 100", "سجل النماذج", "شهري", "MLOps Lead"),
        ("Model-registry completeness", "Percent", "100%", "registered models / production models × 100", "Model registry", "Monthly", "MLOps Lead"),
        ("المرحلة 1", "Q1-Q2", "مبادرة سجل النماذج", "MLOps Lead", "سجل نماذج تشغيلي", "ai_model_registry"),
        ("Phase 1", "Q1-Q2", "Model-registry initiative", "MLOps Lead", "Operating model registry", "ai_model_registry"),
    ),
    FamilySpec(
        "model_risk",
        _f("model_risk", "sdaia"),
        ("إدارة مخاطر نماذج الذكاء الاصطناعي", "تقييم مخاطر 100% من النماذج الحرجة", "ضبط مخاطر النموذج", "9 أشهر"),
        ("Manage AI model risk", "100% critical models risk-assessed", "Controlled model risk", "9 months"),
        ("فجوة تقييم مخاطر النماذج", "مرتفعة", "نماذج حرجة بلا تقييم", "إكمال تقييم المخاطر"),
        ("Model-risk gap", "High", "Critical models without assessment", "Complete risk assessments"),
        ("اكتمال تقييم مخاطر النماذج", "نسبة", "100%", "النماذج المقيّمة / النماذج الحرجة × 100", "سجل مخاطر النماذج", "ربع سنوي", "Model Risk Officer"),
        ("Model-risk assessment completeness", "Percent", "100%", "assessed models / critical models × 100", "Model-risk register", "Quarterly", "Model Risk Officer"),
        ("المرحلة 2", "Q2-Q3", "مبادرة مخاطر النماذج", "Model Risk Officer", "سجل مخاطر معتمد", "model_risk"),
        ("Phase 2", "Q2-Q3", "Model-risk initiative", "Model Risk Officer", "Approved risk register", "model_risk"),
    ),
    FamilySpec(
        "human_oversight",
        _f("human_oversight", "sdaia"),
        ("ضمان الإشراف البشري على النماذج", "نقاط إشراف بشري على 100% من الحالات عالية الأثر", "بقاء القرار البشري في المسار الحرج", "6 أشهر"),
        ("Assure human oversight of models", "Human checkpoints on 100% of high-impact cases", "Human decision remains on the critical path", "6 months"),
        ("فجوة الإشراف البشري", "مرتفعة", "حالات عالية الأثر بلا إشراف", "فرض نقاط الإشراف"),
        ("Human-oversight gap", "High", "High-impact cases without oversight", "Enforce oversight points"),
        ("تغطية نقاط الإشراف البشري", "نسبة", "100%", "الحالات المشرفة / الحالات عالية الأثر × 100", "سجل الإشراف", "شهري", "AI Governance Lead"),
        ("Human-oversight coverage", "Percent", "100%", "overseen cases / high-impact cases × 100", "Oversight register", "Monthly", "AI Governance Lead"),
        ("المرحلة 1", "Q1-Q2", "مبادرة الإشراف البشري", "AI Governance Lead", "إجراء إشراف معتمد", "human_oversight"),
        ("Phase 1", "Q1-Q2", "Human-oversight initiative", "AI Governance Lead", "Approved oversight procedure", "human_oversight"),
    ),
    FamilySpec(
        "data_readiness",
        _f("data_readiness", "sdaia"),
        ("جاهزية بيانات تدريب وتشغيل النماذج", "اعتماد جاهزية البيانات بنسبة 100% قبل الإطلاق", "بيانات صالحة للنماذج", "9 أشهر"),
        ("Ready training and operating data for models", "100% data-readiness approval before launch", "Model-fit data", "9 months"),
        ("فجوة جاهزية البيانات", "متوسطة", "إطلاق بلا بوابة جاهزية", "فرض بوابة الجاهزية"),
        ("Data-readiness gap", "Medium", "Launch without a readiness gate", "Enforce the readiness gate"),
        ("اعتماد جاهزية البيانات قبل الإطلاق", "نسبة", "100%", "النماذج المعتمدة / إطلاقات الإنتاج × 100", "بوابة الجاهزية", "ربع سنوي", "Data Steward"),
        ("Pre-launch data-readiness approval", "Percent", "100%", "approved models / production launches × 100", "Readiness gate", "Quarterly", "Data Steward"),
        ("المرحلة 2", "Q2-Q3", "مبادرة جاهزية البيانات", "Data Steward", "بوابة جاهزية تشغيلية", "data_readiness"),
        ("Phase 2", "Q2-Q3", "Data-readiness initiative", "Data Steward", "Operating readiness gate", "data_readiness"),
    ),
    FamilySpec(
        "bias_fairness",
        _f("bias", "fairness", "bias_fairness", "sdaia"),
        ("ضبط التحيز والإنصاف في النماذج", "اختبار إنصاف 100% من النماذج عالية الأثر", "مخرجات عادلة وقابلة للمراجعة", "9 أشهر"),
        ("Control model bias and fairness", "Fairness tests on 100% of high-impact models", "Reviewable fair outcomes", "9 months"),
        ("فجوة اختبار الإنصاف", "مرتفعة", "نماذج بلا اختبار تحيز", "تشغيل اختبارات الإنصاف"),
        ("Bias-and-fairness gap", "High", "Models without bias tests", "Run fairness tests"),
        ("تغطية اختبارات الإنصاف", "نسبة", "100%", "النماذج المختبرة / النماذج عالية الأثر × 100", "سجل الإنصاف", "ربع سنوي", "Responsible AI Lead"),
        ("Fairness-test coverage", "Percent", "100%", "tested models / high-impact models × 100", "Fairness register", "Quarterly", "Responsible AI Lead"),
        ("المرحلة 2", "Q2-Q3", "مبادرة الإنصاف", "Responsible AI Lead", "تقرير إنصاف دوري", "bias_fairness"),
        ("Phase 2", "Q2-Q3", "Fairness initiative", "Responsible AI Lead", "Periodic fairness report", "bias_fairness"),
    ),
    FamilySpec(
        "explainability",
        _f("explainability", "sdaia"),
        ("تفسير قرارات النماذج عالية الأثر", "توفير تفسير لكل قرار عالي الأثر بنسبة 100%", "شفافية القرار الآلي", "9 أشهر"),
        ("Explain high-impact model decisions", "An explanation for 100% of high-impact decisions", "Automated-decision transparency", "9 months"),
        ("فجوة قابلية التفسير", "متوسطة", "قرارات بلا تفسير", "فرض طبقة التفسير"),
        ("Explainability gap", "Medium", "Decisions without explanations", "Enforce the explanation layer"),
        ("تغطية تفسير القرارات", "نسبة", "100%", "القرارات المفسرة / القرارات عالية الأثر × 100", "طبقة التفسير", "شهري", "AI Governance Lead"),
        ("Decision-explanation coverage", "Percent", "100%", "explained decisions / high-impact decisions × 100", "Explanation layer", "Monthly", "AI Governance Lead"),
        ("المرحلة 2", "Q2-Q3", "مبادرة قابلية التفسير", "AI Governance Lead", "طبقة تفسير تشغيلية", "explainability"),
        ("Phase 2", "Q2-Q3", "Explainability initiative", "AI Governance Lead", "Operating explanation layer", "explainability"),
    ),
    FamilySpec(
        "monitoring",
        _f("monitoring", "sdaia"),
        ("رصد أداء وانحراف النماذج", "رصد 100% من نماذج الإنتاج", "اكتشاف الانحراف مبكراً", "6 أشهر"),
        ("Monitor model performance and drift", "100% of production models monitored", "Early drift detection", "6 months"),
        ("فجوة رصد النماذج", "مرتفعة", "نماذج بلا رصد", "تشغيل الرصد"),
        ("Model-monitoring gap", "High", "Unmonitored models", "Operate monitoring"),
        ("تغطية رصد نماذج الإنتاج", "نسبة", "100%", "النماذج المرصودة / نماذج الإنتاج × 100", "منصة الرصد", "شهري", "MLOps Lead"),
        ("Production-model monitoring coverage", "Percent", "100%", "monitored models / production models × 100", "Monitoring platform", "Monthly", "MLOps Lead"),
        ("المرحلة 3", "Q3-Q4", "مبادرة رصد النماذج", "MLOps Lead", "لوحة رصد تشغيلية", "monitoring"),
        ("Phase 3", "Q3-Q4", "Model-monitoring initiative", "MLOps Lead", "Operating monitoring dashboard", "monitoring"),
    ),
    FamilySpec(
        "mlops",
        _f("mlops", "sdaia"),
        ("تشغيل سلسلة MLOps محكمة", "نشر 100% من النماذج عبر خط معتمد", "إطلاق منضبط للنماذج", "9 أشهر"),
        ("Operate a controlled MLOps pipeline", "100% models released through an approved pipeline", "Controlled model release", "9 months"),
        ("فجوة خط MLOps", "متوسطة", "نشر خارج الخط المعتمد", "فرض خط النشر"),
        ("MLOps-pipeline gap", "Medium", "Release outside the approved pipeline", "Enforce the release pipeline"),
        ("نشر النماذج عبر الخط المعتمد", "نسبة", "100%", "النماذج عبر الخط / إطلاقات الإنتاج × 100", "منصة MLOps", "شهري", "MLOps Lead"),
        ("Approved-pipeline model release", "Percent", "100%", "pipelined models / production releases × 100", "MLOps platform", "Monthly", "MLOps Lead"),
        ("المرحلة 3", "Q3-Q4", "مبادرة MLOps", "MLOps Lead", "خط نشر معتمد", "mlops"),
        ("Phase 3", "Q3-Q4", "MLOps initiative", "MLOps Lead", "Approved release pipeline", "mlops"),
    ),
    FamilySpec(
        "incident_handling",
        _f("incident_handling", "ai_incident", "sdaia"),
        ("معالجة حوادث الذكاء الاصطناعي", "إغلاق 100% من الحوادث ضمن مهلة التصعيد", "استجابة منضبطة للحوادث", "6 أشهر"),
        ("Handle AI incidents", "100% incidents closed within the escalation window", "Controlled incident response", "6 months"),
        ("فجوة معالجة حوادث الذكاء الاصطناعي", "مرتفعة", "مسار حادث غير مجرب", "تجريب مسار الحوادث"),
        ("AI-incident-handling gap", "High", "Unexercised incident path", "Exercise the incident path"),
        ("إغلاق حوادث الذكاء الاصطناعي في المهلة", "نسبة", "100%", "الحوادث المغلقة في المهلة / إجمالي الحوادث × 100", "سجل حوادث الذكاء الاصطناعي", "ربع سنوي", "AI Governance Lead"),
        ("On-time AI-incident closure", "Percent", "100%", "on-time closures / total incidents × 100", "AI incident register", "Quarterly", "AI Governance Lead"),
        ("المرحلة 3", "Q3-Q4", "مبادرة حوادث الذكاء الاصطناعي", "AI Governance Lead", "إجراء حوادث معتمد", "incident_handling"),
        ("Phase 3", "Q3-Q4", "AI-incident initiative", "AI Governance Lead", "Approved incident procedure", "incident_handling"),
    ),
)


DT_FAMILIES: Tuple[FamilySpec, ...] = (
    FamilySpec(
        "DGA",
        _f("dga", "digital_government_authority"),
        ("امتثال إطار DGA للحكومة الرقمية", "تغطية ضوابط DGA بنسبة 100%", "الالتزام بإطار الحكومة الرقمية", "12 شهراً"),
        ("Comply with the DGA digital-government framework", "100% DGA control coverage", "Digital-government alignment", "12 months"),
        ("فجوة ضوابط DGA", "مرتفعة", "ضوابط DGA غير مكتملة", "إغلاق فجوات DGA"),
        ("DGA control gap", "High", "Incomplete DGA controls", "Close DGA gaps"),
        ("تغطية ضوابط DGA", "نسبة", "100%", "الضوابط المغلقة / المطلوبة × 100", "سجل امتثال DGA", "ربع سنوي", "Digital Transformation Lead"),
        ("DGA control coverage", "Percent", "100%", "closed controls / required controls × 100", "DGA compliance register", "Quarterly", "Digital Transformation Lead"),
        ("المرحلة 1", "Q1-Q2", "برنامج امتثال DGA", "Digital Transformation Lead", "ملف امتثال DGA", "DGA"),
        ("Phase 1", "Q1-Q2", "DGA compliance program", "Digital Transformation Lead", "DGA compliance file", "DGA"),
    ),
    FamilySpec(
        "digital_services",
        _f("digital_services", "dga"),
        ("تشغيل الخدمات الرقمية الحكومية", "إتاحة 100% من الخدمات ذات الأولوية رقمياً", "خدمة رقمية مكتملة للمستفيد", "12 شهراً"),
        ("Operate government digital services", "100% priority services available digitally", "Complete digital service for the beneficiary", "12 months"),
        ("فجوة الخدمات الرقمية", "مرتفعة", "خدمات أولوية غير مكتملة رقمياً", "إكمال إتاحة الخدمات الرقمية"),
        ("Digital-services gap", "High", "Priority services not fully digital", "Complete digital-service availability"),
        ("إتاحة الخدمات الرقمية ذات الأولوية", "نسبة", "100%", "الخدمات المتاحة رقمياً / خدمات الأولوية × 100", "كتالوج الخدمات", "ربع سنوي", "Service Owner"),
        ("Priority digital-service availability", "Percent", "100%", "digitally available services / priority services × 100", "Service catalog", "Quarterly", "Service Owner"),
        ("المرحلة 1", "Q1-Q2", "مبادرة الخدمات الرقمية", "Service Owner", "كتالوج خدمات رقمية", "digital_services"),
        ("Phase 1", "Q1-Q2", "Digital-services initiative", "Service Owner", "Digital service catalog", "digital_services"),
    ),
    FamilySpec(
        "interoperability",
        _f("interoperability", "dga"),
        ("تحقيق قابلية التشغيل البيني", "ربط 100% من التكاملات المعتمدة", "تبادل منضبط بين الأنظمة", "9 أشهر"),
        ("Achieve interoperability", "100% approved integrations connected", "Controlled system exchange", "9 months"),
        ("فجوة قابلية التشغيل البيني", "مرتفعة", "تكاملات معتمدة غير مربوطة", "إكمال الربط"),
        ("Interoperability gap", "High", "Approved integrations not connected", "Complete the connections"),
        ("اكتمال التكاملات المعتمدة", "نسبة", "100%", "التكاملات المربوطة / المعتمدة × 100", "سجل التكامل", "ربع سنوي", "Integration Lead"),
        ("Approved-integration completeness", "Percent", "100%", "connected integrations / approved integrations × 100", "Integration register", "Quarterly", "Integration Lead"),
        ("المرحلة 2", "Q2-Q3", "مبادرة قابلية التشغيل البيني", "Integration Lead", "خريطة تكامل معتمدة", "interoperability"),
        ("Phase 2", "Q2-Q3", "Interoperability initiative", "Integration Lead", "Approved integration map", "interoperability"),
    ),
    FamilySpec(
        "citizen_experience",
        _f("citizen_experience", "dga"),
        ("تحسين تجربة المستفيد الرقمية", "رضا المستفيد لا يقل عن 85%", "رحلة مستفيد واضحة ومتصلة", "9 أشهر"),
        ("Improve digital beneficiary experience", "Beneficiary satisfaction of at least 85%", "A clear connected beneficiary journey", "9 months"),
        ("فجوة تجربة المستفيد", "متوسطة", "رحلة المستفيد غير مكتملة", "إكمال رحلة المستفيد"),
        ("Beneficiary-experience gap", "Medium", "Incomplete beneficiary journey", "Complete the beneficiary journey"),
        ("رضا المستفيد عن الخدمات الرقمية", "نسبة", "85%", "التقييمات الإيجابية / إجمالي التقييمات × 100", "استبيان المستفيد", "ربع سنوي", "CX Lead"),
        ("Beneficiary satisfaction with digital services", "Percent", "85%", "positive ratings / total ratings × 100", "Beneficiary survey", "Quarterly", "CX Lead"),
        ("المرحلة 2", "Q2-Q3", "مبادرة تجربة المستفيد", "CX Lead", "خريطة رحلة المستفيد", "citizen_experience"),
        ("Phase 2", "Q2-Q3", "Beneficiary-experience initiative", "CX Lead", "Beneficiary journey map", "citizen_experience"),
    ),
    FamilySpec(
        "apis_integration",
        _f("api", "apis", "integration", "apis_integration", "dga"),
        ("تشغيل واجهات برمجة التطبيقات والتكامل", "نشر 100% من واجهات API المعتمدة", "تكامل قابل لإعادة الاستخدام", "9 أشهر"),
        ("Operate APIs and integration", "100% approved APIs published", "Reusable integration", "9 months"),
        ("فجوة واجهات API", "متوسطة", "واجهات معتمدة غير منشورة", "نشر واجهات API"),
        ("API-integration gap", "Medium", "Approved APIs unpublished", "Publish the APIs"),
        ("نشر واجهات API المعتمدة", "نسبة", "100%", "الواجهات المنشورة / المعتمدة × 100", "بوابة API", "ربع سنوي", "Integration Lead"),
        ("Approved API publication", "Percent", "100%", "published APIs / approved APIs × 100", "API gateway", "Quarterly", "Integration Lead"),
        ("المرحلة 2", "Q2-Q3", "مبادرة واجهات API", "Integration Lead", "بوابة API تشغيلية", "apis_integration"),
        ("Phase 2", "Q2-Q3", "API-integration initiative", "Integration Lead", "Operating API gateway", "apis_integration"),
    ),
    FamilySpec(
        "beneficiary_user_journey",
        _f("beneficiary", "user_journey", "beneficiary_user_journey", "dga"),
        ("تصميم رحلة المستفيد من البداية للنهاية", "تغطية 100% من رحلات الخدمات ذات الأولوية", "مسار مستفيد بلا انقطاع", "9 أشهر"),
        ("Design the end-to-end beneficiary journey", "100% priority-service journeys covered", "An unbroken beneficiary path", "9 months"),
        ("فجوة رحلة المستفيد", "متوسطة", "خدمات بلا خريطة رحلة", "استكمال خرائط الرحلة"),
        ("Beneficiary-journey gap", "Medium", "Services without a journey map", "Complete journey maps"),
        ("تغطية رحلات الخدمات ذات الأولوية", "نسبة", "100%", "الرحلات الموثقة / خدمات الأولوية × 100", "سجل الرحلات", "ربع سنوي", "CX Lead"),
        ("Priority-service journey coverage", "Percent", "100%", "documented journeys / priority services × 100", "Journey register", "Quarterly", "CX Lead"),
        ("المرحلة 3", "Q3-Q4", "مبادرة رحلة المستفيد", "CX Lead", "خرائط رحلة مكتملة", "beneficiary_user_journey"),
        ("Phase 3", "Q3-Q4", "Beneficiary-journey initiative", "CX Lead", "Complete journey maps", "beneficiary_user_journey"),
    ),
    FamilySpec(
        "service_quality",
        _f("service_quality", "dga"),
        ("ضبط جودة الخدمة الرقمية", "الالتزام بمستوى الخدمة المستهدف بنسبة 95%", "خدمة رقمية موثوقة للمستفيد", "12 شهراً"),
        ("Control digital service quality", "95% adherence to the target service level", "Reliable digital service for the beneficiary", "12 months"),
        ("فجوة جودة الخدمة", "متوسطة", "مؤشرات مستوى خدمة غير مفعلة", "تفعيل مؤشرات مستوى الخدمة"),
        ("Service-quality gap", "Medium", "Inactive service-level indicators", "Activate service-level indicators"),
        ("الالتزام بمستوى الخدمة المستهدف", "نسبة", "95%", "الفترات المستوفاة / إجمالي فترات القياس × 100", "لوحة جودة الخدمة", "شهري", "Service Owner"),
        ("Target service-level adherence", "Percent", "95%", "met intervals / measured intervals × 100", "Service-quality dashboard", "Monthly", "Service Owner"),
        ("المرحلة 3", "Q3-Q4", "مبادرة جودة الخدمة", "Service Owner", "لوحة مستوى خدمة", "service_quality"),
        ("Phase 3", "Q3-Q4", "Service-quality initiative", "Service Owner", "Service-level dashboard", "service_quality"),
    ),
)


DOMAIN_FAMILIES: Dict[str, Tuple[FamilySpec, ...]] = {
    "data": DATA_FAMILIES,
    "ai": AI_FAMILIES,
    "dt": DT_FAMILIES,
}


def normalize_framework_token(value: object) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def selected_frameworks_from_request(payload: dict) -> List[str]:
    raw = payload.get("selected_frameworks")
    if raw is None:
        raw = payload.get("frameworks")
    values: List[str] = []
    if isinstance(raw, str):
        values = [part for part in raw.replace("|", ",").split(",") if part.strip()]
    elif isinstance(raw, (list, tuple, set, frozenset)):
        values = [str(item) for item in raw]
    elif isinstance(raw, dict):
        values = [str(key) for key, flag in raw.items() if flag]
    from release_engine_v3.rel37_framework_aliases import (
        canonicalize_request_frameworks,
    )
    mapped = canonicalize_request_frameworks(values)
    if mapped:
        return mapped
    normalized = []
    seen = set()
    for item in values:
        token = normalize_framework_token(item)
        if token and token not in seen:
            seen.add(token)
            normalized.append(token)
    return normalized


def resolve_selected_frameworks(domain: str, payload: dict) -> List[str]:
    selected = selected_frameworks_from_request(payload)
    if selected:
        return selected
    return list(DOMAIN_DEFAULT_FRAMEWORKS.get(domain, ()))


def families_for_request(domain: str, payload: dict) -> List[FamilySpec]:
    selected = set(resolve_selected_frameworks(domain, payload))
    families = DOMAIN_FAMILIES.get(domain, ())
    matched = [family for family in families if family.frameworks & selected]
    if matched:
        return matched
    defaults = set(DOMAIN_DEFAULT_FRAMEWORKS.get(domain, ()))
    return [family for family in families if family.frameworks & defaults] or list(families)


def leakage_terms_for_request(domain: str, payload: dict) -> Tuple[str, ...]:
    selected = set(resolve_selected_frameworks(domain, payload))
    return tuple(
        term
        for term in leakage_terms(domain)
        if normalize_framework_token(term) not in selected
        and term.lower() not in selected
    )
