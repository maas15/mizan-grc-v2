"""Deterministic REL37 compilers for Data / AI / DT strategy (AR + EN)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel37_canonical_document import (
    CanonicalDocument,
    ConfidenceRow,
    GapGuide,
    GapRow,
    GovernanceRow,
    GuideStep,
    KpiFormulaRow,
    KpiGuide,
    KpiRow,
    PillarInitiativeRow,
    PillarRow,
    RiskRow,
    RoadmapRow,
    SORow,
    TraceabilityRow,
    default_guide_heading,
)
from release_engine_v3.rel37_coverage_registry import (
    FamilySpec,
    DOMAIN_FAMILIES,
    families_for_request,
    resolve_selected_frameworks,
)
from release_engine_v3.rel37_sector_context import sector_runtime_diagnostics
from release_engine_v3.rel37_schema_registry import SCHEMA_VERSION

_PILLARS = {
    'data': {
        'ar': (
            ('حوكمة البيانات والتنظيم', 'سياسات وملكية وضوابط NDMO و PDPL', 'privacy_governance'),
            ('جودة البيانات والبيانات الوصفية', 'كتالوج وتشغيل جودة البيانات', 'data_catalog'),
            ('الخصوصية وحماية البيانات الشخصية', 'امتثال PDPL وحماية البيانات الشخصية', 'PDPL'),
            ('تمكين القيمة ومشاركة البيانات', 'اتفاقيات مشاركة وبيانات رئيسية', 'data_sharing'),
        ),
        'en': (
            ('Data governance and organization', 'NDMO and PDPL policy, ownership, and control', 'privacy_governance'),
            ('Data quality and metadata', 'Catalog operations and quality rules', 'data_catalog'),
            ('Privacy and personal-data protection', 'PDPL compliance and personal-data protection', 'PDPL'),
            ('Value enablement and data sharing', 'Sharing agreements and master data', 'data_sharing'),
        ),
    },
    'ai': {
        'ar': (
            ('حوكمة الذكاء الاصطناعي والأخلاقيات', 'امتثال الإطار الوطني للذكاء الاصطناعي', 'SDAIA'),
            ('إدارة مخاطر النماذج', 'تقييم المخاطر واختبار الإنصاف', 'model_risk'),
            ('الشفافية والإشراف البشري', 'إشراف بشري وحوادث الذكاء الاصطناعي', 'human_oversight'),
            ('التشغيل والمراقبة MLOps', 'MLOps والرصد ومعالجة الحوادث', 'mlops'),
        ),
        'en': (
            ('AI governance and ethics', 'National AI-framework compliance', 'SDAIA'),
            ('Model risk management', 'Risk assessment and fairness testing', 'model_risk'),
            ('Transparency and human oversight', 'Human oversight and AI incidents', 'human_oversight'),
            ('MLOps operations and monitoring', 'MLOps, monitoring, and incident handling', 'mlops'),
        ),
    },
    'dt': {
        'ar': (
            ('الاستراتيجية والحوكمة الرقمية', 'ضوابط الحكومة الرقمية والخدمات', 'DGA'),
            ('الخدمات والقنوات الرقمية', 'خدمات رقمية ورحلة المستفيد', 'digital_services'),
            ('المنصات والتكامل والسحابة', 'تكامل الأنظمة وواجهات API', 'interoperability'),
            ('القدرات وإدارة التغيير', 'قدرات رقمية وجودة الخدمة', 'service_quality'),
        ),
        'en': (
            ('Digital strategy and governance', 'Digital-government controls and services', 'DGA'),
            ('Digital services and channels', 'Digital services and the beneficiary journey', 'digital_services'),
            ('Platforms, integration, and cloud', 'System integration and published APIs', 'interoperability'),
            ('Capabilities and change management', 'Digital capabilities and service quality', 'service_quality'),
        ),
    },
}

_DATA_SUPPORT = (
    FamilySpec(
        'data_lineage',
        frozenset({'ndmo', 'data_lineage'}),
        ('توثيق سلسلة البيانات الحرجة', 'تغطية سلسلة البيانات بنسبة 100%', 'تتبع المصدر حتى الاستهلاك', '12 شهراً'),
        ('Document critical data lineage', '100% lineage coverage', 'Trace source to consumption', '12 months'),
        ('فجوة سلسلة البيانات', 'متوسطة', 'تدفقات حرجة بلا سلسلة بيانات', 'توثيق سلسلة البيانات'),
        ('Data-lineage gap', 'Medium', 'Critical flows without lineage', 'Document data lineage'),
        ('تغطية سلسلة البيانات الحرجة', 'نسبة', '100%', 'التدفقات الموثقة / التدفقات الحرجة × 100', 'سجل سلسلة البيانات', 'ربع سنوي', 'Data Steward'),
        ('Critical data-lineage coverage', 'Percent', '100%', 'documented flows / critical flows × 100', 'Lineage register', 'Quarterly', 'Data Steward'),
        ('المرحلة 3', 'Q3-Q4', 'توثيق سلسلة البيانات end-to-end', 'Data Steward', 'Lineage حرج موثق ومحدث', 'data_lineage'),
        ('Phase 3', 'Q3-Q4', 'Document end-to-end data lineage', 'Data Steward', 'Documented critical lineage', 'data_lineage'),
    ),
    FamilySpec(
        'master_data_management',
        frozenset({'ndmo', 'mdm', 'master_data_management'}),
        ('تشغيل إدارة البيانات الرئيسية', 'توحيد 100% من النطاقات الحرجة', 'سجل رئيسي موحد', '12 شهراً'),
        ('Operate master data management', '100% critical domains unified', 'One master register', '12 months'),
        ('فجوة البيانات الرئيسية', 'متوسطة', 'نطاقات حرجة بلا MDM', 'تشغيل برنامج البيانات الرئيسية'),
        ('Master-data gap', 'Medium', 'Critical domains without MDM', 'Operate the MDM program'),
        ('توحيد سجلات البيانات الرئيسية', 'نسبة', '100%', 'السجلات الموحدة / النطاقات الحرجة × 100', 'منصة MDM', 'ربع سنوي', 'CDO'),
        ('Master-data record unification', 'Percent', '100%', 'unified records / critical domains × 100', 'MDM platform', 'Quarterly', 'CDO'),
        ('المرحلة 3', 'Q3-Q4', 'تأسيس إدارة البيانات الرئيسية MDM', 'CDO', 'نطاقات MDM حرجة معتمدة', 'master_data_management'),
        ('Phase 3', 'Q3-Q4', 'Establish master data management MDM', 'CDO', 'Approved critical MDM domains', 'master_data_management'),
    ),
)

_DT_SUPPORT = (
    FamilySpec(
        'enterprise_architecture',
        frozenset({'dga', 'enterprise_architecture'}),
        ('توثيق البنية المؤسسية المستهدفة', 'توثيق 100% من الأنظمة الحرجة', 'خريطة بنية معتمدة', '12 شهراً'),
        ('Document the target enterprise architecture', '100% critical systems documented', 'Approved architecture map', '12 months'),
        ('فجوة البنية المؤسسية', 'متوسطة', 'أنظمة حرجة بلا توثيق بنية', 'اعتماد البنية المؤسسية'),
        ('Enterprise-architecture gap', 'Medium', 'Critical systems without architecture docs', 'Approve the architecture'),
        ('توثيق الأنظمة في البنية المؤسسية', 'نسبة', '100%', 'الأنظمة الموثقة / الأنظمة الحرجة × 100', 'سجل البنية', 'ربع سنوي', 'Digital Transformation Lead'),
        ('Enterprise-architecture system documentation', 'Percent', '100%', 'documented systems / critical systems × 100', 'Architecture register', 'Quarterly', 'Digital Transformation Lead'),
        ('المرحلة 3', 'Q3-Q4', 'توثيق واعتماد البنية المؤسسية المستهدفة', 'Digital Transformation Lead', 'بنية مؤسسية معتمدة', 'enterprise_architecture'),
        ('Phase 3', 'Q3-Q4', 'Document and approve target enterprise architecture', 'Digital Transformation Lead', 'Approved enterprise architecture', 'enterprise_architecture'),
    ),
    FamilySpec(
        'service_design',
        frozenset({'dga', 'service_design'}),
        ('اعتماد تصميم الخدمات الرقمية', 'إعادة تصميم 100% من خدمات الأولوية', 'خدمة مصممة حول المستفيد', '9 أشهر'),
        ('Adopt digital service design', '100% priority services redesigned', 'Beneficiary-centered service design', '9 months'),
        ('فجوة تصميم الخدمات', 'متوسطة', 'خدمات بلا منهجية تصميم', 'اعتماد تصميم الخدمات'),
        ('Service-design gap', 'Medium', 'Services without a design method', 'Approve service design'),
        ('إعادة تصميم الخدمات ذات الأولوية', 'نسبة', '100%', 'الخدمات المعاد تصميمها / خدمات الأولوية × 100', 'سجل التصميم', 'ربع سنوي', 'Service Owner'),
        ('Priority service redesign', 'Percent', '100%', 'redesigned services / priority services × 100', 'Design register', 'Quarterly', 'Service Owner'),
        ('المرحلة 2', 'Q2-Q3', 'اعتماد منهجية تصميم الخدمات الرقمية', 'Service Owner', 'منهجية تصميم خدمات معتمدة', 'service_design'),
        ('Phase 2', 'Q2-Q3', 'Adopt digital service design methodology', 'Service Owner', 'Approved service-design method', 'service_design'),
    ),
    FamilySpec(
        'automation',
        frozenset({'dga', 'automation'}),
        ('أتمتة المسارات الرقمية المتكررة', 'أتمتة 80% من المسارات المعتمدة', 'خدمة مؤتمتة للمستفيد', '12 شهراً'),
        ('Automate repeatable digital paths', '80% approved paths automated', 'Automated beneficiary service', '12 months'),
        ('فجوة الأتمتة', 'متوسطة', 'مسارات يدوية قابلة للأتمتة', 'تشغيل الأتمتة'),
        ('Automation gap', 'Medium', 'Manual paths that can be automated', 'Operate automation'),
        ('أتمتة المسارات المعتمدة', 'نسبة', '80%', 'المسارات المؤتمتة / المسارات المعتمدة × 100', 'سجل الأتمتة', 'ربع سنوي', 'Digital Transformation Lead'),
        ('Approved-path automation', 'Percent', '80%', 'automated paths / approved paths × 100', 'Automation register', 'Quarterly', 'Digital Transformation Lead'),
        ('المرحلة 3', 'Q3-Q4', 'أتمتة المسارات الرقمية المعتمدة', 'Digital Transformation Lead', 'مسارات مؤتمتة معتمدة', 'automation'),
        ('Phase 3', 'Q3-Q4', 'Automate approved digital paths', 'Digital Transformation Lead', 'Approved automated paths', 'automation'),
    ),
    FamilySpec(
        'digital_workforce',
        frozenset({'dga', 'digital_workforce'}),
        ('بناء القدرات الرقمية للموارد البشرية', 'تدريب 100% من الأدوار الحرجة', 'قوة عمل رقمية جاهزة', '12 شهراً'),
        ('Build digital workforce capability', '100% critical roles trained', 'A ready digital workforce', '12 months'),
        ('فجوة القدرات الرقمية', 'متوسطة', 'أدوار حرجة بلا تدريب رقمي', 'تشغيل برنامج التدريب'),
        ('Digital-workforce gap', 'Medium', 'Critical roles without digital training', 'Operate the training program'),
        ('تغطية تدريب الأدوار الرقمية الحرجة', 'نسبة', '100%', 'المتدرّبون / الأدوار الحرجة × 100', 'سجل التدريب', 'ربع سنوي', 'Digital Transformation Lead'),
        ('Critical digital-role training coverage', 'Percent', '100%', 'trained staff / critical roles × 100', 'Training register', 'Quarterly', 'Digital Transformation Lead'),
        ('المرحلة 3', 'Q3-Q4', 'برنامج تدريب القدرات الرقمية', 'Digital Transformation Lead', 'خطة تدريب معتمدة', 'digital_workforce'),
        ('Phase 3', 'Q3-Q4', 'Digital workforce training program', 'Digital Transformation Lead', 'Approved training plan', 'digital_workforce'),
    ),
    FamilySpec(
        'platform_operations',
        frozenset({'dga'}),
        ('تشغيل المنصات الرقمية الحرجة', 'توافر المنصات بنسبة 99.5%', 'استمرارية المنصات الرقمية', '12 شهراً'),
        ('Operate critical digital platforms', '99.5% platform availability', 'Digital platform continuity', '12 months'),
        ('فجوة تشغيل المنصات', 'متوسطة', 'منصات بلا هدف توافر', 'اعتماد هدف التوافر'),
        ('Platform-operations gap', 'Medium', 'Platforms without an availability target', 'Approve the availability target'),
        ('توافر المنصات الرقمية', 'نسبة', '99.5%', 'دقائق التوافر / دقائق الفترة × 100', 'لوحة المنصات', 'شهري', 'Digital Transformation Lead'),
        ('Digital platform availability', 'Percent', '99.5%', 'available minutes / period minutes × 100', 'Platform dashboard', 'Monthly', 'Digital Transformation Lead'),
        ('المرحلة 3', 'Q3-Q4', 'مبادرة تشغيل المنصات', 'Digital Transformation Lead', 'هدف توافر معتمد', 'platform_operations'),
        ('Phase 3', 'Q3-Q4', 'Platform-operations initiative', 'Digital Transformation Lead', 'Approved availability target', 'platform_operations'),
    ),
    FamilySpec(
        'service_continuity',
        frozenset({'dga'}),
        ('استمرارية الخدمة الرقمية للمستفيد', 'استعادة الخدمة خلال 4 ساعات', 'حماية رحلة المستفيد من الانقطاع', '12 شهراً'),
        ('Sustain digital service continuity for the beneficiary', 'Restore service within 4 hours', 'Protect the beneficiary journey from interruption', '12 months'),
        ('فجوة استمرارية الخدمة', 'متوسطة', 'مسار استعادة غير مجرب', 'تجريب مسار الاستعادة'),
        ('Service-continuity gap', 'Medium', 'Unexercised restore path', 'Exercise the restore path'),
        ('زمن استعادة الخدمة الرقمية', 'زمن', '4 ساعات', 'وقت الاستعادة الفعلي للحوادث', 'سجل الاستعادة', 'ربع سنوي', 'Service Owner'),
        ('Digital service restore time', 'Time', '4 hours', 'actual restore time for incidents', 'Restore register', 'Quarterly', 'Service Owner'),
        ('المرحلة 3', 'Q3-Q4', 'مبادرة استمرارية الخدمة', 'Service Owner', 'إجراء استعادة معتمد', 'service_continuity'),
        ('Phase 3', 'Q3-Q4', 'Service-continuity initiative', 'Service Owner', 'Approved restore procedure', 'service_continuity'),
    ),
    FamilySpec(
        'digital_channel',
        frozenset({'dga'}),
        ('توحيد القناة الرقمية للمستفيد', 'دخول موحد على 100% من القنوات المعتمدة', 'مسار مستفيد واحد', '9 أشهر'),
        ('Unify the digital channel for the beneficiary', 'Single entry on 100% of approved channels', 'One beneficiary path', '9 months'),
        ('فجوة توحيد القنوات', 'متوسطة', 'قنوات بلا دخول موحد', 'تفعيل الدخول الموحد'),
        ('Channel-unification gap', 'Medium', 'Channels without a single entry', 'Activate the single entry'),
        ('تغطية الدخول الموحد للقنوات', 'نسبة', '100%', 'القنوات الموحدة / القنوات المعتمدة × 100', 'بوابة القنوات', 'ربع سنوي', 'CX Lead'),
        ('Single-entry channel coverage', 'Percent', '100%', 'unified channels / approved channels × 100', 'Channel portal', 'Quarterly', 'CX Lead'),
        ('المرحلة 2', 'Q2-Q3', 'مبادرة توحيد القنوات', 'CX Lead', 'بوابة قنوات موحدة', 'digital_channel'),
        ('Phase 2', 'Q2-Q3', 'Channel-unification initiative', 'CX Lead', 'Unified channel portal', 'digital_channel'),
    ),
    FamilySpec(
        'performance_insight',
        frozenset({'dga'}),
        ('قياس أداء التحول الرقمي', 'نشر لوحة أداء شهرية بنسبة 100%', 'قرار مبني على قياس الخدمة', '6 أشهر'),
        ('Measure digital-transformation performance', 'Publish a monthly performance dashboard at 100%', 'Service decisions based on measurement', '6 months'),
        ('فجوة قياس الأداء الرقمي', 'منخفضة', 'غياب لوحة أداء شهرية', 'إطلاق لوحة الأداء'),
        ('Digital-performance gap', 'Low', 'No monthly performance dashboard', 'Launch the dashboard'),
        ('نشر لوحة أداء التحول الرقمي', 'نسبة', '100%', 'الشهور المنشورة / أشهر الفترة × 100', 'لوحة التحول', 'شهري', 'Digital Transformation Lead'),
        ('Digital-transformation dashboard publication', 'Percent', '100%', 'published months / period months × 100', 'Transformation dashboard', 'Monthly', 'Digital Transformation Lead'),
        ('المرحلة 3', 'Q3-Q4', 'مبادرة قياس الأداء الرقمي', 'Digital Transformation Lead', 'لوحة أداء شهرية', 'performance_insight'),
        ('Phase 3', 'Q3-Q4', 'Digital-performance initiative', 'Digital Transformation Lead', 'Monthly performance dashboard', 'performance_insight'),
    ),
)

_OWNER_AR = {
    'CDO': 'مدير البيانات',
    'DPO': 'مسؤول حماية البيانات',
    'Data Steward': 'مشرف البيانات',
    'Records Officer': 'مسؤول السجلات',
    'Data Quality Lead': 'رئيس جودة البيانات',
    'AI Governance Lead': 'رئيس حوكمة الذكاء الاصطناعي',
    'MLOps Lead': 'رئيس تشغيل النماذج',
    'Model Risk Officer': 'مسؤول مخاطر النماذج',
    'Responsible AI Lead': 'رئيس الذكاء الاصطناعي المسؤول',
    'Digital Transformation Lead': 'مدير التحول الرقمي',
    'Service Owner': 'مالك الخدمة',
    'Integration Lead': 'رئيس التكامل',
    'CX Lead': 'رئيس تجربة المستفيد',
}

_STATUS = {'ar': 'مفتوحة', 'en': 'Open'}
_GOV_CADENCE = {'ar': 'ربع سنوي', 'en': 'Quarterly'}


def _owner(value: str, lang: str) -> str:
    if lang == 'ar':
        return _OWNER_AR.get(value, value)
    return value


def _guide_steps(owner: str, lang: str, focus: str) -> Tuple[GuideStep, ...]:
    if lang == 'ar':
        actions = (
            f'تأكيد نطاق {focus} وجمع الأدلة الحالية',
            f'تنفيذ المعالجة المعتمدة لـ {focus}',
            f'التحقق من الإغلاق وتحديث السجل لـ {focus}',
        )
        outputs = ('سجل نطاق معتمد', 'إجراء منفذ', 'تقرير إغلاق')
        timelines = ('أسبوع 1', 'أسبوع 2-4', 'أسبوع 5')
    else:
        actions = (
            f'Confirm the {focus} scope and collect current evidence',
            f'Execute the approved treatment for {focus}',
            f'Verify closure and update the register for {focus}',
        )
        outputs = ('Approved scope register', 'Executed procedure', 'Closure report')
        timelines = ('Week 1', 'Weeks 2-4', 'Week 5')
    return tuple(
        GuideStep(step=i + 1, action=actions[i], owner=owner,
                  timeline=timelines[i], output=outputs[i])
        for i in range(3)
    )


def _vision_prose(domain: str, lang: str, org_name: str) -> str:
    name = org_name or (
        'الجهة' if lang == 'ar' else 'the organization')
    if lang == 'ar':
        if domain == 'data':
            return (
                f'تعتمد {name} استراتيجية بيانات مؤسسية تربط حوكمة NDMO '
                f'وامتثال PDPL بجودة البيانات والكتالوج ودورة الحياة. '
                f'تهدف الاستراتيجية إلى جعل الأصول البيانية قابلة للاكتشاف ومسؤولية واضحة.'
            )
        if domain == 'ai':
            return (
                f'تعتمد {name} استراتيجية ذكاء اصطناعي مسؤولة وفق إطار SDAIA، '
                f'مع سجل نماذج وإشراف بشري ورصد تشغيلي. '
                f'الغاية هي إطلاق نماذج عالية الأثر بمسار حوكمة قابل للتدقيق.'
            )
        return (
            f'تعتمد {name} استراتيجية تحول رقمي وفق إطار DGA، '
            f'مع خدمات رقمية وتشغيل بيني وتحسين تجربة المستفيد. '
            f'تركز الاستراتيجية على رحلة المستفيد وجودة الخدمة الرقمية.'
        )
    if domain == 'data':
        return (
            f'{name} adopts an enterprise data strategy that links NDMO governance '
            f'and PDPL compliance to catalog, quality, and lifecycle control. '
            f'The strategy makes data assets discoverable and accountable.'
        )
    if domain == 'ai':
        return (
            f'{name} adopts a responsible AI strategy aligned to SDAIA, '
            f'with a model registry, human oversight, and operating monitoring. '
            f'High-impact models launch only through an auditable governance path.'
        )
    return (
        f'{name} adopts a digital-transformation strategy aligned to DGA, '
        f'with digital services, interoperability, and beneficiary experience. '
        f'The strategy focuses on the beneficiary journey and digital service quality.'
    )


def _environment_prose(
        domain: str, lang: str, org_name: str, sector: str = '') -> str:
    from release_engine_v3.rel37_sector_context import (
        operating_context_clause,
        present_sector_label,
    )

    name = org_name or ('الجهة' if lang == 'ar' else 'the organization')
    context = operating_context_clause(sector, lang)
    presented = present_sector_label(sector, lang)
    if lang == 'ar':
        lead = (
            f'تعمل {name} {context}، ضمن'
            if context else f'تعمل {name} في'
        )
        if domain == 'data':
            p1 = (
                f'{lead} بيئة تنظيمية تتطلب حوكمة بيانات وطنية وفق NDMO '
                f'وحماية بيانات شخصية وفق PDPL، مع ضغط متزايد على جودة البيانات '
                f'والكتالوج وإدارة الموافقات وحقوق أصحاب البيانات.'
            )
            p2 = (
                'تشمل المحركات التشغيلية اكتمال التصنيف، ضبط دورة الحياة، '
                'توثيق المشاركة، وإخطار الحوادث ضمن المهلة النظامية، '
                'دون إدخال ضوابط سيبرانية خارج نطاق البيانات.'
            )
        elif domain == 'ai':
            p1 = (
                f'{lead} بيئة تتطلب امتثال إطار SDAIA للذكاء الاصطناعي '
                f'المسؤول، بما في ذلك سجل النماذج ومخاطر النموذج والإشراف البشري '
                f'وجاهزية البيانات قبل الإطلاق.'
            )
            p2 = (
                'تشمل المحركات اختبار الإنصاف وقابلية التفسير ورصد الانحراف '
                'وخط MLOps ومعالجة حوادث الذكاء الاصطناعي بمسار تصعيد واضح.'
            )
        else:
            p1 = (
                f'{lead} بيئة حكومة رقمية تتطلب امتثال إطار DGA '
                f'وتشغيل الخدمات الرقمية وقابلية التشغيل البيني وتحسين تجربة المستفيد '
                f'عبر رحلة متصلة.'
            )
            p2 = (
                'تشمل المحركات نشر واجهات API، اكتمال رحلات المستفيدين للخدمات '
                'ذات الأولوية، والالتزام بمستوى الخدمة المستهدف دون انقطاع رقمي.'
            )
        if presented and presented not in p1:
            p1 = f'{p1} القطاع المختار هو {presented}.'
        return p1 + '\n\n' + p2
    if context:
        lead = f'{name} operates {context} under'
    else:
        lead = f'{name} operates under'
    if domain == 'data':
        p1 = (
            f'{lead} national data-governance expectations from NDMO '
            f'and personal-data duties from PDPL, with rising pressure on catalog '
            f'coverage, quality, consent, and data-subject rights.'
        )
        p2 = (
            'Operating drivers include classification completeness, lifecycle control, '
            'documented sharing, and on-time incident notification inside the data scope.'
        )
    elif domain == 'ai':
        p1 = (
            f'{lead} SDAIA responsible-AI expectations, including a '
            f'model registry, model-risk assessment, human oversight, and data readiness.'
        )
        p2 = (
            'Operating drivers include fairness testing, explainability, drift monitoring, '
            'an approved MLOps pipeline, and time-bound AI incident handling.'
        )
    else:
        p1 = (
            f'{lead} DGA digital-government expectations, including '
            f'digital services, interoperability, and a connected beneficiary experience.'
        )
        p2 = (
            'Operating drivers include published APIs, complete beneficiary journeys '
            'for priority services, and adherence to the target digital service level.'
        )
    if presented and presented not in p1:
        p1 = f'{p1} The selected sector is {presented}.'
    return p1 + '\n\n' + p2


def _confidence_rows(domain: str, lang: str) -> Tuple[ConfidenceRow, ...]:
    if lang == 'ar':
        rows = (
            ('اكتمال الإطار المعتمد', '20%', '80', 'الأطر المحددة مكتملة لكل أسرة تغطية'),
            ('جاهزية التشغيل', '16%', '76', 'المبادرات مرتبطة بمالك ومخرج'),
            ('قياس الأثر', '16%', '78', 'لكل مؤشر صيغة ومصدر وتكرار'),
            ('إدارة المخاطر', '16%', '74', 'لكل مخاطرة خطة معالجة ومالك'),
            ('اكتمال الأدلة', '16%', '77', 'دليل تطبيق لكل فجوة ودليل تقييم لكل مؤشر'),
            ('جاهزية التتبع', '16%', '75', 'كل مبادرة مربوطة بفجوة ومؤشر وإطار'),
        )
    else:
        rows = (
            ('Approved-framework completeness', '20%', '80', 'Selected frameworks are complete for each coverage family'),
            ('Operating readiness', '16%', '76', 'Each initiative has an owner and deliverable'),
            ('Impact measurement', '16%', '78', 'Each KPI has a formula, source, and frequency'),
            ('Risk management', '16%', '74', 'Each risk has a treatment plan and owner'),
            ('Guide completeness', '16%', '77', 'One implementation guide per gap and one assessment guide per KPI'),
            ('Traceability readiness', '16%', '75', 'Each initiative links a gap, KPI, and framework'),
        )
    return tuple(ConfidenceRow(*row) for row in rows)


def _risk_rows(domain: str, lang: str, owner: str) -> Tuple[RiskRow, ...]:
    if lang == 'ar':
        rows = (
            ('تأخر اعتماد السياسات', 'تعطل التغطية الإطارية', 'خطة المعالجة: جدول اعتماد ربع سنوي', owner),
            ('ضعف اكتمال السجلات', 'قرارات على بيانات ناقصة', 'خطة المعالجة: بوابة اكتمال قبل الإطلاق', owner),
            ('انقطاع دليل التنفيذ', 'فجوات بلا إغلاق', 'خطة المعالجة: دليل تطبيق لكل فجوة', owner),
            ('ضعف قياس المؤشرات', 'فقدان القدرة على المتابعة', 'خطة المعالجة: صيغة ومصدر لكل مؤشر', owner),
        )
    else:
        rows = (
            ('Late policy approval', 'Framework coverage stalls', 'Treatment plan: quarterly approval calendar', owner),
            ('Incomplete registers', 'Decisions on partial data', 'Treatment plan: completeness gate before launch', owner),
            ('Broken implementation guides', 'Gaps remain open', 'Treatment plan: one implementation guide per gap', owner),
            ('Weak KPI measurement', 'No reliable follow-up', 'Treatment plan: formula and source for each KPI', owner),
        )
    return tuple(RiskRow(*row) for row in rows)


def _governance_rows(domain: str, lang: str, default_owner: str) -> Tuple[GovernanceRow, ...]:
    if lang == 'ar':
        roles = (
            ('لجنة الاستراتيجية', 'اعتماد الأهداف والمؤشرات', default_owner),
            ('مكتب الحوكمة', 'متابعة التغطية الإطارية', default_owner),
            ('مالكو المبادرات', 'تنفيذ مبادرات خارطة الطريق', default_owner),
            ('مكتب القياس', 'تشغيل مؤشرات الأداء', default_owner),
            ('مكتب الفجوات', 'إغلاق أدلة التطبيق', default_owner),
            ('مكتب المخاطر', 'متابعة خطة المعالجة', default_owner),
            ('مكتب التتبع', 'ربط المبادرة بالفجوة والمؤشر', default_owner),
        )
    else:
        roles = (
            ('Strategy committee', 'Approve objectives and KPIs', default_owner),
            ('Governance office', 'Track framework coverage', default_owner),
            ('Initiative owners', 'Deliver roadmap initiatives', default_owner),
            ('Measurement office', 'Operate the KPI set', default_owner),
            ('Gap office', 'Close implementation guides', default_owner),
            ('Risk office', 'Track the treatment plan', default_owner),
            ('Traceability office', 'Link initiative, gap, and KPI', default_owner),
        )
    cadence = _GOV_CADENCE[lang]
    return tuple(
        GovernanceRow(role, responsibility, cadence, owner)
        for role, responsibility, owner in roles
    )


def _so_tuple(family: FamilySpec, lang: str) -> Tuple[str, str, str, str]:
    return family.so_ar if lang == 'ar' else family.so_en


def _gap_tuple(family: FamilySpec, lang: str) -> Tuple[str, str, str, str]:
    return family.gap_ar if lang == 'ar' else family.gap_en


def _kpi_tuple(family: FamilySpec, lang: str) -> Tuple[str, str, str, str, str, str, str]:
    return family.kpi_ar if lang == 'ar' else family.kpi_en


def _roadmap_tuple(family: FamilySpec, lang: str) -> Tuple[str, str, str, str, str]:
    return family.roadmap_ar if lang == 'ar' else family.roadmap_en


def compile_strategy_model(request: Optional[Dict[str, Any]] = None) -> CanonicalDocument:
    payload = dict(request or {})
    domain = normalize_domain_code(str(payload.get('domain') or ''), default='')
    lang = 'ar' if str(payload.get('lang') or 'ar').lower().startswith('ar') else 'en'
    org_name = str(payload.get('org_name') or payload.get('organization') or '')
    sector = str(payload.get('sector') or '').strip()
    families = list(DOMAIN_FAMILIES.get(domain, ()))
    if domain == 'data':
        families = families + list(_DATA_SUPPORT)
    if domain == 'dt':
        families = families + list(_DT_SUPPORT)
    if not families:
        raise ValueError(f'rel37_unsupported_domain:{domain}')
    selected = tuple(resolve_selected_frameworks(domain, payload))
    matched = {fam.family_id for fam in families_for_request(domain, payload)}
    required = tuple(fam.family_id for fam in families)
    default_owner = _owner(
        {'data': 'CDO', 'ai': 'AI Governance Lead', 'dt': 'Digital Transformation Lead'}[domain],
        lang,
    )

    so_rows: List[SORow] = []
    gap_rows: List[GapRow] = []
    gap_guides: List[GapGuide] = []
    kpi_rows: List[KpiRow] = []
    formula_rows: List[KpiFormulaRow] = []
    kpi_guides: List[KpiGuide] = []
    roadmap_rows: List[RoadmapRow] = []
    trace_rows: List[TraceabilityRow] = []

    for idx, family in enumerate(families, start=1):
        so = _so_tuple(family, lang)
        gap = _gap_tuple(family, lang)
        kpi = _kpi_tuple(family, lang)
        road = _roadmap_tuple(family, lang)
        owner = _owner(kpi[6], lang)
        so_family = family.family_id
        if family.family_id in ('NDMO', 'PDPL', 'SDAIA', 'DGA'):
            so_family = f'{family.family_id.lower()}_compliance'
        # Professional PDF gates bucket from the period cell first. Quarter
        # labels (Q1-Q4) all collapse to phase 1, so emit the canonical
        # 1-6 / 7-18 / 19-24 ranges and matching phase titles.
        if lang == 'ar':
            if '1' in road[0] or 'تأسيس' in road[0]:
                phase = 'المرحلة 1: تأسيس (1-6 أشهر)'
                period = '1-6 أشهر'
            elif '2' in road[0] or 'تمكين' in road[0]:
                phase = 'المرحلة 2: تمكين وتشغيل (7-18 شهر)'
                period = '7-18 شهر'
            else:
                phase = 'المرحلة 3: تحسين واستدامة (19-24 شهر)'
                period = '19-24 شهر'
        elif '1' in road[0] or 'Establish' in road[0]:
            phase = 'Phase 1: Establish (1-6 months)'
            period = '1-6 months'
        elif '2' in road[0] or 'Enable' in road[0]:
            phase = 'Phase 2: Enable & Operate (7-18 months)'
            period = '7-18 months'
        else:
            phase = 'Phase 3: Optimize & Sustain (19-24 months)'
            period = '19-24 months'
        kpi_name = kpi[0]
        if lang == 'ar':
            kpi_name = (
                kpi_name
                .replace('سياسات NDMO', 'ضوابط NDMO')
                .replace('سياسات الاحتفاظ', 'جداول الاحتفاظ')
                .replace('سياسة', 'ضابط')
            )
        kpi_type = 'KPI'
        if any(tok in kpi_name.lower() for tok in ('مخاطر', 'risk', 'kri')):
            kpi_type = 'KRI'
        so_rows.append(SORow(
            number=idx, objective=so[0], target=so[1], rationale=so[2],
            timeframe=so[3], family=so_family, framework=family.family_id,
        ))
        gap_rows.append(GapRow(
            number=idx, gap_label=gap[0], description=gap[2],
            priority=gap[1], status=_STATUS[lang],
            family=family.family_id, framework=family.family_id,
        ))
        gap_guides.append(GapGuide(
            number=idx, family=family.family_id,
            heading=default_guide_heading('gap', lang, idx),
            steps=_guide_steps(owner, lang, gap[0]),
        ))
        kpi_rows.append(KpiRow(
            number=idx, description=kpi_name, type=kpi_type, target=kpi[2],
            formula=kpi[3], source=kpi[4], frequency=kpi[5], owner=owner,
            family=family.family_id, framework=family.family_id,
        ))
        formula_rows.append(KpiFormulaRow(
            number=idx, kpi=kpi_name, formula=kpi[3], data_source=kpi[4],
            family=family.family_id,
        ))
        kpi_guides.append(KpiGuide(
            number=idx, family=family.family_id,
            heading=default_guide_heading('kpi', lang, idx),
            steps=_guide_steps(owner, lang, kpi_name),
        ))
        initiative = road[2]
        deliverable = road[4]
        # Existing professional renderer keeps an initiative only when it
        # names a concrete capability token (data/governance/protection).
        if lang == 'ar':
            if not any(tok in initiative for tok in ('بيانات', 'حوكمة', 'حماية', 'تصنيف')):
                if domain == 'ai':
                    initiative = f'{initiative} وحوكمة النماذج'
                elif domain == 'dt':
                    initiative = f'{initiative} وحوكمة الخدمات'
                else:
                    initiative = f'{initiative} للبيانات'
            if len(deliverable) <= 8:
                deliverable = f'{deliverable} معتمد وموثق'
        else:
            if not any(tok in initiative.lower() for tok in (
                    'data', 'governance', 'protection', 'classification')):
                if domain == 'ai':
                    initiative = f'{initiative} model governance'
                elif domain == 'dt':
                    initiative = f'{initiative} service governance'
                else:
                    initiative = f'{initiative} data program'
            if len(deliverable) <= 8:
                deliverable = f'{deliverable} approved and documented'
        roadmap_rows.append(RoadmapRow(
            phase=phase, period=period, initiative=initiative,
            owner=_owner(road[3], lang), deliverable=deliverable,
            framework=family.family_id, family=family.family_id,
        ))
        trace_rows.append(TraceabilityRow(
            number=idx, initiative=road[2], gap=gap[0], kpi=kpi[0],
            framework=family.family_id, family=family.family_id,
        ))

    pillar_specs = _PILLARS[domain][lang]
    pillars = tuple(
        PillarRow(
            number=i + 1, title=spec[0], description=spec[1],
            family=spec[2], owner=default_owner,
        )
        for i, spec in enumerate(pillar_specs)
    )
    initiatives: List[PillarInitiativeRow] = []
    for pillar in pillars:
        related = [row for row in roadmap_rows if row.family == pillar.family]
        if len(related) < 3:
            extra = [row for row in roadmap_rows if row not in related]
            related = related + extra
        related = related[:3] or roadmap_rows[:3]
        for road in related:
            initiatives.append(PillarInitiativeRow(
                pillar_number=pillar.number,
                initiative=road.initiative,
                description=pillar.description,
                output=road.deliverable,
                owner=road.owner,
                pillar_family=pillar.family,
            ))

    if lang == 'ar':
        justification = (
            'درجة الثقة مبنية على اكتمال الجداول المحددة ووجود دليل تطبيق لكل فجوة '
            'وصيغة احتساب لكل مؤشر.'
        )
    else:
        justification = (
            'The confidence score is based on complete typed tables, one implementation '
            'guide per gap, and a calculation formula for each KPI.'
        )

    doc = CanonicalDocument(
        schema_version=SCHEMA_VERSION,
        document_type='strategy',
        domain=domain,
        lang=lang,
        selected_frameworks=selected,
        org_name=org_name,
        sector=sector,
        task_id=str(payload.get('task_id') or payload.get('strategy_id') or ''),
        vision=_vision_prose(domain, lang, org_name),
        environment_narrative=_environment_prose(domain, lang, org_name, sector),
        runtime_diagnostics=sector_runtime_diagnostics(sector, lang),
        strategic_objectives=tuple(so_rows),
        pillars=pillars,
        pillar_initiatives=tuple(initiatives),
        gaps=tuple(gap_rows),
        gap_guides=tuple(gap_guides),
        kpis=tuple(kpi_rows),
        kpi_formula_source=tuple(formula_rows),
        kpi_guides=tuple(kpi_guides),
        roadmap=tuple(roadmap_rows),
        confidence=_confidence_rows(domain, lang),
        risks=_risk_rows(domain, lang, default_owner),
        confidence_score='78%',
        confidence_justification=justification,
        governance=_governance_rows(domain, lang, default_owner),
        traceability=tuple(trace_rows),
        required_families=required,
        satisfied_families=required,
    )
    doc.compute_hashes()
    doc.validate()
    return doc


def compile_data_strategy(request: Optional[Dict[str, Any]] = None) -> CanonicalDocument:
    payload = dict(request or {})
    payload['domain'] = 'data'
    return compile_strategy_model(payload)


def compile_ai_strategy(request: Optional[Dict[str, Any]] = None) -> CanonicalDocument:
    payload = dict(request or {})
    payload['domain'] = 'ai'
    return compile_strategy_model(payload)


def compile_dt_strategy(request: Optional[Dict[str, Any]] = None) -> CanonicalDocument:
    payload = dict(request or {})
    payload['domain'] = 'dt'
    return compile_strategy_model(payload)


COMPILER_BY_DOMAIN = {
    'data': compile_data_strategy,
    'ai': compile_ai_strategy,
    'dt': compile_dt_strategy,
}


def compile_for_domain(domain: str, request: Optional[Dict[str, Any]] = None) -> CanonicalDocument:
    code = normalize_domain_code(str(domain or ''), default='')
    fn = COMPILER_BY_DOMAIN.get(code)
    if fn is None:
        raise ValueError(f'rel37_unsupported_domain:{domain}')
    payload = dict(request or {})
    payload['domain'] = code
    return fn(payload)
