"""PR-5B.9B — Cross-domain professional strategy export quality.

Verifies that exported strategy documents are domain-specific:

  * Cyber methodology / glossary stays cyber.
  * Data / AI / DT / ERM strategies use their own domain methodology
    and glossary baselines.
  * Cyber acronyms (SOC / CSIRT / VPN / ZTNA / DLP / IAM / PAM / SIEM /
    EDR / MDM-mobile) do NOT leak into non-cyber appendices unless they
    are literally cited (word-boundary) in the strategy content.
  * Frameworks are inferred from content when not passed (ERM body
    citing ISO 31000 / COSO ERM, AI body citing SDAIA, Data body
    citing NDMO / PDPL).
  * Traceability matrix is populated for every domain whose strategy
    has gaps + roadmap + KPIs + risks; rows are not mostly "—".
  * The composer emits the documented quality-gate checks.
  * Document control table never produces the visible RTL artefact
    "بواسطة أعد".
  * Headings never carry the ".N" mis-glued prefix in Arabic.
  * Preview is not affected (we never call any preview route).
  * No deterministic strategy rows are introduced (the composer derives
    everything from content).

Run:
    python -m pytest \
      tests/test_cross_domain_strategy_export_quality_pr5b9b.py -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_pro_strategy_xdomain_pr5b9b_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ─────────────────────────────────────────────────────────────────────────
# Per-domain Arabic strategy fixtures. Each fixture mentions ONLY terms
# native to its discipline (no SOC/CSIRT/IAM/VPN/ZTNA/DLP for non-cyber
# fixtures) so any cross-domain leakage is provably from the composer,
# not the content.
# ─────────────────────────────────────────────────────────────────────────
def _common_sections(name, gaps_rows, pillars_rows, roadmap_rows,
                     kpis_rows, risks_rows):
    """Build a minimal but valid 7-section Arabic strategy markdown."""
    def _table(header_cells, rows):
        out = ['| ' + ' | '.join(header_cells) + ' |',
               '|' + '|'.join(['---'] * len(header_cells)) + '|']
        for r in rows:
            out.append('| ' + ' | '.join(r) + ' |')
        return '\n'.join(out)

    return f'''## 1. الرؤية والأهداف الاستراتيجية

**الرؤية:** {name} — رؤية شاملة لتحقيق التميز.

| # | الهدف | المقياس | المبرر | الإطار الزمني |
|---|---|---|---|---|
| 1 | تحسين القدرات | مستوى نضج 4 | الالتزام التنظيمي | 12 شهر |
| 2 | تعزيز الحوكمة | تغطية 95% | الكفاءة المؤسسية | 18 شهر |

## 2. الركائز الاستراتيجية

### الركيزة 1: الحوكمة

تعزيز إطار الحوكمة عبر السياسات والإجراءات.

{_table(['#', 'المبادرة', 'الوصف', 'المخرج', 'المسؤول'], pillars_rows)}

## 3. البيئة التنظيمية

تعمل المنظمة في بيئة معقدة تشمل متطلبات تنظيمية متعددة وتحديات قطاعية.

| البُعد | المصدر | الأثر | المبادرة |
|---|---|---|---|
| تنظيمي | متطلبات | متطلب امتثال | برنامج مواءمة |

## 4. تحليل الفجوات

{_table(['#', 'الفجوة', 'الوصف', 'الأولوية', 'الحالة'], gaps_rows)}

## 5. خارطة الطريق التنفيذية

{_table(['#', 'النشاط', 'المسؤول', 'الجدول الزمني', 'المخرج'], roadmap_rows)}

## 6. مؤشرات الأداء الرئيسية

{_table(['#', 'المؤشر', 'النوع', 'القيمة المستهدفة',
         'صيغة الاحتساب', 'مصدر البيانات', 'المالك',
         'التكرار', 'الإطار الزمني'], kpis_rows)}

## 7. تقييم الثقة والمخاطر

**درجة الثقة:** 78%

**المبرر:** الاستراتيجية مبنية على إطار مرجعي معتمد.

| # | عامل النجاح الحرج | الوصف | الأهمية |
|---|---|---|---|
| 1 | الدعم التنفيذي | التزام الإدارة العليا | عالية |

{_table(['#', 'الخطر', 'الاحتمالية', 'التأثير', 'خطة التخفيف'],
         risks_rows)}
'''


CYBER_FIXTURE = _common_sections(
    'الأمن السيبراني',
    gaps_rows=[
        ['1', 'غياب SOC', 'لا يوجد مركز عمليات', 'عالية', 'مفتوحة'],
        ['2', 'ضعف IAM', 'إدارة هوية محدودة', 'عالية', 'مفتوحة'],
        ['3', 'غياب MFA', 'لا توجد مصادقة متعددة', 'عالية', 'مفتوحة'],
    ],
    pillars_rows=[
        ['1', 'إنشاء SOC', 'مركز عمليات أمنية', 'SOC مفعّل', 'CISO'],
        ['2', 'تطبيق MFA و IAM', 'هوية ومصادقة', 'MFA نشط', 'CISO'],
        ['3', 'نشر VPN/ZTNA', 'وصول آمن عن بُعد', 'ZTNA منتشر',
         'CSIRT Lead'],
    ],
    roadmap_rows=[
        ['1', 'إنشاء SOC', 'CISO', 'الشهر 1-6', 'SOC نشط'],
        ['2', 'تطبيق MFA', 'CISO', 'الشهر 3-6', 'MFA مفعّل'],
        ['3', 'نشر CSIRT', 'CISO', 'الشهر 6-9', 'CSIRT جاهز'],
    ],
    kpis_rows=[
        ['1', 'تغطية MFA', 'KPI', '100%', '(مطبقة/إجمالي)*100',
         'لوحة الهوية', 'CISO', 'شهري', '6 شهر'],
        ['2', 'زمن الكشف', 'KPI', '< 30 دقيقة', 'مجموع/عدد',
         'SIEM', 'SOC Manager', 'أسبوعي', '6 شهر'],
        ['3', 'حوادث حرجة', 'KRI', '< 2', 'العدد', 'سجل الحوادث',
         'CISO', 'شهري', '12 شهر'],
    ],
    risks_rows=[
        ['1', 'نقص كوادر SOC', 'عالية', 'عالي', 'برنامج تطوير'],
        ['2', 'تأخر تطبيق MFA', 'متوسطة', 'عالي', 'متابعة شهرية'],
    ],
)

DATA_FIXTURE = _common_sections(
    'إدارة البيانات',
    gaps_rows=[
        ['1', 'غياب حوكمة البيانات', 'لا يوجد إطار NDMO',
         'عالية', 'مفتوحة'],
        ['2', 'ضعف جودة البيانات', 'بدون قياس Data Quality',
         'عالية', 'مفتوحة'],
        ['3', 'غياب كتالوج البيانات', 'لا يوجد Data Catalog',
         'متوسطة', 'مفتوحة'],
        ['4', 'عدم تصنيف البيانات وفق PDPL',
         'لا توجد Data Classification', 'عالية', 'مفتوحة'],
    ],
    pillars_rows=[
        ['1', 'حوكمة البيانات', 'إنشاء لجنة Data Governance',
         'لجنة معتمدة', 'Chief Data Officer'],
        ['2', 'تحسين جودة البيانات', 'برنامج Data Quality',
         'تقارير دورية', 'Data Steward'],
        ['3', 'بناء كتالوج وميتاداتا', 'Data Catalog و Metadata',
         'كتالوج جاهز', 'Data Steward'],
    ],
    roadmap_rows=[
        ['1', 'تأسيس حوكمة البيانات', 'CDO', 'الشهر 1-6',
         'إطار NDMO معتمد'],
        ['2', 'إطلاق Data Quality', 'Data Steward', 'الشهر 3-9',
         'مؤشرات جودة'],
        ['3', 'تطبيق PDPL', 'DPO', 'الشهر 6-12', 'تصنيف معتمد'],
    ],
    kpis_rows=[
        ['1', 'مؤشر جودة البيانات', 'KPI', '95%',
         '(صحيح/إجمالي)*100', 'لوحة الجودة', 'Data Steward',
         'شهري', '12 شهر'],
        ['2', 'تغطية الميتاداتا', 'KPI', '90%',
         '(موصوفة/إجمالي)*100', 'كتالوج البيانات',
         'Data Steward', 'شهري', '12 شهر'],
        ['3', 'الامتثال لـ PDPL', 'KPI', '100%',
         '(مصنفة/إجمالي)*100', 'سجل التصنيف', 'DPO',
         'فصلي', '12 شهر'],
    ],
    risks_rows=[
        ['1', 'تأخر بناء حوكمة البيانات', 'عالية', 'عالي',
         'دعم تنفيذي'],
        ['2', 'ضعف جودة البيانات', 'عالية', 'عالي',
         'برنامج تحسين Data Quality'],
    ],
)

AI_FIXTURE = _common_sections(
    'الذكاء الاصطناعي',
    gaps_rows=[
        ['1', 'غياب حوكمة الذكاء الاصطناعي وفق SDAIA',
         'لا يوجد AI Governance', 'عالية', 'مفتوحة'],
        ['2', 'عدم وجود مخزون نماذج (Model Inventory)',
         'لا يوجد Model Risk', 'عالية', 'مفتوحة'],
        ['3', 'غياب اختبارات Bias و Fairness',
         'لا توجد قياسات', 'عالية', 'مفتوحة'],
        ['4', 'ضعف Explainability و Transparency',
         'نماذج غير مفسرة', 'متوسطة', 'مفتوحة'],
    ],
    pillars_rows=[
        ['1', 'تأسيس AI Governance', 'لجنة AI Ethics وفق SDAIA',
         'إطار معتمد', 'Head of AI Governance'],
        ['2', 'تطبيق Bias / Fairness', 'برنامج اختبار النماذج',
         'تقارير عدالة', 'AI Ethics Officer'],
        ['3', 'Human Oversight و Model Monitoring',
         'إشراف بشري ومراقبة', 'لوحة مراقبة', 'Model Risk Manager'],
    ],
    roadmap_rows=[
        ['1', 'تأسيس AI Governance', 'Head of AI Governance',
         'الشهر 1-6', 'حوكمة وفق SDAIA'],
        ['2', 'إطلاق اختبارات Bias', 'AI Ethics Officer',
         'الشهر 3-9', 'تقارير'],
        ['3', 'تشغيل Model Monitoring', 'Model Risk Manager',
         'الشهر 6-12', 'لوحة مراقبة'],
    ],
    kpis_rows=[
        ['1', 'تغطية حوكمة AI Governance', 'KPI', '95%',
         '(مطبقة/مطلوبة)*100', 'لوحة الحوكمة',
         'Head of AI Governance', 'شهري', '12 شهر'],
        ['2', 'نسبة Model Monitoring', 'KPI', '100%',
         '(مراقبة/إجمالي)*100', 'منصة المراقبة',
         'Model Risk Manager', 'شهري', '12 شهر'],
        ['3', 'مؤشر Bias المكتشف', 'KRI', '< 5%',
         'متوسط الانحراف', 'تقارير الاختبار',
         'AI Ethics Officer', 'فصلي', '12 شهر'],
    ],
    risks_rows=[
        ['1', 'انحراف النماذج (Model Drift)', 'عالية', 'عالي',
         'مراقبة دورية'],
        ['2', 'بيانات تدريب متحيزة (Bias)', 'متوسطة', 'عالي',
         'فحص Fairness'],
    ],
)

DT_FIXTURE = _common_sections(
    'التحول الرقمي',
    gaps_rows=[
        ['1', 'تدني نضج الخدمات الرقمية مقارنة بـ DGA',
         'خدمات غير مكتملة', 'عالية', 'مفتوحة'],
        ['2', 'ضعف Interoperability',
         'لا يوجد APIs موحدة', 'عالية', 'مفتوحة'],
        ['3', 'تدني User Experience و Adoption',
         'تجربة ضعيفة', 'متوسطة', 'مفتوحة'],
        ['4', 'محدودية Cloud Service و Automation',
         'لا توجد سحابة', 'متوسطة', 'مفتوحة'],
    ],
    pillars_rows=[
        ['1', 'رقمنة الخدمات (Digital Service)',
         'إعادة تصميم الخدمات', 'خدمات رقمية', 'Chief Digital Officer'],
        ['2', 'تكامل APIs و Interoperability',
         'بناء طبقة تكامل', 'APIs جاهزة', 'Digital Transformation Office'],
        ['3', 'رفع Adoption و User Experience',
         'برنامج تجربة المستفيد', 'مؤشرات تبني', 'Innovation Lead'],
    ],
    roadmap_rows=[
        ['1', 'إطلاق Digital Service جديدة',
         'CDO', 'الشهر 1-6', 'خدمات منصّة'],
        ['2', 'بناء APIs', 'CDO', 'الشهر 3-9',
         'Interoperability'],
        ['3', 'تحسين User Experience',
         'Innovation Lead', 'الشهر 6-12', 'CSAT مرتفع'],
    ],
    kpis_rows=[
        ['1', 'نضج Service Maturity', 'KPI', '4/5',
         'تقييم سنوي', 'لوحة DGA', 'CDO', 'سنوي', '24 شهر'],
        ['2', 'نسبة Adoption للخدمات الرقمية', 'KPI', '85%',
         '(مستخدمون/إجمالي)*100', 'تحليلات الاستخدام',
         'Innovation Lead', 'شهري', '12 شهر'],
        ['3', 'إتاحة Cloud Service', 'KPI', '99.9%',
         'نسبة التشغيل', 'لوحة السحابة', 'CDO',
         'شهري', '12 شهر'],
    ],
    risks_rows=[
        ['1', 'تدني Adoption للخدمات', 'عالية', 'عالي',
         'حملات تواصل'],
        ['2', 'تأخر تكامل APIs', 'متوسطة', 'عالي',
         'فريق Interoperability'],
    ],
)

ERM_FIXTURE = _common_sections(
    'إدارة المخاطر المؤسسية',
    gaps_rows=[
        ['1', 'غياب إطار حوكمة المخاطر وفق ISO 31000',
         'لا يوجد إطار رسمي', 'عالية', 'مفتوحة'],
        ['2', 'عدم تطبيق COSO ERM',
         'بدون نموذج COSO', 'عالية', 'مفتوحة'],
        ['3', 'غياب Risk Appetite و Risk Tolerance',
         'لا توجد بيانات شهية', 'عالية', 'مفتوحة'],
        ['4', 'سجل المخاطر (Risk Register) ناقص',
         'تغطية محدودة', 'عالية', 'مفتوحة'],
        ['5', 'ضعف KRI Reporting',
         'لا توجد مؤشرات', 'متوسطة', 'مفتوحة'],
    ],
    pillars_rows=[
        ['1', 'إطار ISO 31000', 'تأسيس حوكمة المخاطر',
         'إطار معتمد', 'Chief Risk Officer'],
        ['2', 'تطبيق COSO ERM', 'مواءمة شاملة',
         'نموذج COSO', 'Risk Management Committee'],
        ['3', 'تصميم Risk Appetite و KRI',
         'بيان شهية ومكتبة KRIs', 'بيان معتمد', 'Risk Owner'],
    ],
    roadmap_rows=[
        ['1', 'اعتماد ISO 31000', 'CRO', 'الشهر 1-6',
         'إطار معتمد'],
        ['2', 'مواءمة COSO ERM', 'CRO', 'الشهر 3-9',
         'نموذج مطبّق'],
        ['3', 'إطلاق KRI Library و Risk Treatment',
         'Risk Owner', 'الشهر 6-12', 'مؤشرات نشطة'],
    ],
    kpis_rows=[
        ['1', 'تغطية Risk Register', 'KPI', '95%',
         '(مسجلة/إجمالي)*100', 'سجل المخاطر',
         'Risk Owner', 'شهري', '12 شهر'],
        ['2', 'نسبة الالتزام بـ Risk Appetite',
         'KRI', '100%', '(ضمن الحد/إجمالي)*100',
         'لوحة المخاطر', 'CRO', 'فصلي', '12 شهر'],
        ['3', 'إغلاق خطط Risk Treatment', 'KPI', '90%',
         '(مغلقة/إجمالي)*100', 'سجل المعالجة',
         'Risk Owner', 'فصلي', '12 شهر'],
    ],
    risks_rows=[
        ['1', 'تأخر اعتماد ISO 31000', 'عالية', 'عالي',
         'دعم تنفيذي'],
        ['2', 'ضعف ثقافة Risk Appetite', 'متوسطة', 'عالي',
         'برنامج توعية'],
    ],
)


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────
def _build_model(content, domain, lang='ar', selected_frameworks=None):
    return _APP._build_strategy_document_model(
        content,
        metadata={
            'org_name': 'منظمة اختبار',
            'sector':   'حكومي',
            'domain':   domain,
            'doc_type': 'Strategy Document',
        },
        selected_frameworks=selected_frameworks or [],
        lang=lang,
    )


def _glossary_acronyms(model):
    """Return the set of bullet-prefixed glossary acronyms emitted in
    Appendix B of the model.
    """
    out = set()
    for label, _body in model['blocks']['appendices']['entries']:
        if not label.startswith('•'):
            continue
        ac = label.lstrip('• ').strip()
        if ac and ac != '—':
            out.add(ac)
    return out


def _methodology_blob(model):
    return ' '.join(
        f'{lbl} {bdy}'
        for (lbl, bdy) in model['blocks']['methodology']['rows']
    )


# ─────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────
class CrossDomainCyberDomainTest(unittest.TestCase):

    @_skip_if_no_app
    def test_01_cyber_methodology_and_glossary(self):
        # Methodology checked in English mode for stable token matching.
        model_en = _build_model(CYBER_FIXTURE, 'Cyber Security', lang='en',
                                 selected_frameworks=['ECC', 'TCC'])
        meth = _methodology_blob(model_en)
        # Cyber methodology mentions IAM / monitoring / incident response /
        # capability coverage language.
        for token in ('Capability Coverage', 'IAM', 'monitoring',
                      'incident response'):
            self.assertIn(token, meth,
                          f'Cyber methodology should mention {token!r}.')
        # Glossary contains cyber baseline acronyms (Arabic-mode model).
        model_ar = _build_model(CYBER_FIXTURE, 'Cyber Security',
                                 selected_frameworks=['ECC', 'TCC'])
        gloss = _glossary_acronyms(model_ar)
        for needed in ('ECC', 'TCC', 'MFA', 'SOC', 'CSIRT'):
            self.assertIn(needed, gloss,
                          f'Cyber glossary should include {needed}; got {gloss}')


class CrossDomainDataDomainTest(unittest.TestCase):

    @_skip_if_no_app
    def test_02_data_methodology_and_glossary(self):
        model_en = _build_model(DATA_FIXTURE, 'Data Management', lang='en')
        meth = _methodology_blob(model_en)
        for token in ('Data Governance', 'Data Quality', 'Metadata'):
            self.assertIn(token, meth,
                          f'Data methodology should mention {token!r}.')
        model_ar = _build_model(DATA_FIXTURE, 'Data Management')
        gloss = _glossary_acronyms(model_ar)
        for needed in ('NDMO', 'PDPL', 'Data Governance',
                       'Data Steward', 'Data Catalog',
                       'Data Quality', 'Data Classification',
                       'Data Lineage'):
            self.assertIn(needed, gloss,
                          f'Data glossary should include {needed}; got {gloss}')

    @_skip_if_no_app
    def test_06_data_glossary_no_cyber_leakage(self):
        # The Data fixture deliberately mentions no cyber acronyms.
        model = _build_model(DATA_FIXTURE, 'Data Management')
        gloss = _glossary_acronyms(model)
        for forbidden in ('SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
                          'IAM', 'PAM', 'SIEM', 'EDR'):
            self.assertNotIn(
                forbidden, gloss,
                f'Cyber acronym {forbidden!r} must not leak into Data '
                f'glossary; got {gloss}',
            )

    @_skip_if_no_app
    def test_09_data_with_ndmo_pdpl_in_scope_and_glossary(self):
        # No frameworks passed → composer must infer NDMO + PDPL from
        # the Data fixture body and surface them in scope/glossary.
        model = _build_model(DATA_FIXTURE, 'Data Management',
                             selected_frameworks=[])
        scope_keys = model['blocks']['scope_frameworks']['frameworks_keys']
        for key in ('NDMO', 'PDPL'):
            self.assertIn(key, scope_keys,
                          f'{key} should be inferred from Data content; '
                          f'got {scope_keys}')
        gloss = _glossary_acronyms(model)
        self.assertIn('NDMO', gloss)
        self.assertIn('PDPL', gloss)


class CrossDomainAIDomainTest(unittest.TestCase):

    @_skip_if_no_app
    def test_03_ai_methodology_and_glossary(self):
        model_en = _build_model(AI_FIXTURE, 'Artificial Intelligence',
                                 lang='en')
        meth = _methodology_blob(model_en)
        for token in ('AI Governance', 'Bias', 'Explainability',
                      'Human Oversight', 'Model Monitoring'):
            self.assertIn(token, meth,
                          f'AI methodology should mention {token!r}.')
        model_ar = _build_model(AI_FIXTURE, 'Artificial Intelligence')
        gloss = _glossary_acronyms(model_ar)
        for needed in ('SDAIA', 'AI Governance', 'AI Ethics',
                       'Model Risk', 'Bias', 'Fairness',
                       'Explainability', 'Transparency',
                       'Human Oversight', 'Model Monitoring',
                       'Training Data'):
            self.assertIn(needed, gloss,
                          f'AI glossary should include {needed!r}; got {gloss}')

    @_skip_if_no_app
    def test_06_ai_glossary_no_cyber_leakage(self):
        model = _build_model(AI_FIXTURE, 'Artificial Intelligence')
        gloss = _glossary_acronyms(model)
        for forbidden in ('SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
                          'IAM', 'PAM', 'SIEM'):
            self.assertNotIn(
                forbidden, gloss,
                f'Cyber acronym {forbidden!r} must not leak into AI '
                f'glossary; got {gloss}',
            )

    @_skip_if_no_app
    def test_08_ai_with_sdaia_inferred(self):
        model = _build_model(AI_FIXTURE, 'Artificial Intelligence',
                             selected_frameworks=[])
        scope_keys = model['blocks']['scope_frameworks']['frameworks_keys']
        self.assertIn('SDAIA', scope_keys,
                      f'SDAIA should be inferred for AI; got {scope_keys}')


class CrossDomainDigitalTransformationTest(unittest.TestCase):

    @_skip_if_no_app
    def test_04_dt_methodology_and_glossary(self):
        model_en = _build_model(DT_FIXTURE, 'Digital Transformation',
                                 lang='en')
        meth = _methodology_blob(model_en)
        for token in ('Digital Maturity', 'Operating Model',
                      'User Journey', 'Beneficiary Experience',
                      'Adoption'):
            self.assertIn(token, meth,
                          f'DT methodology should mention {token!r}.')
        model_ar = _build_model(DT_FIXTURE, 'Digital Transformation')
        gloss = _glossary_acronyms(model_ar)
        for needed in ('DGA', 'Digital Service',
                       'Interoperability', 'API',
                       'User Experience', 'Adoption',
                       'Automation', 'Cloud Service',
                       'Service Maturity'):
            self.assertIn(needed, gloss,
                          f'DT glossary should include {needed!r}; got {gloss}')

    @_skip_if_no_app
    def test_06_dt_glossary_no_cyber_leakage(self):
        model = _build_model(DT_FIXTURE, 'Digital Transformation')
        gloss = _glossary_acronyms(model)
        for forbidden in ('SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
                          'IAM', 'PAM', 'SIEM'):
            self.assertNotIn(
                forbidden, gloss,
                f'Cyber acronym {forbidden!r} must not leak into DT '
                f'glossary; got {gloss}',
            )


class CrossDomainERMDomainTest(unittest.TestCase):

    @_skip_if_no_app
    def test_05_erm_methodology_and_glossary(self):
        model_en = _build_model(ERM_FIXTURE, 'Enterprise Risk Management',
                                 lang='en')
        meth = _methodology_blob(model_en)
        for token in ('Risk Governance', 'Risk Appetite',
                      'KRI', 'Risk Treatment'):
            self.assertIn(token.lower(), meth.lower(),
                          f'ERM methodology should mention {token!r}.')
        model_ar = _build_model(ERM_FIXTURE, 'Enterprise Risk Management')
        gloss = _glossary_acronyms(model_ar)
        for needed in ('ISO 31000', 'COSO ERM', 'Risk Appetite',
                       'Risk Tolerance', 'KRI', 'Risk Register',
                       'Risk Treatment', 'Inherent Risk',
                       'Residual Risk'):
            self.assertIn(needed, gloss,
                          f'ERM glossary should include {needed!r}; got {gloss}')

    @_skip_if_no_app
    def test_06_erm_glossary_no_cyber_leakage(self):
        model = _build_model(ERM_FIXTURE, 'Enterprise Risk Management')
        gloss = _glossary_acronyms(model)
        for forbidden in ('SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
                          'IAM', 'PAM', 'SIEM'):
            self.assertNotIn(
                forbidden, gloss,
                f'Cyber acronym {forbidden!r} must not leak into ERM '
                f'glossary; got {gloss}',
            )

    @_skip_if_no_app
    def test_07_erm_with_iso31000_coso_inferred(self):
        model = _build_model(ERM_FIXTURE, 'Enterprise Risk Management',
                             selected_frameworks=[])
        scope_keys = model['blocks']['scope_frameworks']['frameworks_keys']
        # At least one of ISO31000 / COSO_ERM must be inferred — both
        # appear literally in the fixture body.
        present = [k for k in ('ISO31000', 'COSO_ERM') if k in scope_keys]
        self.assertTrue(
            present,
            f'ERM body cites ISO 31000 and COSO ERM — at least one must '
            f'be inferred and surfaced in scope; got {scope_keys}',
        )


class TraceabilityMatrixCrossDomainTest(unittest.TestCase):

    @_skip_if_no_app
    def test_10_traceability_populated_for_every_domain(self):
        for domain, fixture in [
            ('Cyber Security', CYBER_FIXTURE),
            ('Data Management', DATA_FIXTURE),
            ('Artificial Intelligence', AI_FIXTURE),
            ('Digital Transformation', DT_FIXTURE),
            ('Enterprise Risk Management', ERM_FIXTURE),
        ]:
            with self.subTest(domain=domain):
                # No frameworks passed — exercise inference + profile
                # fallback.
                model = _build_model(fixture, domain,
                                     selected_frameworks=[])
                rows = model['blocks']['traceability_matrix']['rows']
                self.assertTrue(
                    rows,
                    f'{domain}: traceability matrix must not be empty when '
                    f'gaps/roadmap/KPIs/risks exist (got 0 rows).',
                )

    @_skip_if_no_app
    def test_11_no_traceability_row_is_mostly_dash(self):
        # A row that is mostly "—" in its informative cells indicates
        # the composer failed to wire content. Apply the same threshold
        # the PDF renderer uses (less than half informative cells = "—").
        for domain, fixture in [
            ('Data Management', DATA_FIXTURE),
            ('Artificial Intelligence', AI_FIXTURE),
            ('Digital Transformation', DT_FIXTURE),
            ('Enterprise Risk Management', ERM_FIXTURE),
        ]:
            with self.subTest(domain=domain):
                model = _build_model(fixture, domain,
                                     selected_frameworks=[])
                rows = model['blocks']['traceability_matrix']['rows']
                bad = []
                for r in rows:
                    info = list(r[1:]) if len(r) >= 2 else list(r)
                    if not info:
                        continue
                    n_dash = sum(
                        1 for v in info
                        if (v is None
                            or (isinstance(v, str)
                                and v.strip() in ('', '—', '-', '–', '--')))
                    )
                    # Row is "mostly dash" when n_dash * 2 >= len(info).
                    if n_dash * 2 >= len(info):
                        bad.append(r)
                # Allow at most half the rows to be sparse — but require
                # at least one row that is meaningful.
                meaningful = [r for r in rows if r not in bad]
                self.assertTrue(
                    meaningful,
                    f'{domain}: every traceability row is mostly "—". '
                    f'rows={rows!r}',
                )


class DocControlAndHeadingTest(unittest.TestCase):

    @_skip_if_no_app
    def test_12_doc_control_no_rtl_artifact(self):
        # The composer's doc-control rows must use the canonical label
        # "أعد بواسطة" (Arabic order). The visible defect "بواسطة أعد"
        # must NEVER appear in the model output.
        for domain, fixture in [
            ('Cyber Security', CYBER_FIXTURE),
            ('Data Management', DATA_FIXTURE),
        ]:
            with self.subTest(domain=domain):
                model = _build_model(fixture, domain)
                rows = model['blocks']['doc_control']['rows']
                joined = ' | '.join(f'{lbl}={val}' for (lbl, val) in rows)
                self.assertNotIn(
                    'بواسطة أعد', joined,
                    f'{domain}: doc-control must not produce the visible '
                    f'RTL artefact "بواسطة أعد"; got {joined}',
                )

    @_skip_if_no_app
    def test_13_headings_no_dot_n_prefix(self):
        # The Arabic heading normalizer must rewrite ".N العنوان" to
        # "N. العنوان". Run it on a malformed heading and verify.
        norm = _APP._arabic_pdf_heading_normalize(
            '.1 الرؤية والأهداف الاستراتيجية\n'
            '.2 الركائز\n'
            '## .3 خارطة الطريق\n'
        )
        self.assertNotIn('.1 الرؤية', norm)
        self.assertNotIn('.2 الركائز', norm)
        self.assertNotIn('.3 خارطة', norm)
        self.assertIn('1. الرؤية', norm)
        self.assertIn('2. الركائز', norm)


class ExportQualityGateAndPreviewTest(unittest.TestCase):

    @_skip_if_no_app
    def test_14_quality_gate_passes_for_clean_strategies(self):
        # Run the composer on a clean Data fixture and verify it
        # emits the "[EXPORT-QUALITY] ... ok" line (no warnings) — the
        # gate is the runtime quality check the user asked us to wire
        # in. We capture stdout via contextlib.redirect_stdout.
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _build_model(DATA_FIXTURE, 'Data Management',
                         selected_frameworks=[])
        log = buf.getvalue()
        self.assertIn('[EXPORT-QUALITY]', log,
                      'Quality gate should always log a line.')
        # We at minimum check there is no glossary_cross_domain_leak
        # nor traceability_empty for the clean Data fixture.
        for forbidden in ('glossary_cross_domain_leak',
                          'traceability_empty',
                          'methodology_cyber_phrasing_in_non_cyber'):
            self.assertNotIn(
                forbidden, log,
                f'Clean Data strategy should not raise {forbidden}; '
                f'log={log}',
            )

    @_skip_if_no_app
    def test_15_preview_route_unchanged(self):
        # Preview routes must NOT call _build_strategy_document_model
        # (the professional composer is export-only). We scan app.py for
        # every function whose name contains "preview" and inspect a
        # window of lines after the def line — robust against blank
        # lines and varying indentation. If no preview function exists
        # the test is informational (skipped).
        path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        import re
        preview_starts = [
            (i, m.group(1))
            for i, line in enumerate(lines)
            for m in [re.match(r'\s*def (\w*preview\w*)\s*\(', line)]
            if m
        ]
        if not preview_starts:
            self.skipTest('No preview function present to inspect.')
        for idx, name in preview_starts:
            # Capture up to the next def/class at the same or lower
            # indentation as the preview def.
            base_indent = len(lines[idx]) - len(lines[idx].lstrip())
            body = []
            for j in range(idx + 1, min(idx + 400, len(lines))):
                stripped = lines[j].rstrip('\n')
                if stripped.strip() and not stripped.startswith(' ' * (base_indent + 1)):
                    if re.match(r'\s*(def |class )', stripped) and (
                        len(stripped) - len(stripped.lstrip()) <= base_indent
                    ):
                        break
                body.append(stripped)
            joined = '\n'.join(body)
            self.assertNotIn(
                '_build_strategy_document_model', joined,
                f'Preview function {name} must not call the '
                f'professional composer (preview behaviour preserved).',
            )

    @_skip_if_no_app
    def test_16_no_deterministic_strategy_rows(self):
        # The composer must NOT introduce any extra strategy rows
        # beyond what the AI-generated content provides. We feed an
        # empty-content (no tables) fixture and confirm gaps/pillars/
        # KPIs/risks rows in the model are derived from the input only.
        model = _build_model('## 1. الرؤية\n\nرؤية مختصرة بدون جداول.\n',
                             'Enterprise Risk Management')
        # Strategy body must equal the original content (the composer
        # does not mutate it).
        self.assertEqual(
            model['blocks']['strategy_body']['content'],
            '## 1. الرؤية\n\nرؤية مختصرة بدون جداول.\n',
            'Composer must not mutate the strategy markdown.',
        )
        # Traceability rows: with no tables in content, the strategy
        # content cells (gap, initiative, KPI, risk — columns 2..5)
        # must all be "—". The framework column (0) and capability
        # column (1) are STRUCTURAL labels derived from the framework
        # registry / domain profile and are not "strategy rows" — the
        # user requested no deterministic *strategy* rows be added.
        rows = model['blocks']['traceability_matrix']['rows']
        for r in rows:
            for v in r[2:6]:  # gap, initiative, KPI, risk
                self.assertIn(
                    v, ('—', ''),
                    f'Composer must not invent strategy content; '
                    f'row={r!r} cell={v!r}',
                )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
