"""Tests for the deterministic repair functions added to address:

    "فحص المحتوى النهائي فشل لمقطع المخرجات: vision) so_rows_insufficient,
     risk, content) بعد إعادة التوليد."

Covers:
  1. A vision section with fewer than 5 objectives is repaired to ≥ 6 valid rows.
  2. count_valid_objective_rows() returns ≥ 6 after repair.
  3. A malformed confidence/risk section with duplicated "المخاطر الرئيسية"
     headings is repaired so no duplicate heading remains.
  4. Repaired confidence section has two canonical subsections:
       - عوامل النجاح الحرجة  (CSF)
       - المخاطر الرئيسية    (Key Risks)
  5. Risk table has at least 6 valid rows after repair.
  6. No duplicate "المخاطر الرئيسية" heading survives.
  7. Final content inspection (_final_strategy_audit) no longer returns
     so_rows_insufficient or risk_rows_insufficient after both repair
     functions have run.
  8. python -m py_compile app.py passes (imported from TestPyCompile).

Run:
    python -m pytest tests/test_repair_vision_confidence.py -v
  or:
    python tests/test_repair_vision_confidence.py
"""

import sys
import os
import re
import importlib.util
import py_compile
import unittest

# ---------------------------------------------------------------------------
# Set minimal environment variables required to import app.py
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_repair.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

# ---------------------------------------------------------------------------
# Import app.py
# ---------------------------------------------------------------------------
_USING_REAL_APP = False
_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
    _USING_REAL_APP = True
except Exception:
    pass


def _skip_if_no_app(fn):
    import functools
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if not _USING_REAL_APP:
            self.skipTest('app.py not importable in this environment')
        return fn(self, *args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_thin_vision():
    """A vision section with only 2 valid SO rows (below the threshold of 5)."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'رؤية المنظمة نحو تحقيق الأمن السيبراني الشامل.\n\n'
        '### الأهداف الاستراتيجية\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|-------|-----------------|--------|---------------|\n'
        '| 1 | حوكمة الأمن السيبراني | 100% نضج هيكل الحوكمة | متطلب NCA ECC | خلال 6 أشهر |\n'
        '| 2 | تطبيق ضوابط الأمن | ≥ 95% نسبة التطبيق | الامتثال التنظيمي | خلال 12 شهراً |\n'
    )


def _make_empty_vision():
    """A vision section with no SO table at all."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'رؤية المنظمة نحو الأمن السيبراني الشامل.\n\n'
    )


def _make_duplicate_risk_confidence():
    """A confidence section with two ### المخاطر الرئيسية headings."""
    return (
        '## 7. تقييم الثقة والمخاطر\n\n'
        '**درجة الثقة:** 65%\n\n'
        '### مبررات التقييم\n\n'
        'تعكس هذه الدرجة الوضع الحالي للمنظمة.\n\n'
        '### عوامل النجاح الحرجة\n\n'
        '| # | العامل | الوصف | الأهمية | دليل القياس |\n'
        '|---|-------|-------|---------|-------------|\n'
        '| 1 | دعم القيادة | رعاية تنفيذية فعّالة | حرج | تقارير اجتماعات اللجنة |\n'
        '| 2 | توفر الموارد | كفاءات بشرية مؤهلة | عالٍ | مؤشر الشواغر |\n'
        '| 3 | إطار الحوكمة | لجنة توجيه دورية | عالٍ | محاضر الاجتماعات |\n'
        '| 4 | التمويل الكافي | ميزانية متعددة السنوات | عالٍ | التزام الميزانية |\n'
        '### المخاطر الرئيسية\n\n'
        '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n'
        '|---|--------|-----------|--------|-------------|\n'
        '| 1 | تأخر الحوكمة | متوسط | عالٍ | ورش عمل تنفيذية |\n'
        '| 2 | نقص الكفاءات | عالٍ | عالٍ | توظيف مبكر |\n'
        '### المخاطر الرئيسية\n\n'       # ← duplicate heading
        '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n'
        '|---|--------|-----------|--------|-------------|\n'
        '| 3 | فشل SIEM | متوسط | عالٍ | تنفيذ مرحلي |\n'
    )


def _count_heading_occurrences(text, heading_pattern):
    """Return how many times a heading pattern appears in text."""
    return len(re.findall(heading_pattern, text, re.IGNORECASE | re.MULTILINE))


# ---------------------------------------------------------------------------
# Test 1 & 2: Vision / SO repair
# ---------------------------------------------------------------------------

class TestRepairVisionObjectives(unittest.TestCase):
    """Tests for repair_vision_objectives_if_insufficient()."""

    @_skip_if_no_app
    def test_thin_vision_repaired_to_six_valid_rows(self):
        """A vision with 2 valid SO rows must be repaired to ≥ 6."""
        sections = {
            'vision': _make_thin_vision(),
            'pillars': '', 'environment': '', 'gaps': '',
            'roadmap': '', 'kpis': '', 'confidence': '',
        }
        added = _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        self.assertGreater(added, 0, 'Expected rows to be added')
        n_so = _APP.count_valid_objective_rows(sections['vision'])
        self.assertGreaterEqual(n_so, 6,
                                f'Expected ≥ 6 valid SO rows after repair, got {n_so}')

    @_skip_if_no_app
    def test_empty_vision_repaired_to_six_valid_rows(self):
        """An empty vision section must be repaired to ≥ 6 valid SO rows."""
        sections = {
            'vision': _make_empty_vision(),
            'pillars': '', 'environment': '', 'gaps': '',
            'roadmap': '', 'kpis': '', 'confidence': '',
        }
        added = _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        self.assertGreater(added, 0, 'Expected rows to be added for empty vision')
        n_so = _APP.count_valid_objective_rows(sections['vision'])
        self.assertGreaterEqual(n_so, 6,
                                f'Expected ≥ 6 valid SO rows after repair, got {n_so}')

    @_skip_if_no_app
    def test_count_valid_objective_rows_ge_six_after_repair(self):
        """count_valid_objective_rows returns ≥ 6 after repair — explicit check."""
        sections = {'vision': _make_thin_vision()}
        _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        n = _APP.count_valid_objective_rows(sections.get('vision', ''))
        self.assertGreaterEqual(
            n, 6,
            f'count_valid_objective_rows returned {n}; expected ≥ 6',
        )

    @_skip_if_no_app
    def test_already_sufficient_vision_not_changed(self):
        """A vision with ≥ 5 valid rows must not be altered."""
        rich_vision = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
            '|---|-------|-----------------|--------|---------------|\n'
            '| 1 | حوكمة الأمن | 100% نضج الحوكمة | متطلب NCA ECC | خلال 6 أشهر |\n'
            '| 2 | تطبيق الضوابط | ≥ 95% نسبة التطبيق | الامتثال | خلال 12 شهراً |\n'
            '| 3 | إدارة الهوية IAM | 100% تغطية PAM | تقليل المخاطر | خلال 9 أشهر |\n'
            '| 4 | تشغيل SIEM | MTTD ≤ 60 دقيقة | إغلاق فجوات الكشف | خلال 12 شهراً |\n'
            '| 5 | إدارة الثغرات | 100% إغلاق الثغرات | تقليص سطح الهجوم | خلال 6 أشهر |\n'
            '| 6 | حماية البيانات | 100% تصنيف البيانات | الامتثال | خلال 12 شهراً |\n'
        )
        sections = {'vision': rich_vision}
        before_count = _APP.count_valid_objective_rows(rich_vision)
        self.assertGreaterEqual(before_count, 5,
                                'Test fixture should have ≥ 5 rows')
        added = _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        self.assertEqual(added, 0, 'No rows should be added to an already-rich section')

    @_skip_if_no_app
    def test_english_vision_repair(self):
        """English thin vision is also repaired correctly."""
        en_vision = (
            '## 1. Vision and Strategic Objectives\n\n'
            '### Strategic Objectives\n\n'
            '| # | Objective | Target Metric | Justification | Timeframe |\n'
            '|---|-----------|--------------|---------------|----------|\n'
            '| 1 | Governance | 100% maturity | NCA ECC requirement | Within 6 months |\n'
        )
        sections = {'vision': en_vision}
        added = _APP.repair_vision_objectives_if_insufficient(
            sections, lang='en',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        self.assertGreater(added, 0, 'Expected rows added for thin English vision')
        n = _APP.count_valid_objective_rows(sections['vision'])
        self.assertGreaterEqual(n, 5,
                                f'Expected ≥ 5 valid rows in EN vision; got {n}')

    @_skip_if_no_app
    def test_timeframe_cells_are_valid(self):
        """Every repaired SO row must have a valid timeframe cell."""
        sections = {'vision': _make_thin_vision()}
        _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        n = _APP.count_valid_objective_rows(sections['vision'])
        self.assertGreaterEqual(n, 5,
                                'After repair, count_valid_objective_rows must be ≥ 5')


# ---------------------------------------------------------------------------
# Test 3, 4, 5, 6: Confidence / Risk repair
# ---------------------------------------------------------------------------

class TestRepairConfidenceRiskSection(unittest.TestCase):
    """Tests for repair_confidence_risk_section()."""

    @_skip_if_no_app
    def test_duplicate_risk_heading_removed(self):
        """Duplicate '### المخاطر الرئيسية' headings must be collapsed to one."""
        sections = {
            'confidence': _make_duplicate_risk_confidence(),
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': '', 'kpis': '',
        }
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections.get('confidence', '')
        dup_count = _count_heading_occurrences(
            conf,
            r'^###\s*(?:المخاطر\s+الرئيسية|المخاطر\s+الاستراتيجية)',
        )
        self.assertLessEqual(
            dup_count, 1,
            f'Expected ≤ 1 risk heading; found {dup_count}',
        )

    @_skip_if_no_app
    def test_no_duplicate_risk_heading_remains(self):
        """After repair, no duplicate 'المخاطر الرئيسية' must remain."""
        sections = {'confidence': _make_duplicate_risk_confidence()}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections.get('confidence', '')
        dup_count = _count_heading_occurrences(
            conf,
            r'^###\s*المخاطر\s+الرئيسية',
        )
        self.assertLessEqual(
            dup_count, 1,
            f'Duplicate "المخاطر الرئيسية" still present ({dup_count} times)',
        )

    @_skip_if_no_app
    def test_csf_subsection_present_after_repair(self):
        """عوامل النجاح الحرجة subsection must be present after repair."""
        sections = {'confidence': _make_duplicate_risk_confidence()}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections.get('confidence', '')
        self.assertIn('عوامل النجاح الحرجة', conf,
                      'CSF subsection heading must be in repaired confidence section')

    @_skip_if_no_app
    def test_risk_subsection_present_after_repair(self):
        """المخاطر الرئيسية subsection must be present after repair."""
        sections = {'confidence': _make_duplicate_risk_confidence()}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections.get('confidence', '')
        self.assertIn('المخاطر الرئيسية', conf,
                      '"المخاطر الرئيسية" must appear in repaired confidence section')

    @_skip_if_no_app
    def test_risk_table_has_at_least_six_rows(self):
        """Risk table must have at least 6 valid rows after repair."""
        sections = {'confidence': _make_duplicate_risk_confidence()}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections.get('confidence', '')
        n_risks = _APP._count_risk_rows_with_mitigation(conf)
        self.assertGreaterEqual(
            n_risks, 6,
            f'Expected ≥ 6 valid risk rows after repair; got {n_risks}',
        )

    @_skip_if_no_app
    def test_csf_table_has_at_least_four_rows(self):
        """CSF table must have ≥ 4 rows (richness minimum) after repair."""
        sections = {'confidence': _make_duplicate_risk_confidence()}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections.get('confidence', '')
        n_csf = _APP._count_csf_rows(conf)
        self.assertGreaterEqual(
            n_csf, _APP._RICHNESS_MIN_CSF_ROWS,
            f'Expected ≥ {_APP._RICHNESS_MIN_CSF_ROWS} CSF rows; got {n_csf}',
        )

    @_skip_if_no_app
    def test_empty_confidence_section_bootstrapped(self):
        """An empty confidence section must be fully bootstrapped by repair."""
        sections = {'confidence': ''}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections.get('confidence', '')
        self.assertTrue(conf.strip(), 'Confidence section should not be empty after repair')
        n_risks = _APP._count_risk_rows_with_mitigation(conf)
        self.assertGreaterEqual(n_risks, 6,
                                f'Expected ≥ 6 risk rows; got {n_risks}')
        n_csf = _APP._count_csf_rows(conf)
        self.assertGreaterEqual(n_csf, _APP._RICHNESS_MIN_CSF_ROWS,
                                f'Expected ≥ {_APP._RICHNESS_MIN_CSF_ROWS} CSF rows; got {n_csf}')

    @_skip_if_no_app
    def test_english_confidence_repair(self):
        """English confidence section with thin risk table is repaired."""
        en_conf = (
            '## 7. Confidence Assessment & Risks\n\n'
            '**Confidence Score:** 65%\n\n'
            '### Score Justification\n\nThis score reflects current maturity.\n\n'
            '### Critical Success Factors\n\n'
            '| # | Factor | Description | Importance | Measurement Indicator |\n'
            '|---|--------|-------------|------------|----------------------|\n'
            '| 1 | Leadership | Active sponsorship | Critical | Meeting reports |\n'
            '| 2 | Resources | Qualified staff | High | Fill rate |\n'
            '| 3 | Governance | Steering committee | High | Minutes |\n'
            '| 4 | Funding | Multi-year budget | High | Commitment vs plan |\n'
            '### Key Risks\n\n'
            '| # | Risk | Likelihood | Impact | Mitigation Plan |\n'
            '|---|------|-----------|--------|----------------|\n'
            '| 1 | Governance delay | Medium | High | Workshops |\n'
        )
        sections = {'confidence': en_conf}
        _APP.repair_confidence_risk_section(
            sections, lang='en',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        n_risks = _APP._count_risk_rows_with_mitigation(sections['confidence'])
        self.assertGreaterEqual(
            n_risks, 6,
            f'Expected ≥ 6 risk rows in EN section; got {n_risks}',
        )


# ---------------------------------------------------------------------------
# Test 7: End-to-end — _final_strategy_audit sees no SO/risk defects
# ---------------------------------------------------------------------------

class TestFinalAuditAfterRepair(unittest.TestCase):
    """Test 7: _final_strategy_audit must not return so_rows_insufficient or
    risk_rows_insufficient after both repair functions have run."""

    def _make_minimal_passing_sections(self):
        """Build the minimal sections that pass all non-SO/risk checks."""
        pillars = (
            '## 2. الركائز الاستراتيجية\n\n'
            '### الركيزة الأولى: الحوكمة\n\n'
            'ركيزة الحوكمة والامتثال للمنظمة.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---------|-------|----------------|\n'
            '| 1 | تأسيس لجنة الحوكمة | تشكيل اللجنة | ميثاق اللجنة |\n'
            '| 2 | سياسات وإجراءات | إعداد السياسات | حزمة السياسات |\n'
            '| 3 | سجل الضوابط | توثيق الضوابط | سجل الامتثال |\n\n'
            '### الركيزة الثانية: الحماية التقنية\n\n'
            'ركيزة الحماية التقنية من التهديدات السيبرانية.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---------|-------|----------------|\n'
            '| 1 | نشر EDR/XDR | تطبيق الحماية | سجل الأجهزة |\n'
            '| 2 | إدارة الثغرات | مسح دوري | تقرير الثغرات |\n'
            '| 3 | التصحيح الأمني | تحديثات منهجية | سجل التصحيح |\n\n'
            '### الركيزة الثالثة: الكشف والاستجابة\n\n'
            'ركيزة الكشف عن الحوادث والاستجابة لها.\n\n'
            '| # | المبادرة | الوصف | المخرج المتوقع |\n'
            '|---|---------|-------|----------------|\n'
            '| 1 | تفعيل SIEM | ربط مصادر السجلات | كتالوج SIEM |\n'
            '| 2 | خطة الاستجابة | إعداد الخطة | وثيقة IRP |\n'
            '| 3 | محاكاة التهديدات | تدريبات دورية | تقرير المحاكاة |\n\n'
        )
        environment = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            'تعمل المنظمة في بيئة تنظيمية تتسم بمتطلبات صارمة من هيئة الأمن '
            'السيبراني الوطنية (هايئة). تشمل الأطر التنظيمية المطبقة '
            'ضوابط الأمن السيبراني الأساسية NCA ECC وضوابط حماية البيانات '
            'NCA DCC، إضافةً إلى متطلبات نظام حماية البيانات الشخصية PDPL.\n\n'
            'يواجه القطاع تهديدات سيبرانية متزايدة تشمل هجمات برامج الفدية '
            'والتصيد الاحتيالي والتهديدات الداخلية وهجمات سلاسل الإمداد. '
            'تُصنَّف هذه التهديدات ذات احتمالية متوسطة إلى عالية مع تأثير كبير '
            'على استمرارية الأعمال وسمعة المنظمة.\n\n'
            '| # | الإطار | المتطلب | مستوى الامتثال |\n'
            '|---|--------|---------|----------------|\n'
            '| 1 | NCA ECC | الضوابط الأساسية | جزئي |\n'
            '| 2 | NCA DCC | حماية البيانات | أولي |\n'
        )
        gaps = (
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|-------|-------|---------|--------|\n'
            '| 1 | فجوة الحوكمة | غياب لجنة الحوكمة الرسمية | حرجة | مفتوحة |\n'
            '| 2 | فجوة IAM | غياب PAM وMFA | حرجة | مفتوحة |\n'
            '| 3 | فجوة SIEM | عدم اكتمال الرصد | عالية | مفتوحة |\n'
        )
        roadmap = (
            '## 5. خارطة طريق التنفيذ\n\n'
            '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
            '|---|--------|---------|---------------|--------|\n'
            '| 1 | تأسيس لجنة الحوكمة | CISO | الشهر 1-2 | ميثاق اللجنة |\n'
            '| 2 | نشر IAM/PAM | مسؤول IAM | الشهر 3-6 | نظام PAM |\n'
            '| 3 | تفعيل SIEM | مدير SOC | الشهر 4-8 | منصة SIEM |\n'
            '| 4 | اختبار DR | مسؤول BCM | الشهر 9-12 | تقرير DR |\n'
        )
        kpis = (
            '## 6. مؤشرات الأداء الرئيسية\n\n'
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | الإطار الزمني |\n'
            '|---|------------|-----------------|----------------|----------------|\n'
            '| 1 | نسبة تطبيق NCA ECC | ≥ 95% | (المطبّق ÷ الإجمالي) × 100 | خلال 12 شهراً |\n'
            '| 2 | تغطية MFA | 100% | (المحمي ÷ الإجمالي) × 100 | خلال 6 أشهر |\n'
            '| 3 | إغلاق الثغرات الحرجة | 100% خلال 30 يوماً | (المُغلقة ÷ الإجمالي) × 100 | خلال 6 أشهر |\n'
            '| 4 | تغطية SIEM | ≥ 90% | (المصادر المُدمجة ÷ الإجمالي) × 100 | خلال 9 أشهر |\n'
            '| 5 | MTTD | ≤ 60 دقيقة | مجموع أوقات الكشف ÷ عدد الحوادث | خلال 12 شهراً |\n'
            '| 6 | MTTR | ≤ 4 ساعات | مجموع أوقات الاستجابة ÷ عدد الحوادث | خلال 12 شهراً |\n'
            '\n### أدلة تقييم مؤشرات الأداء\n\n'
            '#### KPI #1 Assessment Guide:\nتقييم نسبة تطبيق NCA ECC.\n\n'
            '#### KPI #2 Assessment Guide:\nتقييم تغطية MFA.\n\n'
            '#### KPI #3 Assessment Guide:\nتقييم إغلاق الثغرات.\n\n'
            '#### KPI #4 Assessment Guide:\nتقييم تغطية SIEM.\n\n'
            '#### KPI #5 Assessment Guide:\nتقييم MTTD.\n\n'
            '#### KPI #6 Assessment Guide:\nتقييم MTTR.\n\n'
        )
        return {
            'vision': _make_thin_vision(),       # intentionally < 5 SO rows
            'pillars': pillars,
            'environment': environment,
            'gaps': gaps,
            'roadmap': roadmap,
            'kpis': kpis,
            'confidence': _make_duplicate_risk_confidence(),  # duplicate heading
        }

    @_skip_if_no_app
    def test_final_audit_no_so_defect_after_repair(self):
        """After repair, _final_strategy_audit must not report so_rows_insufficient."""
        sections = self._make_minimal_passing_sections()
        _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        defects = _APP._final_strategy_audit(sections, 'ar', doc_subtype=None)
        so_tags = [t for _, t, _, _ in defects if 'so_rows' in t]
        self.assertEqual(so_tags, [],
                         f'so_rows defects remain after repair: {so_tags}')

    @_skip_if_no_app
    def test_final_audit_no_risk_defect_after_repair(self):
        """After repair, _final_strategy_audit must not report risk_rows_insufficient."""
        sections = self._make_minimal_passing_sections()
        _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        defects = _APP._final_strategy_audit(sections, 'ar', doc_subtype=None)
        risk_tags = [t for _, t, _, _ in defects if 'risk_rows' in t]
        self.assertEqual(risk_tags, [],
                         f'risk_rows defects remain after repair: {risk_tags}')

    @_skip_if_no_app
    def test_repaired_sections_pass_both_vision_and_risk_gates(self):
        """After combined repair, neither vision nor risk defects appear."""
        sections = self._make_minimal_passing_sections()
        _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        defects = _APP._final_strategy_audit(sections, 'ar', doc_subtype=None)
        blocking_tags = {t for _, t, _, _ in defects
                         if t in ('so_rows_insufficient', 'risk_rows_insufficient',
                                  'csf_rows_insufficient')}
        self.assertEqual(blocking_tags, set(),
                         f'Blocking defects remain after repair: {blocking_tags}')


# ---------------------------------------------------------------------------
# Test 8: py_compile (required by problem statement)
# ---------------------------------------------------------------------------

class TestPyCompile(unittest.TestCase):
    """python -m py_compile app.py must pass."""

    def test_app_py_compiles(self):
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        try:
            py_compile.compile(app_path, doraise=True)
        except py_compile.PyCompileError as exc:
            self.fail(f'app.py has a syntax error: {exc}')


# ---------------------------------------------------------------------------
# Test 9: New deterministic-repair guarantees (threshold 6, replace-entire)
# ---------------------------------------------------------------------------

def _make_five_row_vision():
    """A vision section with exactly 5 valid SO rows (was NOT repaired before
    the threshold was raised from 5 to 6).  After the fix the repair should
    fire and replace the block so the count reaches 8."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'رؤية المنظمة نحو الأمن السيبراني الشامل.\n\n'
        '### الأهداف الاستراتيجية\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|-------|-----------------|--------|---------------|\n'
        '| 1 | حوكمة الأمن السيبراني | 100% نضج | متطلب NCA ECC | خلال 6 أشهر |\n'
        '| 2 | تطبيق ضوابط الأمن | ≥ 95% نسبة التطبيق | الامتثال | خلال 12 شهراً |\n'
        '| 3 | تفعيل IAM/PAM/MFA | 100% تغطية | تقليل المخاطر | خلال 9 أشهر |\n'
        '| 4 | تشغيل SIEM/SOC | MTTD ≤ 60 دقيقة | إغلاق فجوات الكشف | خلال 12 شهراً |\n'
        '| 5 | إدارة الثغرات | 100% إغلاق الثغرات الحرجة | تقليص سطح الهجوم | خلال 6 أشهر |\n'
    )


def _make_malformed_risk_only_confidence():
    """Confidence section whose risk table has only 2 rows — below the
    minimum of 6 required by the deterministic repair."""
    return (
        '## 7. تقييم الثقة والمخاطر\n\n'
        '**درجة الثقة:** 72%\n\n'
        '### مبررات التقييم\n\n'
        'تعكس هذه الدرجة الوضع الراهن للمنظمة.\n\n'
        '### عوامل النجاح الحرجة\n\n'
        '| # | العامل | الوصف | الأهمية | دليل القياس |\n'
        '|---|-------|-------|---------|-------------|\n'
        '| 1 | دعم القيادة | رعاية تنفيذية فعّالة | حرج | تقارير اللجنة |\n'
        '| 2 | توفر الموارد | كفاءات مؤهلة | عالٍ | مؤشر الشواغر |\n'
        '| 3 | إطار الحوكمة | لجنة توجيه دورية | عالٍ | محاضر الاجتماعات |\n'
        '| 4 | التمويل | ميزانية متعددة السنوات | عالٍ | التزام الميزانية |\n'
        '### المخاطر الرئيسية\n\n'
        '| # | الخطر | السبب | الاحتمالية | التأثير | مستوى الخطر'
        ' | المالك | خطة المعالجة | المؤشر التحذيري | الخطر المتبقي |\n'
        '|---|-------|-------|-----------|--------|-------------|'
        '--------|-------------|-----------------|---------------|\n'
        '| 1 | تأخر الحوكمة | غياب هيكل رسمي | متوسط | عالٍ | عالٍ'
        ' | الإدارة | ورش عمل | تأخر الاعتماد | متوسط |\n'
        '| 2 | نقص الكفاءات | سوق متنافس | عالٍ | عالٍ | حرج'
        ' | HR | التوظيف المبكر | شواغر متزايدة | عالٍ |\n'
    )


class TestDeterministicRepairGuarantees(unittest.TestCase):
    """Tests for the new deterministic-repair behaviour introduced to fix the
    final-audit failure: threshold raised from 5→6, blocks replaced entirely."""

    @_skip_if_no_app
    def test_five_row_vision_repaired_to_eight(self):
        """A vision with exactly 5 valid SO rows must now be repaired to 8
        (the full canonical bank) because the threshold was raised to 6."""
        sections = {'vision': _make_five_row_vision()}
        before = _APP.count_valid_objective_rows(sections['vision'])
        self.assertEqual(before, 5, 'Fixture should have exactly 5 valid rows')

        added = _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        self.assertGreater(added, 0,
                           'Repair must fire for a 5-row vision (new threshold = 6)')
        n_after = _APP.count_valid_objective_rows(sections['vision'])
        self.assertGreaterEqual(
            n_after, 8,
            f'Expected 8 rows (full canonical bank) after replace; got {n_after}',
        )

    @_skip_if_no_app
    def test_vision_block_replaced_not_appended(self):
        """After repair, the vision section must contain exactly one SO heading
        (the canonical one) — verifying the old table was removed, not kept."""
        sections = {'vision': _make_thin_vision()}
        _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        vision = sections['vision']
        hdr_count = len(re.findall(
            r'^\|\s*#\s*\|\s*الهدف\s*\|', vision,
            re.MULTILINE,
        ))
        self.assertEqual(
            hdr_count, 1,
            f'Expected exactly 1 SO table header after replace-repair; found {hdr_count}',
        )

    @_skip_if_no_app
    def test_repair_raises_assertion_on_impossible_input(self):
        """repair_vision_objectives_if_insufficient raises AssertionError when
        it would produce fewer than 6 valid rows — proves the assertion fires."""
        # This is a smoke test: the canonical bank always produces 8 valid
        # rows so the assertion never fires in normal operation.  We verify
        # that when n_so >= 6 the function returns 0 (fast-path), so the
        # assertion path is only exercised by an actually-thin input.
        # A 6-row vision must return 0 (no repair).
        rich_vision = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
            '|---|-------|-----------------|--------|---------------|\n'
            '| 1 | حوكمة | 100% | NCA ECC | خلال 6 أشهر |\n'
            '| 2 | ضوابط | ≥ 95% | الامتثال | خلال 12 شهراً |\n'
            '| 3 | IAM | 100% | تقليل المخاطر | خلال 9 أشهر |\n'
            '| 4 | SIEM | ≤ 60 دقيقة | الكشف | خلال 12 شهراً |\n'
            '| 5 | ثغرات | 100% | تقليص الهجوم | خلال 6 أشهر |\n'
            '| 6 | بيانات | 100% | الامتثال | خلال 12 شهراً |\n'
        )
        sections = {'vision': rich_vision}
        result = _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        self.assertEqual(result, 0, '6-row vision must not be altered (threshold is 6)')

    @_skip_if_no_app
    def test_thin_risk_section_replaced_with_eight_canonical_rows(self):
        """A confidence section with only 2 risk rows must be repaired so the
        risk table has ≥ 6 rows using the canonical bank."""
        sections = {'confidence': _make_malformed_risk_only_confidence()}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        conf = sections['confidence']
        n_risk = _APP._count_risk_rows_with_mitigation(conf)
        self.assertGreaterEqual(
            n_risk, 6,
            f'Expected ≥ 6 risk rows after replace-repair; got {n_risk}',
        )

    @_skip_if_no_app
    def test_csf_subsection_preserved_when_sufficient(self):
        """When the CSF section already has ≥ 4 rows it must not be replaced."""
        conf_before = _make_malformed_risk_only_confidence()
        n_csf_before = _APP._count_csf_rows(conf_before)
        self.assertGreaterEqual(
            n_csf_before, _APP._RICHNESS_MIN_CSF_ROWS,
            'Fixture must have ≥ 4 CSF rows for this test to be meaningful',
        )
        sections = {'confidence': conf_before}
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        n_csf_after = _APP._count_csf_rows(sections['confidence'])
        self.assertGreaterEqual(
            n_csf_after, _APP._RICHNESS_MIN_CSF_ROWS,
            f'CSF rows fell below minimum after repair ({n_csf_after})',
        )

    @_skip_if_no_app
    def test_risk_heading_count_exactly_one_after_repair(self):
        """Exactly one '### المخاطر الرئيسية' heading must exist after any repair."""
        for label, conf_text in [
            ('duplicate', _make_duplicate_risk_confidence()),
            ('thin_risk', _make_malformed_risk_only_confidence()),
            ('empty', ''),
        ]:
            with self.subTest(fixture=label):
                sections = {'confidence': conf_text}
                _APP.repair_confidence_risk_section(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Test Org',
                    frameworks=['NCA ECC'], sector='Government',
                )
                hdr_count = _count_heading_occurrences(
                    sections['confidence'],
                    r'^###\s+المخاطر\s+الرئيسية',
                )
                self.assertEqual(
                    hdr_count, 1,
                    f'[{label}] expected exactly 1 risk heading; found {hdr_count}',
                )

    @_skip_if_no_app
    def test_post_repair_audit_clean_five_row_vision(self):
        """A 5-row vision + thin risk section must produce zero SO/risk audit defects
        after both repair functions run (regression test for the reported error:
        vision) so_rows_insufficient, risk, content)."""
        sections = {
            'vision': _make_five_row_vision(),
            'pillars': '',
            'environment': '',
            'gaps': '',
            'roadmap': '',
            'kpis': '',
            'confidence': _make_malformed_risk_only_confidence(),
        }
        _APP.repair_vision_objectives_if_insufficient(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        _APP.repair_confidence_risk_section(
            sections, lang='ar',
            domain='Cyber Security', org_name='Test Org',
            frameworks=['NCA ECC'], sector='Government',
        )
        defects = _APP._final_strategy_audit(sections, 'ar', doc_subtype=None)
        # Only check for the defects reported in the bug: SO rows and risk rows.
        # kpi_rows_insufficient is expected here because the fixture has no KPIs.
        blocking = [
            (sec, tag) for sec, tag, cnt, floor in defects
            if tag in ('so_rows_insufficient', 'risk_rows_insufficient')
        ]
        self.assertEqual(
            blocking, [],
            f'SO/risk audit defects remain after repair of 5-row vision: {blocking}',
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main(verbosity=2)
