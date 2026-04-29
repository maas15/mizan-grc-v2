"""Tests for repair_kpi_section_if_missing_frequency.

Addresses: "(kpis) missing_frequency_column" after strategy regeneration.

Covers:
  1. A KPI section missing "التكرار" is repaired to include the canonical
     Arabic KPI table with التكرار column.
  2. The repaired KPI table contains at least 8 KPI/KRI rows.
  3. The repaired KPI table contains:
       - مصدر البيانات
       - المالك
       - التكرار
       - الإطار الزمني
  4. After repair, validate_arabic_strategy_semantic_richness no longer
     returns (kpis_missing_frequency_column, ...).
  5. KPI repair does not modify sections["vision"], sections["gaps"],
     sections["roadmap"], or sections["confidence"].
  6. Existing trace-table-safety tests still pass (py_compile).
  7. KPI section missing frequency uses the 9-column canonical schema.
  8. count_substantive_kpis and count_substantive_kpis_strict correctly
     count rows from the canonical 9-column (المؤشر header) table.
  9. English KPI section missing Frequency is repaired similarly.
 10. If frequency is already present, repair is a no-op (0 rows returned).

Run:
    python -m pytest tests/test_kpi_frequency_repair.py -v
  or:
    python tests/test_kpi_frequency_repair.py
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
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_kpi_freq.db')
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
except Exception as _import_err:
    print(f'[WARN] Could not import app.py: {_import_err}')


def _skip_if_no_app(fn):
    import functools
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if not _USING_REAL_APP:
            self.skipTest('app.py not importable in this environment')
        return fn(self, *args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_OLD_SCHEMA_KPI_SECTION_AR = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | المبرر | الإطار الزمني |\n'
    '|---|-------------|-----------------|----------------|--------|----------------|\n'
    '| 1 | نسبة تطبيق ضوابط NCA ECC | 90% | (المطبق ÷ الإجمالي) × 100 | امتثال تنظيمي | خلال 12 شهراً |\n'
    '| 2 | نسبة إغلاق الفجوات | 100% | (المغلق ÷ الإجمالي) × 100 | تتبع التقدم | خلال 9 أشهر |\n'
    '| 3 | متوسط زمن الاستجابة | ≤ 4 ساعات | مجموع الأوقات ÷ العدد | جاهزية SOC | خلال 6 أشهر |\n'
    '| 4 | نسبة تدريب التوعية | ≥ 90% | (المجتازين ÷ المستهدفين) × 100 | تقليل المخاطر البشرية | خلال 9 أشهر |\n'
    '| 5 | تغطية تقييم الموردين | 100% | (المقيّم ÷ الإجمالي) × 100 | مخاطر سلسلة الإمداد | خلال 12 شهراً |\n'
    '| 6 | نسبة اكتمال السياسات | ≥ 95% | (السياسات المعتمدة ÷ الإجمالي) × 100 | متطلب حوكمة | خلال 6 أشهر |\n'
)

_ALREADY_HAS_FREQUENCY_AR = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب '
    '| مصدر البيانات | المالك | التكرار | الإطار الزمني |\n'
    '|---|--------|---------------|-----------------|---------------|'
    '----------------|--------|----------|----------------|\n'
    '| 1 | نسبة تطبيق ضوابط NCA ECC | KPI | 90% | (المطبق ÷ الإجمالي) × 100 '
    '| سجل الضوابط | فريق الحوكمة | شهري | خلال 12 شهراً |\n'
)

_OLD_SCHEMA_KPI_SECTION_EN = (
    '## 6. Key Performance Indicators\n\n'
    '| # | KPI Description | Target Value | Calculation Formula | Justification | Timeframe |\n'
    '|---|-----------------|--------------|---------------------|---------------|-----------|\n'
    '| 1 | NCA ECC Control Implementation Rate | 90% | (Implemented ÷ Total) × 100 | Regulatory compliance | Within 12 months |\n'
    '| 2 | Gap Closure Rate | 100% | (Closed ÷ Total) × 100 | Track progress | Within 9 months |\n'
    '| 3 | Mean Incident Response Time | ≤ 4 hours | Sum of times ÷ Count | SOC readiness | Within 6 months |\n'
    '| 4 | Awareness Training Pass Rate | ≥ 90% | (Passed ÷ Enrolled) × 100 | Reduce human risk | Within 9 months |\n'
    '| 5 | Third-Party Assessment Coverage | 100% | (Assessed ÷ Total) × 100 | Supply chain risk | Within 12 months |\n'
)


def _make_full_sections_ar(kpis_text=None):
    """Return a minimal but structurally valid sections dict for Arabic."""
    return {
        'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            'رؤية المنظمة.\n\n'
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
            '|---|-------|-----------------|--------|---------------|\n'
            '| 1 | هدف 1 | مقياس 1 | مبرر 1 | خلال 6 أشهر |\n'
            '| 2 | هدف 2 | مقياس 2 | مبرر 2 | خلال 12 شهراً |\n'
        ),
        'pillars': '## 2. الركائز الاستراتيجية\n\n### الركيزة 1\n\n| # | المبادرة | الوصف | المخرج |\n|---|---------|-------|-------|\n| 1 | مبادرة | وصف | مخرج |\n',
        'environment': '## 3. البيئة التنظيمية والتهديدات\n\nفقرة أولى عن البيئة التنظيمية.\n\nفقرة ثانية عن التهديدات السيبرانية.\n',
        'gaps': '## 4. تحليل الفجوات\n\n| # | الفجوة | الوصف | الأولوية | الحالة |\n|---|-------|-------|----------|--------|\n| 1 | فجوة 1 | وصف 1 | عالٍ | مفتوح |\n| 2 | فجوة 2 | وصف 2 | متوسط | مفتوح |\n',
        'roadmap': '## 5. خارطة الطريق التنفيذية\n\n| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n|---|-------|---------|----------------|-------|\n| 1 | نشاط 1 | مسؤول 1 | ربع 1 | مخرج 1 |\n| 2 | نشاط 2 | مسؤول 2 | ربع 2 | مخرج 2 |\n| 3 | نشاط 3 | مسؤول 3 | ربع 3 | مخرج 3 |\n| 4 | نشاط 4 | مسؤول 4 | ربع 4 | مخرج 4 |\n',
        'kpis': kpis_text or _OLD_SCHEMA_KPI_SECTION_AR,
        'confidence': (
            '## 7. تقييم الثقة والمخاطر\n\n'
            '**درجة الثقة:** 70%\n\n'
            'مبررات: التقدم المحرز يدعم الثقة بالنتائج.\n\n'
            '### عوامل النجاح الحرجة\n\n'
            '| # | العامل | الوصف | الأهمية | دليل القياس |\n'
            '|---|-------|-------|---------|-------------|\n'
            '| 1 | دعم القيادة | دعم فعّال من الإدارة العليا | حرج | اجتماعات الحوكمة |\n'
            '| 2 | الكوادر | كوادر مؤهلة | عالٍ | سجل التدريب |\n'
            '| 3 | الموارد | موارد كافية | عالٍ | الميزانية المعتمدة |\n'
            '| 4 | الشراكات | شراكات استراتيجية | متوسط | اتفاقيات الشراكة |\n'
            '### المخاطر الرئيسية\n\n'
            '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة | المالك | مؤشر الإنذار المبكر |\n'
            '|---|--------|-----------|--------|-------------|--------|--------------------|\n'
            '| 1 | مخاطر 1 | متوسط | عالٍ | خطة 1 | مدير | مؤشر 1 |\n'
            '| 2 | مخاطر 2 | عالٍ | متوسط | خطة 2 | مدير | مؤشر 2 |\n'
            '| 3 | مخاطر 3 | منخفض | عالٍ | خطة 3 | مدير | مؤشر 3 |\n'
            '| 4 | مخاطر 4 | متوسط | متوسط | خطة 4 | مدير | مؤشر 4 |\n'
            '| 5 | مخاطر 5 | عالٍ | عالٍ | خطة 5 | مدير | مؤشر 5 |\n'
            '| 6 | مخاطر 6 | منخفض | متوسط | خطة 6 | مدير | مؤشر 6 |\n'
        ),
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestKpiFrequencyRepair(unittest.TestCase):

    @_skip_if_no_app
    def test_missing_frequency_triggers_repair(self):
        """A KPI section without التكرار returns > 0 from repair function."""
        sections = _make_full_sections_ar()
        result = _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar',
            domain='Cyber Security',
            org_name='Test Org',
            sector='Government',
            frameworks=['NCA ECC'],
        )
        self.assertGreater(result, 0,
            'Repair should write rows when التكرار is absent')

    @_skip_if_no_app
    def test_repaired_table_has_at_least_8_rows(self):
        """The repaired KPI table contains at least 8 KPI/KRI rows."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        row_count = _APP.count_substantive_kpis(sections['kpis'])
        self.assertGreaterEqual(row_count, 8,
            f'Expected ≥ 8 rows, got {row_count}')

    @_skip_if_no_app
    def test_repaired_table_has_required_columns(self):
        """The repaired KPI table contains مصدر البيانات، المالك، التكرار، الإطار الزمني."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        kpis = sections['kpis']
        for col in ('مصدر البيانات', 'المالك', 'التكرار', 'الإطار الزمني'):
            self.assertIn(col, kpis,
                f'Expected column "{col}" in repaired KPI section')

    @_skip_if_no_app
    def test_repaired_section_passes_richness_validator(self):
        """After repair, validate_arabic_strategy_semantic_richness no longer
        reports kpis_missing_frequency_column."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, 'ar', doc_subtype=None)
        freq_defects = [t for t, _ in defects
                        if t == 'kpis_missing_frequency_column']
        self.assertEqual(freq_defects, [],
            f'Expected no kpis_missing_frequency_column defects after repair, got: {freq_defects}')

    @_skip_if_no_app
    def test_repair_does_not_modify_other_sections(self):
        """KPI repair must not modify vision, gaps, roadmap, or confidence."""
        sections = _make_full_sections_ar()
        originals = {
            k: sections[k] for k in ('vision', 'gaps', 'roadmap', 'confidence')
        }
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        for key in ('vision', 'gaps', 'roadmap', 'confidence'):
            self.assertEqual(sections[key], originals[key],
                f'Section "{key}" was modified by KPI repair — must not be')

    @_skip_if_no_app
    def test_no_op_when_frequency_already_present(self):
        """If التكرار is already in the KPI section, repair returns 0."""
        sections = _make_full_sections_ar(kpis_text=_ALREADY_HAS_FREQUENCY_AR)
        result = _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        self.assertEqual(result, 0,
            'Repair should be a no-op when التكرار is already present')

    @_skip_if_no_app
    def test_canonical_schema_has_nine_header_columns(self):
        """The repaired section uses the 9-column canonical KPI schema."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        kpis = sections['kpis']
        # Find the main table header line
        header_line = None
        for line in kpis.split('\n'):
            s = line.strip()
            if s.startswith('|') and 'المؤشر' in s and '#' in s:
                header_line = s
                break
        self.assertIsNotNone(header_line, 'Could not find main KPI table header')
        cols = [c.strip() for c in header_line.split('|') if c.strip()]
        self.assertEqual(len(cols), 9,
            f'Expected 9 columns, got {len(cols)}: {cols}')

    @_skip_if_no_app
    def test_count_substantive_kpis_recognizes_new_schema(self):
        """count_substantive_kpis correctly counts rows under المؤشر header."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        n = _APP.count_substantive_kpis(sections['kpis'])
        self.assertGreaterEqual(n, 8,
            f'count_substantive_kpis should find ≥ 8 rows, got {n}')

    @_skip_if_no_app
    def test_count_substantive_kpis_strict_recognizes_new_schema(self):
        """count_substantive_kpis_strict correctly counts rows under المؤشر."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        n = _APP.count_substantive_kpis_strict(sections['kpis'])
        self.assertGreaterEqual(n, _APP._RICHNESS_MIN_KPI_ROWS,
            f'count_substantive_kpis_strict should find ≥ {_APP._RICHNESS_MIN_KPI_ROWS}, got {n}')

    @_skip_if_no_app
    def test_english_missing_frequency_triggers_repair(self):
        """An English KPI section without Frequency is repaired."""
        sections = {
            'vision': '## 1. Vision & Strategic Objectives\n\n',
            'pillars': '## 2. Strategic Pillars\n\n',
            'environment': '## 3. Regulatory Environment & Threat Landscape\n\n',
            'gaps': '## 4. Gap Analysis\n\n',
            'roadmap': '## 5. Implementation Roadmap\n\n',
            'kpis': _OLD_SCHEMA_KPI_SECTION_EN,
            'confidence': '## 7. Confidence Assessment & Risk Register\n\n',
        }
        result = _APP.repair_kpi_section_if_missing_frequency(
            sections, 'en',
            domain='Cyber Security',
            org_name='Test Org',
            sector='Government',
            frameworks=['NCA ECC'],
        )
        self.assertGreater(result, 0,
            'Repair should write rows when Frequency is absent in EN')
        kpis = sections['kpis']
        self.assertIn('Frequency', kpis,
            'Repaired English KPI section must contain "Frequency"')

    @_skip_if_no_app
    def test_guide_coverage_after_repair(self):
        """After repair, KPI guide count matches row count (coverage = 100%)."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        kpis = sections['kpis']
        n_kpis = _APP.count_substantive_kpis_strict(kpis)
        n_guides = _APP.count_kpi_guides(kpis)
        self.assertGreaterEqual(n_guides, n_kpis,
            f'Guide coverage: expected n_guides ({n_guides}) ≥ n_kpis ({n_kpis})')

    @_skip_if_no_app
    def test_kpi_main_header_count_is_one(self):
        """After repair, _KPI_MAIN_TABLE_HEADER_RE finds exactly 1 main header."""
        sections = _make_full_sections_ar()
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        kpis = sections['kpis']
        count = len(_APP._KPI_MAIN_TABLE_HEADER_RE.findall(kpis))
        self.assertEqual(count, 1,
            f'Expected exactly 1 main KPI table header, found {count}')

    @_skip_if_no_app
    def test_final_audit_passes_after_repair(self):
        """_final_strategy_audit returns no kpi-family defects after repair."""
        sections = _make_full_sections_ar()
        # First repair KPI section
        _APP.repair_kpi_section_if_missing_frequency(
            sections, 'ar', domain='Cyber Security',
            org_name='Test Org', sector='Government', frameworks=['NCA ECC'],
        )
        # Also ensure vision has enough rows for audit to pass
        _APP.repair_vision_objectives_if_insufficient(
            sections, 'ar',
            domain='Cyber Security',
            org_name='Test Org',
            frameworks=['NCA ECC'],
            sector='Government',
        )
        defects = _APP._final_strategy_audit(sections, 'ar', doc_subtype=None)
        kpi_defects = [d for d in defects if d[0] == 'kpis']
        self.assertEqual(kpi_defects, [],
            f'Expected no kpi audit defects after repair, got: {kpi_defects}')


class TestPyCompile(unittest.TestCase):
    """Verify app.py has no syntax errors."""

    def test_app_compiles(self):
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        try:
            py_compile.compile(app_path, doraise=True)
        except py_compile.PyCompileError as e:
            self.fail(f'app.py has a syntax error: {e}')


if __name__ == '__main__':
    unittest.main()
