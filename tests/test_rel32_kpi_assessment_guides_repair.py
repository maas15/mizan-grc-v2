"""REL3.2 — deterministic KPI Assessment Guidelines repair tests."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel32_kpi_guides_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

_APP = None
try:
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine_v3.rel32_compiler import (
    compile_canonical_strategy_document,
    is_rel32_compiler_first,
)
from release_engine_v3.rel32_kpi_assessment_guides import (
    kpi_assessment_guides_present,
    refine_kpi_assessment_quality_issues,
    repair_kpi_assessment_guides_in_kpis,
)


def _ctx():
    return {
        'lang': 'ar',
        'domain': 'cyber',
        'backend': {
            'flags': {'rel3': True, 'rel31': True, 'rel32': True},
            'lang': 'ar',
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        },
    }


def _kpis_without_guides() -> str:
    return (
        '## مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | النوع | القيمة المستهدفة | '
        'صيغة الاحتساب | مصدر | التكرار | المالك |\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| 1 | متوسط زمن الكشف عن الحوادث (MTTD) | KPI | '
        '≤ 15 دقيقة | مجموع زمن الكشف / عدد الحوادث | SIEM/SOC | '
        'شهري | مدير SOC |\n'
        '| 2 | متوسط زمن الاستجابة للحوادث (MTTR) | KPI | '
        '≤ 4 ساعات | مجموع زمن الاستجابة / عدد الحوادث | ITSM | '
        'شهري | قائد CSIRT |\n'
    )


def _kpis_with_guides() -> str:
    return (
        _kpis_without_guides()
        + '\n### أدلة تقييم مؤشرات الأداء\n\n'
        '| المؤشر | طريقة التقييم | صيغة الاحتساب | مصدر البيانات | '
        'دورية القياس | المالك | الحد المستهدف | دليل القبول | '
        'تفسير النتيجة |\n'
        '|---|---|---|---|---|---|---|---|---|\n'
        '| MTTD | مراجعة SIEM | f | SIEM | شهري | SOC | ≤15 | logs | ok |\n'
        '| MTTR | مراجعة ITSM | f | ITSM | شهري | CSIRT | ≤4h | logs | ok |\n'
        '\n#### دليل تقييم المؤشر رقم 1: MTTD\n'
        '| الخطوة | الإجراء | الأداة/النظام | المسؤول | المخرج |\n'
        '|---|---|---|---|---|\n'
        '| 1 | قياس | SIEM | SOC | تقرير |\n'
        '\n#### دليل تقييم المؤشر رقم 2: MTTR\n'
        '| الخطوة | الإجراء | الأداة/النظام | المسؤول | المخرج |\n'
        '|---|---|---|---|---|\n'
        '| 1 | قياس | ITSM | CSIRT | تقرير |\n'
    )


class Rel32KpiAssessmentGuidesRepairTests(unittest.TestCase):

    def test_01_missing_guides_repaired_by_compiler(self):
        r = compile_canonical_strategy_document(
            {'kpis': _kpis_without_guides()}, request_context=_ctx())
        kpis = r.legacy_sections.get('kpis', '')
        self.assertTrue(kpi_assessment_guides_present(kpis), kpis[-800:])
        self.assertIn('أدلة تقييم مؤشرات الأداء', kpis)
        self.assertIn('طريقة التقييم', kpis)
        self.assertIn('دليل تقييم المؤشر رقم', kpis)
        self.assertTrue(r.passed, r.blocking_errors)

    def test_02_drafting_mode_force_inject_repairs_deterministically(self):
        sections = {'kpis': _kpis_without_guides()}
        _APP._force_inject_mandatory_section(
            sections, 'kpi_assessment_guides_missing', 'ar',
            domain='cyber', generation_mode='drafting')
        self.assertTrue(kpi_assessment_guides_present(sections['kpis']))

    def test_03_consulting_mode_force_inject_repairs_deterministically(self):
        sections = {'kpis': _kpis_without_guides()}
        _APP._force_inject_mandatory_section(
            sections, 'kpi_assessment_guides_missing', 'ar',
            domain='cyber', generation_mode='consulting')
        self.assertTrue(kpi_assessment_guides_present(sections['kpis']))

    def test_04_stale_issue_cleared_after_repair(self):
        _, diag = repair_kpi_assessment_guides_in_kpis(
            _kpis_without_guides(), lang='ar')
        refined = refine_kpi_assessment_quality_issues(
            ['kpi_assessment_guides_missing'], diag)
        self.assertNotIn('kpi_assessment_guides_missing', refined)
        self.assertTrue(diag.get('stale_issue_cleared'))

    def test_05_invalid_empty_kpi_table_still_blocks_audit(self):
        ok, issues = _APP._audit_doc_quality(
            {'kpis': '## مؤشرات\n\nلا يوجد جدول'}, 'technical', 'ar',
            generation_mode='drafting')
        self.assertFalse(ok)
        self.assertIn('kpi_assessment_guides_missing', issues)

    def test_06_existing_valid_guides_preserved(self):
        original = _kpis_with_guides()
        repaired, diag = repair_kpi_assessment_guides_in_kpis(
            original, lang='ar')
        self.assertIn('MTTD', repaired)
        self.assertIn('طريقة التقييم', repaired)
        self.assertFalse(diag.get('inserted'))

    def test_07_rel32_compiler_first_flag_active(self):
        self.assertTrue(is_rel32_compiler_first(
            domain='cyber', lang='ar',
            flags={'rel3': True, 'rel31': True, 'rel32': True}))


if __name__ == '__main__':
    unittest.main()
