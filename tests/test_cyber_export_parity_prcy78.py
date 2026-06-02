"""PR-CY78 — roadmap phase coverage repair before PDF/docmodel gate."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy78_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_PSR = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _PSR
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


def _roadmap_two_phases_only():
    return (
        '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار المرتبط |\n'
        '|---|---|---|---|---|---|\n'
        '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل معتمد | NCA ECC |\n'
        '| المرحلة 2: تمكين | 7-18 شهر | SOC/SIEM | مدير SOC | مركز تشغيل | NCA ECC |\n'
    )


class Prcy78RoadmapPhaseCoverageTests(unittest.TestCase):

    @_skip
    def test_helpers_present(self):
        self.assertTrue(hasattr(_PSR, 'repair_roadmap_table_rows'))
        self.assertTrue(hasattr(_PSR, 'emit_prcy78_roadmap_phase_coverage_diag'))
        self.assertTrue(hasattr(_APP, '_prcy78_repair_roadmap_phase_coverage'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy78'))

    @_skip
    def test_two_phases_get_phase3_inserted(self):
        rows = [
            ['—', '1-6 أشهر', 'حوكمة', 'CISO', 'out', 'NCA ECC'],
            ['—', '7-18 شهر', 'SOC', 'CISO', 'out2', 'NCA ECC'],
        ]
        repaired, diag = _PSR.repair_roadmap_table_rows(rows, 'ar')
        self.assertTrue(diag['phase_3_present'])
        self.assertTrue(diag['phase_coverage_valid_after'])
        self.assertGreaterEqual(diag['rows_inserted'], 1)
        self.assertTrue(
            any('تحسين' in str(r[0]) for r in repaired))

    @_skip
    def test_phase3_row_is_meaningful_not_dash_only(self):
        rows = [
            ['المرحلة 1: تأسيس', '1-6 أشهر', 'حوكمة', 'CISO', 'out', 'NCA ECC'],
            ['المرحلة 2: تمكين', '7-18 شهر', 'SOC', 'CISO', 'out2', 'NCA ECC'],
        ]
        repaired, _ = _PSR.repair_roadmap_table_rows(rows, 'ar')
        p3 = [r for r in repaired if 'تحسين' in str(r[0])]
        self.assertTrue(p3)
        self.assertGreater(len(p3[0][2]), 20)
        self.assertNotIn('—', p3[0][2])

    @_skip
    def test_invalid_period_report_text_repaired(self):
        rows = [[
            'المرحلة 2: تمكين وتشغيل',
            'تقارير تقدم دورية ومؤشر…',
            'SOC/SIEM',
            'CISO',
            'مخرج',
            'NCA ECC',
        ]]
        repaired, diag = _PSR.repair_roadmap_table_rows(rows, 'ar')
        self.assertEqual(repaired[0][1], '7-18 شهر')
        self.assertGreaterEqual(diag['invalid_period_cells_repaired'], 1)

    @_skip
    def test_truncated_framework_cell_normalized(self):
        rows = [[
            'المرحلة 1: تأسيس',
            '1-6 أشهر',
            'حوكمة',
            'CISO',
            'out',
            'NCA ECC (ESSENTIAL CYBERSECURITY CONTROLS) / NCA DCC (',
        ]]
        repaired, diag = _PSR.repair_roadmap_table_rows(rows, 'ar')
        self.assertIn('NCA', repaired[0][5])
        self.assertNotIn('(', repaired[0][5])
        self.assertGreaterEqual(diag['truncated_framework_cells_repaired'], 1)

    @_skip
    def test_dcc_classification_row_inserted_when_missing(self):
        rows = [
            ['المرحلة 1: تأسيس', '1-6 أشهر', 'حوكمة', 'CISO', 'out', 'NCA ECC'],
            ['المرحلة 2: تمكين', '7-18 شهر', 'تشفير', 'CISO', 'out2', 'NCA DCC'],
            ['المرحلة 2: تمكين', '7-18 شهر', 'DLP', 'CISO', 'out3', 'NCA DCC'],
        ]
        repaired, diag = _PSR.repair_roadmap_table_rows(
            rows, 'ar', ['NCA ECC', 'NCA DCC'])
        blob = ' '.join(' '.join(r) for r in repaired)
        self.assertIn('تصنيف وجرد', blob)
        self.assertNotIn(
            'data_classification',
            diag.get('missing_dcc_families_after', []))

    @_skip
    def test_dcc_encryption_row_preserved(self):
        rows = [
            ['المرحلة 2: تمكين', '7-18 شهر',
             'تطبيق ضوابط التشفير وإدارة المفاتيح',
             'مدير حماية البيانات', 'ضوابط مطبقة', 'NCA DCC'],
        ]
        repaired, _ = _PSR.repair_roadmap_table_rows(
            rows, 'ar', ['NCA DCC'])
        blob = ' '.join(' '.join(r) for r in repaired)
        self.assertIn('تشفير', blob)

    @_skip
    def test_dcc_dlp_row_preserved(self):
        rows = [
            ['المرحلة 2: تمكين', '7-18 شهر',
             'تفعيل DLP ومراقبة تسرب البيانات',
             'مدير حماية البيانات', 'منصة DLP', 'NCA DCC'],
        ]
        repaired, _ = _PSR.repair_roadmap_table_rows(
            rows, 'ar', ['NCA DCC'])
        blob = ' '.join(' '.join(r) for r in repaired)
        self.assertIn('DLP', blob)

    @_skip
    def test_pdf_gate_passes_phase_coverage_after_repair(self):
        from professional_strategy_render import (
            PDFRenderTracker, run_pdf_quality_gate,
        )
        from tests.test_cyber_export_parity_prcy50 import _model as _m50

        model = _m50()
        model['blocks']['roadmap']['tables'] = [{
            'schema': 'roadmap',
            'header': list(_PSR.SCHEMA_ROADMAP_AR),
            'rows': [
                ['—', '1-6 أشهر', 'حوكمة', 'CISO', 'out', 'NCA ECC'],
                ['—', '7-18 شهر', 'SOC', 'CISO', 'out2', 'NCA ECC'],
            ],
        }]
        _PSR.apply_prcy78_roadmap_phase_coverage_to_model(model, 'ar')
        checks = _PSR.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['roadmap_phase_coverage_valid'])
        subgate = _PSR.identify_docmodel_failing_subgate(checks)
        self.assertNotEqual(subgate, 'roadmap_phase_coverage_valid')
        tracker = PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 6
        tracker.kpi_tables_rendered = 2
        _, payload = run_pdf_quality_gate(
            tracker, '', lang='ar', model=model)
        blockers = payload.get('blockers') or []
        self.assertFalse(any(
            'roadmap_phase_coverage' in b for b in blockers))


if __name__ == '__main__':
    unittest.main()
