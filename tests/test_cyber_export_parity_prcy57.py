"""PR-CY57 — Final executive polish: priorities/risks, roadmap owner/output,
KPI source/target semantics, Arabic spacing, PDF spacing.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy57.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy57_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')

_P41 = None
_APP = None
_APP_SOURCE = ''
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _P41
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'),
              encoding='utf-8') as _f:
        _APP_SOURCE = _f.read()
except Exception as _e:
    raise SystemExit(f'Cannot load: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


def _model():
    from tests.test_cyber_export_parity_prcy50 import _model as _m50
    return _m50()


class ExportParityPrcy57Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_executive_summary_priorities_and_risks_filled(self):
        grid = self.model['blocks']['executive_summary']['summary_grid']
        priorities = grid.get('priorities') or []
        risks = grid.get('key_risks') or []
        self.assertGreaterEqual(len(priorities), 3, msg=priorities)
        self.assertGreaterEqual(len(risks), 1, msg=risks)
        self.assertTrue(all(p and p != '—' for p in priorities))
        self.assertTrue(all(r and r != '—' for r in risks))

    @_skip
    def test_roadmap_owner_aligned_with_initiative(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        soc = next(r for r in rows if 'SOC' in str(r[2]))
        self.assertIn('SOC', soc[3])
        csirt = next(r for r in rows if 'CSIRT' in str(r[2]))
        self.assertIn('CSIRT', csirt[3])
        dlp = next(
            r for r in rows
            if 'DLP' in str(r[2]) or 'بيانات' in str(r[2]))
        self.assertIn('بيانات', dlp[3])

    @_skip
    def test_roadmap_output_aligned_with_initiative(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        soc = next(r for r in rows if 'SOC' in str(r[2]))
        self.assertIn('SOC', str(soc[4]))
        csirt = next(r for r in rows if 'CSIRT' in str(r[2]))
        self.assertIn('CSIRT', str(csirt[4]))
        for r in rows:
            self.assertNotIn(str(r[4]).lower(), ('mon', 'out', 'run'))

    @_skip
    def test_kpi_target_source_semantics(self):
        tbl = _P41.split_kpi_tables(
            '| # | المؤشر | النوع | القيمة | صيغة | مصدر | المالك | التكرار | الإطار |\n'
            '|---|---|---|---|---|---|---|---|---|\n'
            '| 1 | زمن الاستجابة للحوادث | KPI | 100% | x | GRC | CISO | شهري | 12ش |\n'
            '| 2 | إغلاق الثغرات الحرجة | KPI | 100% | x | LMS | CISO | شهري | 12ش |\n',
            'ar')
        main = [t for t in tbl if t['schema'] == 'kpi_main'][0]
        formula = [t for t in tbl if t['schema'] == 'kpi_formula'][0]
        self.assertNotIn('%', main['rows'][0][3])
        self.assertIn('ساع', main['rows'][0][3])
        self.assertIn('SIEM', formula['rows'][0][3])
        self.assertIn('ثغر', formula['rows'][1][3])
        self.assertNotIn('LMS', formula['rows'][1][3])

    @_skip
    def test_prcy57_arabic_spacing_cleanup(self):
        samples = (
            'مكتملمع البرنامج',
            'البرنامجمع التنفيذ',
            'الثغراتكل الحرجة',
            'التعافيمن الكوارث',
            'الحيويةفي الأنظمة',
            'الأضعففي الروابط',
        )
        for s in samples:
            fixed = _P41.normalize_arabic_for_render(s)
            for bad in (
                    'مكتملمع', 'البرنامجمع', 'الثغراتكل',
                    'التعافيمن', 'الحيويةفي', 'الأضعففي'):
                self.assertNotIn(bad, fixed, msg=s)

    @_skip
    def test_pdf_confidence_card_and_table_spacing(self):
        self.assertIn('leading=15', _APP_SOURCE)
        self.assertIn('factor_hdr_sty', _APP_SOURCE)
        self.assertEqual(
            _P41.PDF_TABLE_LAYOUT_PROFILES['conf_factor']['padding'], 6)
        self.assertEqual(
            _P41.PDF_TABLE_LAYOUT_PROFILES['roadmap']['padding'], 6)
        self.assertEqual(
            _P41.PDF_TABLE_LAYOUT_PROFILES['kpi_main']['padding'], 6)

    @_skip
    def test_docmodel_all_subgates_pass_on_fixture(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docmodel_professional_passed'])


if __name__ == '__main__':
    unittest.main()
