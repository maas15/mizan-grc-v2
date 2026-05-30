"""PR-CY52 — PDF table-cell rendering, Arabic cleanup, density gates.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy52.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy52_')
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


class ExportParityPrcy52Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_pdf_gap_text_no_towa_or_alkh(self):
        """Extracted/rendered gap guide text must not contain طوة or الخ."""
        guides = [t for t in self.model['blocks']['gap_analysis']['tables']
                  if t.get('schema') == 'gap_action']
        self.assertTrue(guides)
        blob = ' '.join(
            str(c) for t in guides for r in t.get('rows') or [] for c in r)
        blob += ' ' + ' '.join(str(h) for t in guides for h in t.get('header') or [])
        self.assertFalse(_P41.contains_forbidden_gap_fragments(blob))
        self.assertEqual(guides[0]['header'][0], 'الخطوة')
        repaired = _P41.prepare_final_render_text('طوة الخ', 'ar')
        self.assertEqual(repaired, 'الخطوة')
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_gap_headers_clean'])
        self.assertTrue(checks['gap_guide_header_final_clean'])

    @_skip
    def test_confidence_factor_labels_intact_in_model(self):
        factors = [t for t in self.model['blocks']['confidence_risk_register']['tables']
                   if t['schema'] == 'conf_factor'][0]
        canonical = [f[0] for f in _P41.CANONICAL_CONFIDENCE_FACTORS_AR]
        names = [r[0] for r in factors['rows']]
        self.assertEqual(names, canonical)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_confidence_factor_labels_intact'])
        self.assertTrue(_P41.confidence_factor_labels_intact([factors]))

    @_skip
    def test_roadmap_cells_compacted_no_long_dcc_fragments(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        for r in rows:
            for c in r:
                self.assertLessEqual(len(str(c)), _P41.ROADMAP_CELL_MAX_LEN)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_roadmap_cell_density_valid'])
        self.assertTrue(_P41.roadmap_cell_density_valid(rows))

    @_skip
    def test_kpi_type_column_never_dash(self):
        main = [t for t in self.model['blocks']['kpi_kri_framework']['tables']
                if t['schema'] == 'kpi_main'][0]
        for r in main['rows']:
            self.assertIn(r[2], ('KPI', 'KRI'))
            self.assertNotEqual(r[2], '—')
        # Missing type column must infer KPI/KRI.
        tbl = _P41.split_kpi_tables(
            '| # | المؤشر | النوع | القيمة |\n|---|---|---|---|\n'
            '| 1 | risk exposure index | — | 10% |\n'
            '| 2 | MFA adoption rate |  | 95% |\n', 'ar')
        main2 = [t for t in tbl if t['schema'] == 'kpi_main'][0]
        self.assertEqual(main2['rows'][0][2], 'KRI')
        self.assertEqual(main2['rows'][1][2], 'KPI')
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_kpi_type_column_valid'])

    @_skip
    def test_arabic_spacing_cy52_concat_fixes(self):
        samples = {
            'كاملمع': 'كامل مع',
            'المخاطرمع': 'المخاطر مع',
            'الاستثمارفي': 'الاستثمار في',
            'التدريبفي': 'التدريب في',
        }
        for bad, good in samples.items():
            out = _P41.prepare_final_render_text(bad, 'ar')
            self.assertIn(good, out)
            self.assertNotIn(bad, out)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['final_arabic_spacing_pdf_passed'])

    @_skip
    def test_docx_still_has_professional_sections_after_cy51(self):
        keys = _P41.get_professional_export_section_keys(self.model)
        for req in _P41.DOCX_REQUIRED_PROFESSIONAL_SECTIONS:
            self.assertIn(req, keys, msg=req)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docx_professional_sections_present'])

    @_skip
    def test_prcy52_pdf_renderer_helpers_present(self):
        self.assertIn('_pro_render_conf_factor_cards', _APP_SOURCE)
        self.assertIn('schema_table_col_weights', _APP_SOURCE)
        self.assertTrue(callable(_P41.pdf_gap_headers_clean))
        self.assertTrue(callable(_P41.kpi_type_column_valid))
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        for gate in ('pdf_gap_headers_clean', 'pdf_kpi_type_column_valid',
                     'pdf_confidence_factor_labels_intact',
                     'pdf_roadmap_cell_density_valid',
                     'final_arabic_spacing_pdf_passed'):
            self.assertIn(gate, checks, msg=gate)

    @_skip
    def test_docmodel_all_subgates_pass_on_fixture(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docmodel_professional_passed'], checks)


if __name__ == '__main__':
    unittest.main(verbosity=2)
