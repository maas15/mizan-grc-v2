"""PR-CY50 — final Preview/PDF/DOCX parity and table-cell rendering gates.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy50.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy50_')
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


_SECS = {
    'vision': '| # | الهدف | x | x | x |\n|---|---|---|---|---|\n| 1 | a | b | c | d |\n',
    'environment': 'NCA-ECC.\n| البُعد | المصدر | التأثير |\n|---|---|---|\n| تنظيمي | ECC | عالٍ |\n',
    'gaps': (
        '| # | الفجوة | x | x | x |\n|---|---|---|---|---|\n| 1 | gap | d | h | o |\n\n'
        '#### دليل تطبيق الفجوة 1\n1. step one\n'),
    'roadmap': (
        '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n|---|---|---|---|---|\n'
        '| 1 | DLP تصنيف البيانات | CISO | 1-6 | out |\n'
        '| 2 | SOC/SIEM | Mgr | 7-18 | mon |\n'
        '| 3 | CSIRT | CISO | 19-24 | run |\n'),
    'kpis': (
        '| # | المؤشر | النوع | القيمة | صيغة | مصدر | المالك | التكرار | الإطار |\n'
        '|---|---|---|---|---|---|---|---|---|\n'
        '| 1 | زمن الاستجابة للحوادث | KPI | 100% | x | x | CISO | شهري | 12ش |\n'
        '| 2 | إغلاق الثغرات الحرجة | KPI | 100% | x | x | CISO | شهري | 12ش |\n'),
    'confidence': (
        '**درجة الثقة:** .%76\n| # | الخطر | الاحتمالية | التأثير | خطة |\n'
        '|---|---|---|---|---|\n| 1 | risk | عالية | حرج | plan |\n'),
}


def _model():
    base = {
        'lang': 'ar',
        'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        'blocks': {
            'executive_summary': {'title': 'الملخص', 'paragraphs': ['x']},
            'scope_frameworks': {
                'title': 'النطاق',
                'frameworks': [{'key': 'NCA ECC', 'display': 'NCA ECC'}],
            },
            'methodology': {
                'title': 'المنهجية',
                'rows': [('المنهج', 'تفاصيل')],
            },
            'governance_ownership': {
                'rows': [['CISO', 'scope', 'acc', 'rep', 'NCA ECC']]},
            'traceability_matrix': {
                'rows': [
                    ['NCA ECC', 'cap', 'gap', 'init', 'kpi', 'risk'],
                    ['NCA DCC', 'cap2', 'gap2', 'init2', 'kpi2', 'risk2'],
                ]},
            'appendices': {'entries': [('A', 'appendix body')]},
        },
    }
    return _P41.enrich_professional_blocks(
        base, _SECS,
        {'mandatory_themes': ['حوكمة'], 'horizon_months': '24'}, 'ar')


class ExportParityPrcy50Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_docx_required_professional_sections_present(self):
        keys = _P41.get_professional_export_section_keys(self.model)
        for req in _P41.DOCX_REQUIRED_PROFESSIONAL_SECTIONS:
            self.assertIn(req, keys, msg=req)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docx_professional_sections_present'])

    @_skip
    def test_docx_no_raw_1_to_7_fallback_source(self):
        self.assertIn('docx_no_raw_1_to_7_fallback', _APP_SOURCE)
        self.assertIn('_docx_is_strategy or _docx_professional', _APP_SOURCE)
        self.assertIn('[DOCX-EXPORT-PARITY]', _APP_SOURCE)
        diag = _P41.build_renderer_parity_check(self.model, route_name='docx')
        self.assertTrue(diag['docx_no_raw_1_to_7_fallback'])

    @_skip
    def test_table_cells_arabic_spacing_cleanup(self):
        for bad in ('72 ساعةمن', 'الناشئةعن', 'الكاملمع'):
            out = _P41.prepare_final_render_text(bad, 'ar')
            self.assertNotIn(bad, out)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['final_table_cell_arabic_cleanup_passed'])

    @_skip
    def test_gap_guide_header_alkhutwa_never_towa(self):
        guides = [t for t in self.model['blocks']['gap_analysis']['tables']
                  if t.get('schema') == 'gap_action']
        self.assertTrue(guides)
        self.assertEqual(guides[0]['header'][0], 'الخطوة')
        for r in guides[0]['rows']:
            self.assertNotIn('طوة', r[0])
            self.assertNotIn('الخ', r[0])
        out = _P41.prepare_final_render_text('طوة الخ', 'ar')
        self.assertEqual(out, 'الخطوة')
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['gap_guide_header_final_clean'])

    @_skip
    def test_roadmap_dcc_rows_map_to_nca_dcc(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        dlp_rows = [r for r in rows if 'DLP' in str(r[2]) or 'بيانات' in str(r[2])]
        self.assertTrue(dlp_rows)
        for r in dlp_rows:
            self.assertIn('DCC', str(r[5]))
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['roadmap_framework_mapping_valid'])

    @_skip
    def test_roadmap_phase_coverage_1_6_7_18_19_24(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        blob = ' '.join(str(r[0]) + ' ' + str(r[1]) for r in rows)
        self.assertIn('1-6', blob)
        self.assertIn('7-18', blob)
        self.assertIn('19-24', blob)
        for r in rows:
            self.assertFalse(_P41._is_dash_heavy_row(r))
        self.assertTrue(_P41.roadmap_phase_coverage_valid(rows))

    @_skip
    def test_time_based_kpis_use_time_targets(self):
        main = [t for t in self.model['blocks']['kpi_kri_framework']['tables']
                if t['schema'] == 'kpi_main'][0]
        time_row = next(
            r for r in main['rows']
            if _P41._is_time_based_metric(r[1]))
        self.assertNotIn('%', time_row[3])
        self.assertTrue(
            any(k in time_row[3] for k in ('ساع', 'hour', 'دقي', 'minute')))
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['kpi_metric_semantics_valid'])

    @_skip
    def test_vulnerability_metrics_use_vulnerability_wording(self):
        formula = [t for t in self.model['blocks']['kpi_kri_framework']['tables']
                   if t['schema'] == 'kpi_formula'][0]
        vuln = next(r for r in formula['rows'] if 'ثغر' in r[1])
        self.assertIn('ثغر', vuln[2])
        self.assertNotIn('حادث', vuln[2])

    @_skip
    def test_confidence_factor_names_intact(self):
        factors = [t for t in self.model['blocks']['confidence_risk_register']['tables']
                   if t['schema'] == 'conf_factor'][0]
        self.assertEqual(factors['header'][0], 'العامل')
        for r in factors['rows']:
            self.assertGreaterEqual(len(r[0]), 4)
            self.assertNotIn(r[0], ('ال', 'عامل', 'اك'))
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['confidence_table_layout_valid'])

    @_skip
    def test_preview_pdf_docx_parity_gates_pass(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['preview_pdf_docx_parity_passed'])
        self.assertTrue(checks['docmodel_professional_passed'], checks)
        diag = _P41.build_renderer_parity_check(
            self.model, route_name='pdf', output_type='pdf')
        self.assertTrue(diag['preview_pdf_docx_parity_passed'])
        self.assertIn('[PDF-EXPORT-PARITY]', _APP_SOURCE)

    @_skip
    def test_ensure_strategy_professional_model_sets_render_layer(self):
        base = {'lang': 'ar', 'blocks': {'roadmap': {'title': 'x'}}}
        out = _P41.ensure_strategy_professional_model(
            base, content='\n'.join(_SECS.values()), sections=_SECS, lang='ar')
        self.assertEqual(out.get('render_layer'), 'prcy41_professional')


if __name__ == '__main__':
    unittest.main(verbosity=2)
