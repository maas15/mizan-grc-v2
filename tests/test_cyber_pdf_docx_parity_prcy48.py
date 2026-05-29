"""PR-CY48 — PDF/DOCX parity and professional document-model quality.

Run:
    python -m pytest tests/test_cyber_pdf_docx_parity_prcy48.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_pdf_docx_parity_prcy48_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_P41 = None
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
    'environment': 'NCA-ECC context.\n| البُعد | المصدر | التأثير |\n|---|---|---|\n| تنظيمي | ECC | عالٍ |\n',
    'gaps': '| # | الفجوة | x | x | x |\n|---|---|---|---|---|\n| 1 | gap | d | h | o |\n\n#### دليل تطبيق الفجوة 1\n1. step one\n',
    'roadmap': '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n|---|---|---|---|---|\n| 1 | init | CISO | 1-3 | out |\n| 2 | soc | Mgr | 3-6 | mon |\n',
    'kpis': '| # | المؤشر | النوع | القيمة | صيغة | مصدر | المالك | التكرار | الإطار |\n|---|---|---|---|---|---|---|---|---|\n| 1 | تفعيل MFA | KPI | 100% | x | x | CISO | شهري | 12ش |\n',
    'confidence': '**درجة الثقة:** .%76\n| # | الخطر | الاحتمالية | التأثير | خطة |\n|---|---|---|---|---|\n| 1 | risk | عالية | حرج | plan |\n',
}


def _model():
    base = {
        'lang': 'ar',
        'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        'blocks': {
            'executive_summary': {
                'title': 'الملخص',
                'paragraphs': ['purpose line', 'dup purpose line'],
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
        base, {k: _SECS[k.replace('kpis', 'kpis').replace('vision', 'vision')]
               for k in ('vision', 'environment', 'gaps', 'roadmap', 'kpis', 'confidence')},
        {'mandatory_themes': ['حوكمة'], 'horizon_months': '24'}, 'ar')


class ParityAndQualityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_pdf_docx_same_section_order(self):
        keys = _P41.get_professional_export_section_keys(self.model)
        for req in ('governance_ownership', 'traceability_matrix', 'appendices'):
            self.assertIn(req, keys)
        self.assertEqual(
            self.model.get('professional_section_order'),
            list(_P41.PROFESSIONAL_EXPORT_SECTION_ORDER))

    @_skip
    def test_executive_summary_no_duplicate_paras_confidence_76(self):
        ex = self.model['blocks']['executive_summary']
        self.assertEqual(ex.get('paragraphs'), [])
        self.assertEqual(ex['summary_grid']['confidence_score'], '76%')

    @_skip
    def test_arabic_final_spacing(self):
        samples = {
            'متكاملمع': 'متكامل مع',
            'أوليمع': 'أولى مع',
            'الأمنيةفي': 'الأمنية في',
            'الأصولمن': 'الأصول من',
            'الناتجةعن': 'الناتجة عن',
        }
        for bad, good in samples.items():
            out = _P41.prepare_final_render_text(bad, 'ar')
            self.assertIn(good, out)
            self.assertNotIn(bad, out)

    @_skip
    def test_gap_guide_header_alkhutwa(self):
        guides = [t for t in self.model['blocks']['gap_analysis']['tables']
                  if t.get('schema') == 'gap_action']
        self.assertTrue(guides)
        self.assertEqual(guides[0]['header'][0], 'الخطوة')

    @_skip
    def test_roadmap_phases_meaningful(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        phases = ' '.join(r[0] for r in rows)
        self.assertIn('1-6', phases)
        self.assertIn('7-18', phases)
        self.assertIn('19-24', phases)
        self.assertIn('19-24', phases)
        for r in rows:
            self.assertFalse(_P41._is_dash_heavy_row(r))

    @_skip
    def test_kpi_formulas_not_metric_echo(self):
        formula = [t for t in self.model['blocks']['kpi_kri_framework']['tables']
                   if t['schema'] == 'kpi_formula'][0]
        for r in formula['rows']:
            self.assertIn('×', r[2])
            self.assertFalse(_P41._is_formula_echo(r[2], r[1]))

    @_skip
    def test_confidence_factors_canonical_separate_from_risks(self):
        conf = self.model['blocks']['confidence_risk_register']
        factors = [t for t in conf['tables'] if t['schema'] == 'conf_factor'][0]
        risks = [t for t in conf['tables'] if t['schema'] == 'risk_register']
        self.assertEqual(len(factors['rows']), 6)
        self.assertEqual(factors['rows'][0][0], 'اكتمال المدخلات')
        for r in factors['rows']:
            self.assertNotEqual(r[3], '76%')
        self.assertTrue(risks)

    @_skip
    def test_traceability_split_by_framework(self):
        splits = self.model['blocks']['traceability_matrix']['split_tables']
        titles = [s.get('title') for s in splits]
        self.assertIn('NCA ECC', titles)
        self.assertIn('NCA DCC', titles)

    @_skip
    def test_docx_source_has_exec_grid_and_split_trace(self):
        self.assertIn('executive_summary_grid_rows', _APP_SOURCE)
        self.assertIn('_split_tbls', _APP_SOURCE)

    @_skip
    def test_quality_gate_extended_checks(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_docx_section_parity'])
        self.assertTrue(checks['confidence_factor_table_valid'])
        self.assertTrue(checks['docmodel_professional_passed'], checks)


if __name__ == '__main__':
    unittest.main(verbosity=2)
