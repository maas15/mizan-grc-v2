"""PR-CY49 — Preview/PDF/DOCX renderer parity after PR-CY48.

Run:
    python -m pytest tests/test_cyber_export_renderer_parity_prcy49.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy49_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')

_P41 = None
_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _P41
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
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
    'gaps': '| # | الفجوة | x | x | x |\n|---|---|---|---|---|\n| 1 | gap | d | h | o |\n',
    'roadmap': '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n|---|---|---|---|---|\n| 1 | init | CISO | 1-3 | out |\n',
    'kpis': '| # | المؤشر | النوع | القيمة | صيغة | مصدر | المالك | التكرار | الإطار |\n|---|---|---|---|---|---|---|---|---|\n| 1 | تفعيل MFA | KPI | 100% | x | x | CISO | شهري | 12ش |\n',
    'confidence': '**درجة الثقة:** .%76\n| # | الخطر | الاحتمالية | التأثير | خطة |\n|---|---|---|---|---|\n| 1 | risk | عالية | حرج | plan |\n',
}


def _model():
    base = {
        'lang': 'ar',
        'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        'blocks': {
            'executive_summary': {'title': 'الملخص', 'paragraphs': ['x']},
            'governance_ownership': {
                'rows': [['CISO', 'scope', 'acc', 'rep', 'NCA ECC']]},
            'traceability_matrix': {
                'rows': [['NCA ECC', 'cap', 'gap', 'init', 'kpi', 'risk']]},
            'appendices': {'entries': [('A', 'body')]},
        },
    }
    return _P41.enrich_professional_blocks(
        base, _SECS,
        {'mandatory_themes': ['حوكمة'], 'horizon_months': '24'}, 'ar')


class ExportRendererParityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_docx_section_order_matches_pdf(self):
        self.assertEqual(
            list(_P41.PROFESSIONAL_EXPORT_SECTION_ORDER),
            self.model.get('professional_section_order'))

    @_skip
    def test_docx_required_sections_in_export_keys(self):
        keys = _P41.get_professional_export_section_keys(self.model)
        for req in ('executive_summary', 'governance_ownership',
                    'traceability_matrix', 'appendices'):
            self.assertIn(req, keys)

    @_skip
    def test_arabic_spacing_in_table_cells(self):
        for bad in ('الكاملمع', 'الساعةمع', 'أقلمن', 'الموظفينمع'):
            out = _P41.prepare_final_render_text(bad, 'ar')
            self.assertNotIn(bad, out)

    @_skip
    def test_roadmap_spec_always_has_three_phases(self):
        rows = _P41.get_roadmap_spec_rows(self.model)
        self.assertTrue(_P41.roadmap_phase_coverage_valid(rows))

    @_skip
    def test_pdf_gate_no_false_roadmap_block_when_spec_rows_exist(self):
        from professional_strategy_render import PDFRenderTracker, run_pdf_quality_gate
        tracker = PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 3
        tracker.kpi_tables_rendered = 2
        passed, payload = run_pdf_quality_gate(
            tracker, _SECS['roadmap'], lang='ar', model=self.model)
        blockers = payload.get('blockers') or []
        self.assertNotIn('pdf_render_failed:roadmap_table_not_rendered', blockers)
        self.assertTrue(passed, payload)

    @_skip
    def test_pdf_gate_build_failed_when_rows_not_rendered(self):
        from professional_strategy_render import PDFRenderTracker, run_pdf_quality_gate
        tracker = PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 0
        tracker.kpi_tables_rendered = 2
        passed, payload = run_pdf_quality_gate(
            tracker, _SECS['roadmap'], lang='ar', model=self.model)
        self.assertFalse(passed)
        self.assertIn(
            'pdf_render_failed:build_failed:roadmap_rows_lost_in_render',
            payload.get('blockers') or [])

    @_skip
    def test_parity_check_payload(self):
        diag = _P41.build_renderer_parity_check(
            self.model, route_name='docx', output_type='docx')
        self.assertTrue(diag['professional_model_used'])
        self.assertTrue(diag['executive_summary_present'])
        self.assertGreaterEqual(diag['roadmap_spec_rows'], 3)
        self.assertTrue(diag['roadmap_phase_coverage'])
        self.assertGreaterEqual(diag['kpi_split_tables'], 1)
        self.assertTrue(diag['confidence_model_valid'])

    @_skip
    def test_kpi_split_tables_identical_count(self):
        self.assertGreaterEqual(_P41.kpi_split_table_count(self.model), 2)

    @_skip
    def test_docx_source_uses_professional_export_order(self):
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                  encoding='utf-8') as f:
            src = f.read()
        self.assertIn('PROFESSIONAL_EXPORT_SECTION_ORDER', src)
        self.assertIn('_docx_render_professional_block', src)
        self.assertIn('[DOCX-EXPORT-PARITY]', src)


if __name__ == '__main__':
    unittest.main(verbosity=2)
