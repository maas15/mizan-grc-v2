"""PR-CY51 — DOCX hard-fail, Arabic cleanup, named PDF docmodel sub-gates.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy51.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy51_')
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


class ExportParityPrcy51Tests(unittest.TestCase):

    @_skip
    def test_strategy_doc_type_arabic_recognized(self):
        self.assertTrue(
            _P41.is_strategy_export_doc_type('وثيقة استراتيجية', 'cyber'))
        self.assertTrue(
            _P41.is_strategy_export_doc_type('Strategy Document', ''))

    @_skip
    def test_arabic_concat_fixes_cy51(self):
        samples = {
            'اختراقمن': 'اختراق من',
            'التهديداتفي': 'التهديدات في',
            'المخاطرمن': 'المخاطر من',
        }
        for bad, good in samples.items():
            out = _P41.prepare_final_render_text(bad, 'ar')
            self.assertIn(good, out)
            self.assertNotIn(bad, out)

    @_skip
    def test_pdf_error_names_failing_subgate(self):
        from professional_strategy_render import PDFRenderTracker, run_pdf_quality_gate
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        model['blocks']['environment_context']['paragraphs'] = ['اختراقمن']
        tracker = PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 3
        tracker.kpi_tables_rendered = 2
        passed, payload = run_pdf_quality_gate(
            tracker, '', lang='ar', model=model)
        self.assertFalse(passed)
        blockers = payload.get('blockers') or []
        self.assertTrue(any(
            b.startswith('pdf_render_failed:docmodel_professional_quality:')
            for b in blockers), blockers)

    @_skip
    def test_pdf_gate_passes_when_all_subgates_pass(self):
        from professional_strategy_render import PDFRenderTracker, run_pdf_quality_gate
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        tracker = PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 3
        tracker.kpi_tables_rendered = 2
        passed, payload = run_pdf_quality_gate(
            tracker, '', lang='ar', model=model)
        self.assertTrue(payload.get('docmodel_professional_passed'), payload)
        self.assertTrue(passed, payload.get('blockers'))

    @_skip
    def test_docx_hard_fail_source_present(self):
        self.assertIn(
            'docx_render_failed:professional_model_required', _APP_SOURCE)
        self.assertIn('emit_docmodel_professional_failure', _APP_SOURCE)
        self.assertIn('is_strategy_export_doc_type', _APP_SOURCE)

    @_skip
    def test_docx_strategy_blocks_raw_markdown_lines(self):
        self.assertIn(
            '_docx_is_strategy or _docx_professional', _APP_SOURCE)
        self.assertIn('docx_no_raw_1_to_7_fallback', _APP_SOURCE)

    @_skip
    def test_identify_docmodel_failing_subgate(self):
        checks = {
            'docmodel_professional_passed': False,
            'final_table_cell_arabic_cleanup_passed': False,
            'docx_professional_sections_present': True,
            'docx_no_raw_1_to_7_fallback': True,
        }
        sub = _P41.identify_docmodel_failing_subgate(checks)
        self.assertEqual(sub, 'final_table_cell_arabic_cleanup_passed')
        suffix = _P41.subgate_to_failure_suffix(sub)
        self.assertEqual(suffix, 'final_table_cell_arabic_cleanup_failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
