"""PR-CY77 — Arabic PDF table fallback cleanup + vertical stack resolution."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy77_')
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


def _base_model():
    from tests.test_cyber_export_parity_prcy50 import _model as _m50
    return _m50()


class Prcy77PdfFallbackCleanupTests(unittest.TestCase):

    @_skip
    def test_helpers_present(self):
        self.assertTrue(hasattr(_PSR, 'apply_pdf_final_table_fallback_cleanup'))
        self.assertTrue(hasattr(_PSR, 'emit_pdf_final_table_fallback_cleanup_diag'))
        self.assertTrue(hasattr(_PSR, '_apply_prcy77_warning_driven_ar_pdf_fallbacks'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy77'))

    @_skip
    def test_arabic_strategic_objectives_always_use_objective_cards(self):
        model = _base_model()
        tbl = {
            'schema': 'strategic_objectives',
            'header': list(_PSR.SCHEMA_STRATEGIC_OBJECTIVES_AR),
            'rows': [['1', 'x' * 280, 't', 'r', '24']],
        }
        model['blocks']['vision_objectives']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('strategic_objectives'), 'objective_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)
        self.assertTrue(ev.get('pdf_table_vertical_stack_warnings'))

    @_skip
    def test_dense_roadmap_rows_use_roadmap_cards(self):
        model = _base_model()
        tbl = {
            'schema': 'roadmap',
            'header': list(_PSR.SCHEMA_ROADMAP_AR),
            'rows': [[
                'المرحلة 1 — تأسيس',
                '1-6 أشهر',
                'مبادرة ' + ('x' * 120),
                'CISO',
                'مخرج',
                'NCA ECC',
            ]],
        }
        model['blocks']['roadmap']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('roadmap'), 'roadmap_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_kpi_dash_resequenced_before_pdf_render(self):
        model = _base_model()
        tbl = {
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [
                ['1', 'KPI-A', 'KPI', '≥ 95%', 'شهري', 'CISO', '12 شهر'],
                ['—', 'DCC KPI', 'KPI', '≥ 90%', 'شهري', 'CISO', '12 شهر'],
            ],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        diag = _PSR.apply_pdf_final_table_fallback_cleanup(model, 'ar')
        rows = model['blocks']['kpi_kri_framework']['tables'][0]['rows']
        self.assertEqual(diag.get('kpi_rows_resequenced'), 1)
        self.assertEqual(rows[1][0], '2')

    @_skip
    def test_dense_kpi_table_uses_kpi_cards(self):
        model = _base_model()
        tbl = {
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [[
                '1', 'x' * 120, 'KPI', '≥ 95%', 'شهري', 'CISO', '12 شهر',
            ]],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('kpi_main'), 'kpi_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_dense_governance_uses_governance_cards(self):
        model = _base_model()
        model['blocks']['governance_ownership']['rows'] = [[
            'CISO', 'scope' * 40, 'acc' * 40, 'rep' * 40, 'NCA ECC',
        ]]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('governance'), 'governance_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_dense_traceability_uses_trace_cards(self):
        model = _base_model()
        st = {
            'schema': 'trace_fw_gap',
            'title': 'DCC',
            'header': list(_PSR.SCHEMA_TRACE_FW_GAP_AR),
            'rows': [['NCA DCC', 'cap', 'gap' * 120]],
        }
        model['blocks']['traceability_matrix']['split_tables'] = [st]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('trace_fw_gap'), 'trace_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_roadmap_period_role_repaired_before_pdf_render(self):
        model = _base_model()
        tbl = {
            'schema': 'roadmap',
            'header': list(_PSR.SCHEMA_ROADMAP_AR),
            'rows': [[
                'المرحلة 1 — تأسيس',
                'خبراء استخبارات التهديدات السيبرانية',
                'مبادرة DLP',
                'CISO',
                'مخرج',
                'NCA DCC',
            ]],
        }
        model['blocks']['roadmap']['tables'] = [tbl]
        diag = _PSR.apply_pdf_final_table_fallback_cleanup(model, 'ar')
        period = model['blocks']['roadmap']['tables'][0]['rows'][0][1]
        self.assertEqual(period, '1-6 أشهر')
        self.assertGreaterEqual(diag.get('roadmap_period_cells_repaired', 0), 1)

    @_skip
    def test_truncation_artifact_removed_before_pdf_render(self):
        model = _base_model()
        tbl = {
            'schema': 'roadmap',
            'header': list(_PSR.SCHEMA_ROADMAP_AR),
            'rows': [[
                'المرحلة 2 — تمكين',
                '7-18 شهر',
                'تشغيل مركز التش…',
                'CISO',
                'مخرج',
                'NCA ECC',
            ]],
        }
        model['blocks']['roadmap']['tables'] = [tbl]
        diag = _PSR.apply_pdf_final_table_fallback_cleanup(model, 'ar')
        init = model['blocks']['roadmap']['tables'][0]['rows'][0][2]
        self.assertNotIn('…', init)
        self.assertGreaterEqual(diag.get('truncation_artifacts_removed', 0), 1)


if __name__ == '__main__':
    unittest.main()
