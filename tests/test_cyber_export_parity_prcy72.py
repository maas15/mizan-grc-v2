"""PR-CY72 — PDF vertical stack resolution + PR-CY71 persistence verify."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy72_')
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


class Prcy72PdfStackAndParityTests(unittest.TestCase):

    @_skip
    def test_helpers_present(self):
        self.assertTrue(hasattr(_PSR, '_apply_prcy72_mandatory_ar_pdf_fallbacks'))
        self.assertTrue(hasattr(_PSR, '_stack_fallback_for_schema'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy72'))

    @_skip
    def test_kpi_main_stack_resolved_by_kpi_cards(self):
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
        self.assertTrue(ev.get('pdf_table_vertical_stack_warnings'))

    @_skip
    def test_kpi_formula_stack_resolved_by_kpi_cards(self):
        model = _base_model()
        tbl = {
            'schema': 'kpi_formula',
            'header': list(_PSR.SCHEMA_KPI_FORMULA_AR),
            'rows': [[
                '1', 'metric ' * 30, 'formula ' * 40, 'source ' * 20,
            ]],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('kpi_formula'), 'kpi_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_governance_stack_resolved_by_role_cards(self):
        model = _base_model()
        model['blocks']['governance_ownership']['rows'] = [[
            'CISO', 'x' * 180, 'a', 'b', 'c']]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('governance'), 'governance_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_traceability_stack_resolved_by_trace_cards(self):
        model = _base_model()
        st = {
            'schema': 'trace_fw_init',
            'title': 'DCC',
            'header': ['Capability', 'Gap', 'Initiative', 'KPI'],
            'rows': [['DLP', 'y' * 200, 'init', 'kpi']],
        }
        model['blocks']['traceability_matrix']['split_tables'] = [st]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('trace_fw_init'), 'trace_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_actionable_warnings_zero_with_fallbacks(self):
        model = _base_model()
        model['blocks']['kpi_kri_framework']['tables'] = [{
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [['1', 'x' * 100, 'KPI', '≥95%', 'q', 'CISO', '12m']],
        }]
        model['blocks']['governance_ownership']['rows'] = [
            ['CISO', 'z' * 100, 'a', 'b', 'c']]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)
        self.assertFalse(ev.get('unresolved_warnings'))

    @_skip
    def test_parity_fails_when_dcc_roadmap_under_three(self):
        from tests.test_cyber_export_parity_prcy71 import _sections
        sections = _sections()
        val = _APP._prcy69_validate_final_artifact(
            '', sections, ['nca_ecc', 'nca_dcc'], 'ar', 'cyber', strict=True)
        self.assertFalse(val.get('parity_valid'))

    @_skip
    def test_parity_fails_when_dcc_kpi_missing(self):
        from tests.test_cyber_export_parity_prcy70 import _minimal_sections
        sections = _minimal_sections()
        out, _ = _APP._prcy71_ensure_required_dcc_roadmap_rows(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        val = _APP._prcy69_validate_final_artifact(
            '', out, ['nca_ecc', 'nca_dcc'], 'ar', 'cyber', strict=True)
        blockers = '|'.join(val.get('blockers') or [])
        self.assertIn('prcy71_final_artifact_missing_dcc_kpi', blockers)

    @_skip
    def test_loose_dcc_kpi_does_not_satisfy_canonical_check(self):
        loose = 'مستوى حماية البيانات الحساسة'
        self.assertFalse(_APP._prcy71_dcc_kpi_present(loose, 'ar'))

    @_skip
    def test_final_artifact_contains_three_dcc_roadmap_rows(self):
        from tests.test_cyber_export_parity_prcy70 import _minimal_sections
        from tests.test_cyber_export_parity_prcy71 import _ROADMAP_ONE_DCC_AR
        sections = _minimal_sections(roadmap=_ROADMAP_ONE_DCC_AR)
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        result = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='generation')
        diag = result.get('diag') or {}
        self.assertTrue(diag.get('dcc_roadmap_required_rows_present'))
        self.assertGreaterEqual(
            diag.get('prcy71_dcc_roadmap_rows_count', 0), 3)
        fams = _APP._prcy71_present_dcc_roadmap_families(
            (result.get('sections') or {}).get('roadmap', ''))
        self.assertIn('encryption', fams)
        self.assertIn('dlp', fams)

    @_skip
    def test_docx_pdf_use_same_prcy71_hash(self):
        from tests.test_cyber_export_parity_prcy70 import _minimal_sections
        from tests.test_cyber_export_parity_prcy71 import _ROADMAP_ONE_DCC_AR
        sections = _minimal_sections(roadmap=_ROADMAP_ONE_DCC_AR)
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        docx = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='docx')
        pdf = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='pdf')
        h_docx = docx.get('prcy71_final_artifact_hash') or (
            docx.get('diag') or {}).get('prcy71_final_artifact_hash')
        h_pdf = pdf.get('prcy71_final_artifact_hash') or (
            pdf.get('diag') or {}).get('prcy71_final_artifact_hash')
        self.assertEqual(h_docx, h_pdf)
        self.assertTrue((docx.get('diag') or {}).get('prcy71_written_to_final_markdown'))
        self.assertTrue((pdf.get('diag') or {}).get('prcy71_written_to_content_json'))


if __name__ == '__main__':
    unittest.main()
