"""PR-CY54 — PDF vertical-stack diagnostics and targeted fallbacks.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy54.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy54_')
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


def _model():
    from tests.test_cyber_export_parity_prcy50 import _model as _m50
    return _m50()


def _long_objectives_model():
    base = _model()
    tbl = {
        'schema': 'strategic_objectives',
        'header': list(_P41.SCHEMA_STRATEGIC_OBJECTIVES_AR),
        'rows': [[
            '1',
            'x' * 280,
            'target text',
            'rationale text',
            '24 شهر',
        ]],
    }
    base['blocks']['vision_objectives']['tables'] = [tbl]
    return base


class ExportParityPrcy54Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_warning_count_equals_len_warnings(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        warnings = checks.get('table_vertical_stack_warnings') or []
        self.assertEqual(
            checks.get('table_vertical_stack_warning_count'), len(warnings))
        for w in warnings:
            self.assertIn('schema', w)
            self.assertIn('cell_preview', w)
            self.assertIn('estimated_lines', w)

    @_skip
    def test_empty_warnings_with_stale_count_does_not_block_stack_gate(self):
        from professional_strategy_render import PDFRenderTracker, run_pdf_quality_gate
        model = _model()
        tracker = PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 3
        tracker.kpi_tables_rendered = 2
        # Simulate legacy divergence: count on tracker path vs empty list.
        tracker.table_vertical_stack_warnings = []
        passed, payload = run_pdf_quality_gate(
            tracker, '', lang='ar', model=model)
        self.assertEqual(
            payload.get('table_vertical_stack_warning_count'),
            len(payload.get('table_vertical_stack_warnings') or []))
        self.assertTrue(payload.get('pdf_table_vertical_stack_warnings'))

    @_skip
    def test_strategic_objectives_fallback_resolves_warnings(self):
        model = _long_objectives_model()
        raw = _P41.collect_vertical_stack_warnings(model)
        self.assertTrue(raw)
        self.assertEqual(raw[0]['schema'], 'strategic_objectives')
        ev = _P41.evaluate_vertical_stack_gate(model)
        self.assertIn('strategic_objectives',
                      ev['fallback_applied_by_schema'])
        self.assertEqual(ev['table_vertical_stack_warning_count'], 0)
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['pdf_table_vertical_stack_warnings'])

    @_skip
    def test_governance_fallback_mapping(self):
        gov_rows = [['CISO', 'scope' * 40, 'acc' * 40, 'rep' * 40, 'NCA ECC']]
        model = {
            'blocks': {
                'governance_ownership': {
                    'title': 'gov',
                    'rows': gov_rows,
                    'header': list(_P41.SCHEMA_GOVERNANCE_AR),
                },
            },
        }
        raw = _P41.collect_vertical_stack_warnings(model)
        self.assertTrue(any(w['schema'] == 'governance' for w in raw))
        fb = _P41.compute_pdf_stack_fallbacks(model)
        self.assertEqual(fb.get('governance'), 'governance_cards')
        ev = _P41.evaluate_vertical_stack_gate(model)
        self.assertEqual(ev['table_vertical_stack_warning_count'], 0)

    @_skip
    def test_traceability_fallback_mapping(self):
        model = {
            'blocks': {
                'traceability_matrix': {
                    'title': 'trace',
                    'split_tables': [{
                        'schema': 'trace_fw_gap',
                        'title': 'NCA ECC',
                        'header': list(_P41.SCHEMA_TRACE_FW_GAP_AR),
                        'rows': [['NCA ECC', 'cap', 'gap' * 120]],
                    }],
                },
            },
        }
        raw = _P41.collect_vertical_stack_warnings(model)
        self.assertTrue(any(w['schema'] == 'trace_fw_gap' for w in raw))
        fb = _P41.compute_pdf_stack_fallbacks(model)
        self.assertEqual(fb.get('trace_fw_gap'), 'trace_cards')
        ev = _P41.evaluate_vertical_stack_gate(model)
        self.assertEqual(ev['table_vertical_stack_warning_count'], 0)

    @_skip
    def test_confidence_cards_no_stack_warnings(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        conf = [t for t in self.model['blocks']['confidence_risk_register']['tables']
                if t['schema'] == 'conf_factor']
        raw = _P41.collect_vertical_stack_warnings(self.model)
        conf_warn = [w for w in raw if w.get('schema') == 'conf_factor']
        self.assertEqual(conf_warn, [])
        self.assertTrue(conf)
        self.assertTrue(checks['pdf_confidence_factor_layout_valid'])

    @_skip
    def test_pdf_gate_passes_when_fallbacks_resolve(self):
        model = _long_objectives_model()
        from professional_strategy_render import PDFRenderTracker, run_pdf_quality_gate
        tracker = PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 3
        tracker.kpi_tables_rendered = 2
        passed, payload = run_pdf_quality_gate(
            tracker, '', lang='ar', model=model)
        self.assertTrue(payload.get('pdf_table_vertical_stack_warnings'), payload)
        self.assertTrue(payload.get('docmodel_professional_passed'), payload)

    @_skip
    def test_vertical_stack_diag_fields(self):
        ev = _P41.evaluate_vertical_stack_gate(self.model)
        diag = _P41.emit_pdf_vertical_stack_diag(ev, gate_blocked=False)
        for key in ('warning_count', 'warnings', 'schemas_with_warnings',
                    'fallback_applied_by_schema', 'count_list_consistent'):
            self.assertIn(key, diag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
