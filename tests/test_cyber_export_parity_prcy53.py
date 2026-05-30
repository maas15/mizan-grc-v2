"""PR-CY53 — PDF table layout hardening for Arabic Cyber strategy.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy53.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy53_')
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


class ExportParityPrcy53Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_strategic_objectives_layout_profile(self):
        prof = _P41.get_pdf_table_layout_profile('strategic_objectives', 5)
        self.assertEqual(prof['render_mode'], 'table')
        weights = prof['col_weights']
        self.assertAlmostEqual(sum(weights), 1.0, places=2)
        # Wider columns for objective, target, rationale (# and horizon narrow).
        self.assertGreater(weights[1], weights[0])
        self.assertGreater(weights[1], weights[4])
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_table_layout_profiles_applied'])

    @_skip
    def test_confidence_factors_card_layout_labels_intact(self):
        prof = _P41.get_pdf_table_layout_profile('conf_factor', 4)
        self.assertEqual(prof['render_mode'], 'cards')
        factors = [t for t in self.model['blocks']['confidence_risk_register']['tables']
                   if t['schema'] == 'conf_factor'][0]
        canonical = [f[0] for f in _P41.CANONICAL_CONFIDENCE_FACTORS_AR]
        self.assertEqual([r[0] for r in factors['rows']], canonical)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_confidence_factor_layout_valid'])
        self.assertIn('_pro_render_conf_factor_cards', _APP_SOURCE)

    @_skip
    def test_governance_split_when_wide(self):
        prof = _P41.get_pdf_table_layout_profile('governance', 5)
        self.assertTrue(prof.get('split_if_wide'))
        gov = self.model['blocks']['governance_ownership']
        self.assertTrue(_P41.governance_pdf_split_valid(self.model['blocks']))
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_governance_split_if_wide'])
        self.assertIn('governance_split', _APP_SOURCE)

    @_skip
    def test_roadmap_rejects_generic_rows(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        self.assertTrue(_P41.roadmap_generic_rows_absent(rows))
        for r in rows:
            init = str(r[2])
            out = str(r[4])
            self.assertNotIn(init, _P41.ROADMAP_GENERIC_INITIATIVES)
            self.assertNotIn(out, _P41.ROADMAP_GENERIC_OUTPUTS)
        weak = _P41._fill_roadmap_row(
            ['P', '1-6', 'تنفيذ حلول', 'خبير', 'مخرج معتمد', 'NCA ECC'], 'ar')
        self.assertNotIn(weak[2], _P41.ROADMAP_GENERIC_INITIATIVES)
        self.assertNotIn(weak[4], _P41.ROADMAP_GENERIC_OUTPUTS)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_roadmap_generic_rows_absent'])

    @_skip
    def test_kpi_target_column_not_formula(self):
        main = [t for t in self.model['blocks']['kpi_kri_framework']['tables']
                if t['schema'] == 'kpi_main'][0]
        for r in main['rows']:
            target = r[3]
            self.assertFalse(_P41._is_formula_like_target(target))
            self.assertNotIn('×', target)
            self.assertNotIn('÷', target)
        formula_like = '(المنجز ÷ المخطط) × 100'
        self.assertTrue(_P41._is_formula_like_target(formula_like))
        derived = _P41._derive_kpi_target(
            'زمن الاستجابة للحوادث', '—', 'ar')
        self.assertIn('4', derived)
        self.assertNotIn('×', derived)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_kpi_target_column_valid'])

    @_skip
    def test_vertical_stack_warnings_detected(self):
        warnings = _P41.estimate_table_vertical_stack_warnings(self.model)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_table_vertical_stack_warnings'])
        self.assertEqual(
            checks.get('table_vertical_stack_warning_count'),
            len(checks.get('table_vertical_stack_warnings') or []))
        # Synthetic long cell should trigger a stack/overflow warning.
        mock = {
            'blocks': {
                'vision_objectives': {
                    'tables': [{
                        'schema': 'strategic_objectives',
                        'header': list(_P41.SCHEMA_STRATEGIC_OBJECTIVES_AR),
                        'rows': [[
                            '1', 'x' * 300, 'target', 'rationale', '24 شهر',
                        ]],
                    }],
                },
            },
        }
        long_warn = _P41.collect_vertical_stack_warnings(mock)
        self.assertTrue(len(long_warn) >= 1)
        self.assertIn('schema', long_warn[0])

    @_skip
    def test_docmodel_all_gates_pass(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docmodel_professional_passed'], checks)


if __name__ == '__main__':
    unittest.main(verbosity=2)
