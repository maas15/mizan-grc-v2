"""PR-CY61 — KPI metric semantic alignment for PDF export gate.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy61.py -v
"""
import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from copy import deepcopy


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy61_')
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


def _kpi_blocks(pairs):
    """Build kpi_kri_framework tables from (name, type, target, formula, source)."""
    main_rows, formula_rows = [], []
    for i, (name, kpi_type, target, formula, source) in enumerate(pairs, 1):
        idx = str(i)
        main_rows.append([idx, name, kpi_type, target, 'شهري', 'CISO', '12ش'])
        formula_rows.append([idx, name, formula, source])
    return {
        'kpi_kri_framework': {
            'tables': [
                {'schema': 'kpi_main',
                 'header': list(_P41.SCHEMA_KPI_MAIN_AR),
                 'rows': main_rows},
                {'schema': 'kpi_formula',
                 'header': list(_P41.SCHEMA_KPI_FORMULA_AR),
                 'rows': formula_rows},
            ],
        },
    }


def _model_with_kpis(pairs):
    from tests.test_cyber_export_parity_prcy50 import _model as _base_model
    model = deepcopy(_base_model())
    model['blocks'].update(_kpi_blocks(pairs))
    return _P41._finalize_professional_blocks(model['blocks'], 'ar'), model


class ExportParityPrcy61Tests(unittest.TestCase):

    @_skip
    def test_incident_response_time_cannot_have_percentage_formula(self):
        name = 'زمن الاستجابة للحوادث الحرجة'
        formula = '(عدد الحوادث المعالجة ضمن SLA ÷ إجمالي الحوادث) × 100'
        blocks, _ = _model_with_kpis([
            (name, 'KPI', '< 4 ساعات', formula, 'ITSM'),
        ])
        main = blocks['kpi_kri_framework']['tables'][0]['rows'][0]
        formula_row = blocks['kpi_kri_framework']['tables'][1]['rows'][0]
        self.assertNotIn('× 100', formula_row[2])
        self.assertIn('أزمنة', formula_row[2])
        self.assertNotIn('%', main[3])

    @_skip
    def test_incident_sla_percentage_metric_renamed(self):
        name = 'معدل فعالية الاستجابة للحوادث الأمنية'
        formula = (
            '(عدد الحوادث الحرجة المعالجة ضمن SLA ÷ إجمالي الحوادث الحرجة) × 100')
        blocks, _ = _model_with_kpis([
            (name, 'KPI', '< 4 ساعات', formula, 'ITSM'),
        ])
        main = blocks['kpi_kri_framework']['tables'][0]['rows'][0]
        self.assertIn('نسبة', main[1])
        self.assertIn('SLA', main[1])
        self.assertIn('≥95%', main[3])
        self.assertIn('× 100', blocks['kpi_kri_framework']['tables'][1]['rows'][0][2])

    @_skip
    def test_iam_pam_target_does_not_repeat_metric_name(self):
        name = 'نسبة تغطية إدارة الهوية والوصول المميز'
        target = name
        formula = '(عدد الحسابات ÷ الإجمالي) × 100'
        blocks, _ = _model_with_kpis([
            (name, 'KPI', target, formula, 'IAM'),
        ])
        main = blocks['kpi_kri_framework']['tables'][0]['rows'][0]
        self.assertNotEqual(main[3], name)
        self.assertIn('≥95%', main[3])
        self.assertIn('IAM', blocks['kpi_kri_framework']['tables'][1]['rows'][0][3])

    @_skip
    def test_vulnerability_percentage_renames_zaman_to_nisba(self):
        name = 'زمن إغلاق الثغرات الأمنية الحرجة'
        formula = '(عدد الثغرات المغلقة ÷ الإجمالي) × 100'
        blocks, _ = _model_with_kpis([
            (name, 'KPI', '95% خلال 72 ساعة', formula, 'VM'),
        ])
        main = blocks['kpi_kri_framework']['tables'][0]['rows'][0]
        self.assertIn('نسبة', main[1])
        self.assertNotIn('زمن', main[1])
        self.assertIn('SLA', main[1])

    @_skip
    def test_phishing_kri_uses_failure_rate_wording(self):
        name = 'مستوى الوعي الأمني للموظفين من التصيد الاحتيالي'
        formula = '(عدد الفاشلين ÷ المختبرين) × 100'
        blocks, _ = _model_with_kpis([
            (name, 'KRI', 'أقل من 5%', formula, 'LMS'),
        ])
        main = blocks['kpi_kri_framework']['tables'][0]['rows'][0]
        self.assertEqual(main[2], 'KRI')
        self.assertIn('فشل', main[1])
        self.assertIn('تصيد', main[1])
        self.assertNotIn('وعي', main[1])

    @_skip
    def test_kpi_metric_semantics_gate_passes_live_pattern(self):
        pairs = [
            ('معدل فعالية الاستجابة للحوادث الأمنية', 'KPI', '< 4 ساعات',
             '(عدد الحوادث الحرجة المعالجة ضمن SLA ÷ إجمالي الحوادث الحرجة) × 100',
             'ITSM'),
            ('نسبة تغطية إدارة الهوية والوصول المميز', 'KPI',
             'نسبة تغطية إدارة الهوية والوصول المميز',
             '(عدد الحسابات ÷ الإجمالي) × 100', 'IAM'),
            ('زمن إغلاق الثغرات الأمنية الحرجة', 'KPI', '95% خلال 72 ساعة',
             '(عدد الثغرات المغلقة ÷ الإجمالي) × 100', 'VM'),
            ('مستوى الوعي الأمني للموظفين من التصيد الاحتيالي', 'KRI',
             'أقل من 5%', '(عدد الفاشلين ÷ المختبرين) × 100', 'LMS'),
        ]
        blocks, base = _model_with_kpis(pairs)
        model = {**base, 'blocks': blocks}
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['kpi_metric_semantics_valid'], checks)
        self.assertFalse(_P41.collect_kpi_metric_semantics_issues(model, 'ar'))

    @_skip
    def test_kpi_metric_semantics_diag_reports_invalid_rows(self):
        bad_model = {
            'lang': 'ar',
            'blocks': _kpi_blocks([
                ('زمن الاستجابة للحوادث', 'KPI', '< 4 ساعات',
                 '(عدد ÷ الإجمالي) × 100', 'ITSM'),
            ]),
        }
        issues = _P41.collect_kpi_metric_semantics_issues(bad_model, 'ar')
        self.assertTrue(issues)
        diag = _P41.build_kpi_metric_semantics_diag(bad_model, 'ar')
        self.assertGreater(diag['invalid_rows'], 0)
        first = diag['issues'][0]
        for key in (
                'row_index', 'metric_name', 'metric_type', 'target', 'formula',
                'source', 'detected_family', 'reason', 'normalized_name',
                'normalized_target', 'normalized_formula', 'normalized_source'):
            self.assertIn(key, first, msg=key)
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            _P41.emit_kpi_metric_semantics_diag(bad_model, 'ar')
        finally:
            sys.stdout = old
        out = buf.getvalue()
        self.assertIn('[KPI-METRIC-SEMANTICS-DIAG]', out)
        self.assertIn('invalid_rows', out)

    @_skip
    def test_prcy46_through_60_regression_hooks_present(self):
        """Sanity: CY61 helpers coexist with prior export parity gates."""
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['kpi_detail_table_valid'])
        self.assertTrue(checks['kpi_formula_source_valid'])
        self.assertTrue(checks['roadmap_framework_mapping_valid'])


if __name__ == '__main__':
    unittest.main()
