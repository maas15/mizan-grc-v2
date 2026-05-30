"""PR-CY58 — Roadmap capability-family validation and KPI semantic fixes.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy58.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy58_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')

_P41 = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _P41
except Exception as _e:
    raise SystemExit(f'Cannot load: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _P41 is None:
            self.skipTest('module unavailable')
        return fn(self, *a, **kw)
    return _w


class ExportParityPrcy58Tests(unittest.TestCase):

    @_skip
    def test_generic_dcc_row_rewritten_before_validation(self):
        row = ['المرحلة 1: تأسيس (1-6 أشهر)', '1-6 أشهر',
               'تطبيق ضوابط', 'CISO', 'سياسة', 'NCA DCC']
        filled, meta = _P41._fill_roadmap_row(row, 'ar')
        self.assertNotIn('تطبيق ضوابط', filled[2])
        self.assertNotEqual(filled[4], 'سياسة')
        self.assertIn('DCC', filled[5])
        self.assertEqual(meta['capability_family'], 'data_classification')
        violations = _P41.collect_roadmap_framework_violations(
            [filled], 'ar', [meta])
        self.assertFalse(violations, msg=violations)

    @_skip
    def test_framework_validation_uses_capability_family_not_display(self):
        row = ['المرحلة 1', '1-6', 'تطبيق ضوابط', 'CISO', 'سياسة', 'NCA DCC']
        filled, meta = _P41._fill_roadmap_row(row, 'ar')
        compact = _P41._compact_roadmap_row([
            filled[0], filled[1], 'ضوابط', filled[3], 'سياسة', filled[5],
        ], 'ar')
        violations = _P41.collect_roadmap_framework_violations(
            [compact], 'ar', [meta])
        self.assertFalse(violations, msg=violations)

    @_skip
    def test_dcc_capabilities_map_to_nca_dcc(self):
        for init, family in (
                ('DLP', 'dlp'),
                ('تشفير', 'encryption'),
                ('تصنيف البيانات', 'data_classification')):
            family_out = _P41._infer_capability_family(
                init, '', 'NCA DCC', 1, 'ar')[0]
            self.assertEqual(family_out, family)
            fw = _P41._framework_for_capability_family(family_out)
            self.assertIn('DCC', fw)

    @_skip
    def test_ecc_capabilities_map_to_nca_ecc(self):
        for init, family in (
                ('SOC/SIEM', 'soc'),
                ('IAM/PAM/MFA', 'iam'),
                ('CSIRT', 'csirt'),
                ('إدارة الثغرات', 'vulnerability'),
                ('حوكمة CISO', 'governance')):
            family_out = _P41._infer_capability_family(
                init, '', 'NCA ECC', 2, 'ar')[0]
            self.assertEqual(family_out, family)
            fw = _P41._framework_for_capability_family(family_out)
            self.assertIn('ECC', fw)

    @_skip
    def test_roadmap_framework_mapping_valid_on_fixture(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['roadmap_framework_mapping_valid'])

    @_skip
    def test_soc_detection_metric_not_incident_formula(self):
        name = 'تغطية SOC وفعالية كشف التهديدات'
        formula = _P41._derive_kpi_formula(name, 'ar')
        self.assertIn('× 100', formula)
        self.assertNotIn('حادث', formula)
        self.assertNotIn('استجاب', formula)
        self.assertTrue(_P41.kpi_formula_source_row_valid(
            name, formula, _P41._derive_kpi_source(name, 'ar'), 'ar'))

    @_skip
    def test_kpi_formula_source_gate_patterns(self):
        cases = (
            ('زمن الاستجابة للحوادث', 'ITSM / SOAR / SIEM', '< 4'),
            ('إغلاق الثغرات الحرجة', 'منصة إدارة الثغرات', '95%'),
            ('تفعيل MFA', 'منصة إدارة الهويات IAM', '100%'),
            ('نجاح النسخ الاحتياطي', 'منصة النسخ الاحتياطي', '99%'),
            ('تغطية DLP للبيانات', 'DLP', '95%'),
        )
        for name, src_hint, target_hint in cases:
            formula = _P41._derive_kpi_formula(name, 'ar')
            source = _P41._derive_kpi_source(name, 'ar')
            target = _P41._derive_kpi_target(name, '100%', 'ar')
            self.assertTrue(_P41.kpi_formula_source_row_valid(
                name, formula, source, 'ar'), msg=name)
            if src_hint:
                self.assertIn(src_hint.split()[0], source, msg=name)
            if target_hint:
                self.assertIn(target_hint.replace('%', ''), target, msg=name)

    @_skip
    def test_prcy58_arabic_spacing_cleanup(self):
        samples = (
            'بناءخط الأساس',
            'الأولضد التهديدات',
            'البياناتفي الأنظمة',
            'الالمسؤولتنفيذي',
            'متخصصةللأمن',
        )
        for s in samples:
            fixed = _P41.normalize_arabic_for_render(s)
            for bad in (
                    'بناءخط', 'الأولضد', 'البياناتفي',
                    'الالمسؤولتنفيذي', 'متخصصةللأمن'):
                self.assertNotIn(bad, fixed, msg=s)

    @_skip
    def test_roadmap_framework_mapping_diag_shape(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        diag = _P41.build_roadmap_framework_mapping_diag(_model(), 'ar')
        for key in (
                'row_count', 'rows_by_capability_family', 'dcc_rows',
                'ecc_rows', 'violations', 'action_taken'):
            self.assertIn(key, diag)

    @_skip
    def test_prcy46_through_57_still_pass(self):
        from tests.test_cyber_export_parity_prcy50 import _model
        model = _model()
        checks = _P41.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['docmodel_professional_passed'])
        self.assertTrue(checks['kpi_formula_source_valid'])
        self.assertTrue(checks['kpi_detail_table_valid'])


if __name__ == '__main__':
    unittest.main()
