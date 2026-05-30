"""PR-CY55 — Final export polish: TOC, roadmap mapping, KPI semantics,
confidence cards, glossary scoping.

Run:
    python -m pytest tests/test_cyber_export_parity_prcy55.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_export_parity_prcy55_')
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


class ExportParityPrcy55Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _model()

    @_skip
    def test_docx_toc_includes_professional_sections(self):
        entries = _P41.get_toc_entries_from_model(self.model)
        self.assertTrue(entries, 'TOC entries must be present')
        blob = ' '.join(str(t) for _, t in entries)
        for fragment in (
                'الملخص', 'النطاق', 'المنهجية', 'الحوكمة', 'تتبع', 'الملاحق'):
            self.assertIn(fragment, blob, msg=fragment)
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docx_toc_professional_sections'])
        self.assertIn('_docx_render_toc_page', _APP_SOURCE)
        self.assertIn('get_toc_entries_from_model', _APP_SOURCE)

    @_skip
    def test_dcc_roadmap_capabilities_map_to_nca_dcc(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        dcc_rows = [
            r for r in rows
            if any(k in str(r[2]).lower() for k in (
                'dlp', 'encryption', 'تشفير', 'تصنيف', 'بيانات'))]
        self.assertTrue(dcc_rows)
        for r in dcc_rows:
            self.assertIn('DCC', str(r[5]))
        enc_fw = _P41._infer_roadmap_framework(
            'تشفير البيانات الحساسة', '1-6 أشهر', 1, '', 'ar')
        self.assertEqual(enc_fw, 'NCA DCC')
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['roadmap_framework_mapping_valid'])

    @_skip
    def test_csirt_soc_iam_map_to_nca_ecc(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        ecc_rows = [
            r for r in rows
            if any(k in str(r[2]).upper() for k in ('CSIRT', 'SOC', 'IAM'))]
        self.assertTrue(ecc_rows)
        for r in ecc_rows:
            self.assertIn('ECC', str(r[5]))
        for init in ('CSIRT', 'SOC/SIEM', 'IAM/PAM/MFA'):
            fw = _P41._infer_roadmap_framework(init, '7-18 شهر', 2, '', 'ar')
            self.assertEqual(fw, 'NCA ECC', msg=init)

    @_skip
    def test_roadmap_output_matches_initiative_not_generic_governance(self):
        rows = self.model['blocks']['roadmap']['tables'][0]['rows']
        csirt = next(r for r in rows if 'CSIRT' in str(r[2]))
        self.assertNotEqual(csirt[4], 'إدارة ولجنة حوكمة فاعلة')
        dlp = next(
            r for r in rows
            if 'DLP' in str(r[2]) or 'بيانات' in str(r[2]))
        self.assertNotEqual(dlp[4], 'إدارة ولجنة حوكمة فاعلة')
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_roadmap_generic_rows_absent'])

    @_skip
    def test_kpi_names_match_formulas(self):
        tbl = _P41.split_kpi_tables(
            '| # | المؤشر | النوع | القيمة |\n|---|---|---|---|\n'
            '| 1 | اكتشاف الثغرات الحرجة | KPI | 95% |\n'
            '| 2 | فعالية التوعية الأمنية | KPI | 100% |\n', 'ar')
        main = [t for t in tbl if t['schema'] == 'kpi_main'][0]
        formula = [t for t in tbl if t['schema'] == 'kpi_formula'][0]
        self.assertIn('إغلاق', main['rows'][0][1])
        self.assertNotIn('اكتشاف', main['rows'][0][1])
        self.assertIn('إكمال', main['rows'][1][1])
        self.assertNotIn('فعالية', main['rows'][1][1])
        self.assertTrue(_P41.kpi_name_formula_aligned(
            main['rows'][0][1], formula['rows'][0][2], 'ar'))
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['kpi_metric_semantics_valid'])

    @_skip
    def test_pdf_confidence_cards_no_reversed_arabic_labels(self):
        self.assertIn('العامل', _APP_SOURCE)
        self.assertNotIn('ةمهاسملا', _APP_SOURCE)
        for frag in _P41.REVERSED_CONFIDENCE_LABEL_FRAGMENTS:
            self.assertFalse(_P41.pdf_confidence_card_labels_readable(frag))
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['pdf_confidence_card_labels_readable'])
        self.assertTrue(checks['pdf_confidence_factor_labels_intact'])

    @_skip
    def test_glossary_excludes_unrelated_domains_for_ecc_dcc(self):
        appendices = _APP._build_appendices_block(
            ['ECC', 'DCC'],
            lang='ar',
            content_sections={'vision': 'استراتيجية NCA ECC و NCA DCC'},
            domain_code='cyber',
        )
        blob = ' '.join(str(x) for pair in appendices for x in pair)
        self.assertNotIn('DGA', blob)
        self.assertNotIn('NDMO', blob)
        self.assertNotIn('ISO31000', blob)
        self.assertIn('ECC', blob)
        self.assertIn('DCC', blob)

    @_skip
    def test_docmodel_all_subgates_pass_on_fixture(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docmodel_professional_passed'])


if __name__ == '__main__':
    unittest.main()
