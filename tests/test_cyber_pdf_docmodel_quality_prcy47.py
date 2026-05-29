"""PR-CY47 — professional PDF document-model quality.

The Arabic Cyber strategy PDF exported successfully (PR-CY46) but the document
still carried markdown residue, malformed/duplicated executive summary,
mis-mapped roadmap/KPI tables, a broken confidence ".%76" score, raw
confidence/risk tables, and a dropped traceability section.

These tests pin the rendering-layer (``professional_strategy_render``) fixes:
clean prose, structured environment/confidence/risk/gap tables, header-aware
roadmap + KPI mapping, roadmap phase coverage, and the docmodel-professional
quality gate.

Run:
    python -m pytest tests/test_cyber_pdf_docmodel_quality_prcy47.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_pdf_docmodel_prcy47_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


_APP_SOURCE = ''
_P41 = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _P41
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    with open(_APP_PATH, 'r', encoding='utf-8') as _f:
        _APP_SOURCE = _f.read()
except Exception as _e:  # noqa: BLE001
    raise SystemExit(f'Cannot load modules: {_e!r}')


_SECS = {
    'vision': (
        '## 1. الرؤية والأهداف\n\n**الرؤية:** بناء قدرات الأمن السيبراني.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | إنشاء إدارة الأمن السيبراني | اعتماد الهيكل | حوكمة | 6 شهور |\n'),
    'environment': (
        '## 3. البيئة التنظيمية والتهديدات\n\nالسياق التنظيمي: NCA-ECC.\n\n'
        '| البُعد | الإشارة / المصدر | التأثير المحتمل |\n'
        '|--------|------------------|----------------|\n'
        '| تنظيمي | NCA-ECC | عالٍ |\n'
        '| تهديد | تصيد phishing | عالٍ |\n'),
    'gaps': (
        '## 4. تحليل الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|---|---|---|---|\n'
        '| 1 | غياب إدارة الأمن السيبراني | لا توجد إدارة | حرجة | مفتوحة |\n\n'
        '#### دليل تطبيق الفجوة رقم 1\n'
        '1. اعتماد الهيكل التنظيمي\n'
        '2. تعيين CISO\n'),
    'roadmap': (
        '## 5. خارطة الطريق التنفيذية\n\n'
        '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
        '|---|---|---|---|---|\n'
        '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | الإدارة العليا '
        '| الشهر 1-3 | إدارة قائمة |\n'
        '| 2 | بناء SOC + SIEM | SOC Manager | الشهر 3-6 | مراقبة 24/7 |\n'),
    'kpis': (
        '## 6. مؤشرات الأداء\n\n'
        '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب '
        '| مصدر البيانات | المالك | التكرار | الإطار الزمني |\n'
        '|---|---|---|---|---|---|---|---|---|\n'
        '| 1 | تفعيل MFA | KPI | 100% | عدد الحسابات المفعّلة ÷ الإجمالي '
        '| IAM | CISO | شهري | 12ش |\n'),
    'confidence': (
        '## 7. تقييم الثقة والمخاطر\n\n**درجة الثقة:** .%76\n\n'
        '| # | عامل النجاح الحرج | الوصف | الأهمية |\n'
        '|---|---|---|---|\n'
        '| 1 | الدعم التنفيذي | التزام الإدارة العليا | عالية |\n\n'
        '| # | الخطر | الاحتمالية | التأثير | خطة التخفيف |\n'
        '|---|---|---|---|---|\n'
        '| 1 | غياب إدارة الأمن السيبراني | عالية | حرج | إنشاء إدارة |\n'),
}


def _build_model():
    base = {
        'lang': 'ar',
        'selected_frameworks': ['NCA DCC', 'NCA ECC'],
        'order': ['executive_summary', 'vision_objectives',
                  'environment_context', 'gap_analysis', 'roadmap',
                  'kpi_kri_framework', 'confidence_risk_register',
                  'governance_ownership', 'traceability_matrix'],
        'blocks': {
            'executive_summary': {
                'title': 'الملخص التنفيذي',
                'paragraphs': [
                    'بناء قدرات الأمن السيبراني وإنشاء إدارة متخصصة.',
                    '#### دليل تطبيق الفجوة رقم 1\n| 1 | اعتماد | CISO |'],
            },
            'governance_ownership': {
                'rows': [['CISO', 'إدارة الأمن السيبراني', 'مساءلة',
                          'مجلس الإدارة', 'NCA ECC']]},
            'traceability_matrix': {
                'rows': [['NCA ECC', 'الحوكمة', 'غياب إدارة',
                          'إنشاء إدارة', 'تفعيل', 'خطر حوكمة']]},
        },
    }
    return _P41.enrich_professional_blocks(
        base,
        {'vision': _SECS['vision'], 'environment': _SECS['environment'],
         'gaps': _SECS['gaps'], 'roadmap': _SECS['roadmap'],
         'kpis': _SECS['kpis'], 'confidence': _SECS['confidence']},
        {'mandatory_themes': ['الحوكمة', 'المراقبة'], 'horizon_months': '24'},
        'ar')


class DocModelQualityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _build_model()
        cls.blocks = cls.model['blocks']

    # 1
    def test_executive_summary_no_raw_table_residue(self):
        ex = self.blocks['executive_summary']
        for p in ex.get('paragraphs') or []:
            self.assertNotIn('|', p)
            self.assertNotIn('دليل تطبيق', p)
            self.assertNotIn('دليل تنفيذ', p)
        grid = ex.get('summary_grid') or {}
        self.assertTrue(grid)
        # Frameworks in canonical order: NCA ECC before NCA DCC.
        fws = grid.get('frameworks') or []
        self.assertEqual(fws[0], _P41.FRAMEWORK_ORDER[0])
        self.assertEqual(fws[1], _P41.FRAMEWORK_ORDER[1])

    # 2
    def test_confidence_score_normalized(self):
        conf = self.blocks['confidence_risk_register']
        self.assertEqual(conf.get('confidence_score'), '76%')
        for p in conf.get('paragraphs') or []:
            self.assertNotIn('.%', p)

    # 3
    def test_environment_table_no_separators(self):
        env = self.blocks['environment_context']
        for p in env.get('paragraphs') or []:
            self.assertNotIn('|', p)
            self.assertNotIn('---', p)
        tbls = env.get('tables') or []
        self.assertTrue(tbls, 'environment must have a structured table')
        self.assertEqual(tbls[0]['schema'], 'environment')
        self.assertEqual(list(tbls[0]['header']), list(_P41.SCHEMA_ENV_AR))

    # 4
    def test_gap_guides_render_alkhutwa(self):
        guides = [t for t in (self.blocks['gap_analysis'].get('tables') or [])
                  if t.get('schema') == 'gap_action']
        self.assertTrue(guides, 'gap implementation guide table expected')
        self.assertEqual(guides[0]['header'][0], 'الخطوة')
        for t in guides:
            for r in t['rows']:
                for c in r:
                    self.assertNotIn('طوة الخ', str(c))

    # 5
    def test_roadmap_phase_coverage(self):
        road = (self.blocks['roadmap'].get('tables') or [])[0]
        phases = ' '.join(str(r[0]) for r in road['rows'])
        self.assertIn('1-6', phases)
        self.assertIn('7-18', phases)
        self.assertIn('تأسيس', phases)
        self.assertIn('تمكين', phases)

    # 6
    def test_kpi_detail_formula_source_valid(self):
        kpi_tbls = self.blocks['kpi_kri_framework'].get('tables') or []
        formula = [t for t in kpi_tbls if t.get('schema') == 'kpi_formula']
        self.assertTrue(formula, 'kpi detail (formula/source) table expected')
        for r in formula[0]['rows']:
            self.assertFalse(_P41._is_freq_or_timeframe(r[2]),
                             f'formula must not be a frequency: {r[2]!r}')
            self.assertFalse(_P41._is_freq_or_timeframe(r[3]),
                             f'source must not be a timeframe: {r[3]!r}')

    # 7
    def test_confidence_risk_tables_clean(self):
        conf = self.blocks['confidence_risk_register']
        schemas = [t['schema'] for t in conf.get('tables') or []]
        self.assertIn('risk_register', schemas)
        self.assertIn('conf_factor', schemas)
        for t in conf.get('tables') or []:
            for r in t['rows']:
                for c in r:
                    self.assertNotIn('|', str(c))
                    self.assertNotIn('---', str(c))

    # 8
    def test_governance_rendered(self):
        gov = self.blocks['governance_ownership']
        self.assertTrue(gov.get('rows'))

    # 9
    def test_traceability_rendered(self):
        trace = self.blocks['traceability_matrix']
        self.assertTrue(trace.get('split_tables') or trace.get('rows'))

    # 10
    def test_no_raw_pipe_separator_in_rendered_paragraphs(self):
        # Block paragraphs become PDF Paragraphs verbatim; none may carry a
        # raw markdown table separator/pipe row.
        for kind in ('vision_objectives', 'environment_context',
                     'gap_analysis', 'confidence_risk_register',
                     'executive_summary'):
            for p in (self.blocks.get(kind) or {}).get('paragraphs') or []:
                self.assertNotIn('|---|', p)
                self.assertNotIn('|', p)

    def test_docmodel_professional_gate_passes(self):
        checks = _P41.prcy47_docmodel_professional_checks(self.model, 'ar')
        self.assertTrue(checks['docmodel_professional_passed'], checks)
        tracker = _P41.PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 4
        tracker.kpi_tables_rendered = 2
        passed, payload = _P41.run_pdf_quality_gate(
            tracker, _SECS['roadmap'], lang='ar', model=self.model)
        self.assertTrue(passed, payload)
        self.assertTrue(payload['docmodel_professional_passed'])

    def test_cleanup_diag_recorded(self):
        diag = self.model.get('docmodel_cleanup') or {}
        self.assertIn('residue_count_after', diag)
        self.assertEqual(diag['residue_count_after'], 0)
        self.assertEqual(diag['action_taken'], 'sanitized')


class TraceabilityRenderSourceTests(unittest.TestCase):

    def test_traceability_split_uses_append_not_extend(self):
        idx = _APP_SOURCE.find('def _pro_render_traceability(')
        self.assertGreater(idx, 0)
        body = _APP_SOURCE[idx:idx + 2500]
        self.assertNotIn('flow.extend(fl)', body)
        self.assertIn('flow.append(fl)', body)

    def test_docmodel_cleanup_log_present(self):
        self.assertIn('[PDF-DOCMODEL-CLEANUP]',
                      _APP_SOURCE + open(
                          os.path.join(os.path.dirname(__file__), '..',
                                       'professional_strategy_render.py'),
                          encoding='utf-8').read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
