"""PR-CY41 — Professional Arabic PDF/DOCX rendering layer tests."""

import functools
import importlib.util
import os
import re
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_prcy41_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


_P41 = None
_APP = None
_APP_SOURCE = ''
try:
    import professional_strategy_render as _P41
except ImportError as _e:
    raise SystemExit(f'Cannot import professional_strategy_render: {_e!r}')

try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    with open(_APP_PATH, 'r', encoding='utf-8') as _f:
        _APP_SOURCE = _f.read()
except Exception as _e:  # noqa: BLE001
    raise SystemExit(f'Cannot load app: {_e!r}')


def _skip_app(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app not loaded')
        return fn(self, *a, **kw)
    return _w


_SO_MD = (
    '## الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | حوكمة الأمن | ≥ 95% | مبرر | 12 شهر |\n'
)

_KPI_WIDE = (
    '## مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات | تواتر | المالك | الإطار |\n'
    '|---|---|---|---|---|---|---|\n'
    '| 1 | تغطية الترقيع | 95% | (x/y)*100 | إدارة الثغرات | شهري | CISO | 12m |\n'
)

_ROADMAP_MD = (
    '## خارطة الطريق\n\n'
    '### المرحلة 1\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | Q1 | حوكمة | CISO | مخرج | ECC |\n'
)


class ArabicSpacingTests(unittest.TestCase):

    def test_concat_fixes_applied(self):
        raw = 'امتثاللا وتقلعن السيبرانيمع'
        out = _P41.normalize_arabic_for_render(raw)
        self.assertIn('امتثال لا', out)
        self.assertIn('تقل عن', out)
        self.assertIn('السيبراني مع', out)

    def test_acronyms_preserved(self):
        raw = 'NCA ECC و NCA DCC و CISO'
        out = _P41.normalize_arabic_for_render(raw)
        self.assertIn('NCA ECC', out)
        self.assertIn('CISO', out)


class TableSchemaTests(unittest.TestCase):

    def test_strategic_objectives_table_schema(self):
        tables = _P41.parse_markdown_tables(_SO_MD)
        spec = _P41.normalize_strategic_objectives_table(tables, 'ar')
        self.assertIsNotNone(spec)
        self.assertEqual(spec['schema'], 'strategic_objectives')
        self.assertEqual(len(spec['header']), 5)
        self.assertGreaterEqual(len(spec['rows']), 1)

    def test_kpi_split_into_two_tables(self):
        tables = _P41.split_kpi_tables(_KPI_WIDE, 'ar')
        self.assertGreaterEqual(len(tables), 2)
        schemas = {t['schema'] for t in tables}
        self.assertIn('kpi_main', schemas)
        self.assertIn('kpi_formula', schemas)

    def test_roadmap_table_has_rows(self):
        spec = _P41.normalize_roadmap_table(_ROADMAP_MD, 'ar')
        self.assertIsNotNone(spec)
        self.assertGreater(len(spec['rows']), 0)

    def test_roadmap_gate_blocks_empty_rows(self):
        tr = _P41.PDFRenderTracker()
        tr.sections_present['roadmap'] = True
        tr.roadmap_rows_rendered = 0
        passed, payload = _P41.run_pdf_quality_gate(
            tr, _ROADMAP_MD, lang='ar')
        self.assertFalse(passed)
        self.assertTrue(any(
            'roadmap_table_not_rendered' in b for b in payload.get('blockers', [])))


class MarkdownResidueTests(unittest.TestCase):

    def test_strip_bold_labels_and_markers(self):
        raw = '**الرؤية:** نص <!-- trace:x --> [REQUIRES_AI_TARGET_REPAIR]'
        out = _P41.strip_markdown_residue(raw)
        self.assertNotIn('**', out)
        self.assertNotIn('REQUIRES_AI', out)
        self.assertNotIn('<!--', out)

    def test_confidence_score_not_reversed(self):
        raw = '**درجة الثقة:** .%82'
        out = _P41.fix_confidence_display(raw)
        self.assertIn('82%', out)
        self.assertNotIn('.%82', out)


class ExecutiveSummaryTests(unittest.TestCase):

    def test_framework_order_in_grid(self):
        blk = {'paragraphs': ['purpose text']}
        enhanced = _P41.enhance_executive_summary(
            blk, {'gaps': 'فجوة 1\nفجوة 2', 'confidence': '82%'},
            {}, ['ECC', 'DCC'], 'ar')
        fws = enhanced['summary_grid']['frameworks']
        self.assertTrue(fws[0].startswith('NCA ECC'))
        self.assertTrue(any('DCC' in f for f in fws))


class AppIntegrationTests(unittest.TestCase):

    @_skip_app
    def test_build_professional_model_entry_exists(self):
        self.assertTrue(hasattr(_APP, '_build_professional_strategy_document_model'))

    @_skip_app
    def test_pdf_quality_gate_tag_in_source(self):
        self.assertIn('[PDF-QUALITY-GATE]', _APP_SOURCE)

    @_skip_app
    def test_pdf_schema_table_renderer_exists(self):
        self.assertIn('_pro_render_schema_table', _APP_SOURCE)
        self.assertIn('repeatRows=1', _APP_SOURCE)

    @_skip_app
    def test_governance_headers_five_col(self):
        self.assertIn("'نطاق المسؤولية', 'المساءلة'", _APP_SOURCE)

    @_skip_app
    def test_traceability_split_tables_preferred(self):
        self.assertIn('split_tables', _APP_SOURCE)

    @_skip_app
    def test_contract_logic_not_modified(self):
        self.assertIn('read_only=bool(cyber_sealed_artifact)', _APP_SOURCE)
        self.assertNotIn('cyber_contract.py', _APP_SOURCE)


class RegressionTests(unittest.TestCase):

    @_skip_app
    def test_prcy40_sealed_path_still_present(self):
        self.assertIn('_strategy_row_is_sealed_cyber', _APP_SOURCE)

    @_skip_app
    def test_strategic_objectives_compose_log_preserved(self):
        self.assertIn('[STRATEGIC-OBJECTIVES-SCHEMA-FIRST-COMPOSE]', _APP_SOURCE)


if __name__ == '__main__':
    unittest.main()
