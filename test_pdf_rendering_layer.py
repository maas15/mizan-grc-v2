"""PR-CY42B — Professional PDF/DOCX rendering-layer tests.

These tests validate the PR-CY42B presentation polish (executive-summary
cards, roadmap timeline, split KPI tables, governance split, traceability
split, pagination helpers, and the visual quality gate) as it is integrated
into the EXISTING production rendering architecture
(``professional_strategy_render`` + ``app``).

Important — single production model:
    The production builder ``_build_professional_strategy_document_model``
    returns a *dict-shaped* model (``model['blocks']`` is a dict keyed by
    block kind, ``model['order']`` is the section order). PR-CY42B does NOT
    introduce a second / list-shaped model. These tests therefore assert
    against the production dict model and prove the PR-CY42B features are
    rendered from it.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_prcy42b_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


import professional_strategy_render as P42  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_APP_PATH = os.path.join(_HERE, 'app.py')
_spec = importlib.util.spec_from_file_location('app', _APP_PATH)
APP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(APP)
with open(_APP_PATH, 'r', encoding='utf-8') as _f:
    APP_SOURCE = _f.read()


# Production-model rendering-layer entry points (delegating to the module).
_build_professional_strategy_document_model = (
    APP._build_professional_strategy_document_model)
_render_professional_model_as_markdown = (
    APP._render_professional_model_as_markdown)
_run_pdf_quality_gate = APP._run_pdf_quality_gate
_apply_arabic_spacing_fixes = APP._apply_arabic_spacing_fixes
_strip_render_markdown_residue = APP._strip_render_markdown_residue
_prepare_pdf_arabic_text = APP._prepare_pdf_arabic_text
_ensure_arabic_pdf_font = APP._ensure_arabic_pdf_font
_pdf_peek_follow_lines = APP._pdf_peek_follow_lines
_pdf_is_roadmap_timeline_table = APP._pdf_is_roadmap_timeline_table
_pdf_is_exec_summary_cards_table = APP._pdf_is_exec_summary_cards_table


_RICH_CONTENT_AR = (
    "## الرؤية والأهداف الاستراتيجية\n"
    "هذه وثيقة اختبار لطبقة العرض في مجال الأمن السيبراني.\n\n"
    "| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |\n"
    "|---|---|---|---|---|\n"
    "| 1 | رفع الحوكمة | 90% | الامتثال | 12 شهر |\n"
    "| 2 | تعزيز الرصد | 95% | خفض المخاطر | 18 شهر |\n\n"
    "## خارطة الطريق\n"
    "| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n"
    "|---|---|---|---|---|---|\n"
    "| المرحلة 1 | 1-2 | تأسيس الحوكمة | CISO | نموذج تشغيل | NCA ECC |\n"
    "| المرحلة 2 | 3-6 | تطوير SOC | SOC Manager | لوحة رصد | NCA ECC |\n"
    "| المرحلة 3 | 7-18 | برنامج IAM | IAM Lead | ضوابط وصول | NCA DCC |\n\n"
    "## مؤشرات الأداء والمخاطر\n"
    "| # | المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب |"
    " مصدر البيانات | المالك | الإطار الزمني |\n"
    "|---|---|---|---|---|---|---|---|\n"
    "| 1 | زمن الاستجابة | KPI | 4 ساعات | x/y | SIEM | CISO | 12 شهر |\n"
    "| 2 | نسبة الالتزام | KPI | 95% | a/b | GRC Platform | CISO | 12 شهر |\n"
    "| 3 | تصنيف البيانات الحساسة | KRI | 100% | c/d | DLP | Data Lead | 12 شهر |\n\n"
    "## تقييم الثقة والمخاطر\n"
    "درجة الثقة: 82%\n"
)

_CLEAN_DIAGNOSTICS = {
    'pages': 6,
    'arabic_font_valid': True,
    'dense_table_count': 0,
    'orphan_heading_count': 0,
    'table_header_orphan_count': 0,
    'dense_page_count': 0,
    'continued_table_header_missing_count': 0,
    'section_spacing_warnings': 0,
    'table_overflow_warnings': 0,
}


def _build_rich_model():
    return _build_professional_strategy_document_model(
        _RICH_CONTENT_AR,
        metadata={'org_name': 'QA', 'sector': 'Government',
                  'doc_type': 'Cyber Strategy', 'domain': 'cyber',
                  'mandatory_themes': ['الحوكمة', 'الرصد', 'إدارة الهوية',
                                       'الاستجابة', 'الامتثال']},
        sections=None,
        selected_frameworks=['ECC', 'DCC'],
        lang='ar',
        domain='cyber',
    )


class ProductionModelShapeTests(unittest.TestCase):
    """Compatibility: the single production model must stay dict-shaped."""

    @classmethod
    def setUpClass(cls):
        cls.model = _build_rich_model()

    def test_model_blocks_is_dict_not_list(self):
        self.assertIsInstance(self.model, dict)
        self.assertIsInstance(self.model.get('blocks'), dict)
        self.assertNotIsInstance(self.model.get('blocks'), list)

    def test_order_is_list_and_render_layer_marked(self):
        self.assertIsInstance(self.model.get('order'), list)
        self.assertEqual(self.model.get('render_layer'), 'prcy41_professional')

    def test_downstream_consumers_keys_present(self):
        blocks = self.model['blocks']
        # The PDF/DOCX call sites read these exact dict paths.
        self.assertIn('traceability_matrix', blocks)
        self.assertIn('rows', blocks['traceability_matrix'])
        self.assertIn('toc', blocks)
        self.assertIn('entries', blocks['toc'])
        self.assertIn('doc_control', blocks)

    def test_roadmap_block_has_structured_table(self):
        rm = self.model['blocks']['roadmap']
        self.assertTrue(rm.get('tables'))
        self.assertGreaterEqual(len(rm['tables'][0]['rows']), 3)

    def test_kpi_block_split_into_two_tables(self):
        kpi = self.model['blocks']['kpi_kri_framework']
        schemas = {t['schema'] for t in kpi.get('tables') or []}
        self.assertIn('kpi_main', schemas)
        self.assertIn('kpi_formula', schemas)

    def test_executive_summary_grid_present(self):
        ex = self.model['blocks']['executive_summary']
        self.assertIn('summary_grid', ex)
        self.assertTrue(ex['summary_grid'].get('frameworks'))


class MarkdownSerializationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _build_rich_model()
        cls.md = _render_professional_model_as_markdown(cls.model)

    def test_roadmap_timeline_and_detailed_render(self):
        self.assertIn('### Timeline', self.md)
        self.assertIn('### Detailed Roadmap', self.md)

    def test_timeline_before_detailed(self):
        self.assertLess(self.md.find('### Timeline'),
                        self.md.find('### Detailed Roadmap'))

    def test_kpi_split_tables_render(self):
        self.assertIn('صيغة الاحتساب', self.md)
        self.assertIn('مصدر البيانات', self.md)

    def test_executive_summary_cards_render(self):
        self.assertIn('| البطاقة | المحتوى |', self.md)
        self.assertIn('أهم الأولويات', self.md)
        self.assertIn('درجة الثقة', self.md)

    def test_framework_order_ecc_before_dcc(self):
        self.assertGreaterEqual(self.md.find('NCA ECC'), 0)
        self.assertLess(self.md.find('NCA ECC'), self.md.find('NCA DCC'))

    def test_governance_headers_present(self):
        self.assertIn('نطاق المسؤولية', self.md)
        self.assertIn('التقارير / التصعيد', self.md)

    def test_no_internal_markers_or_comments(self):
        self.assertNotIn('[REQUIRES_AI_', self.md)
        self.assertNotIn('<!--', self.md)


class VisualQualityGateTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = _build_rich_model()
        cls.md = _render_professional_model_as_markdown(cls.model)

    def test_gate_passes_with_clean_diagnostics(self):
        gate = _run_pdf_quality_gate(
            self.model, self.md, pdf_text=self.md,
            diagnostics=dict(_CLEAN_DIAGNOSTICS))
        self.assertTrue(gate['passed'], gate)
        self.assertTrue(gate['passed_visual_polish'])
        self.assertTrue(gate['pagination_polish_passed'])
        self.assertTrue(gate['roadmap_timeline_rendered'])
        self.assertTrue(gate['executive_summary_cards_rendered'])
        self.assertEqual(gate['raw_markdown_residue_count'], 0)

    def test_gate_fails_on_roadmap_heading_without_rows(self):
        model = _build_professional_strategy_document_model(
            '## خارطة الطريق\n## مؤشرات الأداء\n',
            metadata={'domain': 'cyber'}, lang='ar', domain='cyber')
        md = _render_professional_model_as_markdown(model)
        gate = _run_pdf_quality_gate(
            model, md, pdf_text=md,
            diagnostics={'pages': 3, 'arabic_font_valid': True})
        self.assertFalse(gate['passed'])
        self.assertEqual(gate['roadmap_failure_reason'],
                         'no_roadmap_rows_in_model')

    def test_gate_detects_dense_tables(self):
        gate = _run_pdf_quality_gate(
            self.model, self.md, pdf_text=self.md,
            diagnostics={'pages': 6, 'arabic_font_valid': True,
                         'dense_table_count': 7, 'dense_page_count': 5})
        self.assertFalse(gate['passed_visual_polish'])

    def test_gate_fails_with_unreadable_glyphs(self):
        gate = _run_pdf_quality_gate(
            self.model, self.md, pdf_text='IIIIIIII ■■■ \ufffd',
            diagnostics={'pages': 2, 'arabic_font_valid': False})
        self.assertFalse(gate['visual_text_quality_passed'])

    def test_pagination_gate_tolerates_minor_warnings(self):
        gate = _run_pdf_quality_gate(
            self.model, self.md, pdf_text=self.md,
            diagnostics={'pages': 6, 'arabic_font_valid': True,
                         'dense_table_count': 1, 'dense_page_count': 1,
                         'section_spacing_warnings': 1})
        self.assertTrue(gate['pagination_polish_passed'])


class ArabicAndResidueTests(unittest.TestCase):

    def test_arabic_spacing_fixes_applied(self):
        src = 'امتثاللا تقلعن السيبرانيمع لـ100'
        out = _apply_arabic_spacing_fixes(src)
        self.assertIn('امتثال لا', out)
        self.assertIn('لـ 100', out)
        self.assertNotIn('امتثاللا', out)

    def test_markdown_residue_cleanup(self):
        src = '**نص** <!-- trace:abc --> [REQUIRES_AI_X]'
        out = _strip_render_markdown_residue(src)
        self.assertNotIn('**', out)
        self.assertNotIn('<!--', out)
        self.assertNotIn('REQUIRES_AI', out)

    def test_mixed_arabic_english_acronyms_readable(self):
        s = 'رفع جاهزية SOC و SIEM إلى 82% خلال 1-6 أشهر'
        out = _prepare_pdf_arabic_text(
            s, reshaper=None, bidi_display=None, preserve_acronyms=True)
        self.assertIn('SOC', out)
        self.assertIn('SIEM', out)
        self.assertIn('82%', out)

    def test_arabic_font_registration_succeeds(self):
        name, bold = _ensure_arabic_pdf_font(required=False)
        self.assertTrue(name)
        self.assertTrue(bold)


class HelperDetectionTests(unittest.TestCase):

    def test_peek_follow_lines(self):
        lines = ['## الأهداف', 'نص قصير', '| أ | ب |', '|---|---|', '|1|2|']
        follow = _pdf_peek_follow_lines(lines, 0, 3)
        self.assertGreaterEqual(len(follow), 2)

    def test_timeline_table_detection(self):
        tbl = [['المرحلة', 'الفترة', 'أهم المبادرات', 'المسؤول', 'الإطار']]
        self.assertTrue(_pdf_is_roadmap_timeline_table(tbl))

    def test_exec_cards_table_detection(self):
        tbl = [['البطاقة', 'المحتوى']]
        self.assertTrue(_pdf_is_exec_summary_cards_table(tbl))

    def test_theme_tokens_available(self):
        theme = APP._build_strategy_pdf_theme('ar', 'cyber')
        self.assertEqual(theme['heading_align'], 'RIGHT')
        self.assertIn('primary', theme)


class SingleRendererPathTests(unittest.TestCase):
    """Guardrail: exactly one production builder; no duplicate model path."""

    def test_single_production_builder_definition(self):
        n = len(re.findall(
            r'^def _build_professional_strategy_document_model\b',
            APP_SOURCE, flags=re.MULTILINE))
        self.assertEqual(n, 1)

    def test_builder_delegates_to_production_module(self):
        self.assertIn('build_professional_strategy_document_model as _p41_build',
                      APP_SOURCE)

    def test_no_list_based_blocks_model_introduced(self):
        # The legacy reference returned model['blocks'] as a list; ensure the
        # production model remains dict-based.
        model = _build_rich_model()
        self.assertIsInstance(model['blocks'], dict)


if __name__ == '__main__':
    unittest.main()
