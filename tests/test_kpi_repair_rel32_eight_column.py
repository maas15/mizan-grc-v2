"""KPI canonical repair — REL32 8-column schema regression tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_kpi_repair_8col_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

from release_engine.kpi_model import repair_kpi_canonical_families
from release_engine_v3.rel32_compiler import compile_canonical_strategy_document
from release_engine_v3.rel32_preview_table_dom import (
    evaluate_preview_dom_binding_check,
    render_preview_table_html,
)
from professional_strategy_render import parse_markdown_tables


def _ctx():
    return {
        'lang': 'ar',
        'domain': 'cyber',
        'backend': {
            'flags': {'rel3': True, 'rel31': True, 'rel32': True},
            'lang': 'ar',
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        },
    }


class KpiRepairEightColumnTests(unittest.TestCase):

    def test_repair_preserves_owner_column_in_main_table(self):
        doc = compile_canonical_strategy_document(_ctx())
        kpis = doc.legacy_sections.get('kpis') or ''
        tables = parse_markdown_tables(kpis)
        self.assertGreaterEqual(len(tables), 1)
        main_hdr = tables[0][0]
        main_row = tables[0][1]
        self.assertEqual(len(main_hdr), 8)
        self.assertEqual(len(main_row), 8)
        self.assertIn('المالك', main_hdr)
        self.assertIn('CISO', main_row[-1])

    def test_formula_appendix_rel32_four_column_schema(self):
        doc = compile_canonical_strategy_document(_ctx())
        kpis = doc.legacy_sections.get('kpis') or ''
        self.assertIn('| # | المؤشر | صيغة الاحتساب | مصدر البيانات |', kpis)
        self.assertIn('| 1 | متوسط زمن اكتشاف', kpis)
        self.assertIn('SIEM / SOC', kpis)

    def test_assessment_guide_table_is_not_four_column_formula(self):
        doc = compile_canonical_strategy_document(_ctx())
        kpis = doc.legacy_sections.get('kpis') or ''
        tables = parse_markdown_tables(kpis)
        guide = next(
            t for t in tables
            if t and 'طريقة التقييم' in (t[0] or []))
        self.assertEqual(len(guide[0]), 9)
        self.assertNotEqual(len(guide[0]), 4)

    def test_canonical_compiler_row1_passes_dom_gate(self):
        doc = compile_canonical_strategy_document(_ctx())
        kpis = doc.legacy_sections.get('kpis') or ''
        tables = parse_markdown_tables(kpis)
        hdr, row = tables[0][0], tables[0][1]
        html = render_preview_table_html(hdr, [row], schema_id='kpi_main')
        diag = evaluate_preview_dom_binding_check(html, 'kpi_main')
        self.assertTrue(diag['preview_dom_binding_passed'], diag.get('blocking_errors'))
        self.assertIn('CISO', diag['first_row_cells_by_header'].get('المالك', ''))
        self.assertIn('شهري', diag['first_row_cells_by_header'].get('التكرار', ''))
        self.assertIn('SIEM', diag['first_row_cells_by_header'].get('مصدر', ''))


if __name__ == '__main__':
    unittest.main()
