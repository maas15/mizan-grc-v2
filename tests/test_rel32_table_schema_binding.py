"""REL3.2 — schema-bound strategy table rendering tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel32_table_bind_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

from release_engine_v3.rel32_compiler import compile_canonical_strategy_document
from release_engine_v3.rel32_table_schema_binding import (
    apply_rel32_schema_binding_to_blocks,
    bind_table_row,
    evaluate_table_schema_binding_check,
    rebind_table_spec,
    row_dict_to_cells,
    schema_header_labels,
    _repair_kpi_row_dict,
)
from professional_strategy_render import (
    SCHEMA_KPI_MAIN_AR,
    enrich_professional_blocks,
    split_kpi_tables,
)


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


class Rel32TableSchemaBindingTests(unittest.TestCase):

    def test_01_kpi_table_values_under_correct_headers(self):
        scrambled_hdr = [
            'المالك', 'التكرار', 'مصدر', 'صيغة الاحتساب',
            'القيمة المستهدفة', 'النوع', 'وصف المؤشر', '#',
        ]
        row = [
            'مدير SOC', 'شهري', 'SIEM', 'مجموع زمن الكشف / عدد الحوادث',
            '≤ 15 دقيقة', 'KPI', 'MTTD', '1',
        ]
        bound, _ = bind_table_row(scrambled_hdr, row, 'kpi_main', row_index=1)
        cells = row_dict_to_cells(bound, 'kpi_main')
        self.assertEqual(cells[0], '1')
        self.assertIn('MTTD', cells[1])
        self.assertEqual(cells[2].upper(), 'KPI')
        self.assertIn('15', cells[3])
        self.assertIn('مجموع', cells[4])
        self.assertIn('SIEM', cells[5])
        self.assertIn('شهري', cells[6])
        self.assertIn('SOC', cells[7])

    def test_02_kpi_type_not_under_target(self):
        hdr = list(SCHEMA_KPI_MAIN_AR)
        row = ['1', 'MTTD', '≤ 15 دقيقة', 'KPI', 'f', 'SIEM', 'شهري', 'SOC']
        tbl = rebind_table_spec(
            {'schema': 'kpi_main', 'header': hdr, 'rows': [row]}, lang='ar')
        bound = (tbl or {}).get('bound_rows') or []
        self.assertEqual(bound[0].get('type'), 'KPI')
        self.assertIn('15', bound[0].get('target', ''))
        diag = evaluate_table_schema_binding_check(tbl, lang='ar')
        self.assertNotIn('kpi_type_under_target', ''.join(
            diag.get('mismatched_cells') or []))

    def test_03_target_percent_not_under_formula(self):
        hdr = ['المالك', 'التكرار', 'مصدر', 'صيغة الاحتساب',
               'القيمة المستهدفة', 'النوع', 'وصف المؤشر', '#']
        row = ['SOC', 'شهري', 'SIEM', '≤ 15 دقيقة', 'f', 'KPI', 'MTTD', '1']
        tbl = rebind_table_spec(
            {'schema': 'kpi_main', 'header': hdr, 'rows': [row]}, lang='ar')
        bound = (tbl or {}).get('bound_rows') or []
        self.assertTrue(bound)
        self.assertIn('f', bound[0].get('target', ''))
        self.assertIn('15', bound[0].get('formula', ''))

    def test_04_owner_not_under_frequency(self):
        scrambled_hdr = [
            'المالك', 'التكرار', 'مصدر', 'صيغة الاحتساب',
            'القيمة المستهدفة', 'النوع', 'وصف المؤشر', '#',
        ]
        row = ['مدير SOC', 'شهري', 'SIEM', 'f', '≤ 4h', 'KPI', 'MTTR', '2']
        bound, _ = bind_table_row(
            scrambled_hdr, row, 'kpi_main', row_index=2)
        bound = _repair_kpi_row_dict(bound)
        self.assertIn('شهري', bound.get('frequency', ''))
        self.assertIn('SOC', bound.get('owner', ''))

    def test_05_roadmap_columns_bound_correctly(self):
        hdr = ['الإطار المرتبط', 'المخرج المتوقع', 'المسؤول',
               'المبادرة', 'الإطار الزمني', 'المرحلة']
        row = ['ECC', 'مخرج', 'CISO', 'تأسيس SOC', '1-6 أشهر', 'المرحلة 1']
        bound, _ = bind_table_row(hdr, row, 'roadmap', row_index=1)
        cells = row_dict_to_cells(bound, 'roadmap')
        self.assertIn('المرحلة', cells[0])
        self.assertIn('1-6', cells[1])
        self.assertIn('SOC', cells[2])
        self.assertIn('CISO', cells[3])

    def test_06_gap_action_guide_bound(self):
        hdr = ['الناتج', 'الإطار الزمني', 'المسؤول', 'الإجراء', 'الخطوة']
        row = ['تقرير', '6-12 شهراً', 'CISO', 'تنفيذ', '1']
        bound, _ = bind_table_row(hdr, row, 'gap_action', row_index=1)
        cells = row_dict_to_cells(bound, 'gap_action')
        self.assertEqual(cells[0], '1')
        self.assertEqual(cells[1], 'تنفيذ')
        self.assertIn('CISO', cells[2])

    def test_07_split_kpi_tables_emits_eight_column_schema(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        kpis = compiled.legacy_sections.get('kpis', '')
        tables = split_kpi_tables(kpis, lang='ar')
        main = next(t for t in tables if t.get('schema') == 'kpi_main')
        self.assertEqual(len(main['header']), 8)
        self.assertEqual(main['header'], list(SCHEMA_KPI_MAIN_AR))
        self.assertGreaterEqual(len(main['rows']), 1)
        self.assertEqual(len(main['rows'][0]), 8)

    def test_08_professional_blocks_schema_binding_passes(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        model = {
            'lang': 'ar',
            'blocks': {'cover': {'title': 'x'}},
            'order': ['cover'],
        }
        enriched = enrich_professional_blocks(
            model, compiled.legacy_sections, {}, 'ar')
        bound = apply_rel32_schema_binding_to_blocks(
            enriched.get('blocks') or {}, lang='ar')
        summary = bound.get('_rel32_table_schema_binding') or {}
        self.assertTrue(summary.get('all_passed'), summary)
        self.assertEqual(summary.get('blocking_errors'), [])

    def test_09_rtl_reversal_flag_blocks_when_applied(self):
        tbl = {
            'schema': 'kpi_main',
            'header': list(SCHEMA_KPI_MAIN_AR),
            'rows': [['1', 'MTTD', 'KPI', '≤15m', 'f', 'SIEM', 'شهري', 'SOC']],
        }
        diag = evaluate_table_schema_binding_check(
            tbl, lang='ar', rtl_reversal_applied=True)
        self.assertFalse(diag['schema_binding_passed'])
        self.assertTrue(diag['blocking_errors'])

    def test_10_canonical_kpi_headers_match_schema_labels(self):
        labels = schema_header_labels('kpi_main', 'ar')
        self.assertEqual(labels, list(SCHEMA_KPI_MAIN_AR))


if __name__ == '__main__':
    unittest.main()
