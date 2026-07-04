"""REL3.2 — KPI main 8-column schema consistency across preview/DOCX/PDF."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel32_kpi_main_schema_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

from release_engine_v3.rel32_compiler import compile_canonical_strategy_document
from release_engine_v3.rel32_kpi_main_schema_evidence import (
    evaluate_kpi_main_schema_from_export_text,
    evaluate_kpi_main_schema_from_model,
    evaluate_kpi_main_schema_from_preview_html,
    extract_kpi_main_header_labels_from_text,
)
from release_engine_v3.rel32_preview_table_dom import render_preview_table_html
from release_engine_v3.rel32_table_schema_binding import (
    REL32_KPI_MAIN_EXPECTED_SCHEMA_AR,
    _repair_kpi_row_dict,
    evaluate_kpi_main_schema_consistency,
    rebind_table_spec,
    schema_header_labels,
)
from professional_strategy_render import (
    SCHEMA_KPI_MAIN_AR,
    compute_pdf_export_layout_fallbacks,
    ensure_strategy_professional_model,
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


_FALLBACK_7COL_HDR = [
    '#', 'المؤشر', 'النوع', 'القيمة المستهدفة',
    'التكرار', 'المالك', 'الإطار الزمني',
]
_FALLBACK_7COL_ROW = [
    '1', 'MTTD', 'KPI', '≤ 15 دقيقة', 'CISO', '—', '12 شهر',
]


class Rel32KpiMainSchemaConsistencyTests(unittest.TestCase):

    def test_canonical_schema_object_matches_professional_render(self):
        self.assertEqual(
            list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR),
            list(SCHEMA_KPI_MAIN_AR),
        )
        self.assertEqual(
            schema_header_labels('kpi_main', 'ar'),
            list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR),
        )

    def test_pdf_fails_when_timeframe_replaces_formula_source(self):
        diag = evaluate_kpi_main_schema_consistency(
            route_name='pdf',
            header_labels=_FALLBACK_7COL_HDR,
            rows=[_FALLBACK_7COL_ROW],
        )
        self.assertFalse(diag['kpi_main_schema_passed'])
        self.assertIn('الإطار الزمني', diag['forbidden_columns'])
        self.assertIn('rel32_kpi_main_forbidden_columns', diag['blocking_errors'])
        self.assertIn('rel32_kpi_main_seven_column_fallback', diag['blocking_errors'])
        self.assertFalse(diag['formula_column_present'])
        self.assertFalse(diag['source_column_present'])

    def test_docx_fails_when_timeframe_replaces_formula_source(self):
        md = (
            '## مؤشرات الأداء الرئيسية\n\n'
            '| ' + ' | '.join(_FALLBACK_7COL_HDR) + ' |\n'
            '|---|---|---|---|---|---|---|\n'
            '| ' + ' | '.join(_FALLBACK_7COL_ROW) + ' |\n'
        )
        diag = evaluate_kpi_main_schema_from_export_text(md, route_name='docx')
        self.assertFalse(diag['kpi_main_schema_passed'])
        self.assertIn('الإطار الزمني', diag['forbidden_columns'])
        self.assertIn('rel32_kpi_main_forbidden_columns', diag['blocking_errors'])

    def test_preview_fails_when_owner_under_frequency(self):
        hdr = list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR)
        diag = evaluate_kpi_main_schema_consistency(
            route_name='preview',
            header_labels=hdr,
            bound_rows=[{
                'row_num': '1',
                'indicator': 'MTTD',
                'type': 'KPI',
                'target': '≤ 15 دقيقة',
                'formula': 'مجموع زمن الكشف / عدد الحوادث',
                'source': 'SIEM',
                'frequency': 'CISO',
                'owner': '—',
            }],
        )
        self.assertFalse(diag['kpi_main_schema_passed'])
        self.assertIn('CISO', diag['owner_values_in_frequency'])
        self.assertIn('rel32_kpi_main_owner_in_frequency', diag['blocking_errors'])

    def test_docx_pdf_pass_with_canonical_eight_column_schema(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        kpis = compiled.legacy_sections.get('kpis', '')
        diag_docx = evaluate_kpi_main_schema_from_export_text(
            kpis, route_name='docx')
        self.assertTrue(diag_docx['kpi_main_schema_passed'], diag_docx)
        self.assertEqual(
            diag_docx['header_labels'],
            list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR))
        self.assertEqual(diag_docx['missing_columns'], [])
        self.assertEqual(diag_docx['forbidden_columns'], [])
        self.assertEqual(diag_docx['owner_values_in_frequency'], [])
        self.assertTrue(diag_docx['formula_column_present'])
        self.assertTrue(diag_docx['source_column_present'])

    def test_formula_and_source_present_for_all_compiler_rows(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        model = {
            'lang': 'ar',
            'render_layer': 'prcy41_professional',
            'blocks': {'cover': {'title': 'x'}},
            'order': ['cover'],
        }
        enriched = enrich_professional_blocks(
            model, compiled.legacy_sections, {}, 'ar')
        diag = evaluate_kpi_main_schema_from_model(
            enriched, route_name='model')
        self.assertTrue(diag['kpi_main_schema_passed'], diag)
        self.assertGreater(diag['row_count'], 0)
        self.assertNotIn(
            'rel32_kpi_main_missing_formula_values', diag['blocking_errors'])
        self.assertNotIn(
            'rel32_kpi_main_missing_source_values', diag['blocking_errors'])

    def test_no_route_uses_seven_column_kpi_fallback(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        model = {
            'lang': 'ar',
            'blocks': {'kpi_kri_framework': {'tables': []}},
        }
        enriched = enrich_professional_blocks(
            model, compiled.legacy_sections, {}, 'ar')
        fb = compute_pdf_export_layout_fallbacks(enriched, 'ar')
        self.assertNotIn(fb.get('kpi_main'), ('kpi_cards',))
        self.assertNotIn(fb.get('kpi_formula'), ('kpi_cards',))
        main = next(
            t for t in (
                (enriched.get('blocks') or {}).get('kpi_kri_framework') or {}
            ).get('tables') or []
            if t.get('schema') == 'kpi_main')
        self.assertEqual(len(main['header']), 8)
        self.assertEqual(main['header'], list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR))

    def test_cached_professional_model_reapplies_schema_binding(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        base = {
            'lang': 'ar',
            'render_layer': 'prcy41_professional',
            'blocks': {
                'kpi_kri_framework': {
                    'tables': [{
                        'schema': 'kpi_main',
                        'header': list(_FALLBACK_7COL_HDR),
                        'rows': [_FALLBACK_7COL_ROW],
                    }],
                },
            },
        }
        repaired = ensure_strategy_professional_model(base, lang='ar')
        main = next(
            t for t in (
                (repaired.get('blocks') or {}).get('kpi_kri_framework') or {}
            ).get('tables') or []
            if t.get('schema') == 'kpi_main')
        self.assertEqual(main['header'], list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR))
        self.assertEqual(len(main['rows'][0]), 8)
        self.assertNotIn('الإطار الزمني', main['header'])

    def test_rebind_repairs_owner_in_frequency_from_registry(self):
        tbl = rebind_table_spec({
            'schema': 'kpi_main',
            'header': list(_FALLBACK_7COL_HDR),
            'rows': [[
                '1', 'متوسط زمن اكتشاف الحوادث (MTTD)', 'KPI',
                '≤ 15 دقيقة', 'CISO', '—', '12 شهر',
            ]],
        }, lang='ar')
        bound = (tbl or {}).get('bound_rows') or []
        self.assertTrue(bound)
        row = bound[0]
        self.assertIn('CISO', row.get('owner', '').upper())
        self.assertIn('شهري', row.get('frequency', ''))
        self.assertNotIn('CISO', row.get('frequency', ''))

    def test_returned_docx_evidence_extracts_canonical_headers(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        kpis = compiled.legacy_sections.get('kpis', '')
        headers = extract_kpi_main_header_labels_from_text(kpis)
        self.assertEqual(headers, list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR))

    def test_split_kpi_tables_never_emits_seven_column_main(self):
        compiled = compile_canonical_strategy_document({}, request_context=_ctx())
        tables = split_kpi_tables(compiled.legacy_sections.get('kpis', ''), 'ar')
        main = next(t for t in tables if t.get('schema') == 'kpi_main')
        self.assertEqual(len(main['header']), 8)
        self.assertNotIn('الإطار الزمني', main['header'])


if __name__ == '__main__':
    unittest.main()
