"""REL32 preview table DOM binding tests (HTML/DOM level)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel32_preview_dom_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

from release_engine_v3.rel32_compiler import compile_canonical_strategy_document
from release_engine_v3.rel32_preview_table_dom import (
    cell_under_header,
    evaluate_preview_dom_binding_check,
    extract_table_dom_binding,
    render_preview_table_html,
)
from release_engine_v3.rel32_table_schema_binding import schema_header_labels


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


class Rel32PreviewTableDomBindingTests(unittest.TestCase):

    def test_01_kpi_preview_cell_under_header_row1(self):
        scrambled_hdr = [
            'المالك', 'التكرار', 'مصدر', 'صيغة الاحتساب',
            'القيمة المستهدفة', 'النوع', 'وصف المؤشر', '#',
        ]
        row = [
            'CISO / مدير الامتثال', 'شهري', 'SIEM / SOC',
            'مجموع زمن الكشف / عدد الحوادث', '< 4 ساعات', 'KPI',
            'MTTD', '1',
        ]
        html_out = render_preview_table_html(
            scrambled_hdr, [row], schema_id='kpi_main', is_rtl=True)
        self.assertIn('CISO', cell_under_header(html_out, 'المالك'))
        self.assertIn('شهري', cell_under_header(html_out, 'التكرار'))
        self.assertIn('SIEM', cell_under_header(html_out, 'مصدر'))
        self.assertIn('KPI', cell_under_header(html_out, 'النوع'))
        diag = evaluate_preview_dom_binding_check(html_out, 'kpi_main')
        self.assertTrue(diag['preview_dom_binding_passed'])
        self.assertEqual(diag['mismatched_headers'], [])
        self.assertEqual(diag['blocking_errors'], [])

    def test_02_kpi_formula_table_headers_and_binding(self):
        headers = ['مصدر البيانات', 'صيغة الاحتساب', 'المؤشر', '#']
        row = ['SIEM / SOC', 'مجموع / عدد', 'MTTD', '1']
        html_out = render_preview_table_html(
            headers, [row], schema_id='kpi_formula', is_rtl=True)
        dom = extract_table_dom_binding(html_out)
        self.assertEqual(dom['header_labels_from_dom'], [
            '#', 'المؤشر', 'صيغة الاحتساب', 'مصدر البيانات',
        ])
        self.assertIn('MTTD', cell_under_header(html_out, 'المؤشر'))
        self.assertIn('مجموع', cell_under_header(html_out, 'صيغة الاحتساب'))
        self.assertIn('SIEM', cell_under_header(html_out, 'مصدر البيانات'))
        self.assertNotIn('MTTD', cell_under_header(html_out, 'صيغة الاحتساب'))
        self.assertNotIn('مجموع', cell_under_header(html_out, 'مصدر البيانات'))

    def test_03_roadmap_preview_binding(self):
        headers = [
            'الإطار', 'المخرج', 'المالك', 'المبادرة', 'الإطار الزمني', 'المرحلة',
        ]
        row = ['NCA DCC', 'مخرج', 'مدير SOC', 'تأسيس SOC', '7-18 شهر', 'المرحلة 2']
        html_out = render_preview_table_html(
            headers, [row], schema_id='roadmap', is_rtl=True)
        self.assertIn('7-18', cell_under_header(html_out, 'الفترة'))
        self.assertIn('SOC', cell_under_header(html_out, 'المسؤول'))
        self.assertIn('NCA', cell_under_header(html_out, 'الإطار المرتبط'))

    def test_04_gap_action_preview_binding(self):
        headers = ['الناتج', 'الإطار الزمني', 'المسؤول', 'الإجراء', 'الخطوة']
        row = ['تقرير معتمد', '6-12 شهراً', 'CISO', 'تنفيذ الضوابط', '1']
        html_out = render_preview_table_html(
            headers, [row], schema_id='gap_action', is_rtl=True)
        self.assertIn('تنفيذ', cell_under_header(html_out, 'الإجراء'))
        self.assertIn('CISO', cell_under_header(html_out, 'المسؤول'))
        self.assertIn('6-12', cell_under_header(html_out, 'الإطار الزمني'))
        self.assertIn('تقرير', cell_under_header(html_out, 'الناتج'))

    def test_05_diagnostic_rel32_preview_table_dom_binding_check(self):
        kpi_hdr = schema_header_labels('kpi_main', lang='ar')
        kpi_row = [
            '1', 'MTTD', 'KPI', '< 4 ساعات',
            'f', 'SIEM / SOC', 'شهري', 'CISO',
        ]
        html_out = render_preview_table_html(
            kpi_hdr, [kpi_row], schema_id='kpi_main', is_rtl=True)
        diag = evaluate_preview_dom_binding_check(html_out, 'kpi_main')
        self.assertEqual(diag['table_id'], 'kpi_main')
        self.assertEqual(diag['schema_labels'], kpi_hdr)
        self.assertTrue(diag['preview_dom_binding_passed'])
        self.assertEqual(diag['mismatched_headers'], [])
        self.assertEqual(diag['blocking_errors'], [])

    def test_06_compiler_kpi_markdown_renders_canonical_headers(self):
        doc = compile_canonical_strategy_document(_ctx())
        kpis = doc.legacy_sections.get('kpis') or ''
        self.assertIn('وصف المؤشر', kpis)
        self.assertIn('المؤشر', kpis)
        self.assertIn('صيغة الاحتساب', kpis)
        lines = [ln for ln in kpis.splitlines() if ln.strip().startswith('|')]
        main_hdr = None
        formula_hdr = None
        for ln in lines:
            if 'وصف المؤشر' in ln:
                main_hdr = ln
            if 'المؤشر' in ln and 'وصف المؤشر' not in ln and 'مصدر البيانات' in ln:
                formula_hdr = ln
        self.assertIsNotNone(main_hdr)
        self.assertIsNotNone(formula_hdr)

    def test_07_js_preview_schema_file_contains_canonical_labels(self):
        js_path = ROOT / 'static' / 'js' / 'rel32-preview-table-schema.js'
        text = js_path.read_text(encoding='utf-8')
        for lbl in ('وصف المؤشر', 'التكرار', 'المالك', 'المؤشر', 'مصدر البيانات'):
            self.assertIn(lbl, text)
        self.assertIn('REL32-PREVIEW-TABLE-DOM-BINDING-CHECK', text)
        self.assertIn('validateKpiMainSemantics', text)
        self.assertIn('rel32_preview_table_header_value_mismatch', text)

    def test_08_shifted_positional_kpi_html_fails_runtime_gate(self):
        """Positional preview (no schema binder) with shifted values must fail."""
        headers = schema_header_labels('kpi_main', lang='ar')
        shifted_row = [
            '1', 'متوسط زمن اكتشاف الحوادث الأمنية', 'KPI', '< 4 ساعات',
            'مجموع أزمنة اكتشاف الحوادث / عدد الحوادث', 'CISO', 'SIEM / SOC', 'شهري',
        ]
        parts = ['<div class="table-wrapper" dir="rtl"><table><thead><tr>']
        parts.extend(f'<th>{h}</th>' for h in headers)
        parts.append('</tr></thead><tbody><tr>')
        parts.extend(f'<td>{c}</td>' for c in shifted_row)
        parts.append('</tr></tbody></table></div>')
        html_out = ''.join(parts)
        diag = evaluate_preview_dom_binding_check(html_out, 'kpi_main')
        self.assertFalse(diag['preview_dom_binding_passed'])
        self.assertTrue(any(
            'rel32_preview_table_header_value_mismatch:kpi_main:المالك' in e
            or 'rel32_preview_table_schema_binder_not_applied' in e
            for e in diag['blocking_errors']
        ))

    def test_09_canonical_kpi_row_from_user_evidence_passes(self):
        headers = schema_header_labels('kpi_main', lang='ar')
        row = [
            '1', 'متوسط زمن اكتشاف الحوادث الأمنية', 'KPI', '< 4 ساعات',
            'مجموع أزمنة اكتشاف الحوادث / عدد الحوادث', 'SIEM / SOC', 'شهري', 'CISO',
        ]
        html_out = render_preview_table_html(
            headers, [row], schema_id='kpi_main', is_rtl=True)
        self.assertIn('CISO', cell_under_header(html_out, 'المالك'))
        self.assertIn('شهري', cell_under_header(html_out, 'التكرار'))
        self.assertIn('SIEM', cell_under_header(html_out, 'مصدر'))
        diag = evaluate_preview_dom_binding_check(html_out, 'kpi_main')
        self.assertTrue(diag['preview_dom_binding_passed'])


if __name__ == '__main__':
    unittest.main()
