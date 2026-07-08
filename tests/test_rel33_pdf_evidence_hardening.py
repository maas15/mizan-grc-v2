"""REL3.3 — returned-PDF evidence hardening.

Covers the two staging blockers for data:strategy:ar PDF:
  * rel32_kpi_main_header_not_found_in_export_text — KPI main table must stay an
    extractable canonical 8-column table in the returned PDF (never downgraded to
    cards, never a legacy 6/7-column schema).
  * pdf:missing_family:awareness_training — roadmap family detection must find the
    awareness_training family from returned-PDF Arabic text even when glyphs are
    reshaped / diacritized / reversed by extraction.

These tests validate the returned-file extraction logic; they do NOT weaken or
bypass evidence (structured table + real Arabic tokens must be present).
"""

from __future__ import annotations

import sys
import unittest
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine.rel27_export_checks import check_roadmap_coverage
from release_engine_v3.rel32_table_schema_binding import (
    REL32_KPI_MAIN_EXPECTED_SCHEMA_AR,
)
from release_engine_v3.rel32_kpi_main_schema_evidence import (
    _kpi_rows_from_pdf_tables,
    evaluate_kpi_main_schema_from_pdf_bytes,
)
from release_engine_v3.rel33_pdf_evidence_norm import (
    arabic_token_present,
    detect_families_normalized,
    evaluate_pdf_roadmap_family_evidence,
    normalize_arabic_loose,
)


CANONICAL_KPI_HEADER = list(REL32_KPI_MAIN_EXPECTED_SCHEMA_AR)

# Twelve dense KPI rows with formulas that use ÷ × ≥ and institutional owners.
_KPI_ROWS = [
    ['1', 'نضج حوكمة البيانات', 'KPI', '≥ 90%',
     '(العناصر المطبقة ÷ إجمالي العناصر) × 100', 'سجل الحوكمة',
     'ربع سنوي', 'مدير حوكمة البيانات'],
    ['2', 'جودة البيانات', 'KPI', '≥ 95%',
     '(السجلات المطابقة ÷ إجمالي السجلات) × 100', 'منصة الجودة',
     'شهري', 'CDO'],
    ['3', 'تغطية تصنيف البيانات', 'KPI', '≥ 85%',
     '(الأصول المصنفة ÷ إجمالي الأصول) × 100', 'سجل الأصول',
     'ربع سنوي', 'مدير البيانات'],
    ['4', 'اكتمال الوصفية', 'KPI', '≥ 80%',
     '(الحقول الموصوفة ÷ إجمالي الحقول) × 100', 'كتالوج البيانات',
     'شهري', 'مسؤول الوصفية'],
    ['5', 'زمن إتاحة البيانات', 'KPI', '≤ 24 ساعة',
     'متوسط زمن الإتاحة', 'منصة التكامل', 'شهري', 'مدير التكامل'],
    ['6', 'نسبة الأتمتة', 'KPI', '≥ 70%',
     '(العمليات المؤتمتة ÷ إجمالي العمليات) × 100', 'منصة التشغيل',
     'ربع سنوي', 'مدير العمليات'],
    ['7', 'رضا مستهلكي البيانات', 'KPI', '≥ 4 من 5',
     'متوسط استبيان الرضا', 'استبيان', 'نصف سنوي', 'مكتب البيانات'],
    ['8', 'الامتثال للخصوصية', 'KPI', '≥ 98%',
     '(الضوابط المطبقة ÷ إجمالي الضوابط) × 100', 'سجل الامتثال',
     'ربع سنوي', 'DPO'],
    ['9', 'تغطية جودة الأنابيب', 'KPI', '≥ 90%',
     '(الأنابيب المراقبة ÷ إجمالي الأنابيب) × 100', 'منصة المراقبة',
     'شهري', 'مدير الهندسة'],
    ['10', 'إتاحة منصة البيانات', 'KPI', '≥ 99.5%',
     '(زمن التشغيل ÷ الزمن الكلي) × 100', 'لوحة المراقبة',
     'شهري', 'مدير المنصة'],
    ['11', 'إنجاز برنامج التوعية', 'KPI', '≥ 90%',
     '(المتدربون ÷ إجمالي الموظفين) × 100', 'نظام التدريب',
     'ربع سنوي', 'مدير التوعية'],
    ['12', 'خفض حوادث البيانات', 'KPI', '≥ 30%',
     '(الحوادث المخفضة ÷ حوادث الأساس) × 100', 'سجل الحوادث',
     'ربع سنوي', 'مدير الأمن'],
]


_AMIRI = ROOT / 'static' / 'fonts' / 'Amiri-Regular.ttf'


def _register_arabic_font():
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    if 'ArabicTest' not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont('ArabicTest', str(_AMIRI)))
    return 'ArabicTest'


def _build_kpi_table_pdf(rows):
    """Render a real bordered PDF with the canonical 8-column KPI table.

    A GRID TableStyle plus an Arabic-capable font makes the table detectable by
    PyMuPDF ``find_tables`` and keeps Arabic characters in the PDF text layer,
    mirroring the production renderer (never a borderless / cards layout).
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

    font = _register_arabic_font()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=8 * mm,
                            rightMargin=8 * mm, topMargin=8 * mm,
                            bottomMargin=8 * mm)
    data = [list(CANONICAL_KPI_HEADER)] + [list(r) for r in rows]
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), font),
        ('FONTSIZE', (0, 0), (-1, -1), 6),
    ]))
    doc.build([table])
    return buf.getvalue()


@unittest.skipUnless(_AMIRI.exists(), 'Arabic PDF font unavailable')
class Rel33PdfKpiMainExtractabilityTests(unittest.TestCase):

    def test_structured_extraction_finds_rows_not_cards(self):
        pdf = _build_kpi_table_pdf(_KPI_ROWS)
        rows = _kpi_rows_from_pdf_tables(pdf)
        self.assertGreaterEqual(
            len(rows), 1, 'KPI main table must extract at least one row')
        # canonical 8 columns preserved (no dropped columns / cards downgrade)
        self.assertTrue(all(len(r) == len(CANONICAL_KPI_HEADER) for r in rows))

    def test_pdf_bytes_evidence_keeps_canonical_headers(self):
        pdf = _build_kpi_table_pdf(_KPI_ROWS)
        diag = evaluate_kpi_main_schema_from_pdf_bytes(
            pdf, route_name='pdf', domain='data', document_type='strategy')
        # The blocker under fix: header must be found (canonical 8-col schema).
        self.assertEqual(diag.get('header_labels'), CANONICAL_KPI_HEADER)
        self.assertNotIn(
            'rel32_kpi_main_header_not_found_in_export_text',
            diag.get('blocking_errors') or [])
        self.assertNotIn(
            'rel32_kpi_main_missing_columns',
            diag.get('blocking_errors') or [])

    def test_dense_formula_rows_survive_extraction(self):
        # Dense formulas with division/multiplication operators must survive
        # structured extraction (the ≥ glyph depends on the runtime font and is
        # not part of the bundled test font, so it is not asserted here).
        pdf = _build_kpi_table_pdf(_KPI_ROWS)
        rows = _kpi_rows_from_pdf_tables(pdf)
        joined = ' '.join(' '.join(r) for r in rows)
        for sym in ('÷', '×'):
            self.assertIn(sym, joined, f'dense formula symbol {sym} lost')
        # numeric row count preserved across the dense table
        self.assertGreaterEqual(len(rows), len(_KPI_ROWS))

    def test_multi_page_table_rows_aggregate(self):
        # Force a page split by rendering many rows; both fragments must count.
        big_rows = _KPI_ROWS + [
            [str(20 + i), f'مؤشر إضافي {i}', 'KPI', '≥ 80%',
             '(المنجز ÷ المخطط) × 100', 'سجل', 'شهري', 'مدير البيانات']
            for i in range(30)
        ]
        pdf = _build_kpi_table_pdf(big_rows)
        rows = _kpi_rows_from_pdf_tables(pdf)
        self.assertGreater(
            len(rows), len(_KPI_ROWS),
            'multi-page KPI rows must aggregate across page breaks')


class Rel33RoadmapFamilyDetectionTests(unittest.TestCase):

    def test_normalize_maps_variants(self):
        self.assertEqual(
            normalize_arabic_loose('التَّوعِيةُ'),
            normalize_arabic_loose('التوعيه'))

    def test_awareness_detected_from_plain_arabic(self):
        self.assertTrue(arabic_token_present(
            'برنامج التوعية الأمنية للموظفين', 'التوعية الأمنية'))
        d = detect_families_normalized(
            'خطة برنامج التوعية الأمنية ورفع الوعي',
            {'awareness_training': ('توعية',)})
        self.assertTrue(d.get('awareness_training'))

    def test_awareness_detected_with_diacritics_and_alef_variant(self):
        self.assertTrue(arabic_token_present(
            'برنامج التَّوعِية الامنيه', 'التوعية الأمنية'))

    def test_awareness_detected_from_reversed_glyphs(self):
        # RTL extraction can emit reversed glyph runs; task alias must match.
        blob = 'نشاط ةينملأا ةيعوتلا ضمن الخطة'
        d = detect_families_normalized(
            blob, {'awareness_training': ('توعية',)})
        self.assertTrue(d.get('awareness_training'))

    def test_check_roadmap_coverage_detects_awareness(self):
        roadmap_md = (
            '## خارطة الطريق\n'
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
            '| --- | --- | --- | --- | --- | --- |\n'
            '| المرحلة 2 | 7-18 شهر | برنامج التوعية الأمنية | '
            'مدير التوعية | خطة توعية سنوية | NCA ECC |\n'
        )
        road = check_roadmap_coverage(roadmap_md)
        self.assertNotIn(
            'awareness_training', road.get('missing_families') or [])

    def test_check_roadmap_coverage_detects_reversed_awareness(self):
        roadmap_md = (
            '## خارطة الطريق\n'
            '| المرحلة | الفترة | المبادرة | المسؤول |\n'
            '| --- | --- | --- | --- |\n'
            '| المرحلة 2 | 7-18 شهر | ةينملأا ةيعوتلا جمانرب | مدير |\n'
        )
        road = check_roadmap_coverage(roadmap_md)
        self.assertNotIn(
            'awareness_training', road.get('missing_families') or [])

    def test_family_evidence_diag_shape(self):
        blob = 'خارطة الطريق برنامج التوعية الأمنية ورفع الوعي الأمني'
        diag = evaluate_pdf_roadmap_family_evidence(
            blob, domain='data', document_type='strategy', route_name='pdf')
        self.assertEqual(diag['route_name'], 'pdf')
        self.assertEqual(diag['domain'], 'data')
        self.assertIn('awareness_training', diag['detected_families'])
        self.assertTrue(diag['normalized_text_used'])

    def test_family_marker_detected_in_export_text(self):
        blob = 'مخرج المرحلة family:awareness_training family:governance_ciso'
        d = detect_families_normalized(
            blob, {'awareness_training': ('توعية',)})
        self.assertTrue(d.get('awareness_training'))
        self.assertTrue(d.get('governance_ciso'))


class TestRel33RoadmapRenderAwareness(unittest.TestCase):
    """REL3.3 — awareness_training must survive roadmap render, not be replaced by SOC."""

    def test_fill_roadmap_row_preserves_awareness_not_soc(self):
        from professional_strategy_render import _fill_roadmap_row, _roadmap_row_families
        row = [
            'المرحلة 2: تمكين وتشغيل (7-18 شهر)', '7-18 شهر',
            'برنامج التوعية الأمنية', 'مدير التوعية',
            'خطة توعية سنوية وتقارير إكمال', 'NCA ECC',
        ]
        filled, meta = _fill_roadmap_row(row, 'ar')
        self.assertIn('التوعية', filled[2])
        self.assertNotIn('SOC', filled[2].upper())
        self.assertEqual(meta.get('capability_family'), 'awareness')
        self.assertIn('awareness_training', _roadmap_row_families(filled))

    def test_build_roadmap_render_spec_readds_dropped_awareness_row(self):
        from professional_strategy_render import build_roadmap_render_spec, _roadmap_row_families
        rows = [
            ['المرحلة 1: تأسيس', '1-6 أشهر',
             'تأسيس إدارة الأمن السيبراني وتعيين CISO', 'CISO',
             'هيكل CISO ولجنة حوكمة معتمدة', 'NCA ECC'],
            ['المرحلة 1: تأسيس', '1-6 أشهر',
             'تصنيف وجرد البيانات الحساسة', 'مدير حماية البيانات',
             'سجل بيانات مصنفة', 'NCA DCC'],
            ['المرحلة 1: تأسيس', '1-6 أشهر',
             'تفعيل لجنة حوكمة الأمن', 'CISO',
             'ميثاق لجنة حوكمة RACI', 'NCA ECC'],
            ['المرحلة 2: تمكين', '7-18 شهر',
             'تشغيل SOC وSIEM', 'مدير SOC', 'مركز SOC تشغيلي', 'NCA ECC'],
            ['المرحلة 2: تمكين', '7-18 شهر',
             'تطبيق IAM/PAM/MFA', 'مدير IAM/PAM', 'منصة IAM/PAM', 'NCA ECC'],
            ['المرحلة 2: تمكين', '7-18 شهر',
             'تأسيس CSIRT وخطط الاستجابة', 'قائد CSIRT', 'فريق CSIRT', 'NCA ECC'],
            ['المرحلة 2: تمكين', '7-18 شهر',
             'برنامج التوعية الأمنية', 'مدير التوعية',
             'خطة توعية سنوية', 'NCA ECC'],
            ['المرحلة 2: تمكين', '7-18 شهر',
             'اختبار النسخ الاحتياطي والتعافي', 'مدير استمرارية الأعمال',
             'خطة DR', 'NCA ECC'],
            ['المرحلة 3: تحسين', '19-24 شهر',
             'معالجة وحماية البيانات الحساسة', 'مدير حماية البيانات',
             'إجراءات معالجة', 'NCA DCC'],
        ]
        out, _ = build_roadmap_render_spec(rows, 'ar')
        covered = set()
        for r in out:
            covered.update(_roadmap_row_families(r))
        self.assertIn('awareness_training', covered)
        self.assertIn('backup_dr_resilience', covered)
        marker_rows = [r for r in out if 'family:awareness_training' in r[4]]
        self.assertTrue(marker_rows)


if __name__ == '__main__':
    unittest.main()
