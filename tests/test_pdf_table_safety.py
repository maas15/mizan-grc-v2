"""Tests for the PDF table-safety helpers (Phase 5 of the Mizan domain
contamination & PDF errors fix, problem statement PART 7).

Covers:
  1. ``_sanitize_table_for_reportlab`` rectangularises ragged rows.
  2. ``None`` cells are converted to empty strings.
  3. Fully-empty data rows are dropped, but the header row is preserved.
  4. ``colWidths`` containing ``None`` / non-numeric / non-positive entries is
     replaced with equal widths derived from ``available_width``.
  5. Bad ``colWidths`` length is replaced with equal widths.
  6. Output ``colWidths`` length always equals output column count.
  7. Long-cell content survives sanitisation untouched (no truncation).
  8. The 9-column Arabic KPI canonical schema is preserved through
     sanitisation (no header damage; column count = 9; finite widths).
  9. ``_sanitize_pdf_story`` drops ``None`` flowables and replaces invalid
     ``Spacer`` dimensions with a safe spacer.
 10. Sanitiser is idempotent (calling twice produces the same result).
"""
import os
import sys
import unittest

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_pdf_safety.db')
# Force AI providers OFF (consistent with tests/test_domain_isolation.py).
os.environ['OPENAI_API_KEY']    = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY']    = ''
os.environ['GROQ_API_KEY']      = ''
os.environ['DEEPSEEK_API_KEY']  = ''

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
except Exception:
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *args, **kwargs)
    return wrapper


class TestSanitiseTableForReportlab(unittest.TestCase):
    @_skip_if_no_app
    def test_ragged_rows_are_rectangularised(self):
        rows = [
            ['#', 'A', 'B', 'C'],
            ['1', 'x'],            # short
            ['2', 'y', 'yy', 'yyy', 'extra'],  # long
        ]
        out, _ = _APP._sanitize_table_for_reportlab(
            rows, available_width=400)
        col_count = max(len(r) for r in out)
        for r in out:
            self.assertEqual(len(r), col_count)

    @_skip_if_no_app
    def test_none_cells_become_empty_string(self):
        rows = [['#', 'Owner'], [None, None], ['1', None]]
        out, _ = _APP._sanitize_table_for_reportlab(
            rows, available_width=400)
        for r in out:
            for c in r:
                self.assertNotEqual(c, None)
                self.assertIsInstance(c, str)

    @_skip_if_no_app
    def test_empty_data_rows_dropped_but_header_kept(self):
        rows = [
            ['#', 'Metric'],
            ['', ''],          # fully empty — drop
            ['1', 'KPI A'],    # keep
            [None, None],      # fully empty after None→'' — drop
            ['2', 'KPI B'],    # keep
        ]
        out, _ = _APP._sanitize_table_for_reportlab(
            rows, available_width=400)
        # Header + 2 data rows expected
        self.assertEqual(len(out), 3)
        self.assertEqual(out[0][1], 'Metric')

    @_skip_if_no_app
    def test_invalid_colwidths_recomputed_to_equal(self):
        rows = [['#', 'A', 'B'], ['1', 'x', 'y']]
        # bad colWidths: contains None and a non-positive value
        out, cw = _APP._sanitize_table_for_reportlab(
            rows, available_width=300, col_widths=[None, 0, -5])
        self.assertEqual(len(cw), 3)
        for w in cw:
            self.assertIsInstance(w, float)
            self.assertGreater(w, 0)
            self.assertEqual(w, 100.0)  # 300 / 3

    @_skip_if_no_app
    def test_wrong_length_colwidths_recomputed(self):
        rows = [['a', 'b', 'c'], ['1', '2', '3']]
        out, cw = _APP._sanitize_table_for_reportlab(
            rows, available_width=600, col_widths=[100, 200])
        self.assertEqual(len(cw), 3)
        self.assertEqual(cw, [200.0, 200.0, 200.0])

    @_skip_if_no_app
    def test_output_colwidths_length_matches_col_count(self):
        for cols in (1, 3, 5, 7, 9, 10):
            rows = [list(range(cols)), list(range(cols))]
            out, cw = _APP._sanitize_table_for_reportlab(
                rows, available_width=500)
            self.assertEqual(len(cw), cols, f"col_count={cols}")
            self.assertEqual(len(out[0]), cols)

    @_skip_if_no_app
    def test_long_cell_content_preserved(self):
        long_text = 'The quick brown fox ' * 20  # ~ 400 chars
        rows = [['#', 'Risk'], ['1', long_text]]
        out, _ = _APP._sanitize_table_for_reportlab(
            rows, available_width=300)
        self.assertEqual(out[1][1], long_text)

    @_skip_if_no_app
    def test_arabic_9col_kpi_schema_preserved(self):
        header = ['#', 'المؤشر', 'النوع KPI/KRI', 'القيمة المستهدفة',
                  'صيغة الاحتساب', 'مصدر البيانات', 'المالك',
                  'التكرار', 'الإطار الزمني']
        rows = [header,
                ['1', 'مقياس 1', 'KPI', '95%', 'a/b', 'النظام', 'CDO',
                 'شهري', 'سنة'],
                ['2', 'مقياس 2', 'KRI', '< 5', 'count', 'لوحة', 'CISO',
                 'ربع سنوي', '6 أشهر']]
        out, cw = _APP._sanitize_table_for_reportlab(
            rows, available_width=540)
        self.assertEqual(len(out), 3)
        self.assertEqual(len(out[0]), 9)
        self.assertEqual(out[0], header)
        self.assertEqual(len(cw), 9)
        for w in cw:
            self.assertGreater(w, 0)

    @_skip_if_no_app
    def test_idempotent(self):
        rows = [['#', 'A', 'B'], ['1', None, 'x'], ['', '', ''],
                ['2', 'y', None]]
        out1, cw1 = _APP._sanitize_table_for_reportlab(
            rows, available_width=300)
        out2, cw2 = _APP._sanitize_table_for_reportlab(
            out1, available_width=300, col_widths=cw1)
        self.assertEqual(out1, out2)
        self.assertEqual(cw1, cw2)

    @_skip_if_no_app
    def test_no_available_width_no_colwidths(self):
        rows = [['#', 'A'], ['1', 'x']]
        out, cw = _APP._sanitize_table_for_reportlab(rows)
        self.assertIsNone(cw)
        self.assertEqual(len(out), 2)


class TestSanitisePdfStory(unittest.TestCase):
    @_skip_if_no_app
    def test_drops_none_flowables(self):
        try:
            from reportlab.platypus import Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
        except ImportError:
            self.skipTest('reportlab not installed')
        styles = getSampleStyleSheet()
        story = [
            Paragraph('hello', styles['Normal']),
            None,
            Spacer(1, 12),
            None,
            Paragraph('world', styles['Normal']),
        ]
        out = _APP._sanitize_pdf_story(story)
        self.assertEqual(len(out), 3)
        for fl in out:
            self.assertIsNotNone(fl)

    @_skip_if_no_app
    def test_invalid_spacer_replaced_with_safe(self):
        try:
            from reportlab.platypus import Spacer
        except ImportError:
            self.skipTest('reportlab not installed')
        bad = Spacer(1, 12)
        # Tamper to invalid dimensions:
        bad.height = None  # type: ignore
        out = _APP._sanitize_pdf_story([bad])
        self.assertEqual(len(out), 1)
        # Replacement spacer must have valid positive height.
        rep = out[0]
        self.assertIsNotNone(getattr(rep, 'height', None))
        self.assertGreater(float(rep.height), 0)

    @_skip_if_no_app
    def test_empty_story_returns_empty_list(self):
        self.assertEqual(_APP._sanitize_pdf_story([]), [])
        self.assertEqual(_APP._sanitize_pdf_story(None), [])


class TestPdfTableNoNoneTypeError(unittest.TestCase):
    """Smoke-test: build a real ReportLab Table from a 9-column KPI table
    that contains None cells, ragged rows, and very long content. After
    passing through ``_sanitize_table_for_reportlab`` the table must build
    without raising ``TypeError`` (the reported bug)."""

    @_skip_if_no_app
    def test_real_table_builds_after_sanitise(self):
        try:
            from io import BytesIO
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer
            from reportlab.lib import colors
        except ImportError:
            self.skipTest('reportlab not installed')

        rows = [
            ['#', 'Metric', 'Type', 'Target', 'Formula', 'Source',
             'Owner', 'Frequency', 'Timeframe'],
            ['1', None, 'KPI', '95%', None, 'System', 'CDO', 'Monthly', '1y'],
            ['2', 'X' * 200, 'KRI', '<5', 'a/b', None, 'CISO', None, None],
            ['', '', '', '', '', '', '', '', ''],   # empty row → must drop
            ['3', 'M3'],                              # short row → pad
        ]
        out, cw = _APP._sanitize_table_for_reportlab(
            rows, available_width=500)
        self.assertEqual(len(out[0]), 9)
        self.assertEqual(len(cw), 9)

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        t = Table(out, colWidths=cw, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1D2B4F')),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('GRID',       (0, 0), (-1, -1), 0.25, colors.grey),
        ]))
        # The build call below would raise the original bug
        # ("'<' not supported between instances of 'NoneType' and 'NoneType'")
        # if any None made it through to ReportLab's layout engine.
        doc.build([t, Spacer(1, 12)])
        self.assertGreater(len(buf.getvalue()), 100)


if __name__ == '__main__':
    unittest.main()
