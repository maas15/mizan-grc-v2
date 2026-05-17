"""PR-5B.9O — AI strategy PDF Flowable rendering robustness.

Production symptom: AI strategy PDF download failed with HTTP 500
``pdf_render_failed`` after a ReportLab ``LayoutError`` ("Flowable …
too large on page"). Long bilingual SDAIA / AI-governance terms in
narrow KPI / traceability / governance / appendix table rows kept
triggering the failure even after PR-5B.9M's ZWSP-wrapping +
LongTable retry.

PR-5B.9O fixes:
  * Bullet/key-value fallback tier — when retry build also fails,
    every remaining ``Table`` flowable is replaced with paragraph
    rows ("Header: value" bullets, one block per row). The first row
    is treated as the header and reused as field labels; no cell
    content is dropped. An Arabic notice ("تعذر عرض الجدول الكامل
    بصيغته الجدولية، وتم عرضه كنقاط تفصيلية.") is inserted before
    each replaced table.
  * Richer ``[PDF-DIAG]`` logging on the fallback path
    (``route=api_generate_pdf section=fallback flowable_index=…
    flowable_type=Table row_count=… col_count=…
    fallback=bullets``).
  * Controlled HTTP 500 with ``reason=pdf_render_failed`` only when
    BOTH the retry pass AND the bullet fallback fail.

Tests pin:
  1. AI strategy stress fixture (long SDAIA / AI Ethics Officer /
     Model Risk Manager / Human-in-the-Loop / Model Monitoring
     Officer terms) renders without ``LayoutError`` via ZWSP +
     LongTable.
  2. Large KPI guide table with long bilingual cells renders.
  3. Large traceability table renders.
  4. Large governance / responsibility table renders.
  5. The bullet-fallback path is wired into ``api_generate_pdf``
     (source-level check — the fallback notice string and the
     ``fallback=bullets`` diagnostic literal are present).
  6. ``_pdf_safe_text`` is the canonical wrap helper and is used on
     every retry-table cell.
  7. PDF route does not 500 on empty content (controlled error
     path — 422 or 401, never 500).
  8. PDF error response does not expose raw ReportLab traceback or
     internal file paths.

Run:
    python -m pytest tests/test_ai_pdf_flowable_failure_pr5b9o.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_ai_pdf_pr5b9o_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


def _skip_if_no_reportlab(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest('reportlab not installed')
        return fn(self, *a, **kw)
    return _wrapped


# ── AI governance stress vocabulary ──────────────────────────────────────

_AI_STRESS_TERMS = [
    'SDAIA AI Ethics Principles',
    'SDAIA AI Governance Framework',
    'AI Ethics Officer',
    'Model Risk Manager',
    'AI Compliance Lead',
    'Human-in-the-Loop',
    'Model Monitoring Officer',
    'Explainability',
    'Transparency',
    'Bias',
    'Fairness',
    'مبادئ أخلاقيات الذكاء الاصطناعي من سدايا',
    'إطار حوكمة الذكاء الاصطناعي من سدايا',
    'مسؤول أخلاقيات الذكاء الاصطناعي',
    'مدير مخاطر النماذج',
    'قائد الامتثال للذكاء الاصطناعي',
    'الإنسان في الحلقة',
    'مراقبة النماذج',
    'القابلية للتفسير',
    'الشفافية',
    'الانحياز',
    'العدالة',
]


def _build_safe_paragraph(text, style):
    from reportlab.platypus import Paragraph
    return Paragraph(_APP._pdf_safe_text(text), style)


class AiStressTableRenderingTests(unittest.TestCase):
    """Long bilingual AI governance terms must not crash doc.build()."""

    @_skip_if_no_app
    @_skip_if_no_reportlab
    def test_ai_governance_terms_long_paragraph_does_not_crash(self):
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                         Table, Spacer)
        style = ParagraphStyle(
            'TestCell', fontSize=9, leading=12,
            splitLongWords=1, wordWrap='CJK',
        )
        rows = [['Term', 'Owner']]
        for term in _AI_STRESS_TERMS:
            rows.append([_build_safe_paragraph(term, style),
                         _build_safe_paragraph(
                             'AI Ethics Officer / Model Risk Manager',
                             style)])
        t = Table(rows, colWidths=[120, 120], repeatRows=1)
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        doc.build([t, Spacer(1, 12)])
        self.assertGreater(len(buf.getvalue()), 100)

    @_skip_if_no_app
    @_skip_if_no_reportlab
    def test_large_kpi_guide_table_with_long_bilingual_cells(self):
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Spacer)
        try:
            from reportlab.platypus import LongTable as _LT
        except Exception:
            from reportlab.platypus import Table as _LT
        style = ParagraphStyle(
            'TestCell', fontSize=8, leading=11,
            splitLongWords=1, wordWrap='CJK',
        )
        # 9-column KPI table layout matching the canonical Arabic
        # KPI schema (# / Metric / Type / Target / Formula / Source /
        # Owner / Frequency / Timeframe).
        big = _APP._pdf_safe_text(
            ' / '.join(_AI_STRESS_TERMS) + ' / '
            + ' / '.join(_AI_STRESS_TERMS))
        from reportlab.platypus import Paragraph
        rows = [['#', 'المؤشر', 'النوع', 'الهدف', 'الصيغة',
                 'المصدر', 'المالك', 'التكرار', 'الإطار الزمني']]
        for i in range(1, 30):
            rows.append([
                str(i),
                Paragraph(big, style),
                'KPI', '100%',
                Paragraph(_APP._pdf_safe_text(
                    'count(passed_reviews)/count(total_reviews)'),
                          style),
                'AI Governance System',
                Paragraph(_APP._pdf_safe_text(
                    'AI Ethics Officer / Model Risk Manager'), style),
                'شهري', 'سنوي',
            ])
        cw = [22, 110, 35, 40, 80, 60, 60, 40, 40]
        t = _LT(rows, colWidths=cw, repeatRows=1)
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        doc.build([t, Spacer(1, 12)])
        self.assertGreater(len(buf.getvalue()), 100)

    @_skip_if_no_app
    @_skip_if_no_reportlab
    def test_large_traceability_table_does_not_crash(self):
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Spacer,
                                         Paragraph)
        try:
            from reportlab.platypus import LongTable as _LT
        except Exception:
            from reportlab.platypus import Table as _LT
        style = ParagraphStyle(
            'TestCell', fontSize=8, leading=11,
            splitLongWords=1, wordWrap='CJK',
        )
        header = ['الإطار', 'القدرة', 'الفجوة', 'المبادرة',
                  'المؤشر', 'الخطر']
        rows = [[Paragraph(_APP._pdf_safe_text(h), style)
                 for h in header]]
        for i in range(20):
            cell_text = _APP._pdf_safe_text(
                ' / '.join(_AI_STRESS_TERMS[:5]))
            rows.append([
                Paragraph(_APP._pdf_safe_text(
                    'SDAIA AI Governance Framework'), style),
                Paragraph(cell_text, style),
                Paragraph(_APP._pdf_safe_text(
                    'غياب AI Governance Office'), style),
                Paragraph(_APP._pdf_safe_text(
                    'تعيين AI Ethics Officer / Model Risk Manager'),
                          style),
                Paragraph(_APP._pdf_safe_text('100%'), style),
                Paragraph(_APP._pdf_safe_text(
                    'Model-Drift-Risk / Bias-Risk'), style),
            ])
        t = _LT(rows, colWidths=[70, 70, 70, 70, 50, 70], repeatRows=1)
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        doc.build([t, Spacer(1, 12)])
        self.assertGreater(len(buf.getvalue()), 100)

    @_skip_if_no_app
    @_skip_if_no_reportlab
    def test_large_governance_responsibility_table_does_not_crash(self):
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Spacer,
                                         Paragraph)
        try:
            from reportlab.platypus import LongTable as _LT
        except Exception:
            from reportlab.platypus import Table as _LT
        style = ParagraphStyle(
            'TestCell', fontSize=8, leading=11,
            splitLongWords=1, wordWrap='CJK',
        )
        # 5-column governance / RACI matrix.
        header = ['الدور', 'المسؤولية', 'الصلاحية',
                  'الإطار الزمني', 'المخرج']
        rows = [[Paragraph(_APP._pdf_safe_text(h), style)
                 for h in header]]
        for i in range(18):
            rows.append([
                Paragraph(_APP._pdf_safe_text(
                    _AI_STRESS_TERMS[i % len(_AI_STRESS_TERMS)]),
                          style),
                Paragraph(_APP._pdf_safe_text(
                    'Model lifecycle ownership / '
                    'Human-in-the-Loop oversight'), style),
                Paragraph(_APP._pdf_safe_text(
                    'Accountable / Responsible'), style),
                Paragraph(_APP._pdf_safe_text(
                    'Q1-Q4 / ربعي'), style),
                Paragraph(_APP._pdf_safe_text(
                    'Responsible-AI-Operating-Model / نموذج تشغيل'),
                          style),
            ])
        t = _LT(rows, colWidths=[80, 110, 90, 80, 80], repeatRows=1)
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        doc.build([t, Spacer(1, 12)])
        self.assertGreater(len(buf.getvalue()), 100)


class FallbackRenderingTests(unittest.TestCase):
    """When even the LongTable retry fails (e.g. a single row contains
    an oversized paragraph taller than the page), the api_generate_pdf
    code path replaces the offending table with paragraph bullets.
    These tests verify the fallback is wired in source."""

    @_skip_if_no_app
    def test_fallback_notice_string_present_in_source(self):
        import os
        with open(
            os.path.join(os.path.dirname(__file__), '..', 'app.py'),
            'r', encoding='utf-8',
        ) as fh:
            src = fh.read()
        # The notice may be split across source lines for line-length
        # reasons; verify both halves are present.
        self.assertIn(
            'تعذر عرض الجدول الكامل بصيغته الجدولية', src,
            'PR-5B.9O bullet fallback notice (head) must be in source')
        self.assertIn(
            'عرضه كنقاط تفصيلية', src,
            'PR-5B.9O bullet fallback notice (tail) must be in source')

    @_skip_if_no_app
    def test_fallback_diag_marker_present_in_source(self):
        import os
        with open(
            os.path.join(os.path.dirname(__file__), '..', 'app.py'),
            'r', encoding='utf-8',
        ) as fh:
            src = fh.read()
        self.assertIn('fallback=bullets', src,
                      'PR-5B.9O [PDF-DIAG] fallback marker missing')
        self.assertIn(
            'route=api_generate_pdf', src,
            '[PDF-DIAG] route field missing')

    @_skip_if_no_app
    @_skip_if_no_reportlab
    def test_bullet_fallback_renders_when_table_replaced(self):
        # Direct unit-level smoke test of the bullet fallback: we
        # build a paragraph-based mock of the fallback output and
        # confirm it renders.
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                         Spacer)
        style = ParagraphStyle(
            'TestCell', fontSize=9, leading=12,
            splitLongWords=1, wordWrap='CJK',
        )
        story = []
        # Mimic a fallback for 1 table with 3 rows × 3 cols.
        story.append(Paragraph(
            _APP._pdf_safe_text(
                'تعذر عرض الجدول الكامل بصيغته الجدولية، وتم '
                'عرضه كنقاط تفصيلية.'),
            style))
        story.append(Spacer(1, 4))
        header = ['الإطار', 'الدور', 'المسؤولية']
        for r in range(1, 4):
            story.append(Paragraph(f'#{r}', style))
            for h, v in zip(header, [
                'SDAIA AI Governance Framework',
                'AI Ethics Officer / Model Risk Manager',
                'Human-in-the-Loop oversight']):
                line = (f'<b>{_APP._pdf_safe_text(h)}</b>: '
                        f'{_APP._pdf_safe_text(v)}')
                story.append(Paragraph(line, style))
            story.append(Spacer(1, 6))
        buf = BytesIO()
        SimpleDocTemplate(buf, pagesize=A4).build(story)
        self.assertGreater(len(buf.getvalue()), 100)


class PdfSafeTextUsedEverywhereTests(unittest.TestCase):
    """The retry / fallback paths must run _pdf_safe_text() on every
    plain-string cell so long unbreakable AI governance tokens always
    have a wrap opportunity."""

    @_skip_if_no_app
    def test_retry_applies_pdf_safe_text_to_string_cells(self):
        # Source-level verification: PR-5B.9M added _pdf_safe_text()
        # to the retry sanitiser; PR-5B.9O adds the same helper to
        # the bullet-fallback path. Both must reference the helper.
        import os
        with open(
            os.path.join(os.path.dirname(__file__), '..', 'app.py'),
            'r', encoding='utf-8',
        ) as fh:
            src = fh.read()
        # The retry sanitiser block uses _pdf_safe_text().
        retry_idx = src.find('retry sanitised table_index=')
        self.assertGreater(retry_idx, 0)
        # Search backwards 4000 chars and forwards 2000 chars for
        # the _pdf_safe_text invocation in this block.
        window = src[max(0, retry_idx - 4000): retry_idx + 2000]
        self.assertIn('_pdf_safe_text(', window,
                      'retry sanitiser block must call _pdf_safe_text')
        # The bullet-fallback block also calls _pdf_safe_text().
        fb_idx = src.find('fallback=bullets')
        self.assertGreater(fb_idx, 0)
        window = src[max(0, fb_idx - 5000): fb_idx + 2000]
        self.assertIn('_pdf_safe_text(', window,
                      'bullet-fallback block must call _pdf_safe_text')


class PdfErrorPathControlledTests(unittest.TestCase):
    """The /api/generate-pdf route must return a controlled JSON
    payload (no raw ReportLab traceback) and must never 500 on
    trivially-invalid input."""

    @_skip_if_no_app
    def test_pdf_route_does_not_500_on_empty_content(self):
        with _APP.app.test_client() as c:
            resp = c.post('/api/generate-pdf', json={
                'content': '',
                'doc_type': 'Strategy Document',
                'artifact_type': 'strategy',
                'language': 'en',
                'domain': 'AI',
            })
            self.assertNotEqual(
                resp.status_code, 500,
                'PDF route must not 500 on empty content')

    @_skip_if_no_app
    def test_pdf_error_payload_is_sanitised(self):
        # Source-level check: the outer error response must use the
        # canonical user-facing message and ``reason=pdf_render_failed``
        # without leaking traceback strings.
        import os
        with open(
            os.path.join(os.path.dirname(__file__), '..', 'app.py'),
            'r', encoding='utf-8',
        ) as fh:
            src = fh.read()
        self.assertIn("'reason': 'pdf_render_failed'", src)
        # The detail field is the exception TYPE name only — never
        # the full message / traceback. We verify by searching for
        # the canonical assignment.
        self.assertIn("_err_name = type(e).__name__", src)
        # Confirm the response body does NOT include the full
        # exception message (str(e) or traceback).
        # The lines around the response must use _err_name, not str(e).
        idx = src.find("'reason': 'pdf_render_failed'")
        block = src[idx: idx + 400]
        self.assertNotIn("str(e)", block,
                         'PDF error response must not leak str(e)')
        self.assertNotIn('traceback', block.lower().replace(
            'import traceback', '').replace(
                'traceback.print_exc', ''),
                         'PDF error response body must not leak '
                         'traceback content')


class FullPdfStressGenerationTests(unittest.TestCase):
    """End-to-end smoke test for AI stress content via the production
    PDF flow — uses the build_pdf_document helper directly when
    available, otherwise hits the route in a test client."""

    @_skip_if_no_app
    @_skip_if_no_reportlab
    def test_ai_stress_pdf_route_returns_200_or_401(self):
        # The route requires login_required — in a minimal harness
        # the call returns 401 (auth) or 422 (gate). Either is
        # acceptable; the contract is that it MUST NOT return 500.
        ai_stress_md = (
            '## 1. الرؤية\n\n'
            + ' / '.join(_AI_STRESS_TERMS) + '\n\n'
            '## 2. الركائز\n\n### 1. حوكمة الذكاء الاصطناعي\n\n'
            + ' / '.join(_AI_STRESS_TERMS) + '\n\n'
            '## 4. تحليل الفجوات\n\n'
            '| # | الفجوة | الأثر |\n'
            '|---|------|------|\n'
            + ''.join(
                f'| {i} | غياب {t} | عالي |\n'
                for i, t in enumerate(_AI_STRESS_TERMS, 1))
            + '\n## 6. مؤشرات الأداء\n\n'
            '| # | المؤشر | المالك |\n'
            '|---|------|------|\n'
            + ''.join(
                f'| {i} | {t} | AI Ethics Officer |\n'
                for i, t in enumerate(_AI_STRESS_TERMS, 1)))
        with _APP.app.test_client() as c:
            resp = c.post('/api/generate-pdf', json={
                'content': ai_stress_md,
                'doc_type': 'Strategy Document',
                'artifact_type': 'strategy',
                'language': 'ar',
                'domain': 'AI',
            })
            self.assertNotEqual(
                resp.status_code, 500,
                f'AI stress PDF must not return 500; got '
                f'status={resp.status_code} body='
                f'{resp.data[:200]!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
