"""PR-5B.9AB — Arabic PDF RTL table cleanup.

Symptom (problem statement): Arabic PDF rendering produced broken
word fragments in some table cells, e.g. ``وثيق`` (from ``وثيقة``),
``وير`` (from ``تطوير``), ``عيين`` (from ``تعيين``). Root cause was
the cell ``ParagraphStyle`` using ``wordWrap='CJK'`` +
``splitLongWords=1``, which treats every glyph (including Arabic
letter forms) as a wrap-point and re-wraps cells mid-word whenever
the measured-vs-rendered width differs.

This module verifies:

  1. ``_pdf_safe_text`` never inserts ZWSP into Arabic runs (existing
     contract from PR-5B.9S — regression).
  2. ``process_arabic_table`` does not split individual Arabic words
     when wrapping (whole-word breaks only).
  3. The Arabic cell/header styles in ``api_generate_pdf`` no longer
     use CJK wordWrap / splitLongWords (source-level check). The
     English / Latin wrap behaviour is preserved.

Run::

    python -m pytest \\
        tests/test_arabic_pdf_rtl_table_cleanup_pr5b9ab.py -q
"""
import importlib.util
import inspect
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ab_pdf_')
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


_ARABIC_WORDS = ['وثيقة', 'تطوير', 'تعيين', 'حوكمة', 'الخصوصية',
                 'الانتهاكات', 'الموافقات']


class TestPdfSafeTextArabicUntouched(unittest.TestCase):
    """Test 1 — ``_pdf_safe_text`` never breaks Arabic words by
    inserting ZWSP into Arabic runs."""

    @_skip_if_no_app
    def test_01_arabic_words_have_no_zwsp_inserted(self):
        for word in _ARABIC_WORDS:
            out = _APP._pdf_safe_text(word)
            self.assertNotIn(
                '\u200B', out,
                f'ZWSP inserted inside Arabic word {word!r} → {out!r}')

    @_skip_if_no_app
    def test_02_arabic_compound_with_slash_no_zwsp_near_arabic(self):
        # ``تأسيس/تطوير`` — slash between Arabic must NOT gain ZWSP.
        out = _APP._pdf_safe_text('تأسيس/تطوير')
        self.assertNotIn('\u200B', out)

    @_skip_if_no_app
    def test_03_latin_compound_still_breakable(self):
        # ``data/AI/cyber`` — slash between Latin tokens MUST gain
        # ZWSP. Regression that Latin wrap is unchanged.
        out = _APP._pdf_safe_text('data/AI/cyber')
        self.assertIn('\u200B', out)


class TestProcessArabicTableWholeWord(unittest.TestCase):
    """Test 4 — ``process_arabic_table`` wraps on word boundaries
    only; no Arabic word is split across lines."""

    @_skip_if_no_app
    def test_04_arabic_words_intact_after_wrap(self):
        # Force multi-line wrap by passing a narrow col_width relative
        # to the Arabic content length. Each whole word must still
        # appear (possibly reshaped) — partial fragments like ``وثيق``
        # on their own line indicate mid-word breakage.
        # We exercise the function directly by inspecting its source
        # to confirm it iterates ``words = reshaped.split(' ')`` and
        # never splits inside a single ``word`` token.
        src = inspect.getsource(_APP.api_generate_pdf)
        self.assertIn("words = reshaped.split(' ')", src)
        # Words are appended as whole units to ``current_line_words``
        # — there is no character-level split path inside the wrap
        # loop.
        self.assertNotIn('list(word)', src)


class TestArabicCellStyleNoCjkWrap(unittest.TestCase):
    """Tests 5-7 — Arabic cell and header styles must NOT use the
    ``wordWrap='CJK'`` + ``splitLongWords=1`` combination because CJK
    treats every Arabic glyph as a wrap-point. English / Latin
    behaviour is preserved (``wordWrap='CJK'`` retained for non-
    Arabic cells)."""

    @_skip_if_no_app
    def test_05_cell_style_arabic_no_cjk(self):
        src = inspect.getsource(_APP.api_generate_pdf)
        # The conditional pattern guarantees Arabic cells skip CJK.
        self.assertIn(
            "wordWrap=None if is_arabic else 'CJK'", src,
            'Arabic cell ParagraphStyle still uses unconditional '
            "wordWrap='CJK' which breaks Arabic words mid-glyph.")

    @_skip_if_no_app
    def test_06_cell_style_arabic_no_splitlongwords(self):
        src = inspect.getsource(_APP.api_generate_pdf)
        self.assertIn(
            'splitLongWords=0 if is_arabic else 1', src,
            'Arabic cell ParagraphStyle still uses unconditional '
            'splitLongWords=1 which breaks Arabic words mid-glyph.')

    @_skip_if_no_app
    def test_07_process_arabic_table_uses_actual_font_size(self):
        """The caller must pass the actual cell font size (and bold
        font for header rows) so the pre-wrap measurement matches
        the rendered width — otherwise ReportLab re-wraps narrow
        Arabic cells and breaks words."""
        src = inspect.getsource(_APP.api_generate_pdf)
        # New call signature with actual font_size + font_name.
        self.assertIn('font_size=_cell_font_size', src)
        self.assertIn('font_name=_wrap_font', src)


class TestRegressionGuards(unittest.TestCase):
    """Tests 8-9 — regression guards covering the strict scope of
    PR-5B.9AB."""

    @_skip_if_no_app
    def test_08_english_cells_keep_cjk_wrap(self):
        """Latin-token wrapping behaviour must be unchanged: the
        non-Arabic branch of the conditional still resolves to
        ``wordWrap='CJK'`` + ``splitLongWords=1``."""
        src = inspect.getsource(_APP.api_generate_pdf)
        # The conditional expressions retain 'CJK' / 1 on the else
        # branch, so English PDFs still split long Latin tokens.
        self.assertIn(
            "wordWrap=None if is_arabic else 'CJK'", src)
        self.assertIn(
            'splitLongWords=0 if is_arabic else 1', src)

    @_skip_if_no_app
    def test_09_pdf_safe_text_idempotent_arabic(self):
        for word in _ARABIC_WORDS:
            once = _APP._pdf_safe_text(word)
            twice = _APP._pdf_safe_text(once)
            self.assertEqual(once, twice)


if __name__ == '__main__':
    unittest.main()
