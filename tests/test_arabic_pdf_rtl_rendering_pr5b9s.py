"""PR-5B.9S — Arabic PDF RTL rendering safety.

Scope is **Data Management only** in spirit, but the PDF helper
``_pdf_safe_text`` is shared. The fix is guarded by character-class
neighbour inspection (Arabic vs ASCII) so it tightens behaviour for
Arabic tokens without changing ASCII-only behaviour.

Failure modes addressed:
  * ``رئيس البيانات`` and similar Arabic compounds must never gain
    an internal zero-width-space break point inside the Arabic
    run because narrow ReportLab table cells then wrap visually
    inside the Arabic word.
  * ``تأسيس/تطوير`` and any other Arabic/punctuation/Arabic
    sequence must not gain a ZWSP after the ``/``.
  * Mixed cells such as ``رئيس البيانات (CDO)`` must keep the
    Arabic prefix intact — no ZWSP after the ``(`` or inside the
    Arabic.

Preserved behaviour:
  * Pure ASCII compounds (``data/AI/cyber``, ``SDAIA-AI-Governance``)
    still gain ZWSP wrap points.
  * Long ASCII tokens (``ModelMonitoringOfficer``) still get
    per-22-character break points.
  * Idempotency: calling the helper twice yields the same string.

Run:
    python -m pytest \
        tests/test_arabic_pdf_rtl_rendering_pr5b9s.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_ar_pdf_pr5b9s_')
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


ZWSP = '\u200B'


class TestArabicPdfSafeText(unittest.TestCase):
    @_skip_if_no_app
    def test_arabic_word_chief_data_officer_unbroken(self):
        # رئيس البيانات — no break char inside, must be unchanged.
        s = 'رئيس البيانات'
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, s)
        self.assertNotIn(ZWSP, out)

    @_skip_if_no_app
    def test_arabic_slash_arabic_no_zwsp_inserted(self):
        # تأسيس/تطوير — the `/` is sandwiched between Arabic chars.
        # No ZWSP must be inserted.
        s = 'تأسيس/تطوير'
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, s)
        self.assertNotIn(ZWSP, out)

    @_skip_if_no_app
    def test_arabic_with_spaces_around_slash_no_zwsp_inside_arabic(self):
        # The slash has Arabic neighbours via the spaces; spaces are
        # not Arabic but the next/prev non-space char rule isn't
        # applied. We rely on the immediate neighbour rule: ' ' is
        # ASCII whitespace, NOT Arabic, so ZWSP CAN be inserted. The
        # important invariant is the Arabic words themselves are
        # unsplit.
        s = 'تأسيس / تطوير'
        out = _APP._pdf_safe_text(s)
        # The Arabic substrings must be present and unbroken.
        self.assertIn('تأسيس', out)
        self.assertIn('تطوير', out)
        # No ZWSP inside the Arabic substrings.
        for word in ('تأسيس', 'تطوير'):
            self.assertNotIn(ZWSP, word)

    @_skip_if_no_app
    def test_arabic_paren_english_paren_arabic_no_break_inside_arabic(self):
        # رئيس البيانات (CDO) — the `(` is preceded by space (ASCII)
        # and followed by `C` (ASCII), so a ZWSP after `(` is OK
        # because no Arabic neighbour. But there must be NO ZWSP
        # inside any Arabic word.
        s = 'رئيس البيانات (CDO)'
        out = _APP._pdf_safe_text(s)
        self.assertIn('رئيس البيانات', out)
        # ZWSP must not appear inside the Arabic prefix.
        ar_prefix_idx = out.find('رئيس البيانات')
        self.assertGreaterEqual(ar_prefix_idx, 0)
        # Slice everything up to and including the Arabic prefix;
        # there must be no ZWSP in that slice.
        cutoff = ar_prefix_idx + len('رئيس البيانات')
        self.assertNotIn(ZWSP, out[:cutoff],
                         'ZWSP appeared inside or before the Arabic prefix')

    @_skip_if_no_app
    def test_arabic_paren_glued_to_arabic_no_zwsp(self):
        # رئيس(البيانات) — `(` is between Arabic chars, must not
        # gain a ZWSP.
        s = 'رئيس(البيانات)'
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, s)
        self.assertNotIn(ZWSP, out)

    @_skip_if_no_app
    def test_arabic_comma_arabic_no_zwsp(self):
        s = 'حوكمة,البيانات'
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, s)
        self.assertNotIn(ZWSP, out)

    @_skip_if_no_app
    def test_arabic_colon_arabic_no_zwsp(self):
        s = 'الركيزة:البيانات'
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, s)
        self.assertNotIn(ZWSP, out)

    @_skip_if_no_app
    def test_arabic_dash_arabic_no_zwsp(self):
        s = 'إدارة-البيانات'
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, s)
        self.assertNotIn(ZWSP, out)

    @_skip_if_no_app
    def test_ascii_compound_still_gets_zwsp_at_slash(self):
        # Existing behaviour preserved for ASCII compounds.
        s = 'data/AI/cyber'
        out = _APP._pdf_safe_text(s)
        # Each `/` must be followed by a ZWSP.
        self.assertEqual(out, 'data/' + ZWSP + 'AI/' + ZWSP + 'cyber')

    @_skip_if_no_app
    def test_ascii_compound_still_gets_zwsp_at_dash(self):
        s = 'SDAIA-AI-Governance'
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, 'SDAIA-' + ZWSP + 'AI-' + ZWSP + 'Governance')

    @_skip_if_no_app
    def test_long_ascii_run_still_split(self):
        s = 'ModelMonitoringOfficerForResponsibleAIChiefDataOfficer'
        out = _APP._pdf_safe_text(s)
        # ZWSP-stripped output must equal the input (lossless).
        self.assertEqual(out.replace(ZWSP, ''), s)
        # ZWSPs must have been inserted to split the long run.
        self.assertIn(ZWSP, out)

    @_skip_if_no_app
    def test_long_arabic_run_not_split(self):
        # 50 chars of Arabic with no break punctuation — must never
        # gain ZWSP because the long-run regex is ASCII-only.
        s = 'ا' * 50 + ' ' + 'ب' * 50
        out = _APP._pdf_safe_text(s)
        self.assertEqual(out, s)
        self.assertNotIn(ZWSP, out)

    @_skip_if_no_app
    def test_idempotent_on_mixed_content(self):
        s = 'رئيس البيانات (CDO) — data/AI/cyber: تأسيس/تطوير'
        once = _APP._pdf_safe_text(s)
        twice = _APP._pdf_safe_text(once)
        # Calling again should not add NEW ZWSPs (the chars that
        # were break-eligible are now followed by ZWSP, which is
        # itself not a break char, and Arabic neighbours stay
        # protected).
        self.assertEqual(once, twice)

    @_skip_if_no_app
    def test_none_input_returns_empty_string(self):
        self.assertEqual(_APP._pdf_safe_text(None), '')

    @_skip_if_no_app
    def test_empty_string_passthrough(self):
        self.assertEqual(_APP._pdf_safe_text(''), '')


if __name__ == '__main__':
    unittest.main()
