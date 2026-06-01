"""PR-CY73 — standalone DLP row, exec summary truncation, KPI alignment."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy73_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_PSR = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _PSR
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


_ROADMAP_HDR = (
    '## 5. \u062e\u0627\u0631\u0637\u0629 \u0627\u0644\u0637\u0631\u064a\u0642\n\n'
    '| \u0627\u0644\u0645\u0631\u062d\u0644\u0629 | \u0627\u0644\u0645\u062f\u0629 | '
    '\u0627\u0644\u0646\u0634\u0627\u0637 | \u0627\u0644\u0645\u0633\u0624\u0648\u0644 | '
    '\u0627\u0644\u0645\u062e\u0631\u062c | \u0627\u0644\u0625\u0637\u0627\u0631 |\n'
    '|---|---|---|---|---|---|\n'
)

_ROADMAP_DLP_IN_OUTPUT_ONLY = (
    _ROADMAP_HDR
    + '| \u0627\u0644\u0645\u0631\u062d\u0644\u0629 1 | 1-6 \u0623\u0634\u0647\u0631 | '
    '\u062a\u0637\u0628\u064a\u0642 \u062a\u0635\u0646\u064a\u0641 \u0648\u0648\u0633\u0645 '
    '\u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u062d\u0633\u0627\u0633\u0629 | '
    'CISO | \u0633\u062c\u0644 | NCA DCC |\n'
    + '| \u0627\u0644\u0645\u0631\u062d\u0644\u0629 2 | 7-18 \u0634\u0647\u0631 | '
    '\u062a\u0637\u0628\u064a\u0642 \u062a\u0634\u0641\u064a\u0631 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a '
    '\u0627\u0644\u0634\u0627\u0645\u0644 | CISO | \u0645\u0646\u0635\u0629 DLP '
    '\u0648\u0642\u0648\u0627\u0639\u062f \u0645\u0631\u0627\u0642\u0628\u0629 \u062a\u0633\u0631\u0628 '
    '\u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0645\u0641\u0639\u0651\u0644\u0629 | NCA DCC |\n'
    + '| \u0627\u0644\u0645\u0631\u062d\u0644\u0629 1 | 1-6 \u0623\u0634\u0647\u0631 | '
    '\u062a\u0623\u0633\u064a\u0633 SOC | CISO | SOC | NCA ECC |\n'
    + '| \u0627\u0644\u0645\u0631\u062d\u0644\u0629 2 | 6-12 \u0634\u0647\u0631 | '
    'IAM/MFA | CISO | MFA | NCA ECC |\n'
)

_KPI_DETECTION_MISMATCH = (
    '## 6. \u0645\u0624\u0634\u0631\u0627\u062a \u0627\u0644\u0623\u062f\u0627\u0621 \u0627\u0644\u0631\u0626\u064a\u0633\u064a\u0629\n\n'
    '| # | \u0648\u0635\u0641 \u0627\u0644\u0645\u0624\u0634\u0631 | \u0627\u0644\u0642\u064a\u0645\u0629 \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641\u0629 | '
    '\u0635\u064a\u063a\u0629 \u0627\u0644\u0627\u062d\u062a\u0633\u0627\u0628 | '
    '\u0645\u0635\u062f\u0631 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a/\u0627\u0644\u0623\u062f\u0627\u0629 | '
    '\u062a\u0648\u0627\u062a\u0631 \u0627\u0644\u0642\u064a\u0627\u0633 |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | \u0645\u062a\u0648\u0633\u0637 \u0632\u0645\u0646 \u0627\u0643\u062a\u0634\u0627\u0641 \u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a | '
    '< 4 \u0633\u0627\u0639\u0627\u062a | '
    '\u0645\u062a\u0648\u0633\u0637 \u0632\u0645\u0646 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b '
    '\u0627\u0644\u062d\u0631\u062c\u0629 | SIEM | \u0634\u0647\u0631\u064a |\n'
)

_KPI_RESPONSE_FORMULA = (
    '## 6. \u0645\u0624\u0634\u0631\u0627\u062a \u0627\u0644\u0623\u062f\u0627\u0621 \u0627\u0644\u0631\u0626\u064a\u0633\u064a\u0629\n\n'
    '| # | \u0648\u0635\u0641 \u0627\u0644\u0645\u0624\u0634\u0631 | \u0627\u0644\u0642\u064a\u0645\u0629 \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641\u0629 | '
    '\u0635\u064a\u063a\u0629 \u0627\u0644\u0627\u062d\u062a\u0633\u0627\u0628 | '
    '\u0645\u0635\u062f\u0631 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a/\u0627\u0644\u0623\u062f\u0627\u0629 | '
    '\u062a\u0648\u0627\u062a\u0631 \u0627\u0644\u0642\u064a\u0627\u0633 |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | MTTR | < 4 \u0633\u0627\u0639\u0627\u062a | '
    '\u0645\u062c\u0645\u0648\u0639 \u0623\u0632\u0645\u0646\u0629 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 \u0644\u0644\u062d\u0648\u0627\u062f\u062b '
    '\u0627\u0644\u062d\u0631\u062c\u0629 / \u0639\u062f\u062f \u0627\u0644\u062d\u0648\u0627\u062f\u062b \u0627\u0644\u062d\u0631\u062c\u0629 | '
    'SIEM | \u0634\u0647\u0631\u064a |\n'
)

_VISION_STUB = (
    '## 1. \u0627\u0644\u0631\u0624\u064a\u0629\n\n### \u0627\u0644\u0623\u0647\u062f\u0627\u0641\n\n'
    '| # | \u0627\u0644\u0647\u062f\u0641 | \u0627\u0644\u0645\u0642\u064a\u0627\u0633 | '
    '\u0627\u0644\u0645\u0628\u0631\u0631 | \u0627\u0644\u0625\u0637\u0627\u0631 |\n'
    '|---|---|---|---|---|\n'
    '| 1 | \u0625\u0646\u0634\u0627\u0621 \u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u0623\u0645\u0646 | '
    '100% | q | 6m |\n'
)

_CONF = '## 7. \u0627\u0644\u062b\u0642\u0629\n\n**\u062f\u0631\u062c\u0629:** 82%\n'

_LONG_ENC_INIT = (
    '\u062a\u0637\u0628\u064a\u0642 \u062a\u0634\u0641\u064a\u0631 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a '
    '\u0627\u0644\u0634\u0627\u0645\u0644 \u2014 \u0636\u0648\u0627\u0628\u0637 \u0627\u0644\u062a\u0634\u0641\u064a\u0631 '
    '\u0648\u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d \u0648\u062a\u063a\u0637\u064a\u0629 '
    '\u0627\u0644\u062a\u0634\u0641\u064a\u0631 \u2014 \u062d\u0645\u0627'
)

_CANONICAL_ENC = (
    '\u062a\u0637\u0628\u064a\u0642 \u0636\u0648\u0627\u0628\u0637 \u0627\u0644\u062a\u0634\u0641\u064a\u0631 '
    '\u0648\u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u0645\u0641\u0627\u062a\u064a\u062d'
)

_DLP_INIT = (
    '\u062a\u0641\u0639\u064a\u0644 DLP \u0648\u0645\u0631\u0627\u0642\u0628\u0629 \u062a\u0633\u0631\u0628 '
    '\u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a'
)


def _sections(**kw):
    base = {
        'vision': _VISION_STUB,
        'pillars': '## 2.\n',
        'environment': '## 3.\n',
        'gaps': '## 4.\nGap guide.\n',
        'roadmap': _ROADMAP_DLP_IN_OUTPUT_ONLY,
        'kpis': _KPI_DETECTION_MISMATCH,
        'confidence': _CONF,
    }
    base.update(kw)
    return base


class Prcy73FinalCleanupTests(unittest.TestCase):

    @_skip
    def test_helpers_present(self):
        self.assertTrue(hasattr(_APP, '_prcy73_standalone_dlp_roadmap_row_present'))
        self.assertTrue(hasattr(_PSR, '_prcy73_sanitize_exec_priority_label'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy73'))

    @_skip
    def test_dlp_in_output_cell_does_not_count_as_standalone_row(self):
        roadmap = _ROADMAP_DLP_IN_OUTPUT_ONLY
        fams = _APP._prcy71_present_dcc_roadmap_families(roadmap)
        self.assertNotIn('dlp', fams)
        self.assertFalse(_APP._prcy73_standalone_dlp_roadmap_row_present(
            roadmap))

    @_skip
    def test_missing_standalone_dlp_roadmap_row_is_inserted(self):
        sections = _sections()
        out, actions = _APP._prcy73_ensure_standalone_dlp_roadmap_row(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        self.assertTrue(_APP._prcy73_standalone_dlp_roadmap_row_present(
            out.get('roadmap', '')))
        self.assertIn('prcy73:standalone_dlp_roadmap_row_inserted', actions)
        self.assertIn(_DLP_INIT, out.get('roadmap', ''))

    @_skip
    def test_exec_summary_truncated_fragment_removed(self):
        clean = _PSR._prcy73_sanitize_exec_priority_label(_LONG_ENC_INIT)
        self.assertNotIn('\u2014 \u062d\u0645\u0627', clean)
        self.assertEqual(clean, _CANONICAL_ENC)
        priorities = _PSR._derive_executive_priorities(
            _sections(roadmap=_ROADMAP_DLP_IN_OUTPUT_ONLY), {}, 'ar')
        joined = ' '.join(priorities)
        self.assertNotIn('\u2014 \u062d\u0645\u0627', joined)

    @_skip
    def test_detection_kpi_does_not_keep_response_formula(self):
        kpis = _KPI_DETECTION_MISMATCH
        self.assertFalse(_APP._prcy68_kpi_detection_response_aligned(
            kpis, 'ar'))
        fixed, changed = _APP._prcy68_normalize_kpi_detection_response(
            kpis, 'ar')
        self.assertTrue(changed)
        self.assertIn(
            '\u0645\u062a\u0648\u0633\u0637 \u0632\u0645\u0646 \u0627\u0643\u062a\u0634\u0627\u0641 '
            '\u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a', fixed)
        self.assertIn(
            '\u0645\u062c\u0645\u0648\u0639 \u0623\u0632\u0645\u0646\u0629 \u0627\u0643\u062a\u0634\u0627\u0641 '
            '\u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a / \u0639\u062f\u062f '
            '\u0627\u0644\u062a\u0647\u062f\u064a\u062f\u0627\u062a \u0627\u0644\u0645\u0643\u062a\u0634\u0641\u0629',
            fixed)
        self.assertNotIn(
            '\u0645\u062a\u0648\u0633\u0637 \u0632\u0645\u0646 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629',
            fixed)
        self.assertTrue(_APP._prcy68_kpi_detection_response_aligned(
            fixed, 'ar'))

    @_skip
    def test_response_formula_renames_metric_when_needed(self):
        kpis = _KPI_RESPONSE_FORMULA
        fixed, changed = _APP._prcy68_normalize_kpi_detection_response(
            kpis, 'ar')
        self.assertTrue(changed)
        self.assertIn(
            '\u0645\u062a\u0648\u0633\u0637 \u0632\u0645\u0646 \u0627\u0644\u0627\u0633\u062a\u062c\u0627\u0628\u0629 '
            '\u0644\u0644\u062d\u0648\u0627\u062f\u062b \u0627\u0644\u062d\u0631\u062c\u0629', fixed)
        self.assertIn('ITSM / SOAR / SIEM', fixed)
        self.assertTrue(_APP._prcy68_kpi_detection_response_aligned(
            fixed, 'ar'))


if __name__ == '__main__':
    unittest.main()
