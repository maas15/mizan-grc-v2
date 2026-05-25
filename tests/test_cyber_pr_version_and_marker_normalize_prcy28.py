"""PR-CY28 — Persistent runtime unresolved KPI target marker fix.

Verifies the PR-CY28 deliverables on top of PR-CY25/26/27:

  A. ``_cyber_final_export_contract`` emits the ``[CYBER-PR-VERSION]``
     diagnostic at entry with ``prcy25/26/27/28=True``.
  B. HTML-escaped / fullwidth / URL-encoded ``[REQUIRES_AI_*]`` marker
     variants are folded back to the canonical bracketed form by the
     PR-CY28 scanner so they cannot bypass the hard blocking gate.
  C. The contract uses a single mutable ``final_markdown`` variable
     such that after PR-CY27 last-chance repair the
     ``[REQUIRES_AI_TARGET_REPAIR]`` token is absent from the returned
     ``final_markdown`` for the canonical row_3 incident-response
     example from the problem statement.
"""
import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_prcy28_')
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
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


class PRVersionDiagnosticTests(unittest.TestCase):

    @_skip_if_no_app
    def test_version_stamp_emitted_with_all_flags(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._cyber_final_export_contract(
                '# Strategy\n\nbody', metadata={'domain': 'cyber'},
                selected_frameworks=['ECC'], lang='en', domain='cyber',
                output_type='unit_test',
            )
        out = buf.getvalue()
        self.assertIn('[CYBER-PR-VERSION]', out)
        self.assertIn("'prcy25': True", out)
        self.assertIn("'prcy26': True", out)
        self.assertIn("'prcy27': True", out)
        self.assertIn("'prcy28': True", out)
        self.assertIn("'output_type': 'unit_test'", out)


class MarkerVariantNormalizationTests(unittest.TestCase):

    @_skip_if_no_app
    def test_html_entity_brackets_detected(self):
        text = 'value=&#91;REQUIRES_AI_TARGET_REPAIR&#93; trailing'
        found = _APP._prcy25_scan_unresolved_markers(text)
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', found)

    @_skip_if_no_app
    def test_named_entity_brackets_detected(self):
        text = '&lbrack;REQUIRES_AI_TARGET_REPAIR&rbrack;'
        found = _APP._prcy25_scan_unresolved_markers(text)
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', found)

    @_skip_if_no_app
    def test_url_encoded_brackets_detected(self):
        text = '%5BREQUIRES_AI_TARGET_REPAIR%5D'
        found = _APP._prcy25_scan_unresolved_markers(text)
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', found)

    @_skip_if_no_app
    def test_fullwidth_brackets_detected(self):
        text = '\uff3bREQUIRES_AI_TARGET_REPAIR\uff3d'
        found = _APP._prcy25_scan_unresolved_markers(text)
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', found)

    @_skip_if_no_app
    def test_canonical_marker_still_detected(self):
        text = 'foo [REQUIRES_AI_TARGET_REPAIR] bar'
        found = _APP._prcy25_scan_unresolved_markers(text)
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', found)

    @_skip_if_no_app
    def test_normalize_marker_variants_idempotent(self):
        text = 'X [REQUIRES_AI_TARGET_REPAIR] Y'
        self.assertEqual(
            _APP._prcy28_normalize_marker_variants(text), text)


class FinalMarkdownAssertionTests(unittest.TestCase):
    """The contract must use a single mutable ``final_markdown``
    variable and assert it after PR-CY27 last-chance repair."""

    @_skip_if_no_app
    def test_kpi_row3_marker_removed_from_returned_final_markdown(self):
        # Canonical row_3 incident-response example from the problem
        # statement. PR-CY27 must repair the marker and PR-CY28 must
        # surface the repaired bytes in the returned ``final_markdown``.
        md = (
            '## Vision\n\nOrg vision.\n\n'
            '## Key Performance Indicators (KPIs)\n\n'
            '| Description | Target | Formula | Source | Owner | Frequency |\n'
            '|---|---|---|---|---|---|\n'
            '| MFA coverage of privileged accounts | 95% | covered/total | '
            'IAM/PAM | CISO | Monthly |\n'
            '| SIEM use-case coverage of MITRE ATT&CK | 80% | covered/total |'
            ' SIEM | SOC | Quarterly |\n'
            '| Incident response Mean Time To Respond (MTTR) | '
            '[REQUIRES_AI_TARGET_REPAIR] | hours_to_contain | SIEM/SOC | '
            'CISO | Monthly |\n'
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = _APP._cyber_final_export_contract(
                md, metadata={'domain': 'cyber'},
                selected_frameworks=['ECC'], lang='en', domain='cyber',
                output_type='unit_test',
            )
        out = buf.getvalue()
        # Repair diagnostic must fire.
        self.assertIn('[CYBER-KPI-TARGET-REPAIR]', out)
        # Canonical marker must be removed from the returned bytes.
        self.assertNotIn(
            '[REQUIRES_AI_TARGET_REPAIR]', result.get('final_markdown', ''))
        # And the post-repair assertion must surface a pass diagnostic.
        self.assertIn('post_repair_assertion_passed', out)


if __name__ == '__main__':
    unittest.main()
