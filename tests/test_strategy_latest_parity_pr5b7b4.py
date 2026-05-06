"""PR-5B.7B.4 — Preview/export formatting parity for /api/strategy/latest.

Asserts:
  * ``STRATEGY_SECTION_ORDER`` is the canonical 7-section tuple.
  * ``_assemble_canonical_from_sections`` honours the order, skips empty
    sections, joins with two newlines, and applies (or skips)
    ensure_markdown_formatting.
  * ``_canonical_content_from_db`` delegates its sections_json branch to
    the new helper.
  * ``api_strategy_latest`` returns the legacy keys plus the additive
    ``content``, ``canonical_hash``, ``canonical_source`` keys.
  * ``api_strategy_latest`` invokes the export-domain isolation guard with
    the DB row's domain/language and converts ``DomainContaminationError``
    to HTTP 422 with the same body shape used by export routes.
  * ``api_strategy_latest``'s preview canonical_hash equals the export-time
    canonical_hash logged by ``_canonical_content_from_db`` for the same row.

Run:
    python -m pytest tests/test_strategy_latest_parity_pr5b7b4.py -v
"""
import hashlib
import json
import os
import re
import sys
import unittest

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL',
                      'sqlite:///tmp/test_strategy_latest_parity_pr5b7b4.db')
os.environ['OPENAI_API_KEY']    = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY']    = ''
os.environ['GROQ_API_KEY']      = ''
os.environ['DEEPSEEK_API_KEY']  = ''

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception:
    _APP = None


@unittest.skipIf(_APP is None, "app.py not importable in this environment")
class StrategySectionOrderConstantPR5B7B4(unittest.TestCase):
    """The shared section-order constant exists and matches the canonical 7."""

    def test_constant_is_canonical_tuple(self):
        self.assertEqual(
            _APP.STRATEGY_SECTION_ORDER,
            ("vision", "pillars", "environment", "gaps", "roadmap", "kpis", "confidence"),
        )

    def test_constant_is_immutable_tuple(self):
        self.assertIsInstance(_APP.STRATEGY_SECTION_ORDER, tuple)


@unittest.skipIf(_APP is None, "app.py not importable in this environment")
class AssembleCanonicalHelperPR5B7B4(unittest.TestCase):
    """Behavioural unit tests for _assemble_canonical_from_sections."""

    def test_empty_dict_returns_empty_string(self):
        self.assertEqual(_APP._assemble_canonical_from_sections({}), "")

    def test_non_dict_returns_empty_string(self):
        self.assertEqual(_APP._assemble_canonical_from_sections(None), "")
        self.assertEqual(_APP._assemble_canonical_from_sections("not a dict"), "")
        self.assertEqual(_APP._assemble_canonical_from_sections(42), "")

    def test_skips_empty_and_whitespace_sections(self):
        result = _APP._assemble_canonical_from_sections(
            {"vision": "V text", "pillars": "", "gaps": "   ",
             "kpis": "K text"},
            apply_formatting=False,
        )
        self.assertIn("V text", result)
        self.assertIn("K text", result)
        self.assertNotIn("   ", result.split("V text")[0] +
                                result.split("K text")[-1])

    def test_skips_non_string_sections(self):
        result = _APP._assemble_canonical_from_sections(
            {"vision": "V", "pillars": 123, "gaps": ["a", "b"]},
            apply_formatting=False,
        )
        self.assertEqual(result, "V")

    def test_order_enforced_regardless_of_input_order(self):
        # Insert sections in reverse order; helper must emit canonical order.
        d = {}
        d["confidence"] = "C"
        d["kpis"]       = "K"
        d["roadmap"]    = "R"
        d["gaps"]       = "G"
        d["environment"]= "E"
        d["pillars"]    = "P"
        d["vision"]     = "V"
        result = _APP._assemble_canonical_from_sections(d, apply_formatting=False)
        self.assertEqual(result, "V\n\nP\n\nE\n\nG\n\nR\n\nK\n\nC")

    def test_join_uses_double_newline(self):
        result = _APP._assemble_canonical_from_sections(
            {"vision": "A", "pillars": "B"}, apply_formatting=False)
        self.assertEqual(result, "A\n\nB")

    def test_apply_formatting_false_skips_normalizer(self):
        # ensure_markdown_formatting may add/normalise whitespace; with
        # apply_formatting=False the output must equal a plain join.
        d = {"vision": "  V  ", "pillars": "P"}
        result = _APP._assemble_canonical_from_sections(d, apply_formatting=False)
        self.assertEqual(result, "  V  \n\nP")

    def test_apply_formatting_true_invokes_normalizer(self):
        # When apply_formatting=True the result must equal calling
        # ensure_markdown_formatting on the plain join.
        d = {"vision": "V text", "pillars": "P text"}
        plain = "V text\n\nP text"
        try:
            expected = _APP.ensure_markdown_formatting(plain)
        except Exception:
            self.skipTest("ensure_markdown_formatting raised on minimal input")
        actual = _APP._assemble_canonical_from_sections(d, apply_formatting=True)
        self.assertEqual(actual, expected)

    def test_unknown_keys_are_ignored(self):
        d = {"vision": "V", "pillars": "P", "extra": "X"}
        result = _APP._assemble_canonical_from_sections(d, apply_formatting=False)
        self.assertNotIn("X", result)


@unittest.skipIf(_APP is None, "app.py not importable in this environment")
class StaticSourceWiringPR5B7B4(unittest.TestCase):
    """Static guarantees that the helpers are wired into the right places."""

    @classmethod
    def setUpClass(cls):
        with open(_APP.__file__, encoding='utf-8') as _f:
            cls.src = _f.read()

    def _func_body(self, name):
        m = re.search(
            rf'def {re.escape(name)}\([^)]*\)[^:]*:\n(.*?)(?=\ndef |\Z)',
            self.src, flags=re.S,
        )
        self.assertIsNotNone(m, f"function {name} not found")
        return m.group(0)

    def test_canonical_from_db_uses_helper(self):
        body = self._func_body('_canonical_content_from_db')
        self.assertIn('_assemble_canonical_from_sections', body,
                      '_canonical_content_from_db should delegate to the helper')
        # Domain guard must still be invoked (PR-5B.7B.3 invariant preserved).
        self.assertIn('_enforce_export_domain_isolation', body)
        # And contamination must still propagate (no swallow).
        self.assertIn('except DomainContaminationError', body)

    def test_api_strategy_latest_uses_helper_and_guard(self):
        body = self._func_body('api_strategy_latest')
        self.assertIn('_assemble_canonical_from_sections', body)
        self.assertIn('_enforce_export_domain_isolation', body)
        self.assertIn('_enforce_export_domain_isolation_from_text', body)
        self.assertIn('except DomainContaminationError', body)
        self.assertIn("'reason': 'domain_contamination'", body)
        self.assertIn('422', body)
        # Additive response keys (preview parity).
        self.assertIn("'canonical_hash'", body)
        self.assertIn("'canonical_source'", body)
        self.assertIn("'content'", body)
        # Parity log line.
        self.assertIn('[STRATEGY-PARITY] latest canonical_hash=', body)
        # Pre-PR keys must remain in the response payload.
        for k in ("'success'", "'id'", "'strategy_id'", "'sections'",
                  "'content_json'", "'domain'", "'language'",
                  "'document_title'", "'recovery_attempts'"):
            self.assertIn(k, body, f'response key {k} removed')

    def test_section_order_constant_replaces_inline_literals(self):
        # The exact 7-element list literal should no longer appear at the
        # five inline call sites (api_generate_strategy gate, Tier-3,
        # Tier-4, convergence reassembly, _canonical_content_from_db).
        # Board-summary (6 keys, no 'environment') is unaffected.
        bad_literal = (
            "['vision', 'pillars', 'environment', 'gaps', "
            "'roadmap', 'kpis', 'confidence']"
        )
        self.assertNotIn(bad_literal, self.src,
                         "Inline 7-section list literal still present — "
                         "should reference STRATEGY_SECTION_ORDER instead")
        # And the constant is referenced at least 5 times (5 call sites
        # plus the helper itself).
        self.assertGreaterEqual(self.src.count('STRATEGY_SECTION_ORDER'), 5)


@unittest.skipIf(_APP is None, "app.py not importable in this environment")
class StrategyLatestRouteBehaviourPR5B7B4(unittest.TestCase):
    """End-to-end behavioural tests of /api/strategy/latest with seeded DB rows.

    Uses Flask test client + a logged-in session (bypassing OAuth) and a
    monkey-patched ``ensure_latest_strategy_recoverable`` so we don't need
    the real schema — just need the route to receive a row-like object.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = _APP.app
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False

    def _login(self, client):
        with client.session_transaction() as s:
            s['user_id'] = 4242
            s['user_email'] = 'pr5b7b4@example.com'
            s['user_name'] = 'PR-5B.7B.4 tester'

    def _patch_recovery(self, row):
        """Monkey-patch ensure_latest_strategy_recoverable to return ``row``.
        Returns the original function so the test can restore it.
        """
        orig = _APP.ensure_latest_strategy_recoverable
        _APP.ensure_latest_strategy_recoverable = (
            lambda *a, **kw: (row, 1)
        )
        return orig

    def _restore_recovery(self, orig):
        _APP.ensure_latest_strategy_recoverable = orig

    def _row(self, **overrides):
        # sqlite3.Row supports both index and key access; emulate with a dict
        # subclass that yields .keys() like sqlite3.Row.
        defaults = {
            'id': 7,
            'sections_json': None,
            'content_json':  None,
            'content':       None,
            'domain':        'Cyber Security',
            'language':      'en',
            'document_title':'Strategy Doc',
        }
        defaults.update(overrides)
        return defaults

    def test_400_when_domain_missing(self):
        with self.app.test_client() as c:
            self._login(c)
            r = c.get('/api/strategy/latest')
            self.assertEqual(r.status_code, 400)
            self.assertIn('domain', r.get_json().get('error', '').lower())

    def test_404_when_no_row_found(self):
        orig = self._patch_recovery(None)
        try:
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Cyber%20Security')
                self.assertEqual(r.status_code, 404)
        finally:
            self._restore_recovery(orig)

    def test_sections_json_branch_returns_canonical_payload(self):
        sections = {
            "vision":      "Establish a unified cybersecurity posture.",
            "pillars":     "Pillar A: identity. Pillar B: detection.",
            "environment": "Threat landscape and regulatory drivers.",
            "gaps":        "Gap analysis with prioritised remediation.",
            "roadmap":     "Phased 12-month rollout.",
            "kpis":        "Time-to-detect, time-to-respond.",
            "confidence":  "Score 78. Justification: peer benchmarks.",
        }
        sections_json_str = json.dumps(sections, ensure_ascii=False)
        row = self._row(sections_json=sections_json_str)
        orig = self._patch_recovery(row)
        try:
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Cyber%20Security')
                self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
                body = r.get_json()
                # Pre-PR keys preserved.
                for k in ('success', 'id', 'strategy_id', 'sections',
                          'content_json', 'domain', 'language',
                          'document_title', 'recovery_attempts'):
                    self.assertIn(k, body)
                self.assertEqual(body['sections'], sections)
                self.assertEqual(body['domain'], 'Cyber Security')
                # Additive keys present.
                self.assertEqual(body['canonical_source'], 'sections_json')
                self.assertTrue(body['content'])
                self.assertIsInstance(body['canonical_hash'], str)
                self.assertEqual(len(body['canonical_hash']), 16)
                # Hash is computed against canonical || raw_sections_json_str.
                expected = hashlib.sha256(
                    (body['content'] + '||' + sections_json_str).encode('utf-8')
                ).hexdigest()[:16]
                self.assertEqual(body['canonical_hash'], expected)
        finally:
            self._restore_recovery(orig)

    def test_content_fallback_branch(self):
        row = self._row(
            sections_json=None,
            content="# Strategy\n\nA cybersecurity vision and roadmap.",
        )
        orig = self._patch_recovery(row)
        try:
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Cyber%20Security')
                self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
                body = r.get_json()
                self.assertEqual(body['canonical_source'], 'content_fallback')
                self.assertTrue(body['content'])
                # wrap_vision last-resort still kicks in for the sections key.
                self.assertIsInstance(body['sections'], dict)
                self.assertIn('vision', body['sections'])
                # canonical_hash hashes against empty raw sections_json.
                expected = hashlib.sha256(
                    (body['content'] + '||' + '').encode('utf-8')
                ).hexdigest()[:16]
                self.assertEqual(body['canonical_hash'], expected)
        finally:
            self._restore_recovery(orig)

    def test_neither_sections_json_nor_content_yields_empty_canonical(self):
        row = self._row(sections_json=None, content=None)
        orig = self._patch_recovery(row)
        try:
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Cyber%20Security')
                self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
                body = r.get_json()
                self.assertEqual(body['content'], '')
                self.assertIsNone(body['canonical_source'])
                # Hash is still computed (over empty strings) so callers can
                # rely on the key being present.
                self.assertEqual(len(body['canonical_hash']), 16)
        finally:
            self._restore_recovery(orig)

    def test_domain_contamination_returns_422(self):
        # A Data Management strategy whose pillars carry NCA ECC / MFA.
        contaminated = {
            "vision":  "Improve data quality across the enterprise.",
            "pillars": ("Pillar A focuses on NCA ECC alignment. "
                        "Pillar B mandates MFA on all admin consoles."),
        }
        row = self._row(
            sections_json=json.dumps(contaminated, ensure_ascii=False),
            domain="Data Management",
        )
        orig = self._patch_recovery(row)
        try:
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Data%20Management')
                self.assertEqual(r.status_code, 422, r.get_data(as_text=True))
                body = r.get_json()
                self.assertEqual(body.get('reason'), 'domain_contamination')
                self.assertEqual(body.get('artifact_type'), 'strategy')
                self.assertEqual(body.get('artifact_id'), row['id'])
        finally:
            self._restore_recovery(orig)

    def test_preview_hash_matches_export_hash_for_same_row(self):
        """preview canonical_hash from /api/strategy/latest must equal the
        export canonical_hash produced by _assemble_canonical_from_sections
        + the same hash recipe used inside _canonical_content_from_db."""
        sections = {
            "vision":      "V section text long enough to count.",
            "pillars":     "P section text long enough to count.",
            "environment": "E section text long enough to count.",
            "gaps":        "G section text long enough to count.",
            "roadmap":     "R section text long enough to count.",
            "kpis":        "K section text long enough to count.",
            "confidence":  "C section text long enough to count.",
        }
        sections_json_str = json.dumps(sections, ensure_ascii=False)
        # Preview side.
        row = self._row(sections_json=sections_json_str)
        orig = self._patch_recovery(row)
        try:
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Cyber%20Security')
                self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
                preview_hash = r.get_json()['canonical_hash']
        finally:
            self._restore_recovery(orig)
        # Export side: replicate _canonical_content_from_db's hash recipe
        # using the same helper so the two strings are produced identically.
        canonical = _APP._assemble_canonical_from_sections(sections)
        export_hash = hashlib.sha256(
            (canonical + '||' + sections_json_str).encode('utf-8')
        ).hexdigest()[:16]
        self.assertEqual(preview_hash, export_hash,
                         'Preview canonical_hash must equal export canonical_hash '
                         'for the same DB row')


if __name__ == '__main__':
    unittest.main()
