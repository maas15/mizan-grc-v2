"""PR-5B.7B.3 — Export-time domain isolation guard.

Asserts:
  * `_enforce_export_domain_isolation` is a no-op for non-strategy artifacts.
  * `_enforce_export_domain_isolation` is a no-op when sections are clean.
  * `_enforce_export_domain_isolation` raises `DomainContaminationError`
    when sections contain forbidden cross-domain terms (Data Management
    strategy carrying NCA ECC / MFA).
  * `_enforce_export_domain_isolation` raises `DomainContaminationError`
    when the saved domain is unresolvable (legacy/free-text).
  * `_enforce_export_domain_isolation_from_text` flags a flattened blob
    (used by content-fallback and client-payload paths).
  * Static source guarantees: `_canonical_content_from_db` calls the
    guard, and each of the four export routes converts
    `DomainContaminationError` to HTTP 422 with the
    `domain_contamination` reason.

Run:
    python -m pytest tests/test_export_domain_isolation_pr5b7b3.py -v
"""
import os
import re
import sys
import unittest

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL',
                      'sqlite:///tmp/test_export_domain_isolation_pr5b7b3.db')
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
class ExportDomainIsolationGuardPR5B7B3(unittest.TestCase):
    """Behavioural tests for the new guard helpers."""

    def test_helper_noop_for_non_strategy_artifact(self):
        # Even with cross-domain content, non-strategy artifacts bypass.
        self.assertIsNone(_APP._enforce_export_domain_isolation(
            {"vision": "NCA ECC alignment and MFA rollout."},
            domain="Data Management",
            language="en",
            artifact_type="policy",
            artifact_id=1,
        ))

    def test_helper_clean_data_strategy_passes(self):
        clean = {
            "vision": "Establish a unified data governance framework.",
            "pillars": "Data quality, master data, lineage, stewardship.",
        }
        self.assertIsNone(_APP._enforce_export_domain_isolation(
            clean,
            domain="Data Management",
            language="en",
            artifact_type="strategy",
            artifact_id=42,
        ))

    def test_helper_flags_cyber_terms_in_data_strategy(self):
        contaminated = {
            "vision": "Improve data quality across the enterprise.",
            "pillars": ("Pillar A focuses on NCA ECC alignment. "
                        "Pillar B mandates MFA on all admin consoles."),
        }
        with self.assertRaises(_APP.DomainContaminationError) as cm:
            _APP._enforce_export_domain_isolation(
                contaminated,
                domain="Data Management",
                language="en",
                artifact_type="strategy",
                artifact_id=42,
            )
        msg = str(cm.exception)
        self.assertIn("pillars", msg)
        self.assertIn("Data Management", msg)

    def test_helper_unresolvable_domain_raises_contamination(self):
        # Legacy/free-text saved domain that no longer normalises.
        with self.assertRaises(_APP.DomainContaminationError):
            _APP._enforce_export_domain_isolation(
                {"vision": "Anything."},
                domain="not-a-real-domain-xyz",
                language="en",
                artifact_type="strategy",
                artifact_id=99,
            )

    def test_flattened_text_helper_clean_passes(self):
        self.assertIsNone(_APP._enforce_export_domain_isolation_from_text(
            "Data quality, lineage, and stewardship across the enterprise.",
            domain="Data Management",
            language="en",
            artifact_type="strategy",
            artifact_id=7,
        ))

    def test_flattened_text_helper_flags_contamination(self):
        text = ("# Strategy\n\nPillar 1: NCA ECC alignment.\n"
                "Pillar 2: MFA enforcement.\n")
        with self.assertRaises(_APP.DomainContaminationError):
            _APP._enforce_export_domain_isolation_from_text(
                text,
                domain="Data Management",
                language="en",
                artifact_type="strategy",
                artifact_id=7,
            )

    def test_flattened_text_helper_noop_on_empty(self):
        self.assertIsNone(_APP._enforce_export_domain_isolation_from_text(
            "",
            domain="Data Management",
            language="en",
            artifact_type="strategy",
            artifact_id=7,
        ))

    def test_flattened_text_helper_noop_for_non_strategy(self):
        text = "NCA ECC and MFA references everywhere."
        self.assertIsNone(_APP._enforce_export_domain_isolation_from_text(
            text,
            domain="Data Management",
            language="en",
            artifact_type="policy",
            artifact_id=7,
        ))


@unittest.skipIf(_APP is None, "app.py not importable in this environment")
class ExportDomainIsolationStaticSourcePR5B7B3(unittest.TestCase):
    """Static guarantees: guard wired into _canonical_content_from_db and
    each of the four export routes returns 422 on contamination."""

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

    def test_canonical_from_db_invokes_guard_and_reraises(self):
        body = self._func_body('_canonical_content_from_db')
        # Must call the guard (sections_json branch, possibly text branch too).
        self.assertIn('_enforce_export_domain_isolation', body)
        # Must NOT swallow DomainContaminationError into the parse-failed except.
        self.assertIn('except DomainContaminationError', body)

    def _route_block(self, route_name):
        # Capture the route's body up to the next top-level def/route.
        m = re.search(
            rf'def {re.escape(route_name)}\(.*?(?=\n@app\.route|\ndef api_|\Z)',
            self.src, flags=re.S,
        )
        self.assertIsNotNone(m, f"route {route_name} not found")
        return m.group(0)

    def _assert_route_handles_contamination_with_422(self, route_name):
        body = self._route_block(route_name)
        self.assertIn('DomainContaminationError', body,
                      f'{route_name} does not catch DomainContaminationError')
        self.assertIn("'reason': 'domain_contamination'", body,
                      f'{route_name} does not return domain_contamination reason')
        self.assertIn('422', body,
                      f'{route_name} does not return HTTP 422')
        # Client-payload fallback guard is also present.
        self.assertIn('_enforce_export_domain_isolation_from_text', body,
                      f'{route_name} missing client-payload guard call')

    def test_pdf_route_returns_422(self):
        self._assert_route_handles_contamination_with_422('api_generate_pdf')

    def test_pdf_async_route_returns_422(self):
        self._assert_route_handles_contamination_with_422('api_generate_pdf_async')

    def test_docx_route_returns_422(self):
        self._assert_route_handles_contamination_with_422('api_generate_docx')

    def test_docx_async_route_returns_422(self):
        self._assert_route_handles_contamination_with_422('api_generate_docx_async')


if __name__ == '__main__':
    unittest.main()
