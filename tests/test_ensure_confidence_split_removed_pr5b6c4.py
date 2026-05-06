"""PR-5B.6C.4 — confirm the deterministic Arabic-only confidence/risk
row injector ``_ensure_confidence_split`` is fully removed.

After PR-5B.6C.2 (synthesize_confidence_depth AI-first) and
PR-5B.6C.3 (repair_confidence_risk_section AI-first), the deterministic
Arabic-only injector inside ``enforce_cybersecurity_technical_depth`` is
redundant and must not bypass the AI-first/fail-closed pipeline.

This test asserts:
  1. Source has no ``def _ensure_confidence_split`` definition.
  2. Source has no production call site of ``_ensure_confidence_split(``.
  3. ``app`` module has no ``_ensure_confidence_split`` symbol.
  4. ``enforce_cybersecurity_technical_depth`` does not inject the
     deterministic strings the deleted function used to author.
  5. ``repair_confidence_risk_section`` and ``synthesize_confidence_depth``
     are still present and callable (regression guard).
  6. Deterministic strings unique to the deleted function are gone from
     app.py (narrowed: the strings ``دعم القيادة التنفيذية`` /
     ``الكفاءات السيبرانية`` / ``MSSP`` / ``CISO`` legitimately appear
     elsewhere in cyber-strategy content; only the deleted-function-unique
     ``تأخر اعتماد الحوكمة`` is asserted to be gone everywhere).
"""

import os
import re
import sys
import importlib
import pathlib
import unittest


# ---------------------------------------------------------------------------
# Minimal env so app.py imports cleanly.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_pr5b6c4.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_APP_PY = _REPO_ROOT / 'app.py'
_APP_SRC = _APP_PY.read_text(encoding='utf-8')

app = importlib.import_module('app')


# Strings that the deleted function authored. Some are legitimately reused
# elsewhere in cyber-strategy content; others are unique to the deleted
# function and must be fully gone.
_DELETED_FN_UNIQUE_STRINGS = (
    'تأخر اعتماد الحوكمة',
)
_DELETED_FN_SHARED_STRINGS = (
    'دعم القيادة التنفيذية',
    'نقص الكفاءات السيبرانية',
    'MSSP',
    'CISO',
)


class EnsureConfidenceSplitRemovedTests(unittest.TestCase):
    """PR-5B.6C.4 removal guards."""

    # 1. Static absence of the definition.
    def test_function_definition_absent_from_source(self):
        self.assertNotIn(
            'def _ensure_confidence_split',
            _APP_SRC,
            "PR-5B.6C.4: _ensure_confidence_split definition must be removed.",
        )

    # 1b. Static absence of any production call site.
    def test_no_production_call_site_in_source(self):
        # Allow zero call sites in app.py.
        call_sites = re.findall(r'_ensure_confidence_split\s*\(', _APP_SRC)
        self.assertEqual(
            call_sites,
            [],
            "PR-5B.6C.4: _ensure_confidence_split must have no call sites in app.py.",
        )

    # 2. Symbol absence on the imported module.
    def test_symbol_absent_on_app_module(self):
        self.assertFalse(
            hasattr(app, '_ensure_confidence_split'),
            "PR-5B.6C.4: app module must not expose _ensure_confidence_split.",
        )

    # 3. Cyber-depth smoke: sparse confidence is not enriched with the
    # deterministic Arabic-only strings the deleted function authored.
    def test_cyber_depth_does_not_inject_deterministic_confidence_rows(self):
        enforce = getattr(app, 'enforce_cybersecurity_technical_depth', None)
        if enforce is None:
            self.skipTest('enforce_cybersecurity_technical_depth not present')

        # Sparse confidence section: no CSF/risk subsections, no rows.
        sections = {
            'cover': '## غلاف',
            'executive_summary': '## ملخص تنفيذي',
            'scope': '## النطاق',
            'environment': '## البيئة',
            'pillars': '## ركائز',
            'objectives': '## أهداف',
            'kpis': '## مؤشرات',
            'roadmap': '## خارطة الطريق',
            'gaps': '## الفجوات',
            'confidence': '## 7. تقييم الثقة\n\n**درجة الثقة:** 50%\n',
        }
        before_conf = sections['confidence']

        # Patch enforce_technical_strategy_depth to a no-op so this test
        # isolates the post-depth code path that used to call the deleted
        # _ensure_confidence_split (Step 4). The AI-first depth enricher
        # itself is covered by its own tests.
        import unittest.mock as _mock
        with _mock.patch.object(
            app, 'enforce_technical_strategy_depth',
            return_value={'capability_gaps': []},
        ):
            try:
                enforce(
                    sections,
                    lang='ar',
                    org_name='منظمة تجريبية',
                    sector='General',
                    frameworks=['NCA ECC'],
                    maturity='initial',
                    generation_mode='consulting',
                    diagnostic_gaps=None,
                    domain='Cyber Security',
                )
            except Exception:
                # Other structural passes may raise on this minimal fixture;
                # the only assertion is that the deleted injector did not
                # mutate the confidence section before any such failure.
                pass

        after_conf = sections.get('confidence', '') or ''

        forbidden_in_confidence = [
            'تأخر اعتماد الحوكمة',
            'نقص الكفاءات السيبرانية',
            'دعم القيادة التنفيذية',
        ]
        for needle in forbidden_in_confidence:
            self.assertNotIn(
                needle, after_conf,
                f"PR-5B.6C.4: deterministic injector residue '{needle}' "
                f"reappeared in confidence section.\nBefore: {before_conf!r}\n"
                f"After: {after_conf!r}",
            )

    # 4. Regression: the AI-first replacements still exist.
    def test_repair_confidence_risk_section_still_present(self):
        fn = getattr(app, 'repair_confidence_risk_section', None)
        self.assertIsNotNone(fn, 'repair_confidence_risk_section missing')
        self.assertTrue(callable(fn))

    def test_synthesize_confidence_depth_still_present(self):
        fn = getattr(app, 'synthesize_confidence_depth', None)
        self.assertIsNotNone(fn, 'synthesize_confidence_depth missing')
        self.assertTrue(callable(fn))

    # 5a. Strings unique to the deleted function are fully gone from app.py.
    def test_deleted_function_unique_strings_absent_from_source(self):
        for needle in _DELETED_FN_UNIQUE_STRINGS:
            self.assertNotIn(
                needle, _APP_SRC,
                f"PR-5B.6C.4: deleted-function-unique string '{needle}' "
                f"must be gone from app.py.",
            )

    # 5b. Strings the deleted function shared with other legitimate
    # cyber-strategy content may still appear elsewhere, but must NOT
    # appear inside enforce_cybersecurity_technical_depth itself.
    def test_shared_strings_absent_from_enforce_cybersec_function_body(self):
        m = re.search(
            r'^def enforce_cybersecurity_technical_depth\b.*?(?=^def \w)',
            _APP_SRC,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            'enforce_cybersecurity_technical_depth body not located in app.py',
        )
        body = m.group(0)
        for needle in _DELETED_FN_SHARED_STRINGS:
            self.assertNotIn(
                needle, body,
                f"PR-5B.6C.4: deterministic deleted-injector string "
                f"'{needle}' must not reappear inside "
                f"enforce_cybersecurity_technical_depth.",
            )


if __name__ == '__main__':
    unittest.main()
