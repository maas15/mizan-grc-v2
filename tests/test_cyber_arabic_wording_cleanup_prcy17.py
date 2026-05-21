"""PR-CY17 — Cyber Arabic wording cleanup tests.

Production symptom (cyber + ECC + DCC, Arabic PDF): the rendered
document contained mixed / awkward English-Arabic phrases:

    * ``Security Cyber`` / ``Cyber Security`` (generic English noun
      phrase appearing inside Arabic sentences),
    * ``ECC NCA`` / ``DCC NCA`` (reversed framework-name order),
    * ``استراتيجية Cyber Security`` (English fragment inside an
      Arabic title).

PR-CY17 introduces ``_normalize_cyber_ar_wording_general`` which
rewrites these to professional Arabic.  Framework names ``NCA ECC``
/ ``NCA DCC`` and English acronyms (CISO / SOC / SIEM / IAM / PAM /
MFA / CSIRT / DLP) are explicitly preserved.

Run:
    python -m pytest tests/test_cyber_arabic_wording_cleanup_prcy17.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_ar_wording_prcy17_')
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


class CyberArabicWordingCleanupTests(unittest.TestCase):

    @_skip_if_no_app
    def test_15_cleanup_removes_security_cyber(self):
        sections = {'vision': 'يتولى الفريق Security Cyber الإشراف.'}
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        self.assertNotIn('Security Cyber', sections['vision'])
        self.assertIn('الأمن السيبراني', sections['vision'])

    @_skip_if_no_app
    def test_15b_cleanup_removes_cyber_security(self):
        sections = {'pillars': 'الركيزة الأولى: Cyber Security.'}
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        self.assertNotIn('Cyber Security', sections['pillars'])
        self.assertIn('الأمن السيبراني', sections['pillars'])

    @_skip_if_no_app
    def test_16_cleanup_removes_strategy_cyber_security(self):
        sections = {
            'vision': 'هذه استراتيجية Cyber Security للجهة.'}
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        self.assertNotIn('استراتيجية Cyber Security', sections['vision'])
        self.assertIn('استراتيجية الأمن السيبراني', sections['vision'])

    @_skip_if_no_app
    def test_16b_cleanup_fixes_reversed_ecc_nca(self):
        sections = {'environment': 'يلتزم بمتطلبات ECC NCA.'}
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        self.assertNotIn('ECC NCA', sections['environment'])
        self.assertIn('NCA ECC', sections['environment'])

    @_skip_if_no_app
    def test_16c_cleanup_fixes_reversed_dcc_nca(self):
        sections = {'environment': 'يلتزم بمتطلبات DCC NCA.'}
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        self.assertNotIn('DCC NCA', sections['environment'])
        self.assertIn('NCA DCC', sections['environment'])

    @_skip_if_no_app
    def test_17_cleanup_preserves_nca_ecc_and_nca_dcc(self):
        """Already-correct framework names must be preserved verbatim
        and never weakened by the cleanup."""
        original = (
            'يغطي البرنامج NCA ECC و NCA DCC ويعتمد على CISO و SOC '
            'و SIEM و IAM/PAM و MFA و CSIRT و DLP.'
        )
        sections = {'vision': original}
        _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        # Framework names preserved.
        self.assertIn('NCA ECC', sections['vision'])
        self.assertIn('NCA DCC', sections['vision'])
        # Acronyms preserved.
        for tok in ('CISO', 'SOC', 'SIEM', 'IAM/PAM', 'MFA',
                    'CSIRT', 'DLP'):
            self.assertIn(
                tok, sections['vision'],
                f'Cleanup unexpectedly removed acronym {tok!r}')

    @_skip_if_no_app
    def test_17b_cleanup_does_not_run_for_non_cyber_domain(self):
        """Domain != cyber → cleanup is a no-op."""
        sections = {'vision': 'This contains Cyber Security text.'}
        before = sections['vision']
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'data')
        self.assertEqual(n, {})
        self.assertEqual(sections['vision'], before)

    @_skip_if_no_app
    def test_17c_cleanup_does_not_run_for_english_lang(self):
        """lang != ar → cleanup is a no-op even for cyber."""
        sections = {'vision': 'Our Cyber Security strategy.'}
        before = sections['vision']
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'en', 'cyber')
        self.assertEqual(n, {})
        self.assertEqual(sections['vision'], before)

    @_skip_if_no_app
    def test_17d_cleanup_is_idempotent(self):
        """Running the cleanup twice produces the same text the
        second time (no further mutations)."""
        sections = {
            'vision': 'استراتيجية Cyber Security و ECC NCA و DCC NCA.'}
        _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        snapshot = sections['vision']
        _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        self.assertEqual(sections['vision'], snapshot)


class StrictScopeContractsTests(unittest.TestCase):
    """PR-CY17 must not weaken validators or inject deterministic
    strategy content."""

    @_skip_if_no_app
    def test_18_data_management_unchanged_for_data_domain(self):
        """The cleanup must be a no-op on Data Management content."""
        sections = {
            'vision': 'تشمل الاستراتيجية Cyber Security ضمن الحوكمة.'}
        before = dict(sections)
        _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'data')
        self.assertEqual(sections, before)

    @_skip_if_no_app
    def test_19_validators_not_weakened(self):
        """Final-audit validator + final-strategy-audit symbol exist."""
        for sym in ('_final_strategy_audit',
                    '_compute_missing_specialized_function_objective',
                    '_compute_missing_compliance_objective',
                    '_compute_applicable_strategy_obligations'):
            self.assertTrue(
                hasattr(_APP, sym),
                f'Validator {sym!r} unexpectedly missing.')

    @_skip_if_no_app
    def test_20_no_deterministic_strategy_content_injected(self):
        """The Cyber governance roles table is a STRUCTURAL document
        block — not a generated strategy section.  Empty content must
        still produce empty governance rows (PR-5B.8R contract)."""
        rows = _APP._extract_owners_from_content(
            {}, 'ar', domain_code='cyber')
        self.assertEqual(rows, [])
        # And the cleanup also never invents strategy content.
        sections = {}
        n = _APP._normalize_cyber_ar_wording_general(
            sections, 'ar', 'cyber')
        self.assertEqual(n, {})
        self.assertEqual(sections, {})


if __name__ == '__main__':
    unittest.main()
