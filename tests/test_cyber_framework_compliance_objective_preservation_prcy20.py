"""PR-CY20 — Cyber-scoped framework-compliance objective preservation.

Tests verify:

1. Widened ECC/DCC framework aliases (EN + AR variants from the problem
   statement) are detected by ``_compute_missing_compliance_objective``
   when present in a vision objective row.
2. The validator still requires the compliance objective row to live
   INSIDE the Strategic Objectives table. Framework mentions in scope,
   methodology, appendix, traceability matrix, or glossary do NOT
   satisfy the requirement.
3. ``_extract_accepted_cyber_framework_compliance_rows`` captures the
   verbatim row for the matching framework key.
4. ``_capture_…`` round-trips through ctx and ``_restore_…`` splices the
   preserved row back into a vision text that had been stripped of its
   compliance row, restoring detector pass.

Strictly Cyber-scoped. No deterministic rows are injected; validators
are not weakened.

Run::

    python -m pytest \\
        tests/test_cyber_framework_compliance_objective_preservation_prcy20.py -q
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_fw_compliance_prcy20_')
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
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported in this env')
        return fn(self, *a, **kw)
    return _wrapped


def _vision_with_row(extra_row):
    """Build a minimal vision section whose Strategic Objectives table
    contains a single row supplied by the caller."""
    return (
        '## Vision & Strategic Objectives\n'
        '\n'
        'Vision narrative placeholder.\n'
        '\n'
        '### Strategic Objectives\n'
        '\n'
        '| # | Objective | Target | Justification | Owner |\n'
        '|---|---|---|---|---|\n'
        + extra_row + '\n'
    )


class TestCyberFwComplianceAliasesEcc(unittest.TestCase):

    @_skip_if_no_app
    def test_ecc_english_short_alias(self):
        row = (
            '| 1 | Achieve compliance with NCA ECC across critical '
            'systems | 100% compliance by FY3 | Aligns with national '
            'cybersecurity mandate | CISO |'
        )
        sections = {'vision': _vision_with_row(row)}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['ECC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_ecc_essential_cybersecurity_controls_phrase(self):
        row = (
            '| 1 | Achieve compliance with Essential Cybersecurity '
            'Controls | 100% compliance | Mandated by NCA | CISO |'
        )
        sections = {'vision': _vision_with_row(row)}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['ECC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_ecc_arabic_long_phrase(self):
        row = (
            '| 1 | تحقيق الامتثال للضوابط الأساسية للأمن السيبراني '
            '| امتثال 100% | تكليف وطني | CISO |'
        )
        sections = {'vision': _vision_with_row(row)}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['ECC'], domain='Cyber Security', lang='ar')
        self.assertEqual(missing, [])


class TestCyberFwComplianceAliasesDcc(unittest.TestCase):

    @_skip_if_no_app
    def test_dcc_english_short_alias(self):
        row = (
            '| 1 | Achieve compliance with NCA DCC for sensitive data '
            'pipelines | 100% compliance by FY3 | Aligns with national '
            'data cybersecurity mandate | CISO |'
        )
        sections = {'vision': _vision_with_row(row)}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['DCC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_dcc_data_cybersecurity_controls_phrase(self):
        row = (
            '| 1 | Achieve compliance with Data Cybersecurity Controls '
            '| 100% | NCA mandate | CISO |'
        )
        sections = {'vision': _vision_with_row(row)}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['DCC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_dcc_arabic_alias(self):
        row = (
            '| 1 | تحقيق الامتثال لضوابط الأمن السيبراني للبيانات '
            '| امتثال 100% | تكليف وطني | CISO |'
        )
        sections = {'vision': _vision_with_row(row)}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['DCC'], domain='Cyber Security', lang='ar')
        self.assertEqual(missing, [])


class TestValidatorScopedToVisionObjectives(unittest.TestCase):

    @_skip_if_no_app
    def test_mention_in_scope_section_does_not_satisfy(self):
        # The vision text mentions NCA ECC in a narrative paragraph
        # BEFORE the Strategic Objectives table, with no compliance row
        # inside the table. The validator must still flag ECC as
        # missing.
        vision_text = (
            '## Vision & Strategic Objectives\n\n'
            'Scope: this strategy aligns with NCA ECC Essential '
            'Cybersecurity Controls across all systems.\n\n'
            '### Strategic Objectives\n\n'
            '| # | Objective | Target | Justification | Owner |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Strengthen identity and access management | 100% MFA '
            '| Reduce identity risk | CISO |\n'
        )
        sections = {'vision': vision_text}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['ECC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing, ['ECC'])

    @_skip_if_no_app
    def test_mention_in_other_section_does_not_satisfy(self):
        # Mentions in pillars / appendix / traceability / glossary must
        # not satisfy the vision objective requirement. The validator
        # inspects sections['vision'] only.
        vision_text = (
            '## Vision & Strategic Objectives\n\n'
            'Vision narrative placeholder.\n\n'
            '### Strategic Objectives\n\n'
            '| # | Objective | Target | Justification | Owner |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Strengthen identity and access management | 100% MFA '
            '| Reduce identity risk | CISO |\n'
        )
        sections = {
            'vision': vision_text,
            'pillars': 'Compliance with NCA ECC across pillars.',
            'appendices': 'Glossary: NCA ECC = Essential Cybersecurity '
                          'Controls; compliance required.',
            'traceability': '| ECC-1 | compliance with ECC | obj 1 |',
        }
        missing = _APP._compute_missing_compliance_objective(
            sections, ['ECC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing, ['ECC'])


class TestCyberFwComplianceExtractAndCapture(unittest.TestCase):

    @_skip_if_no_app
    def test_extract_returns_verbatim_row(self):
        row = (
            '| 2 | Achieve compliance with NCA ECC across critical '
            'systems | 100% compliance | National mandate | CISO |'
        )
        vision_text = _vision_with_row(
            '| 1 | Strengthen IAM | 100% MFA | Reduce risk | CISO |\n'
            + row)
        captured = (
            _APP._extract_accepted_cyber_framework_compliance_rows(
                vision_text, ['ECC'], domain='Cyber Security', lang='en'))
        self.assertIn('ECC', captured)
        self.assertIn('NCA ECC', captured['ECC'])

    @_skip_if_no_app
    def test_extract_empty_when_no_qualifying_row(self):
        vision_text = _vision_with_row(
            '| 1 | Strengthen IAM | 100% MFA | Reduce risk | CISO |')
        captured = (
            _APP._extract_accepted_cyber_framework_compliance_rows(
                vision_text, ['ECC'], domain='Cyber Security', lang='en'))
        self.assertEqual(captured, {})

    @_skip_if_no_app
    def test_capture_then_restore_round_trip(self):
        row = (
            '| 2 | Achieve compliance with NCA ECC across critical '
            'systems | 100% compliance | National mandate | CISO |'
        )
        original_vision = _vision_with_row(
            '| 1 | Strengthen IAM | 100% MFA | Reduce risk | CISO |\n'
            + row)
        sections = {'vision': original_vision}
        ctx = {}
        _APP._capture_cyber_preserved_framework_compliance_rows(
            sections, ctx, 'en', 'Cyber Security', ['ECC'])
        preserved = ctx.get(
            '_cyber_preserved_framework_compliance_rows') or {}
        self.assertIn('ECC', preserved)
        # Simulate a regressive rebuild that drops the compliance row
        stripped_vision = _vision_with_row(
            '| 1 | Strengthen IAM | 100% MFA | Reduce risk | CISO |')
        sections['vision'] = stripped_vision
        missing_before = _APP._compute_missing_compliance_objective(
            sections, ['ECC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing_before, ['ECC'])
        restored = (
            _APP._restore_cyber_preserved_framework_compliance_rows(
                sections, ctx, 'en', 'Cyber Security', ['ECC']))
        self.assertTrue(restored)
        missing_after = _APP._compute_missing_compliance_objective(
            sections, ['ECC'], domain='Cyber Security', lang='en')
        self.assertEqual(missing_after, [])

    @_skip_if_no_app
    def test_restore_noop_when_no_preserved_rows(self):
        sections = {'vision': _vision_with_row(
            '| 1 | Strengthen IAM | 100% MFA | Reduce risk | CISO |')}
        ctx = {}
        restored = (
            _APP._restore_cyber_preserved_framework_compliance_rows(
                sections, ctx, 'en', 'Cyber Security', ['ECC']))
        self.assertFalse(restored)

    @_skip_if_no_app
    def test_restore_skipped_when_domain_not_cyber(self):
        # The restore helper is strictly scoped to domain=='cyber' so
        # non-Cyber strategies are never touched by this preservation
        # pipeline.
        row = (
            '| 2 | Achieve compliance with NCA ECC | 100% | mandate '
            '| CISO |')
        sections = {'vision': _vision_with_row(row)}
        ctx = {
            '_cyber_preserved_framework_compliance_rows': {'ECC': row},
        }
        # Strip the row from the live vision so a restore is
        # technically possible from ctx, but the helper must refuse
        # because domain != 'cyber'.
        sections['vision'] = _vision_with_row(
            '| 1 | Strengthen IAM | 100% MFA | Reduce risk | CISO |')
        restored = (
            _APP._restore_cyber_preserved_framework_compliance_rows(
                sections, ctx, 'en', 'data', ['ECC']))
        self.assertFalse(restored)


class TestSourceWiringMarkers(unittest.TestCase):
    """Source-level wiring checks — confirm the PR-CY20 helpers, the
    capture/restore wiring, and the FW-COMPLIANCE-OBJECTIVE-REPAIR
    final-gate restore are present and reachable in ``app.py`` without
    requiring a live AI provider in this sandbox."""

    @_skip_if_no_app
    def test_helpers_defined(self):
        for name in (
            '_extract_accepted_cyber_framework_compliance_rows',
            '_capture_cyber_preserved_framework_compliance_rows',
            '_restore_cyber_preserved_framework_compliance_rows',
            '_emit_cyber_framework_compliance_persistence',
            '_convergence_cyber_framework_compliance_objective_topup_repair',
        ):
            self.assertTrue(
                hasattr(_APP, name),
                f'missing helper: {name}')

    @_skip_if_no_app
    def test_source_wiring_markers(self):
        src_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(src_path, 'r', encoding='utf-8') as fh:
            src = fh.read()
        # Capture-at-start wiring
        self.assertIn(
            '_capture_cyber_preserved_framework_compliance_rows(',
            src)
        # Targeted top-up branch precedes the generic objectives
        # rebuild and the existing PR-CY18 specialized branch.
        self.assertIn(
            '_convergence_cyber_framework_compliance_objective_topup_repair(',
            src)
        # Final-gate restore inside the FW-COMPLIANCE-OBJECTIVE-REPAIR
        # pass.
        marker_start = src.find('[FW-COMPLIANCE-OBJECTIVE-REPAIR]')
        self.assertGreater(marker_start, 0)
        self.assertIn(
            '_restore_cyber_preserved_framework_compliance_rows(',
            src[marker_start:])


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
