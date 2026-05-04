"""PR-5B.5F4: Quarantine of legacy deterministic SO/KPI bank helpers.

The four module-level helpers below (``_build_domain_so_bank_ar``,
``_build_domain_so_bank_en``, ``_build_domain_kpi_bank_ar``,
``_build_domain_kpi_bank_en``) were fully decoupled from production code by
PR-5B.5F2 (``enforce_technical_strategy_depth`` SO/KPI branches) and
PR-5B.5F3 (``repair_vision_objectives_if_insufficient`` /
``repair_kpi_section_if_missing_frequency``).

This test file pins down the quarantine contract added in PR-5B.5F4:

  1. Each of the four helpers raises ``RuntimeError`` (with the substring
     ``"quarantined"``) when invoked with the ``_LEGACY_DETERMINISTIC_BANKS_ENABLED``
     module-level flag at its default ``False`` value.
  2. A static (AST-based) guard proves that *no* production callsite in
     ``app.py`` invokes any of the four helpers, regardless of the flag.
  3. The PR-5B.5F2 / PR-5B.5F3 negative-assertion test files remain
     importable and collectable by pytest (their assertions still hold —
     they monkey-patch the helpers as spies and never invoke them, which
     is precisely what the quarantine guarantees).

Run:  python -m pytest tests/test_legacy_bank_quarantine_pr5b5f4.py -q
"""

import ast
import importlib
import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# Mirrors the env setup in tests/test_strategy_repair_ai_first_pr5b5f3.py.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///tmp/test_legacy_bank_quarantine_pr5b5f4.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')

_QUARANTINED_HELPERS = (
    '_build_domain_so_bank_ar',
    '_build_domain_so_bank_en',
    '_build_domain_kpi_bank_ar',
    '_build_domain_kpi_bank_en',
)

_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


class TestQuarantineFlagDefault(unittest.TestCase):
    """The module-level flag must default to False after PR-5B.5F4."""

    def test_flag_present_and_false(self):
        self.assertTrue(hasattr(_APP, '_LEGACY_DETERMINISTIC_BANKS_ENABLED'),
                        'Quarantine flag _LEGACY_DETERMINISTIC_BANKS_ENABLED '
                        'is missing from app.py (PR-5B.5F4).')
        self.assertIs(_APP._LEGACY_DETERMINISTIC_BANKS_ENABLED, False,
                      'Quarantine flag must default to False.')


class TestQuarantineGuards(unittest.TestCase):
    """Each of the four helpers must raise RuntimeError("...quarantined...")."""

    def test_1_so_bank_ar_raises_runtime_error(self):
        with self.assertRaises(RuntimeError) as cm:
            _APP._build_domain_so_bank_ar('Cyber Security', 'NCA ECC', 'Public')
        msg = str(cm.exception)
        self.assertIn('quarantined', msg)
        self.assertIn('_build_domain_so_bank_ar', msg)
        self.assertIn('synthesize_objectives_depth', msg)

    def test_2_so_bank_en_raises_runtime_error(self):
        with self.assertRaises(RuntimeError) as cm:
            _APP._build_domain_so_bank_en('Cyber Security', 'NCA ECC', 'Public')
        msg = str(cm.exception)
        self.assertIn('quarantined', msg)
        self.assertIn('_build_domain_so_bank_en', msg)
        self.assertIn('synthesize_objectives_depth', msg)

    def test_3_kpi_bank_ar_raises_runtime_error(self):
        with self.assertRaises(RuntimeError) as cm:
            _APP._build_domain_kpi_bank_ar('Cyber Security', 'NCA ECC')
        msg = str(cm.exception)
        self.assertIn('quarantined', msg)
        self.assertIn('_build_domain_kpi_bank_ar', msg)
        self.assertIn('synthesize_kpi_depth', msg)

    def test_4_kpi_bank_en_raises_runtime_error(self):
        with self.assertRaises(RuntimeError) as cm:
            _APP._build_domain_kpi_bank_en('Cyber Security', 'NCA ECC')
        msg = str(cm.exception)
        self.assertIn('quarantined', msg)
        self.assertIn('_build_domain_kpi_bank_en', msg)
        self.assertIn('synthesize_kpi_depth', msg)


class _CallSiteVisitor(ast.NodeVisitor):
    """Collects the line numbers of every Call node whose callee resolves
    (by simple name or attribute name) to one of the quarantined helpers."""

    def __init__(self, targets):
        self.targets = set(targets)
        self.calls = []  # list of (callee_name, lineno)

    def visit_Call(self, node):
        callee = None
        f = node.func
        if isinstance(f, ast.Name):
            callee = f.id
        elif isinstance(f, ast.Attribute):
            callee = f.attr
        if callee in self.targets:
            self.calls.append((callee, node.lineno))
        self.generic_visit(node)


class TestStaticZeroProductionCallsites(unittest.TestCase):
    """AST-walk app.py and prove that none of the four quarantined helpers
    are invoked from production code (i.e., zero ``Call`` nodes whose callee
    name matches any of the four helpers, anywhere in the module)."""

    def test_zero_production_call_sites(self):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), filename=_APP_PY_PATH)
        visitor = _CallSiteVisitor(_QUARANTINED_HELPERS)
        visitor.visit(tree)
        if visitor.calls:
            details = '\n'.join(
                f'  - {name} called at app.py:{lineno}'
                for name, lineno in visitor.calls)
            self.fail(
                'PR-5B.5F4: quarantined deterministic bank helper(s) are '
                'still invoked from production code:\n' + details)

    def test_helpers_are_defined(self):
        """Sanity: the four helpers still exist as module-level callables
        (Option A preserves bodies; Option B / deletion is deferred to
        PR-5B.5F5)."""
        for name in _QUARANTINED_HELPERS:
            self.assertTrue(hasattr(_APP, name),
                            f'Helper {name} should still be defined '
                            '(PR-5B.5F4 quarantine, not deletion).')
            self.assertTrue(callable(getattr(_APP, name)),
                            f'Helper {name} should be callable.')


class TestPriorNegativeAssertionTestsCollectible(unittest.TestCase):
    """The PR-5B.5F2 / PR-5B.5F3 negative-assertion test modules must remain
    importable; their assertions (that production never calls these helpers)
    are *strengthened* — not invalidated — by the quarantine guards."""

    def test_pr5b5f2_test_module_importable(self):
        mod = importlib.import_module(
            'tests.test_strategy_technical_depth_ai_first_pr5b5f2')
        self.assertIsNotNone(mod)

    def test_pr5b5f3_test_module_importable(self):
        mod = importlib.import_module(
            'tests.test_strategy_repair_ai_first_pr5b5f3')
        self.assertIsNotNone(mod)


if __name__ == '__main__':
    unittest.main()
