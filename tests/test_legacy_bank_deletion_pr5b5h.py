"""PR-5B.5H: Deletion of the four quarantined deterministic SO/KPI bank
helpers and the ``_LEGACY_DETERMINISTIC_BANKS_ENABLED`` flag.

PR-5B.5F4 (quarantine) made the four legacy helpers raise ``RuntimeError``
when called and proved zero production callsites via AST.  PR-5B.5G's
post-migration end-to-end suite re-pinned those guarantees across all six
strategy domains × three migrated synth helpers.  PR-5B.5H now physically
removes:

    * ``_build_domain_so_bank_ar``
    * ``_build_domain_so_bank_en``
    * ``_build_domain_kpi_bank_ar``
    * ``_build_domain_kpi_bank_en``
    * ``_LEGACY_DETERMINISTIC_BANKS_ENABLED`` (flag — sole references were
      inside the four helpers' fail-fast guards)

This file replaces ``tests/test_legacy_bank_quarantine_pr5b5f4.py``
(deleted in this same PR; its direct-call quarantine assertions can no
longer hold once the helpers are gone).  It pins down:

  1. The four helper names are absent from the ``app`` module.
  2. The flag is absent from the ``app`` module.
  3. AST scan of ``app.py`` finds zero ``Call`` nodes whose callee name
     matches any of the four helpers (no production callsite, no
     test-only callsite within app).
  4. AST scan finds no ``FunctionDef`` whose name matches any of the
     four helpers (definitions are physically removed).
  5. The PR-5B.5F2 / PR-5B.5F3 / PR-5B.5G negative-assertion test
     modules remain importable.

Run:  python -m pytest tests/test_legacy_bank_deletion_pr5b5h.py -q
"""

import ast
import importlib
import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///tmp/test_legacy_bank_deletion_pr5b5h.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')

_DELETED_HELPERS = (
    '_build_domain_so_bank_ar',
    '_build_domain_so_bank_en',
    '_build_domain_kpi_bank_ar',
    '_build_domain_kpi_bank_en',
)

_DELETED_FLAG = '_LEGACY_DETERMINISTIC_BANKS_ENABLED'

_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


class TestDeletedSymbolsAbsentFromAppModule(unittest.TestCase):
    """The four helper names and the quarantine flag must be absent from
    the imported ``app`` module after PR-5B.5H."""

    def test_helper_symbols_absent(self):
        for name in _DELETED_HELPERS:
            self.assertFalse(
                hasattr(_APP, name),
                f'PR-5B.5H: legacy bank helper {name!r} should be deleted '
                'from app.py but is still present as a module attribute.')

    def test_helper_symbols_not_callable(self):
        for name in _DELETED_HELPERS:
            attr = getattr(_APP, name, None)
            self.assertIsNone(
                attr,
                f'PR-5B.5H: legacy bank helper {name!r} should not be '
                'callable after deletion.')

    def test_quarantine_flag_absent(self):
        self.assertFalse(
            hasattr(_APP, _DELETED_FLAG),
            f'PR-5B.5H: quarantine flag {_DELETED_FLAG!r} should be '
            'removed once the four helpers are deleted.')


class _CallAndDefVisitor(ast.NodeVisitor):
    """Collects every ``ast.Call`` whose callee resolves (by simple name
    or attribute name) to one of the deleted helpers, *and* every
    ``ast.FunctionDef`` whose name matches one of the deleted helpers."""

    def __init__(self, targets):
        self.targets = set(targets)
        self.calls = []  # list of (name, lineno)
        self.defs = []   # list of (name, lineno)

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

    def visit_FunctionDef(self, node):
        if node.name in self.targets:
            self.defs.append((node.name, node.lineno))
        self.generic_visit(node)


class TestStaticDeletionGuard(unittest.TestCase):
    """AST-walk ``app.py`` and prove that no definition or call site
    referencing the four deleted helpers remains in the source."""

    def setUp(self):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as fh:
            self.tree = ast.parse(fh.read(), filename=_APP_PY_PATH)

    def test_no_function_definitions(self):
        v = _CallAndDefVisitor(_DELETED_HELPERS)
        v.visit(self.tree)
        if v.defs:
            details = '\n'.join(
                f'  - def {n} at app.py:{l}' for n, l in v.defs)
            self.fail(
                'PR-5B.5H: legacy bank helper definition(s) still '
                'present in app.py:\n' + details)

    def test_no_call_sites(self):
        v = _CallAndDefVisitor(_DELETED_HELPERS)
        v.visit(self.tree)
        if v.calls:
            details = '\n'.join(
                f'  - {n} called at app.py:{l}' for n, l in v.calls)
            self.fail(
                'PR-5B.5H: legacy bank helper(s) still invoked in '
                'app.py:\n' + details)

    def test_quarantine_flag_assignment_absent(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == _DELETED_FLAG:
                        self.fail(
                            f'PR-5B.5H: assignment to {_DELETED_FLAG!r} '
                            f'still present at app.py:{node.lineno}')


class TestPriorNegativeAssertionTestsCollectible(unittest.TestCase):
    """The PR-5B.5F2 / PR-5B.5F3 / PR-5B.5G negative-assertion test
    modules must remain importable; their assertions (that production
    never references the legacy helper names) are *strengthened*, not
    invalidated, by the deletion."""

    def test_pr5b5f2_test_module_importable(self):
        mod = importlib.import_module(
            'tests.test_strategy_technical_depth_ai_first_pr5b5f2')
        self.assertIsNotNone(mod)

    def test_pr5b5f3_test_module_importable(self):
        mod = importlib.import_module(
            'tests.test_strategy_repair_ai_first_pr5b5f3')
        self.assertIsNotNone(mod)

    def test_pr5b5g_test_module_importable(self):
        mod = importlib.import_module(
            'tests.test_post_migration_e2e_pr5b5g')
        self.assertIsNotNone(mod)


if __name__ == '__main__':
    unittest.main()
