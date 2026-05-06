"""Regression test: `_model_sector` must be assigned before first use
inside `api_generate_strategy` to avoid UnboundLocalError reaching the
end-user (observed runtime error: "cannot access local variable
'_model_sector' where it is not associated with a value").

Static AST-level check — does not exercise the route, does not call the
AI provider, and does not require a live DB. Verifies that the very
first textual use of `_model_sector` inside the function body is
preceded by an unconditional `_model_sector = ...` assignment that lives
at the function's top-level (not nested inside an `if`/`else` branch).
"""

import ast
import os
import unittest


class ModelSectorInitGuard(unittest.TestCase):
    def setUp(self):
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path, 'r', encoding='utf-8') as f:
            src = f.read()
        self.tree = ast.parse(src)

    def _find_func(self, name):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return node
        return None

    def test_model_sector_initialized_before_first_use(self):
        fn = self._find_func('api_generate_strategy')
        self.assertIsNotNone(
            fn, 'api_generate_strategy not found in app.py')

        # Walk the function body in source order. Track the first
        # top-level (non-nested under conditional) assignment to
        # `_model_sector`, and the first appearance of `_model_sector`
        # as a Load (read) anywhere in the body.
        first_top_level_assign_line = None
        first_use_line = None

        # Collect top-level assignments (direct children of fn, possibly
        # inside `try:` since the handler wraps its body in try/except —
        # the assignment we hoisted lives inside the top-level try).
        def iter_top_level_stmts(body):
            for stmt in body:
                yield stmt
                if isinstance(stmt, ast.Try):
                    for s in stmt.body:
                        yield s

        for stmt in iter_top_level_stmts(fn.body):
            if isinstance(stmt, ast.Assign):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == '_model_sector':
                        if first_top_level_assign_line is None:
                            first_top_level_assign_line = stmt.lineno

        # First Load anywhere in the function body
        for node in ast.walk(fn):
            if (isinstance(node, ast.Name)
                    and node.id == '_model_sector'
                    and isinstance(node.ctx, ast.Load)):
                if first_use_line is None or node.lineno < first_use_line:
                    first_use_line = node.lineno

        self.assertIsNotNone(
            first_top_level_assign_line,
            '_model_sector is never assigned at the top level of '
            'api_generate_strategy — this will raise UnboundLocalError '
            'when any conditional branch reads it before assigning.')
        self.assertIsNotNone(
            first_use_line,
            '_model_sector is never read in api_generate_strategy — '
            'expected at least one downstream prompt reference.')
        self.assertLess(
            first_top_level_assign_line, first_use_line,
            'Top-level assignment of _model_sector (line '
            f'{first_top_level_assign_line}) must occur BEFORE its '
            f'first read (line {first_use_line}) in api_generate_strategy '
            'to prevent the runtime UnboundLocalError reported by users.')


if __name__ == '__main__':
    unittest.main()
