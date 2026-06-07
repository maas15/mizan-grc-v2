"""PR-REL2.2 — strategic objectives canonical row model smoke."""

import importlib.util
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel22_so_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


class Rel22SOCanonicalModelTests(unittest.TestCase):

    def test_shifted_so_rows_canonicalized(self):
        from cyber_post_board_ready_prcy89 import (
            _repair_shifted_strategic_objectives,
        )
        vision = (
            '## 1. الرؤية\n\n'
            '| # | الهدف | المستهدف | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | | هدف منزاح | 100% | 6 أشهر |\n'
        )
        sections = {'vision': vision}
        out, shifted = _repair_shifted_strategic_objectives(
            _APP, sections, 'ar')
        self.assertEqual(shifted, 0)
        self.assertIn('هدف', out.get('vision', ''))


if __name__ == '__main__':
    unittest.main()
