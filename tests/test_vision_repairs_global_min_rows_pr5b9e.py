"""PR-5B.9E — Vision repair paths must preserve the existing valid SO row
count and never overwrite a >=6-row vision with a thinner output.

Pins:
  * ``synthesize_objectives_depth`` short-circuits when current rows
    already meet the effective minimum (no AI repair fires).
  * When AI repair does fire, ``synthesize_objectives_depth`` rejects an
    AI output with fewer than ``eff_min`` valid SO rows (RepairError
    with section='vision').
  * The framework-compliance vision repair path computes the row floor
    as ``max(consulting_floor, current_valid_rows)`` so an existing
    6-row vision cannot be replaced with a 4-row vision.

Run:
    python -m pytest tests/test_vision_repairs_global_min_rows_pr5b9e.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_vision_repair_pr5b9e_')
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


def _vision_with_n_rows(n):
    """Build a Vision section with exactly ``n`` valid Strategic
    Objective rows that the canonical row counter recognises."""
    rows = []
    for i in range(1, n + 1):
        rows.append(
            f'| {i} | تطوير القدرة الاستراتيجية رقم {i} '
            '| 100% | تعزيز القدرة المؤسسية وتحقيق الأهداف '
            f'الاستراتيجية رقم {i} | 12 شهراً |'
        )
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'الرؤية: تعزيز القدرات الاستراتيجية للمنظمة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        + '\n'.join(rows) + '\n'
    )


class VisionRowFloorPreservationTests(unittest.TestCase):

    @_skip_if_no_app
    def test_six_rows_short_circuits_no_ai_call(self):
        # A vision section with 6 rows and consulting mode must NOT
        # trigger the AI repair code path — the function returns
        # without calling ai_repair_strategy_section.
        sections = {'vision': _vision_with_n_rows(6)}
        called = {'count': 0}
        original = _APP.ai_repair_strategy_section

        def _spy(*a, **kw):  # pragma: no cover - should not be called
            called['count'] += 1
            return original(*a, **kw)

        _APP.ai_repair_strategy_section = _spy
        try:
            summary = _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='ECC',
                generation_mode='consulting',
            )
        finally:
            _APP.ai_repair_strategy_section = original

        self.assertEqual(called['count'], 0)
        self.assertFalse(summary.get('rebuilt'))
        # Section preserved verbatim (no replacement).
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(sections['vision']), 6,
        )

    @_skip_if_no_app
    def test_ai_repair_rejected_when_returning_four_rows(self):
        # Stub the AI repair to return a 4-row vision; the depth
        # synthesizer must raise RepairError because the consulting
        # min is 6.
        sections = {'vision': _vision_with_n_rows(2)}  # below floor
        original = _APP.ai_repair_strategy_section

        def _stub(*a, **kw):
            return _vision_with_n_rows(4)

        _APP.ai_repair_strategy_section = _stub
        try:
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_objectives_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='ECC',
                    generation_mode='consulting',
                )
            err = ctx.exception
            self.assertEqual(getattr(err, 'section', None), 'vision')
            # The original 2-row vision is preserved on failure (the
            # synthesizer never assigns sections['vision'] when the
            # repaired output is rejected).
            self.assertEqual(
                _APP.count_valid_objective_rows(sections['vision']), 2,
            )
        finally:
            _APP.ai_repair_strategy_section = original

    @_skip_if_no_app
    def test_ai_repair_accepted_when_returning_six_rows(self):
        sections = {'vision': _vision_with_n_rows(2)}
        repaired_text = _vision_with_n_rows(6)
        original = _APP.ai_repair_strategy_section

        def _stub(*a, **kw):
            return repaired_text

        _APP.ai_repair_strategy_section = _stub
        try:
            summary = _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='ECC',
                generation_mode='consulting',
            )
        finally:
            _APP.ai_repair_strategy_section = original

        self.assertTrue(summary.get('rebuilt'))
        self.assertGreaterEqual(summary.get('total_after', 0), 6)

    @_skip_if_no_app
    def test_min_rows_param_cannot_weaken_global_floor(self):
        # Even when min_rows=2 is passed, the synthesizer must
        # internally bump it to _RICHNESS_MIN_SO_ROWS or higher.
        sections = {'vision': _vision_with_n_rows(2)}
        original = _APP.ai_repair_strategy_section
        captured = {}

        def _stub(section_key, sections, lang, domain_context, **kwargs):
            captured['min_rows'] = kwargs.get('min_rows')
            return _vision_with_n_rows(_APP._RICHNESS_MIN_SO_ROWS)

        _APP.ai_repair_strategy_section = _stub
        try:
            _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='ECC',
                generation_mode='drafting',
                min_rows=2,
            )
        finally:
            _APP.ai_repair_strategy_section = original

        self.assertGreaterEqual(
            captured.get('min_rows', 0), _APP._RICHNESS_MIN_SO_ROWS,
        )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
