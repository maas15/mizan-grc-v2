"""PR-5B.5A — AI-first contract for synthesize_objectives_depth.

Asserts that synthesize_objectives_depth no longer relies on
deterministic cyber-default priority banks or top-up rows: it either
leaves a sufficient vision section unchanged, or it delegates to
ai_repair_strategy_section(section_key='vision', ...). On AI failure
or invalid AI output the function raises RepairError (no silent
fallback).

Run:  python -m pytest tests/test_synthesize_objectives_ai_first_pr5b5a.py -v
"""
import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL',
                      'sqlite:///tmp/test_synth_obj_pr5b5a.db')
# Ensure no AI provider is configured, so any unmocked AI call raises.
os.environ['OPENAI_API_KEY']    = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY']    = ''
os.environ['GROQ_API_KEY']      = ''
os.environ['DEEPSEEK_API_KEY']  = ''

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
except Exception:
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *args, **kwargs)
    return wrapper


# A canonical valid Strategic Objectives section (5 rows, all cells
# substantive, all timeframes parseable by count_valid_objective_rows).
_VALID_VISION_EN = (
    "## 1. Vision & Strategic Objectives\n\n"
    "**Vision**: Build a resilient cybersecurity posture for the org.\n\n"
    "### Strategic Objectives\n\n"
    "| # | Objective | Target Metric | Justification | Timeframe |\n"
    "|---|-----------|---------------|---------------|-----------|\n"
    "| 1 | Establish governance committee | Approved charter | "
    "Closes structural gap | Within 6 months |\n"
    "| 2 | Raise awareness pass rate | >= 90% | Closes awareness gap | "
    "Within 9 months |\n"
    "| 3 | Operationalise incident response | Approved IR runbook | "
    "Closes IR capability gap | Within 12 months |\n"
    "| 4 | Implement control baseline | 100% high-priority controls | "
    "Closes maturity gap | Within 12 months |\n"
    "| 5 | Activate third-party risk programme | "
    "100% critical suppliers | Closes supply-chain gap | "
    "Within 12 months |\n"
)

# A repaired vision returned by an AI mock — meets the canonical
# 5-column / >= floor-row schema and contains the expected heading.
_REPAIRED_VISION_EN = (
    "## 1. Vision & Strategic Objectives\n\n"
    "**Vision**: AI-repaired vision narrative.\n\n"
    "| # | Objective | Target Metric | Justification | Timeframe |\n"
    "|---|-----------|---------------|---------------|-----------|\n"
    "| 1 | AI-repaired objective one | KPI alpha | Rationale alpha | "
    "Within 6 months |\n"
    "| 2 | AI-repaired objective two | KPI beta | Rationale beta | "
    "Within 9 months |\n"
    "| 3 | AI-repaired objective three | KPI gamma | Rationale gamma | "
    "Within 12 months |\n"
    "| 4 | AI-repaired objective four | KPI delta | Rationale delta | "
    "Within 12 months |\n"
    "| 5 | AI-repaired objective five | KPI epsilon | Rationale epsilon "
    "| Within 18 months |\n"
)


class TestSynthesizeObjectivesAIFirstPR5B5A(unittest.TestCase):
    @_skip_if_no_app
    def test_valid_objectives_remain_unchanged_no_ai_call(self):
        """Sufficient SO rows ⇒ early return, no AI call, no rebuild."""
        sections = {'vision': _VALID_VISION_EN}
        before = sections['vision']
        with patch.object(_APP, 'ai_repair_strategy_section') as mock_ai:
            result = _APP.synthesize_objectives_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertFalse(result.get('rebuilt'),
                         'rebuilt must be False for sufficient vision')
        self.assertGreaterEqual(result.get('preserved', 0),
                                _APP._RICHNESS_MIN_SO_ROWS)
        self.assertEqual(sections['vision'], before,
                         'vision must be unchanged when sufficient')
        mock_ai.assert_not_called()

    @_skip_if_no_app
    def test_insufficient_objectives_calls_ai_with_section_key_vision(self):
        """Insufficient SO rows ⇒ AI repair invoked with
        section_key='vision' (NOT 'objectives')."""
        sections = {'vision': '## 1. Vision\n\nNo objectives table.\n'}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_VISION_EN) as mock_ai:
            result = _APP.synthesize_objectives_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertTrue(mock_ai.called)
        kwargs = mock_ai.call_args.kwargs
        self.assertEqual(kwargs.get('section_key'), 'vision',
                         'must use section_key="vision"')
        self.assertNotEqual(kwargs.get('section_key'), 'objectives')
        self.assertTrue(result.get('rebuilt'))
        self.assertGreaterEqual(result.get('total_after', 0),
                                _APP._RICHNESS_MIN_SO_ROWS)

    @_skip_if_no_app
    def test_repaired_vision_replaces_sections_vision(self):
        """AI-repaired markdown is written into sections['vision']
        verbatim — old malformed content is NOT merged in."""
        old_bad = ('## 1. Vision\n\n'
                   '| # | Objective | Target | Just | TF |\n'
                   '|---|---|---|---|---|\n'
                   '| 1 | TBD | — | — | — |\n')
        sections = {'vision': old_bad}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_VISION_EN):
            _APP.synthesize_objectives_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertEqual(sections['vision'], _REPAIRED_VISION_EN)
        # Old TBD/placeholder rows must not survive.
        self.assertNotIn('TBD', sections['vision'])

    @_skip_if_no_app
    def test_domain_so_banks_are_not_called(self):
        """_build_domain_so_bank_ar/_en must not be invoked from
        synthesize_objectives_depth (deterministic banks are removed)."""
        sections = {'vision': '## 1. Vision\n\nemtpy\n'}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_VISION_EN), \
             patch.object(_APP, '_build_domain_so_bank_ar') as mock_ar, \
             patch.object(_APP, '_build_domain_so_bank_en') as mock_en:
            _APP.synthesize_objectives_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
            _APP.synthesize_objectives_depth(
                {'vision': ''}, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        mock_ar.assert_not_called()
        mock_en.assert_not_called()

    @_skip_if_no_app
    def test_ai_failure_raises_repair_error(self):
        """When ai_repair_strategy_section raises RepairError, the
        synth function must propagate (not swallow + insert defaults)."""
        sections = {'vision': ''}
        def _fail(**_kw):
            raise _APP.RepairError('ai unavailable')
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_fail):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_objectives_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        # Section must remain untouched — no deterministic fallback.
        self.assertEqual(sections['vision'], '')

    @_skip_if_no_app
    def test_invalid_ai_repaired_vision_is_rejected(self):
        """If the AI returns a vision with too few valid SO rows, the
        synth function rejects it with RepairError and does NOT write
        the bad content into sections['vision']."""
        bad_repair = ("## 1. Vision\n\n**Vision**: too short.\n\n"
                      "| # | Objective | Target | Just | TF |\n"
                      "|---|---|---|---|---|\n"
                      "| 1 | only one row | x | y | Within 1 month |\n")
        sections = {'vision': 'original'}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=bad_repair):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_objectives_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(sections['vision'], 'original')


if __name__ == '__main__':
    unittest.main()
