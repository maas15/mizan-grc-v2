"""PR-5B.6E — AI-first contract for synthesize_gaps_depth.

Asserts that synthesize_gaps_depth no longer relies on deterministic
gap banks, structural-row injection, challenge-flag-driven rows,
diagnostic-gap deterministic rows, or guide-step bank templates. It
either leaves a sufficient gaps section unchanged (returning
{'rebuilt': False, ...}) or delegates to ai_repair_strategy_section
(section_key='gaps', ...). On AI failure or invalid AI output the
function raises RepairError with err.section == 'gaps' and leaves
sections['gaps'] unchanged.

Run:  python -m pytest tests/test_synthesize_gaps_ai_first_pr5b6e.py -v
"""
import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL',
                      'sqlite:///tmp/test_synth_gaps_pr5b6e.db')
# No AI provider configured — unmocked AI calls raise.
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


# Helper: build an AI-repaired English gaps section that satisfies the
# floor (>= 5 rows in consulting/no-structure mode) and 1:1 guides.
def _make_repaired_gaps_en(n=5):
    rows = "\n".join(
        f"| {i} | AI-gap-{i} | AI-described gap {i} | High | Open |"
        for i in range(1, n + 1)
    )
    guides = "\n".join(
        (
            f"#### Gap #{i} Implementation Guide: AI-gap-{i}\n\n"
            f"**Context:** AI-described gap {i}.\n"
            f"**Priority:** High\n\n"
            "| Step | Action | Owner | Timeline | Output |\n"
            "|------|--------|-------|----------|--------|\n"
            f"| 1 | Action 1 for AI-gap-{i} | Owner | Month 1 | Output 1 |\n"
            f"| 2 | Action 2 for AI-gap-{i} | Owner | Month 2 | Output 2 |\n"
            f"| 3 | Action 3 for AI-gap-{i} | Owner | Month 3 | Output 3 |\n"
            f"| 4 | Action 4 for AI-gap-{i} | Owner | Month 4 | Output 4 |\n"
        )
        for i in range(1, n + 1)
    )
    return (
        "## 4. Gap Analysis\n\n"
        "| # | Gap | Description | Priority | Status |\n"
        "|---|-----|-------------|----------|--------|\n"
        f"{rows}\n\n"
        "### Gap Implementation Guidance\n\n"
        f"{guides}\n"
    )


# Sufficient gaps section: 5 rows + 1:1 guide coverage.
_VALID_GAPS_EN = _make_repaired_gaps_en(5)

# Repaired (mock AI return) gaps section.
_REPAIRED_GAPS_EN = _make_repaired_gaps_en(5)

# Malformed: header present but only 1 row, no guides.
_MALFORMED_GAPS_EN = (
    "## 4. Gap Analysis\n\n"
    "| # | Gap | Description | Priority | Status |\n"
    "|---|-----|-------------|----------|--------|\n"
    "| 1 | OLD-MALFORMED-GAP | needs work | High | Open |\n"
)


class TestSynthesizeGapsAIFirstPR5B6E(unittest.TestCase):
    @_skip_if_no_app
    def test_valid_gaps_unchanged_returns_no_rebuild_no_ai_call(self):
        """1. Sufficient gaps section is left untouched and AI is not invoked."""
        sections = {'gaps': _VALID_GAPS_EN}
        before = sections['gaps']
        with patch.object(_APP, 'ai_repair_strategy_section') as mock_ai:
            result = _APP.synthesize_gaps_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get('rebuilt'))
        self.assertEqual(sections['gaps'], before)
        mock_ai.assert_not_called()

    @_skip_if_no_app
    def test_insufficient_gaps_calls_ai_with_section_key_gaps(self):
        """2. Insufficient gaps calls ai_repair_strategy_section with
        section_key='gaps'."""
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_GAPS_EN) as mock_ai:
            result = _APP.synthesize_gaps_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertTrue(mock_ai.called)
        kwargs = mock_ai.call_args.kwargs
        self.assertEqual(kwargs.get('section_key'), 'gaps',
                         'must use section_key="gaps"')
        self.assertTrue(result.get('rebuilt'))

    @_skip_if_no_app
    def test_repaired_gaps_replaces_sections_gaps(self):
        """3. AI-repaired output replaces sections['gaps'] verbatim."""
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_GAPS_EN):
            _APP.synthesize_gaps_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertEqual(sections['gaps'], _REPAIRED_GAPS_EN)

    @_skip_if_no_app
    def test_no_deterministic_gap_rows_inserted_on_ai_failure(self):
        """4. No deterministic gap banks, structural rows, challenge
        rows, or guide-step templates injected when AI fails — the
        section must remain unchanged and a RepairError must be raised
        with section='gaps'."""
        sections = {'gaps': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError('no ai')):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'gaps')
        self.assertEqual(sections['gaps'], '')

    @_skip_if_no_app
    def test_old_malformed_gaps_not_merged(self):
        """5. Old malformed rows must not survive when AI repair
        replaces the section."""
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_GAPS_EN):
            _APP.synthesize_gaps_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertNotIn('OLD-MALFORMED-GAP', sections['gaps'])

    @_skip_if_no_app
    def test_ai_failure_raises_repair_error_section_tagged(self):
        """6. AI helper raising RepairError propagates with
        section='gaps' and leaves sections['gaps'] untouched."""
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError('ai down')):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'gaps')
        # Original (malformed) section is untouched.
        self.assertEqual(sections['gaps'], _MALFORMED_GAPS_EN)

    @_skip_if_no_app
    def test_invalid_ai_repaired_gaps_is_rejected(self):
        """7. If the AI returns too few substantive rows or missing
        guide coverage, raise RepairError and do not overwrite
        sections['gaps']."""
        too_thin = (
            "## 4. Gap Analysis\n\n"
            "| # | Gap | Description | Priority | Status |\n"
            "|---|-----|-------------|----------|--------|\n"
            "| 1 | only one gap | desc | High | Open |\n"
        )
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=too_thin):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'gaps')
        self.assertEqual(sections['gaps'], _MALFORMED_GAPS_EN)

    @_skip_if_no_app
    def test_domain_contaminated_ai_output_is_rejected(self):
        """8. ai_repair_strategy_section is the gate that rejects
        domain-contaminated output. From the synth function's
        perspective: if the AI helper raises RepairError because of
        forbidden cross-domain terms, the synth must propagate."""
        sections = {'gaps': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError(
                              'forbidden cross-domain terms in AI output')):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Data Management', fw_short='DAMA-DMBOK',
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'gaps')
        self.assertEqual(sections['gaps'], '')

    @_skip_if_no_app
    def test_no_unrelated_deterministic_bank_helpers_called(self):
        """9. The gaps synth must not invoke any unrelated deterministic
        bank helpers (SO banks, KPI banks) — and the gap-step bank
        templates (_gap_guide_steps_ar/en) must not be called from the
        AI-first repair path."""
        sections_en = {'gaps': ''}
        sections_ar = {'gaps': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_GAPS_EN), \
             patch.object(_APP, '_build_domain_so_bank_en') as so_en, \
             patch.object(_APP, '_build_domain_so_bank_ar') as so_ar, \
             patch.object(_APP, '_build_domain_kpi_bank_en') as kpi_en, \
             patch.object(_APP, '_build_domain_kpi_bank_ar') as kpi_ar, \
             patch.object(_APP, '_gap_guide_steps_en') as gs_en, \
             patch.object(_APP, '_gap_guide_steps_ar') as gs_ar:
            _APP.synthesize_gaps_depth(
                sections_en, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
            # Use AR repaired (re-use EN content for mock; behavior parity).
            _APP.synthesize_gaps_depth(
                sections_ar, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        so_en.assert_not_called()
        so_ar.assert_not_called()
        kpi_en.assert_not_called()
        kpi_ar.assert_not_called()
        gs_en.assert_not_called()
        gs_ar.assert_not_called()

    @_skip_if_no_app
    def test_schema_has_gaps_entry_with_required_placeholders(self):
        """10. _AI_REPAIR_SECTION_SCHEMA['gaps'] exists and exposes
        both {min_rows} and {min_steps_per_guide} placeholders for each
        language."""
        schema = getattr(_APP, '_AI_REPAIR_SECTION_SCHEMA', {})
        self.assertIn('gaps', schema)
        for lang in ('ar', 'en'):
            tmpl = schema['gaps'][lang]
            self.assertIn('{min_rows}', tmpl)
            self.assertIn('{min_steps_per_guide}', tmpl)

    @_skip_if_no_app
    def test_heading_entry_present_for_gaps(self):
        """11. _AI_REPAIR_SECTION_HEADINGS['gaps'] is intact (was
        already present pre-PR — must not be removed)."""
        headings = getattr(_APP, '_AI_REPAIR_SECTION_HEADINGS', {})
        self.assertIn('gaps', headings)
        self.assertIn('ar', headings['gaps'])
        self.assertIn('en', headings['gaps'])


if __name__ == '__main__':
    unittest.main()
