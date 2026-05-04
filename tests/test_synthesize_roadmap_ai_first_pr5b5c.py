"""PR-5B.5C — AI-first contract for synthesize_roadmap_depth.

Asserts that synthesize_roadmap_depth no longer relies on deterministic
priority banks, generic templates, header skeletons, or
diagnostic-gap "Remediate:" / "معالجة:" rows. It either leaves a
sufficient roadmap section unchanged (returning 0) or delegates to
ai_repair_strategy_section(section_key='roadmap', ...). On AI failure
or invalid AI output the function raises RepairError. The final audit
gate (_count_substantive_roadmap_rows + _RICHNESS_MIN_ROADMAP_ROWS)
still blocks malformed roadmap sections.

Run:  python -m pytest tests/test_synthesize_roadmap_ai_first_pr5b5c.py -v
"""
import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL',
                      'sqlite:///tmp/test_synth_roadmap_pr5b5c.db')
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


# Canonical valid English roadmap section: 5-column schema, 6
# substantive rows (>= drafting floor + headroom for consulting+2).
_VALID_ROADMAP_EN = (
    "## 5. Implementation Roadmap\n\n"
    "| # | Activity | Owner | Timeline | Deliverable |\n"
    "|---|----------|-------|----------|-------------|\n"
    "| 1 | Establish governance committee and approve charter "
    "| CEO / CISO | Months 1-3 | Approved committee charter and "
    "RACI matrix |\n"
    "| 2 | Run awareness and phishing-simulation programme "
    "| HR + CISO | Months 2-9 | >= 90% completion and <= 5% click rate |\n"
    "| 3 | Deploy SIEM and define detection use-cases "
    "| SOC Manager | Months 3-8 | Operational SIEM with 20 use-cases |\n"
    "| 4 | Conduct framework control assessment and remediation plan "
    "| GRC Team | Months 3-6 | Assessment report + remediation plan |\n"
    "| 5 | Develop policies and procedures pack "
    "| Governance Team | Months 2-5 | Approved auditable policy pack |\n"
    "| 6 | Operate quarterly internal-audit cycle "
    "| Internal Audit | Months 6-12 | Quarterly audit reports |\n"
)

_REPAIRED_ROADMAP_EN = (
    "## 5. Implementation Roadmap\n\n"
    "| # | Activity | Owner | Timeline | Deliverable |\n"
    "|---|----------|-------|----------|-------------|\n"
    "| 1 | AI-repaired activity one | Owner-1 | Months 1-3 "
    "| Deliverable-1 |\n"
    "| 2 | AI-repaired activity two | Owner-2 | Months 2-6 "
    "| Deliverable-2 |\n"
    "| 3 | AI-repaired activity three | Owner-3 | Months 3-8 "
    "| Deliverable-3 |\n"
    "| 4 | AI-repaired activity four | Owner-4 | Months 4-9 "
    "| Deliverable-4 |\n"
    "| 5 | AI-repaired activity five | Owner-5 | Months 5-10 "
    "| Deliverable-5 |\n"
    "| 6 | AI-repaired activity six | Owner-6 | Months 6-12 "
    "| Deliverable-6 |\n"
)

# A malformed roadmap: header present but only 1 placeholder-laden row.
_MALFORMED_ROADMAP_EN = (
    "## 5. Implementation Roadmap\n\n"
    "| # | Activity | Owner | Timeline | Deliverable |\n"
    "|---|----------|-------|----------|-------------|\n"
    "| 1 | OLD-MALFORMED-ROW | TBD | TBD | TBD |\n"
)


class TestSynthesizeRoadmapAIFirstPR5B5C(unittest.TestCase):
    @_skip_if_no_app
    def test_valid_roadmap_unchanged_returns_zero_no_ai_call(self):
        """1. Valid roadmap is left untouched and AI is not invoked."""
        sections = {'roadmap': _VALID_ROADMAP_EN}
        before = sections['roadmap']
        with patch.object(_APP, 'ai_repair_strategy_section') as mock_ai:
            n = _APP.synthesize_roadmap_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertEqual(n, 0)
        self.assertEqual(sections['roadmap'], before)
        mock_ai.assert_not_called()

    @_skip_if_no_app
    def test_insufficient_roadmap_calls_ai_with_section_key_roadmap(self):
        """2. Insufficient roadmap calls ai_repair_strategy_section with
        section_key='roadmap' (NOT 'roadmaps')."""
        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_ROADMAP_EN) as mock_ai:
            n = _APP.synthesize_roadmap_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertTrue(mock_ai.called)
        kwargs = mock_ai.call_args.kwargs
        self.assertEqual(kwargs.get('section_key'), 'roadmap',
                         'must use section_key="roadmap"')
        self.assertNotEqual(kwargs.get('section_key'), 'roadmaps')
        self.assertGreaterEqual(n, _APP._RICHNESS_MIN_ROADMAP_ROWS)

    @_skip_if_no_app
    def test_repaired_roadmap_replaces_sections_roadmap(self):
        """3. AI-repaired output replaces sections['roadmap'] verbatim."""
        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_ROADMAP_EN):
            _APP.synthesize_roadmap_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertEqual(sections['roadmap'], _REPAIRED_ROADMAP_EN)

    @_skip_if_no_app
    def test_no_fixed_roadmap_rows_or_workstreams_inserted(self):
        """4. Fixed deterministic rows (e.g. 'IT Operations',
        'GRC Team', 'Months 3-6', 'Months 6-12', priority-bank
        activities, 'Implementation Roadmap' skeleton) are NOT
        injected when AI fails."""
        sections = {'roadmap': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError('no ai')):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_roadmap_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        # No deterministic header, no priority-bank rows, no template rows.
        self.assertEqual(sections['roadmap'], '')

    @_skip_if_no_app
    def test_old_malformed_roadmap_rows_not_merged(self):
        """5. Old malformed rows must not survive when AI repair
        replaces the section."""
        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_ROADMAP_EN):
            _APP.synthesize_roadmap_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertNotIn('OLD-MALFORMED-ROW', sections['roadmap'])
        self.assertNotIn('| TBD |', sections['roadmap'])

    @_skip_if_no_app
    def test_ai_failure_raises_repair_error(self):
        """6. AI helper raising RepairError propagates and leaves
        sections['roadmap'] untouched."""
        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError('ai down')):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_roadmap_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        # Original (malformed) section is untouched.
        self.assertEqual(sections['roadmap'], _MALFORMED_ROADMAP_EN)

    @_skip_if_no_app
    def test_invalid_ai_repaired_roadmap_is_rejected(self):
        """7. If the AI returns too few substantive rows, raise
        RepairError and do not overwrite sections['roadmap']."""
        too_thin = (
            "## 5. Implementation Roadmap\n\n"
            "| # | Activity | Owner | Timeline | Deliverable |\n"
            "|---|----------|-------|----------|-------------|\n"
            "| 1 | only one activity | Owner | Months 1-3 | Done |\n"
        )
        sections = {'roadmap': _MALFORMED_ROADMAP_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=too_thin):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_roadmap_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(sections['roadmap'], _MALFORMED_ROADMAP_EN)

    @_skip_if_no_app
    def test_domain_contaminated_ai_output_is_rejected(self):
        """8. ai_repair_strategy_section is the gate that rejects
        domain-contaminated output. From the synth function's
        perspective: if the AI helper raises RepairError because of
        forbidden cross-domain terms, the synth must propagate."""
        sections = {'roadmap': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError(
                              'forbidden cross-domain terms in AI output')):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_roadmap_depth(
                    sections, lang='en',
                    domain='Data Management', fw_short='DAMA-DMBOK',
                )
        self.assertEqual(sections['roadmap'], '')

    @_skip_if_no_app
    def test_final_audit_still_blocks_malformed_roadmap_sections(self):
        """9. The post-normalisation audit
        (_count_substantive_roadmap_rows + _RICHNESS_MIN_ROADMAP_ROWS)
        must still flag roadmap sections that fall short of the floor —
        regardless of whether the synth function was invoked."""
        bad = ("## 5. Implementation Roadmap\n\n"
               "| # | Activity | Owner | Timeline | Deliverable |\n"
               "|---|----------|-------|----------|-------------|\n"
               "| 1 | only one | Owner | Months 1-3 | Done |\n")
        n = _APP._count_substantive_roadmap_rows(bad)
        self.assertLess(n, _APP._RICHNESS_MIN_ROADMAP_ROWS,
                        'audit floor must still reject thin roadmaps')

    @_skip_if_no_app
    def test_no_unrelated_deterministic_bank_helpers_called(self):
        """10. The roadmap synth must not invoke any unrelated
        deterministic bank helpers (SO banks, KPI banks). There is no
        roadmap bank helper to begin with; this asserts the AI-first
        contract is clean of cross-feature deterministic fallbacks."""
        sections_en = {'roadmap': ''}
        sections_ar = {'roadmap': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_ROADMAP_EN), \
             patch.object(_APP, '_build_domain_so_bank_en') as so_en, \
             patch.object(_APP, '_build_domain_so_bank_ar') as so_ar, \
             patch.object(_APP, '_build_domain_kpi_bank_en') as kpi_en, \
             patch.object(_APP, '_build_domain_kpi_bank_ar') as kpi_ar:
            _APP.synthesize_roadmap_depth(
                sections_en, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
            _APP.synthesize_roadmap_depth(
                sections_ar, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        so_en.assert_not_called()
        so_ar.assert_not_called()
        kpi_en.assert_not_called()
        kpi_ar.assert_not_called()


if __name__ == '__main__':
    unittest.main()
