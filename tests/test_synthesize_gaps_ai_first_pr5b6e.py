"""PR-5B.6E — AI-first contract for ``synthesize_gaps_depth``.

Asserts that gap guidance synthesis no longer relies on deterministic
gap-row banks, generic 5-row gap tables, hard-coded per-gap
"Implementation Guide" templates, or domain-string fallbacks. The
synthesizer either leaves a sufficient gaps section unchanged
(``rebuilt=False``) or delegates to
``ai_repair_strategy_section(section_key='gaps', ...)``. On AI failure
or invalid AI output the function raises :class:`RepairError` with
``setattr(err, 'section', 'gaps')``. The mandatory-section repair
helpers (``_force_inject_mandatory_section`` and
``_targeted_section_repair``) delegate the ``gap_guidance_missing``
branch to ``synthesize_gaps_depth`` and re-raise so the production
``_mark_synth_failed`` plumbing fires.

Run:  python -m pytest tests/test_synthesize_gaps_ai_first_pr5b6e.py -v
"""

import ast
import importlib
import os
import re
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///tmp/test_synthesize_gaps_ai_first_pr5b6e.db')
# No AI provider configured — unmocked AI calls raise.
os.environ['OPENAI_API_KEY']    = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY']    = ''
os.environ['GROQ_API_KEY']      = ''
os.environ['DEEPSEEK_API_KEY']  = ''

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')
_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


# ---------------------------------------------------------------------------
# Canonical fixtures — valid, malformed, repaired gap sections.
# ---------------------------------------------------------------------------

# 5 substantive gap rows + 5 per-gap implementation guides → sufficient.
_VALID_GAPS_EN = (
    "## 4. Gap Analysis\n\n"
    "| # | Gap | Description | Priority | Status |\n"
    "|---|-----|-------------|----------|--------|\n"
    "| 1 | Identity governance immature | RBAC inconsistent across systems "
    "| Critical | Open |\n"
    "| 2 | Logging coverage incomplete | Several systems lack centralized "
    "logging | High | Open |\n"
    "| 3 | Vulnerability scanning ad-hoc | No recurring scan cadence "
    "| High | Open |\n"
    "| 4 | Backup recovery untested | Restores never validated end-to-end "
    "| Medium | Open |\n"
    "| 5 | Third-party risk not tracked | No vendor risk register "
    "| Medium | Open |\n\n"
    "#### Gap #1 Implementation Guide: Identity governance immature\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | Inventory identities | IAM Team | Month 1 | Identity register |\n"
    "| 2 | Define RBAC matrix | IAM Lead | Month 2 | Approved RBAC |\n"
    "| 3 | Provision via IGA tool | IAM Team | Month 3-5 | IGA live |\n"
    "| 4 | Recertification campaign | IAM Lead | Month 6 | Cert report |\n\n"
    "#### Gap #2 Implementation Guide: Logging coverage incomplete\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | Inventory log sources | SOC | Month 1 | Source list |\n"
    "| 2 | Onboard sources to SIEM | SOC | Month 2-4 | SIEM coverage |\n"
    "| 3 | Define use-cases | SOC Lead | Month 3 | Use-case catalog |\n"
    "| 4 | Tune detections | SOC | Month 5-6 | Detection KPIs |\n\n"
    "#### Gap #3 Implementation Guide: Vulnerability scanning ad-hoc\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | Stand up scanner | Vuln Mgmt | Month 1 | Scanner live |\n"
    "| 2 | Define scan cadence | Vuln Lead | Month 1 | Cadence policy |\n"
    "| 3 | Run baseline scan | Vuln Mgmt | Month 2 | Baseline report |\n"
    "| 4 | Track remediation | Vuln Lead | Month 3-6 | Remediation KPIs |\n\n"
    "#### Gap #4 Implementation Guide: Backup recovery untested\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | Define RTO/RPO | BC Lead | Month 1 | RTO/RPO baseline |\n"
    "| 2 | Build restore runbook | BC Team | Month 2 | Runbook v1 |\n"
    "| 3 | Execute restore drill | BC Team | Month 3 | Drill report |\n"
    "| 4 | Remediate gaps | BC Lead | Month 4-5 | Updated runbook |\n\n"
    "#### Gap #5 Implementation Guide: Third-party risk not tracked\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | Build vendor inventory | TPRM | Month 1 | Vendor register |\n"
    "| 2 | Define tiering | TPRM Lead | Month 2 | Tiering model |\n"
    "| 3 | Issue assessments | TPRM | Month 3-4 | Assessments back |\n"
    "| 4 | Remediation tracking | TPRM Lead | Month 5-6 | Risk register |\n"
)

_REPAIRED_GAPS_EN = (
    "## 4. Gap Analysis\n\n"
    "| # | Gap | Description | Priority | Status |\n"
    "|---|-----|-------------|----------|--------|\n"
    "| 1 | AI-repaired gap one | repaired desc one "
    "| Critical | Open |\n"
    "| 2 | AI-repaired gap two | repaired desc two "
    "| High | Open |\n"
    "| 3 | AI-repaired gap three | repaired desc three "
    "| High | Open |\n"
    "| 4 | AI-repaired gap four | repaired desc four "
    "| Medium | Open |\n"
    "| 5 | AI-repaired gap five | repaired desc five "
    "| Medium | Open |\n\n"
    "#### Gap #1 Implementation Guide: AI-repaired gap one\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | repaired action 1a | Owner-1 | Month 1 | repaired output 1a |\n"
    "| 2 | repaired action 1b | Owner-1 | Month 2 | repaired output 1b |\n"
    "| 3 | repaired action 1c | Owner-1 | Month 3 | repaired output 1c |\n"
    "| 4 | repaired action 1d | Owner-1 | Month 4 | repaired output 1d |\n\n"
    "#### Gap #2 Implementation Guide: AI-repaired gap two\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | repaired action 2a | Owner-2 | Month 1 | repaired output 2a |\n"
    "| 2 | repaired action 2b | Owner-2 | Month 2 | repaired output 2b |\n"
    "| 3 | repaired action 2c | Owner-2 | Month 3 | repaired output 2c |\n"
    "| 4 | repaired action 2d | Owner-2 | Month 4 | repaired output 2d |\n\n"
    "#### Gap #3 Implementation Guide: AI-repaired gap three\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | repaired action 3a | Owner-3 | Month 1 | repaired output 3a |\n"
    "| 2 | repaired action 3b | Owner-3 | Month 2 | repaired output 3b |\n"
    "| 3 | repaired action 3c | Owner-3 | Month 3 | repaired output 3c |\n"
    "| 4 | repaired action 3d | Owner-3 | Month 4 | repaired output 3d |\n\n"
    "#### Gap #4 Implementation Guide: AI-repaired gap four\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | repaired action 4a | Owner-4 | Month 1 | repaired output 4a |\n"
    "| 2 | repaired action 4b | Owner-4 | Month 2 | repaired output 4b |\n"
    "| 3 | repaired action 4c | Owner-4 | Month 3 | repaired output 4c |\n"
    "| 4 | repaired action 4d | Owner-4 | Month 4 | repaired output 4d |\n\n"
    "#### Gap #5 Implementation Guide: AI-repaired gap five\n"
    "| Step | Action | Owner | Timeline | Output |\n"
    "|------|--------|-------|----------|--------|\n"
    "| 1 | repaired action 5a | Owner-5 | Month 1 | repaired output 5a |\n"
    "| 2 | repaired action 5b | Owner-5 | Month 2 | repaired output 5b |\n"
    "| 3 | repaired action 5c | Owner-5 | Month 3 | repaired output 5c |\n"
    "| 4 | repaired action 5d | Owner-5 | Month 4 | repaired output 5d |\n"
)

_MALFORMED_GAPS_EN = (
    "## 4. Gap Analysis\n\n"
    "| # | Gap | Description | Priority | Status |\n"
    "|---|-----|-------------|----------|--------|\n"
    "| 1 | OLD-MALFORMED-GAP | TBD | TBD | TBD |\n"
)


# ---------------------------------------------------------------------------
# 1. Sufficient gaps → no AI call, no mutation, rebuilt=False.
# ---------------------------------------------------------------------------

class TestSufficientGapsAreNoOp(unittest.TestCase):

    def test_valid_gaps_unchanged_no_ai_call(self):
        sections = {'gaps': _VALID_GAPS_EN}
        before = sections['gaps']
        with patch.object(_APP, 'ai_repair_strategy_section') as mock_ai:
            result = _APP.synthesize_gaps_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertFalse(result.get('rebuilt'),
                         'sufficient gaps must NOT trigger AI repair')
        self.assertEqual(sections['gaps'], before,
                         'sufficient gaps section must not be mutated')
        mock_ai.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Insufficient gaps → AI is called with section_key='gaps'.
# ---------------------------------------------------------------------------

class TestInsufficientGapsCallsAI(unittest.TestCase):

    def test_insufficient_gaps_calls_ai_with_section_key_gaps(self):
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
        self.assertTrue(result.get('rebuilt'),
                        'AI repair should mark rebuilt=True')

    def test_repaired_output_replaces_sections_gaps(self):
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_GAPS_EN):
            _APP.synthesize_gaps_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertEqual(sections['gaps'], _REPAIRED_GAPS_EN)
        self.assertNotIn('OLD-MALFORMED-GAP', sections['gaps'])
        self.assertNotIn('| TBD |', sections['gaps'])


# ---------------------------------------------------------------------------
# 3. AI failure → RepairError with section='gaps'; sections untouched.
# ---------------------------------------------------------------------------

class TestAIFailureRaisesRepairErrorSectionGaps(unittest.TestCase):

    def test_ai_failure_raises_repair_error_section_gaps(self):
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError('ai down')):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                    generation_mode='drafting',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps',
                         'RepairError must be annotated with section="gaps"')
        # Original (malformed) section is untouched on AI failure.
        self.assertEqual(sections['gaps'], _MALFORMED_GAPS_EN)

    def test_invalid_ai_output_too_few_rows_rejected(self):
        too_thin = (
            "## 4. Gap Analysis\n\n"
            "| # | Gap | Description | Priority | Status |\n"
            "|---|-----|-------------|----------|--------|\n"
            "| 1 | only one gap | only one description | High | Open |\n"
        )
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=too_thin):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                    generation_mode='drafting',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps')
        self.assertEqual(sections['gaps'], _MALFORMED_GAPS_EN,
                         'invalid AI output must NOT overwrite gaps section')

    def test_invalid_ai_output_missing_guides_rejected(self):
        # 5 substantive rows but no per-gap implementation guides.
        rows_no_guides = (
            "## 4. Gap Analysis\n\n"
            "| # | Gap | Description | Priority | Status |\n"
            "|---|-----|-------------|----------|--------|\n"
            "| 1 | Gap one substantive | Description one | Critical | Open |\n"
            "| 2 | Gap two substantive | Description two | High | Open |\n"
            "| 3 | Gap three substantive | Description three | High | Open |\n"
            "| 4 | Gap four substantive | Description four | Medium | Open |\n"
            "| 5 | Gap five substantive | Description five | Medium | Open |\n"
        )
        sections = {'gaps': _MALFORMED_GAPS_EN}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=rows_no_guides):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                    generation_mode='drafting',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps')
        self.assertEqual(sections['gaps'], _MALFORMED_GAPS_EN)


# ---------------------------------------------------------------------------
# 4. Domain resolution failure → RepairError with section='gaps'.
# ---------------------------------------------------------------------------

class TestDomainResolutionFailureFailsClosed(unittest.TestCase):

    def test_unknown_domain_raises_repair_error_section_gaps(self):
        sections = {'gaps': _MALFORMED_GAPS_EN}

        def _boom(*a, **kw):
            raise _APP.DomainResolutionError('unknown domain')

        with patch.object(_APP, 'get_strategy_domain_context',
                          side_effect=_boom):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_gaps_depth(
                    sections, lang='en',
                    domain='Made-Up Domain', fw_short='NCA ECC',
                    generation_mode='drafting',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps')
        self.assertEqual(sections['gaps'], _MALFORMED_GAPS_EN)


# ---------------------------------------------------------------------------
# 5. _force_inject_mandatory_section gap_guidance_missing branch
#    delegates to synthesize_gaps_depth (PR-5B.6E).
# ---------------------------------------------------------------------------

class TestForceInjectGapBranchDelegates(unittest.TestCase):

    def _fi_kwargs(self):
        return dict(
            domain='Cyber Security', fw_short='NCA ECC',
            org_name='Test Org', budget='allocated budget',
            maturity='initial', sector='Government',
            generation_mode='drafting',
        )

    def test_force_inject_delegates_to_synthesize_gaps_depth(self):
        sections = {'gaps': '## 4. Gap Analysis\n'}
        calls = []

        def _spy(secs, lang, **kwargs):
            calls.append({'lang': lang, **kwargs})
            return {'rebuilt': True, 'rows_before': 0, 'rows_after': 5}

        with patch.object(_APP, 'synthesize_gaps_depth', _spy):
            _APP._force_inject_mandatory_section(
                sections, 'gap_guidance_missing', 'en',
                **self._fi_kwargs())
        self.assertEqual(len(calls), 1,
                         'synthesize_gaps_depth must be invoked exactly once')

    def test_force_inject_propagates_repair_error_section_gaps(self):
        sections = {'gaps': '## 4. Gap Analysis\n'}

        def _boom(*a, **kw):
            raise _APP.RepairError('AI unavailable')

        with patch.object(_APP, 'synthesize_gaps_depth', _boom):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP._force_inject_mandatory_section(
                    sections, 'gap_guidance_missing', 'en',
                    **self._fi_kwargs())
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps',
                         'gap branch RepairError must be section="gaps"')


# ---------------------------------------------------------------------------
# 6. _targeted_section_repair gap_guidance_missing branch delegates to
#    synthesize_gaps_depth (PR-5B.6E).
# ---------------------------------------------------------------------------

class TestTargetedSectionRepairGapBranch(unittest.TestCase):

    def _tsr_kwargs(self):
        return dict(
            doc_subtype='technical-strategy',
            lang='en',
            domain='Cyber Security', fw_short='NCA ECC',
            org_name='Test Org', budget='allocated budget',
            maturity='initial', generation_mode='drafting',
        )

    def test_targeted_repair_delegates_to_synthesize_gaps_depth(self):
        sections = {'gaps': '## 4. Gap Analysis\n'}
        calls = []

        def _spy(secs, lang, **kwargs):
            calls.append({'lang': lang, **kwargs})
            return {'rebuilt': True, 'rows_before': 0, 'rows_after': 5}

        with patch.object(_APP, 'synthesize_gaps_depth', _spy):
            _APP._targeted_section_repair(
                sections=sections,
                issues=['gap_guidance_missing'],
                **self._tsr_kwargs())
        self.assertEqual(len(calls), 1,
                         'synthesize_gaps_depth must be invoked once')

    def test_targeted_repair_propagates_repair_error_section_gaps(self):
        sections = {'gaps': '## 4. Gap Analysis\n'}

        def _boom(*a, **kw):
            raise _APP.RepairError('AI unavailable')

        with patch.object(_APP, 'synthesize_gaps_depth', _boom):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP._targeted_section_repair(
                    sections=sections,
                    issues=['gap_guidance_missing'],
                    **self._tsr_kwargs())
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps')


# ---------------------------------------------------------------------------
# 7. Static analysis: deterministic gap content removed from app.py
#    inside _force_inject_mandatory_section AND _targeted_section_repair
#    gap branches.
# ---------------------------------------------------------------------------

class TestNoDeterministicGapContentInRepairHelpers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            cls._source = f.read()
        tree = ast.parse(cls._source)
        cls._fi_src = None
        cls._tsr_src = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.name == '_force_inject_mandatory_section':
                    cls._fi_src = ast.get_source_segment(cls._source, node)
                elif node.name == '_targeted_section_repair':
                    cls._tsr_src = ast.get_source_segment(cls._source, node)
        assert cls._fi_src, 'Could not locate _force_inject_mandatory_section'
        assert cls._tsr_src, 'Could not locate _targeted_section_repair'

    def test_force_inject_has_no_deterministic_gap_content(self):
        forbidden = [
            'Gap #1 Implementation Guide',
            'Gap Implementation Guidance',
            'Identified Gaps:',
            'الفجوات المحددة:',
            'دليل تنفيذ الفجوة',
            'governance absent',
            'Technical controls deficit',
            'Awareness weakness',
            'Incident response absent',
            'Continuous monitoring weak',
        ]
        for needle in forbidden:
            self.assertNotIn(
                needle, self._fi_src,
                f'_force_inject_mandatory_section must not author {needle!r}')

    def test_targeted_section_repair_has_no_deterministic_gap_content(self):
        forbidden = [
            'Gap #1 Implementation Guide',
            '#### Gap #{_n} Implementation Guide',
            '#### دليل تنفيذ الفجوة',
            'Identified Gaps:',
            'الفجوات المحددة:',
            'governance absent',
            'Technical controls deficit',
            'Awareness weakness',
            'Incident response absent',
            'Continuous monitoring weak',
            'No recurring awareness programme',
            'No approved IR playbook',
            'No continuous-compliance dashboard',
        ]
        for needle in forbidden:
            self.assertNotIn(
                needle, self._tsr_src,
                f'_targeted_section_repair must not author {needle!r}')

    def test_force_inject_gap_branch_calls_synthesize_gaps_depth(self):
        # Find gap branch and confirm it references synthesize_gaps_depth.
        m = re.search(
            r"flag\s*==\s*['\"]gap_guidance_missing['\"][\s\S]{0,800}?"
            r"synthesize_gaps_depth",
            self._fi_src,
        )
        self.assertIsNotNone(
            m,
            '_force_inject_mandatory_section gap_guidance_missing branch '
            'must delegate to synthesize_gaps_depth',
        )

    def test_targeted_repair_gap_branch_calls_synthesize_gaps_depth(self):
        m = re.search(
            r"['\"]gap_guidance_missing['\"]\s+in\s+issues[\s\S]{0,800}?"
            r"synthesize_gaps_depth",
            self._tsr_src,
        )
        self.assertIsNotNone(
            m,
            '_targeted_section_repair gap_guidance_missing branch '
            'must delegate to synthesize_gaps_depth',
        )


# ---------------------------------------------------------------------------
# 8. synthesize_gaps_depth body itself authors no deterministic content.
# ---------------------------------------------------------------------------

class TestSynthesizeGapsDepthBodyHasNoDeterministicContent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            cls._source = f.read()
        tree = ast.parse(cls._source)
        cls._fn_src = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'synthesize_gaps_depth'):
                cls._fn_src = ast.get_source_segment(cls._source, node)
                break
        assert cls._fn_src, 'Could not locate synthesize_gaps_depth'

    def test_no_deterministic_gap_rows(self):
        forbidden = [
            'governance absent',
            'Technical controls deficit',
            'Continuous monitoring weak',
            'Awareness weakness',
            'Identified Gaps:',
            'الفجوات المحددة:',
            'Implementation Guide:',
            'دليل تنفيذ الفجوة',
        ]
        for needle in forbidden:
            self.assertNotIn(
                needle, self._fn_src,
                f'synthesize_gaps_depth must not author {needle!r}')

    def test_calls_ai_repair_strategy_section_with_section_key_gaps(self):
        m = re.search(
            r"ai_repair_strategy_section\s*\([\s\S]{0,400}?"
            r"section_key\s*=\s*['\"]gaps['\"]",
            self._fn_src,
        )
        self.assertIsNotNone(
            m,
            'synthesize_gaps_depth must call '
            'ai_repair_strategy_section(section_key="gaps", ...)',
        )


# ---------------------------------------------------------------------------
# 9. Final audit gate (count_substantive_gaps + count_gap_guides) still
#    rejects malformed sections.
# ---------------------------------------------------------------------------

class TestFinalAuditStillBlocksMalformedGaps(unittest.TestCase):

    def test_too_few_substantive_gaps_blocked(self):
        bad = (
            "## 4. Gap Analysis\n\n"
            "| # | Gap | Description | Priority | Status |\n"
            "|---|-----|-------------|----------|--------|\n"
            "| 1 | only one | only desc | High | Open |\n"
        )
        n = _APP.count_substantive_gaps(bad)
        self.assertLess(n, 5,
                        'audit floor must still reject thin gap sections')

    def test_no_guides_blocked(self):
        rows_only = (
            "## 4. Gap Analysis\n\n"
            "| # | Gap | Description | Priority | Status |\n"
            "|---|-----|-------------|----------|--------|\n"
            "| 1 | Gap one | Desc one | Critical | Open |\n"
            "| 2 | Gap two | Desc two | High | Open |\n"
            "| 3 | Gap three | Desc three | High | Open |\n"
            "| 4 | Gap four | Desc four | Medium | Open |\n"
            "| 5 | Gap five | Desc five | Medium | Open |\n"
        )
        n_rows = _APP.count_substantive_gaps(rows_only)
        n_guides = _APP.count_gap_guides(rows_only)
        self.assertGreaterEqual(n_rows, 5)
        self.assertEqual(n_guides, 0,
                         'count_gap_guides must detect missing guides')


if __name__ == '__main__':
    unittest.main()
