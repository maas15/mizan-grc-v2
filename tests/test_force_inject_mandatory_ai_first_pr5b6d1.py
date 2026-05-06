"""PR-5B.6D.1: AI-first ``_force_inject_mandatory_section``.

This module pins down the post-migration contract for the mandatory-
section injector that runs in the production strategy pipeline at three
sites (one inside ``_enforce_technical_strategy_completeness`` and two
inside ``api_generate_strategy`` Tier-3 / Tier-4 last-ditch loops):

  * Strategic Objectives flags
    (``strategic_objectives_row_schema_violation`` /
    ``strategic_objectives_rows_insufficient`` /
    ``strategic_objectives_section_missing``) delegate to
    :func:`synthesize_objectives_depth`.  No deterministic SO rows are
    authored.
  * ``kpi_assessment_guides_missing`` delegates to
    :func:`synthesize_kpi_depth`.  No canned per-KPI "Assessment Guide"
    blocks are authored.
  * ``confidence_score_missing`` and ``score_justification_missing``
    delegate to :func:`synthesize_confidence_depth`.  No hardcoded
    ``55%`` score, no hardcoded justification paragraph, no mode-aware
    canonical block is authored.
  * ``gap_guidance_missing`` is intentionally fail-closed (no
    ``synthesize_gaps_depth`` exists yet); the function raises
    :class:`RepairError` with ``setattr(err, 'section', 'gaps')``.
  * Any unknown flag raises :class:`RepairError` with
    ``setattr(err, 'section', 'strategy')`` rather than silently
    no-op'ing.
  * Each AI-first failure annotates the raised :class:`RepairError`
    with ``setattr(err, 'section', <vision|kpis|confidence|gaps>)`` so
    the production caller's ``except RepairError`` branch routes
    through :func:`_mark_synth_failed`.
  * The three production call sites catch :class:`RepairError` BEFORE
    a generic ``except Exception`` and call :func:`_mark_synth_failed`
    on the request-scoped ``_synth_status`` dict.

Run:
    python -m pytest tests/test_force_inject_mandatory_ai_first_pr5b6d1.py -q
"""

import ast
import importlib
import os
import re
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///tmp/test_force_inject_mandatory_ai_first_pr5b6d1.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')
_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


# ---------------------------------------------------------------------------
# _Patch helper (mirrors PR-5B.6C.2 / PR-5B.6C.3 test pattern).
# ---------------------------------------------------------------------------

class _Patch:
    """Lightweight context manager that swaps a module attribute."""

    def __init__(self, target, name, value):
        self.target = target
        self.name = name
        self.value = value
        self._original = None
        self._had = False

    def __enter__(self):
        self._had = hasattr(self.target, self.name)
        if self._had:
            self._original = getattr(self.target, self.name)
        setattr(self.target, self.name, self.value)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._had:
            setattr(self.target, self.name, self._original)
        else:  # pragma: no cover - defensive
            try:
                delattr(self.target, self.name)
            except AttributeError:
                pass
        return False


# ---------------------------------------------------------------------------
# Common kwargs / shorthand.
# ---------------------------------------------------------------------------

def _fi_kwargs():
    return dict(
        domain='Cyber Security',
        fw_short='NCA ECC',
        org_name='Test Org',
        budget='allocated budget',
        maturity='initial',
        sector='Government',
        generation_mode='drafting',
    )


# ---------------------------------------------------------------------------
# 1. Strategic objectives flag delegates to synthesize_objectives_depth.
# ---------------------------------------------------------------------------

class TestStrategicObjectivesDelegates(unittest.TestCase):

    def _run(self, flag):
        sections = {'vision': '## 1. Vision\n\nThin vision body.\n'}
        calls = []

        def _spy(secs, lang, **kwargs):
            calls.append({'lang': lang, **kwargs})
            return {'rebuilt': True, 'preserved': 0, 'total_after': 6}

        with _Patch(_APP, 'synthesize_objectives_depth', _spy):
            _APP._force_inject_mandatory_section(
                sections, flag, 'en', **_fi_kwargs())
        return sections, calls

    def test_section_missing_delegates(self):
        _, calls = self._run('strategic_objectives_section_missing')
        self.assertEqual(len(calls), 1,
                         'synthesize_objectives_depth must be invoked exactly once')

    def test_rows_insufficient_delegates(self):
        _, calls = self._run('strategic_objectives_rows_insufficient')
        self.assertEqual(len(calls), 1)

    def test_row_schema_violation_delegates(self):
        _, calls = self._run('strategic_objectives_row_schema_violation')
        self.assertEqual(len(calls), 1)


# ---------------------------------------------------------------------------
# 2. KPI assessment guides flag delegates to synthesize_kpi_depth.
# ---------------------------------------------------------------------------

class TestKpiGuidesDelegates(unittest.TestCase):

    def test_kpi_assessment_guides_missing_delegates(self):
        sections = {'kpis': '## 6. KPIs\n'}
        calls = []

        def _spy(secs, lang, **kwargs):
            calls.append({'lang': lang, **kwargs})
            return 0

        with _Patch(_APP, 'synthesize_kpi_depth', _spy):
            _APP._force_inject_mandatory_section(
                sections, 'kpi_assessment_guides_missing', 'en',
                **_fi_kwargs())
        self.assertEqual(len(calls), 1,
                         'synthesize_kpi_depth must be invoked exactly once')


# ---------------------------------------------------------------------------
# 3 & 4. Confidence score / justification flags delegate to
#        synthesize_confidence_depth (or ai_repair_strategy_section via it).
# ---------------------------------------------------------------------------

class TestConfidenceDelegates(unittest.TestCase):

    def _run(self, flag):
        sections = {'confidence': '## 7. Confidence\n'}
        calls = []

        def _spy(secs, lang, **kwargs):
            calls.append({'lang': lang, **kwargs})
            return {'csf_added': 0, 'risks_added': 0,
                    'score_added': True, 'justification_added': True,
                    'mitigation_links': []}

        with _Patch(_APP, 'synthesize_confidence_depth', _spy):
            _APP._force_inject_mandatory_section(
                sections, flag, 'en', **_fi_kwargs())
        return calls

    def test_confidence_score_missing_delegates(self):
        calls = self._run('confidence_score_missing')
        self.assertEqual(len(calls), 1,
                         'synthesize_confidence_depth must be invoked once')

    def test_score_justification_missing_delegates(self):
        calls = self._run('score_justification_missing')
        self.assertEqual(len(calls), 1)


# ---------------------------------------------------------------------------
# 5. Gap guidance flag raises RepairError with section='gaps'.
# ---------------------------------------------------------------------------

class TestGapGuidanceFailClosed(unittest.TestCase):

    def test_gap_guidance_missing_raises_section_gaps(self):
        sections = {'gaps': '## 4. Gaps\n'}
        with self.assertRaises(_APP.RepairError) as cm:
            _APP._force_inject_mandatory_section(
                sections, 'gap_guidance_missing', 'en', **_fi_kwargs())
        self.assertEqual(getattr(cm.exception, 'section', None), 'gaps',
                         'RepairError must be annotated with section="gaps"')
        # No deterministic gap rows are written even though we fail closed.
        self.assertEqual(sections['gaps'], '## 4. Gaps\n',
                         'gap_guidance_missing must NOT mutate sections[gaps]')


# ---------------------------------------------------------------------------
# 6, 7, 8. AI failure in each delegated branch annotates section attr
#          and re-raises RepairError.
# ---------------------------------------------------------------------------

class TestAiFailureAnnotatesSection(unittest.TestCase):

    def test_objectives_branch_failure_section_vision(self):
        sections = {'vision': '## 1. Vision\n'}

        def _boom(*a, **kw):
            raise _APP.RepairError('AI unavailable')

        with _Patch(_APP, 'synthesize_objectives_depth', _boom):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP._force_inject_mandatory_section(
                    sections, 'strategic_objectives_rows_insufficient',
                    'en', **_fi_kwargs())
        self.assertEqual(getattr(cm.exception, 'section', None), 'vision',
                         'objectives branch RepairError must be section="vision"')

    def test_kpi_branch_failure_section_kpis(self):
        sections = {'kpis': '## 6. KPIs\n'}

        def _boom(*a, **kw):
            raise _APP.RepairError('AI unavailable')

        with _Patch(_APP, 'synthesize_kpi_depth', _boom):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP._force_inject_mandatory_section(
                    sections, 'kpi_assessment_guides_missing',
                    'en', **_fi_kwargs())
        self.assertEqual(getattr(cm.exception, 'section', None), 'kpis',
                         'KPI branch RepairError must be section="kpis"')

    def test_confidence_branch_failure_section_confidence(self):
        sections = {'confidence': '## 7. Confidence\n'}

        def _boom(*a, **kw):
            _err = _APP.RepairError('AI unavailable')
            # Even if synthesize_confidence_depth already sets the
            # section attr, the wrapper must re-affirm/preserve it.
            setattr(_err, 'section', 'confidence')
            raise _err

        with _Patch(_APP, 'synthesize_confidence_depth', _boom):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP._force_inject_mandatory_section(
                    sections, 'confidence_score_missing',
                    'en', **_fi_kwargs())
        self.assertEqual(getattr(cm.exception, 'section', None), 'confidence',
                         'confidence branch RepairError must be section="confidence"')


# ---------------------------------------------------------------------------
# 9-12. The function authors NO deterministic content via static analysis.
#       Source-level grep against the new function body asserts that none
#       of the canned KPI/gap/confidence/SO content survived the migration.
# ---------------------------------------------------------------------------

class TestNoDeterministicContentInSource(unittest.TestCase):
    """Static analysis: extract the function body and assert that no
    canned Arabic/English content rows or paragraphs remain inside it.
    """

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            cls._source = f.read()
        tree = ast.parse(cls._source)
        cls._fn_body_src = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == '_force_inject_mandatory_section'):
                cls._fn_body_src = ast.get_source_segment(cls._source, node)
                break
        assert cls._fn_body_src, \
            'Could not locate _force_inject_mandatory_section in app.py'

    def test_no_deterministic_kpi_guide_rows(self):
        forbidden = [
            'KPI #1 Assessment Guide',
            'KPI #2 Assessment Guide',
            'KPI Assessment Guidelines',
            'دليل تقييم المؤشر رقم',
            'أدلة تقييم مؤشرات الأداء',
            'control implementation rate',
            'Gap closure rate',
        ]
        for needle in forbidden:
            self.assertNotIn(
                needle, self._fn_body_src,
                f'_force_inject_mandatory_section must not author {needle!r}')

    def test_no_deterministic_gap_implementation_guides(self):
        forbidden = [
            'Gap #1 Implementation Guide',
            'Gap #2 Implementation Guide',
            'Gap Implementation Guidance',
            'دليل تنفيذ الفجوة رقم',
            'أدلة تنفيذ الفجوات',
            'governance absent',
            'Controls deficit',
        ]
        for needle in forbidden:
            self.assertNotIn(
                needle, self._fn_body_src,
                f'_force_inject_mandatory_section must not author {needle!r}')

    def test_no_deterministic_confidence_score_or_justification(self):
        forbidden = [
            '**Confidence Score:** 55%',
            '**درجة الثقة:** 55%',
            '**Score Justification:**',
            '**مبررات التقييم:**',
            'sustained executive sponsorship',
            'Most critical success',
            'مستوى نضج',
            'تعكس درجة الثقة',
        ]
        for needle in forbidden:
            self.assertNotIn(
                needle, self._fn_body_src,
                f'_force_inject_mandatory_section must not author {needle!r}')

    def test_no_deterministic_strategic_objective_rows(self):
        forbidden = [
            'Establish {domain} governance',
            'Deploy {fw_short} controls',
            'Operationalize IR',
            'Launch monitoring',
            'إنشاء حوكمة',
            'نشر ضوابط',
            'تنفيذ التوعية',
            'تشغيل الاستجابة للحوادث',
            'Strategic Objectives:',
            'الأهداف الاستراتيجية:',
        ]
        for needle in forbidden:
            self.assertNotIn(
                needle, self._fn_body_src,
                f'_force_inject_mandatory_section must not author {needle!r}')

    def test_function_does_not_mutate_sections_directly(self):
        """The new body must not assign into ``sections[...]`` (assignment
        is delegated entirely to the AI-first synthesizers it calls)."""
        # `sections['kpis'] =` / `sections['vision'] =` etc must NOT appear
        # anywhere inside the function body any more.
        forbidden_pat = re.compile(
            r"sections\s*\[\s*['\"](?:kpis|vision|gaps|confidence)['\"]\s*\]\s*=",
        )
        m = forbidden_pat.search(self._fn_body_src)
        self.assertIsNone(
            m,
            f'_force_inject_mandatory_section must not assign into '
            f'sections[<flag-section>] directly; saw {m.group(0) if m else None!r}'
        )


# ---------------------------------------------------------------------------
# 13. Each production call site marks synth_failed via _mark_synth_failed.
#     Verified by AST inspection: every call to
#     ``_force_inject_mandatory_section(...)`` (other than the function
#     definition itself) must be wrapped in a Try whose handlers contain
#     a RepairError handler that calls _mark_synth_failed.
# ---------------------------------------------------------------------------

class TestProductionCallSitesFailClosed(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            cls._source = f.read()
        cls._tree = ast.parse(cls._source)

    def _find_force_inject_call_sites(self):
        sites = []
        for node in ast.walk(self._tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == '_force_inject_mandatory_section'):
                sites.append(node)
        return sites

    def _enclosing_try(self, target_node):
        """Walk the AST and find the innermost ast.Try whose body contains
        ``target_node``."""
        best = None
        for node in ast.walk(self._tree):
            if isinstance(node, ast.Try):
                for stmt in ast.walk(node):
                    if stmt is target_node:
                        # Prefer the innermost one (largest lineno-base).
                        if best is None or node.lineno > best.lineno:
                            best = node
                        break
        return best

    def test_three_call_sites_present(self):
        sites = self._find_force_inject_call_sites()
        self.assertEqual(
            len(sites), 3,
            f'Expected exactly 3 production call sites of '
            f'_force_inject_mandatory_section, found {len(sites)} at '
            f'lines {[s.lineno for s in sites]}',
        )

    def test_each_call_site_handles_repair_error_and_marks_synth_failed(self):
        sites = self._find_force_inject_call_sites()
        for call_node in sites:
            try_node = self._enclosing_try(call_node)
            self.assertIsNotNone(
                try_node,
                f'Call site at line {call_node.lineno} must be wrapped in a try block',
            )
            # Find a handler that catches RepairError.
            repair_handler = None
            for handler in try_node.handlers:
                if handler.type is None:
                    continue
                # handler.type can be ast.Name('RepairError') or ast.Tuple.
                names = []
                if isinstance(handler.type, ast.Name):
                    names = [handler.type.id]
                elif isinstance(handler.type, ast.Tuple):
                    names = [
                        n.id for n in handler.type.elts
                        if isinstance(n, ast.Name)
                    ]
                if 'RepairError' in names:
                    repair_handler = handler
                    break
            self.assertIsNotNone(
                repair_handler,
                f'Call site at line {call_node.lineno} must have an '
                f'`except RepairError` handler before generic Exception',
            )
            # The RepairError handler must call _mark_synth_failed.
            calls_mark = False
            for stmt in ast.walk(repair_handler):
                if (isinstance(stmt, ast.Call)
                        and isinstance(stmt.func, ast.Name)
                        and stmt.func.id == '_mark_synth_failed'):
                    calls_mark = True
                    break
            self.assertTrue(
                calls_mark,
                f'RepairError handler at line {repair_handler.lineno} '
                f'must call _mark_synth_failed(...)',
            )

    def test_repair_error_handler_precedes_generic_exception(self):
        """For each call site that has BOTH a RepairError and a generic
        Exception handler, RepairError must be listed first (Python
        evaluates handlers top-down)."""
        sites = self._find_force_inject_call_sites()
        for call_node in sites:
            try_node = self._enclosing_try(call_node)
            seen_repair = False
            for handler in try_node.handlers:
                if handler.type is None:
                    continue
                names = []
                if isinstance(handler.type, ast.Name):
                    names = [handler.type.id]
                elif isinstance(handler.type, ast.Tuple):
                    names = [n.id for n in handler.type.elts
                             if isinstance(n, ast.Name)]
                if 'RepairError' in names:
                    seen_repair = True
                elif 'Exception' in names:
                    self.assertTrue(
                        seen_repair,
                        f'At call site line {call_node.lineno}: '
                        f'`except RepairError` must precede '
                        f'`except Exception`',
                    )


if __name__ == '__main__':
    unittest.main()
