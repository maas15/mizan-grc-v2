"""PR-5B.5F1: fail-closed hardening for migrated synthesis call sites.

Each scenario monkey-patches one of the migrated synth helpers
(``synthesize_objectives_depth`` / ``synthesize_kpi_depth`` /
``synthesize_roadmap_depth``) to raise ``RepairError`` and asserts:

  * the call site catches ``RepairError`` BEFORE the generic ``Exception``
    fallback;
  * the failure is recorded in a section-keyed ``synth_status`` dict
    (``vision`` / ``roadmap`` / ``kpis``);
  * ``_final_strategy_audit`` surfaces a ``synth_failed:<section>`` defect
    when the dict is threaded in (this is the post-normalization save
    gate's blocker source);
  * the convergence loop refuses to report ``converged=True`` when any
    ``synth_status`` entry is ``failed``;
  * generic ``Exception`` paths keep their legacy log-and-continue
    behavior and do NOT mark a section as failed;
  * the section content is NOT mutated with deterministic fallback rows
    after a ``RepairError``.

Run:  python -m pytest tests/test_strategy_synth_fail_closed_pr5b5f1.py -q
"""

import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_synth_fail_closed.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception:  # pragma: no cover - environment-dependent
    _APP = None


def _skip_if_no_app(test):
    import pytest
    if _APP is None:
        pytest.skip('app.py could not be imported in this environment')
    return test


class _Patch:
    """Lightweight context manager that swaps an attribute and restores it."""

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


def _raise_repair(*_args, **_kwargs):
    raise _APP.RepairError('forced for test')


def _raise_generic(*_args, **_kwargs):
    raise ValueError('generic programming bug')


def _empty_sections():
    return {
        'vision': '',
        'pillars': '',
        'environment': '',
        'gaps': '',
        'roadmap': '',
        'kpis': '',
        'confidence': '',
    }


@unittest.skipIf(_APP is None, 'app.py unavailable')
class FinalSynthesisFailClosed(unittest.TestCase):
    """Scenarios 1–3 + 9 + 10: ``_apply_final_synthesis_pass``."""

    def _run_with(self, **patches):
        sections = _empty_sections()
        ctx = {'sector': 'Government', 'org_name': 'Acme',
               'maturity': 'initial', 'generation_mode': 'consulting'}

        # Stub every synthesizer the pass calls so no AI provider is
        # invoked. Tests override individual entries by name.
        def _noop(*_a, **_k):
            return None

        defaults = dict(
            synthesize_objectives_depth=_noop,
            synthesize_gaps_depth=_noop,
            synthesize_pillars_depth=_noop,
            synthesize_environment_context=_noop,
            synthesize_roadmap_depth=_noop,
            synthesize_kpi_depth=_noop,
            synthesize_confidence_depth=lambda *a, **k: {},
        )
        defaults.update(patches)

        cms = [_Patch(_APP, name, fn) for name, fn in defaults.items()]
        for cm in cms:
            cm.__enter__()
        try:
            summary = _APP._apply_final_synthesis_pass(
                sections, 'ar', 'Cyber Security', 'NCA ECC', ctx=ctx)
        finally:
            for cm in reversed(cms):
                cm.__exit__(None, None, None)
        return sections, summary

    def test_1_objectives_repair_error_marks_vision_failed(self):
        sections, summary = self._run_with(
            synthesize_objectives_depth=_raise_repair)
        self.assertEqual(
            summary.get('synth_status', {}).get('vision'), 'failed')
        # Section content unchanged — no deterministic fallback rows.
        self.assertEqual(sections['vision'], '')

    def test_2_roadmap_repair_error_marks_roadmap_failed(self):
        sections, summary = self._run_with(
            synthesize_roadmap_depth=_raise_repair)
        self.assertEqual(
            summary.get('synth_status', {}).get('roadmap'), 'failed')
        self.assertEqual(sections['roadmap'], '')

    def test_3_kpi_repair_error_marks_kpis_failed(self):
        sections, summary = self._run_with(
            synthesize_kpi_depth=_raise_repair)
        self.assertEqual(
            summary.get('synth_status', {}).get('kpis'), 'failed')
        self.assertEqual(sections['kpis'], '')

    def test_9_generic_exception_does_not_set_synth_failed(self):
        # Replace all three migrated synths with generic exceptions —
        # legacy log-and-continue path must remain.
        sections, summary = self._run_with(
            synthesize_objectives_depth=_raise_generic,
            synthesize_roadmap_depth=_raise_generic,
            synthesize_kpi_depth=_raise_generic)
        status = summary.get('synth_status', {})
        self.assertNotIn('vision', status)
        self.assertNotIn('roadmap', status)
        self.assertNotIn('kpis', status)

    def test_10_no_deterministic_rows_inserted_after_repair_error(self):
        sections, _ = self._run_with(
            synthesize_objectives_depth=_raise_repair,
            synthesize_roadmap_depth=_raise_repair,
            synthesize_kpi_depth=_raise_repair)
        for sk in ('vision', 'roadmap', 'kpis'):
            self.assertEqual(
                sections[sk], '',
                msg=f'section {sk} was mutated after RepairError')


@unittest.skipIf(_APP is None, 'app.py unavailable')
class ConvergenceLoopFailClosed(unittest.TestCase):
    """Scenarios 4–6: ``converge_strategy_sections`` repair branches."""

    def _run_loop(self, **patches):
        sections = _empty_sections()
        # Force every section to fail audit so all repair branches fire.
        ctx = {'sector': 'Government', 'org_name': 'Acme',
               'maturity': 'initial', 'generation_mode': 'consulting'}

        # Stub out the OTHER repair helpers so the loop doesn't fail
        # for unrelated reasons. Replace them with no-ops; they neither
        # raise nor mutate sections (which keeps audit failing).
        def _noop(*_a, **_k):
            return None

        defaults = dict(
            synthesize_objectives_depth=_noop,
            synthesize_pillars_depth=_noop,
            synthesize_environment_context=_noop,
            synthesize_gaps_depth=_noop,
            synthesize_roadmap_depth=_noop,
            synthesize_kpi_depth=_noop,
            synthesize_confidence_depth=_noop,
            rebuild_canonical_kpi_section=_noop,
        )
        defaults.update(patches)

        cms = [_Patch(_APP, name, fn) for name, fn in defaults.items()]
        for cm in cms:
            cm.__enter__()
        try:
            log = _APP.converge_strategy_sections(
                sections, 'ar', 'Cyber Security', 'NCA ECC',
                ctx=ctx, doc_subtype=None, max_iter=1)
        finally:
            for cm in reversed(cms):
                cm.__exit__(None, None, None)
        return sections, log

    def test_4_objectives_repair_error_marks_vision_failed(self):
        sections, log = self._run_loop(
            synthesize_objectives_depth=_raise_repair)
        self.assertEqual(log['synth_status'].get('vision'), 'failed')
        self.assertFalse(log['converged'])
        self.assertEqual(sections['vision'], '')

    def test_5_roadmap_repair_error_marks_roadmap_failed(self):
        sections, log = self._run_loop(
            synthesize_roadmap_depth=_raise_repair)
        self.assertEqual(log['synth_status'].get('roadmap'), 'failed')
        self.assertFalse(log['converged'])

    def test_6_kpi_repair_error_marks_kpis_failed(self):
        # Even when KPI synth raises RepairError, the schema-only
        # ``rebuild_canonical_kpi_section`` MUST still run (PR-5B.5F1
        # restructure).
        rebuild_calls = []

        def _spy_rebuild(*a, **k):
            rebuild_calls.append((a, k))

        sections, log = self._run_loop(
            synthesize_kpi_depth=_raise_repair,
            rebuild_canonical_kpi_section=_spy_rebuild)
        self.assertEqual(log['synth_status'].get('kpis'), 'failed')
        self.assertFalse(log['converged'])
        self.assertGreaterEqual(
            len(rebuild_calls), 1,
            msg='rebuild_canonical_kpi_section must still run when '
                'synthesize_kpi_depth raises RepairError')


@unittest.skipIf(_APP is None, 'app.py unavailable')
class FinalAuditGate(unittest.TestCase):
    """Scenario 8: final audit emits ``synth_failed:<section>`` defects."""

    def test_8_audit_emits_synth_failed_defect_per_failed_section(self):
        # Build sections that already meet every richness threshold —
        # without synth_status the audit returns []; with synth_status
        # it emits one defect per failed entry.
        sections = _empty_sections()
        # Empty sections WILL produce richness defects, but the new
        # synth_failed defect must still be present alongside them.
        synth_status = {
            'vision': 'failed',
            'roadmap': 'failed',
            'kpis': 'failed',
        }
        defects = _APP._final_strategy_audit(
            sections, 'ar', None, synth_status=synth_status)
        defect_tags = {(s, t) for s, t, _, _ in defects}
        self.assertIn(('vision', 'synth_failed:vision'), defect_tags)
        self.assertIn(('roadmap', 'synth_failed:roadmap'), defect_tags)
        self.assertIn(('kpis', 'synth_failed:kpis'), defect_tags)

    def test_8b_audit_without_synth_status_kwarg_unchanged(self):
        # Backward-compatible signature: existing callers that pass
        # only (sections, lang, doc_subtype) still work and get NO
        # synth_failed defects.
        sections = _empty_sections()
        defects = _APP._final_strategy_audit(sections, 'ar', None)
        for sec, tag, _c, _m in defects:
            self.assertFalse(tag.startswith('synth_failed:'))

    def test_8c_audit_synth_status_with_only_ok_entries_no_defects(self):
        sections = _empty_sections()
        defects = _APP._final_strategy_audit(
            sections, 'ar', None,
            synth_status={'vision': 'ok', 'roadmap': 'ok'})
        for sec, tag, _c, _m in defects:
            self.assertFalse(tag.startswith('synth_failed:'))


@unittest.skipIf(_APP is None, 'app.py unavailable')
class RoadmapTopupFailClosed(unittest.TestCase):
    """Scenario 7: roadmap depth-safety top-up fail-closed via helper.

    The top-up site lives inline in the strategy save endpoint; it is
    not directly callable from a unit test. We verify the helper
    contract that the patched call site uses: ``_mark_synth_failed``
    writes ``synth_status['roadmap'] = 'failed'`` and the audit gate
    surfaces a ``synth_failed:roadmap`` defect.
    """

    def test_7_mark_synth_failed_writes_roadmap_failed(self):
        container = {}
        _APP._mark_synth_failed(
            container, 'roadmap', _APP.RepairError('top-up forced'))
        self.assertEqual(
            container.get('synth_status', {}).get('roadmap'), 'failed')
        # Threading the same dict into the audit produces the blocker
        # defect that the post-normalization save gate consumes.
        defects = _APP._final_strategy_audit(
            _empty_sections(), 'ar', None,
            synth_status=container['synth_status'])
        defect_tags = {(s, t) for s, t, _, _ in defects}
        self.assertIn(('roadmap', 'synth_failed:roadmap'), defect_tags)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
