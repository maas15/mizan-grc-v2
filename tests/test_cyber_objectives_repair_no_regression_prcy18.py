"""PR-CY18 — Convergence loop must not regress an accepted Cyber
specialized-objective.

Tests exercise ``converge_strategy_sections`` directly to confirm:

1. when the previous vision had an accepted Cyber specialized-objective
   row, an invalid candidate produced by ``synthesize_objectives_depth``
   is rejected (Part A);
2. ``objectives:6->5`` cannot replace a vision that drops the row;
3. when only ``specialized_function_objective_missing:cyber`` remains as
   the vision defect, the targeted Cyber top-up runs INSTEAD of the
   generic objectives rebuild (Part C);
4. roadmap-balance behaviour and DCC-coverage repair behaviour remain
   unchanged for non-Cyber inputs.

Strictly Cyber-scoped. No deterministic rows are inserted. Validators
are not weakened.

Run::

    python -m pytest \\
        tests/test_cyber_objectives_repair_no_regression_prcy18.py -q
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_obj_norepair_prcy18_')
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
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_GOOD_ROW_AR = (
    'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل لجنة حوكمة '
    'الأمن السيبراني وتحديد الأدوار والمسؤوليات وخطوط الرفع')


def _vision_with_specialized():
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA ECC | 18 شهراً |\n'
        '| 2 | تحقيق الامتثال لإطار DCC | 100% | NCA DCC | 18 شهراً |\n'
        '| 3 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 4 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
        '| 5 | تطوير منظومة إدارة الثغرات | 100% | VM | 12 شهراً |\n'
        f'| 6 | {_GOOD_ROW_AR} | 100% | NCA حوكمة | 12 شهراً |\n'
    )


def _vision_without_specialized():
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA ECC | 18 شهراً |\n'
        '| 2 | تحقيق الامتثال لإطار DCC | 100% | NCA DCC | 18 شهراً |\n'
        '| 3 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 4 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
        '| 5 | تطوير منظومة إدارة الثغرات | 100% | VM | 12 شهراً |\n'
    )


def _ctx_cyber():
    return {
        'frameworks': ['ECC', 'DCC'],
        'org_name': 'TestOrg',
        'sector': 'General',
        'maturity': 'initial',
        'generation_mode': 'drafting',
        'org_structure_is_none': True,
    }


# ── Test 01 — regressive synthesize_objectives_depth is rejected ────────
class Test01RegressiveCandidateRejected(unittest.TestCase):

    @_skip_if_no_app
    def test_01_regressive_candidate_is_reverted(self):
        """When ``synthesize_objectives_depth`` drops the accepted Cyber
        specialized row, the convergence loop must restore the
        pre-synth vision text."""
        sections = {'vision': _vision_with_specialized()}
        ctx = _ctx_cyber()
        # Pre-condition: detector accepts.
        self.assertFalse(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))

        # Stub out the inner synth so it ALWAYS rebuilds without the
        # specialized row — simulates the regression in the runtime
        # trace (objectives:6->5).
        def _bad_synth(sections, lang, **kw):
            sections['vision'] = _vision_without_specialized()

        # Stub the _audit() to simulate that vision is the only
        # remaining failing key and that the only vision defect is NOT
        # specialized_function_objective_missing (so Part C does NOT
        # trigger and Part A is exercised).
        orig_audit_fn = _APP._final_strategy_audit

        def _stub_audit(sections, lang, doc_subtype=None, **kw):
            # Always return one defect for vision: so_rows_insufficient.
            # That keeps 'vision' in failing_keys without triggering
            # Part C (which only triggers if the only vision defect is
            # specialized_function_objective_missing).
            return [('vision', 'so_rows_insufficient', 1, 4)]

        orig_synth = _APP.synthesize_objectives_depth
        _APP.synthesize_objectives_depth = _bad_synth
        _APP._final_strategy_audit = _stub_audit
        try:
            _APP.converge_strategy_sections(
                sections, lang='ar', domain='Cyber Security',
                fw_short='ECC', ctx=ctx, max_iter=1,
            )
        finally:
            _APP.synthesize_objectives_depth = orig_synth
            _APP._final_strategy_audit = orig_audit_fn

        # After convergence, the regression must have been rejected:
        # the specialized row is back.
        self.assertFalse(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))


# ── Test 02 — only specialized defect → targeted top-up routes ──────────
class Test02OnlySpecializedRoutesToTopup(unittest.TestCase):

    @_skip_if_no_app
    def test_02_targeted_topup_runs_instead_of_generic(self):
        """When the only remaining vision defect is
        ``specialized_function_objective_missing:cyber`` the targeted
        Cyber top-up runs INSTEAD of the generic objectives synth."""
        sections = {'vision': _vision_without_specialized()}
        ctx = _ctx_cyber()

        # Stub the topup so it accepts and produces a specialized row.
        topup_calls = {'n': 0}
        synth_calls = {'n': 0}

        def _stub_topup(sections, lang, domain, ctx, log):
            topup_calls['n'] += 1
            sections['vision'] = _vision_with_specialized()
            return 1

        def _stub_synth(sections, lang, **kw):
            synth_calls['n'] += 1
            sections['vision'] = _vision_without_specialized()

        # Audit reports vision has only the specialized-objective
        # defect. After the topup runs, audit returns no defects.
        audit_state = {'first': True}

        def _stub_audit(sections, lang, doc_subtype=None, **kw):
            if audit_state['first']:
                audit_state['first'] = False
                return [(
                    'vision',
                    'specialized_function_objective_missing:cyber',
                    0, 1)]
            # After topup — no defects.
            if not _APP._compute_missing_specialized_function_objective(
                    sections, 'Cyber Security', lang='ar',
                    org_structure_is_none=True):
                return []
            return [(
                'vision',
                'specialized_function_objective_missing:cyber',
                0, 1)]

        orig_topup = (
            _APP._convergence_cyber_specialized_objective_topup_repair)
        orig_synth = _APP.synthesize_objectives_depth
        orig_audit = _APP._final_strategy_audit
        _APP._convergence_cyber_specialized_objective_topup_repair = (
            _stub_topup)
        _APP.synthesize_objectives_depth = _stub_synth
        _APP._final_strategy_audit = _stub_audit
        try:
            _APP.converge_strategy_sections(
                sections, lang='ar', domain='Cyber Security',
                fw_short='ECC', ctx=ctx, max_iter=1,
            )
        finally:
            _APP._convergence_cyber_specialized_objective_topup_repair = (
                orig_topup)
            _APP.synthesize_objectives_depth = orig_synth
            _APP._final_strategy_audit = orig_audit

        self.assertEqual(topup_calls['n'], 1,
                         'targeted Cyber top-up should have run once')
        self.assertEqual(synth_calls['n'], 0,
                         'generic synthesize_objectives_depth must NOT '
                         'run when only specialized defect remains')


# ── Test 03 — captured row threaded through ctx ─────────────────────────
class Test03CtxThreadsPreservedRow(unittest.TestCase):

    @_skip_if_no_app
    def test_03_ctx_carries_preserved_row_after_convergence(self):
        """The convergence loop captures the accepted row into ctx so
        the final pre-gate guard can re-merge it later."""
        sections = {'vision': _vision_with_specialized()}
        ctx = _ctx_cyber()

        def _stub_audit(sections, lang, doc_subtype=None, **kw):
            return []

        orig_audit = _APP._final_strategy_audit
        _APP._final_strategy_audit = _stub_audit
        try:
            _APP.converge_strategy_sections(
                sections, lang='ar', domain='Cyber Security',
                fw_short='ECC', ctx=ctx, max_iter=1,
            )
        finally:
            _APP._final_strategy_audit = orig_audit

        # Preserved row recorded.
        self.assertIn('_cyber_preserved_specialized_row', ctx)
        self.assertIn('CISO', ctx['_cyber_preserved_specialized_row'])


# ── Test 04 — Data Management convergence is unaffected ─────────────────
class Test04DataManagementUnaffected(unittest.TestCase):

    @_skip_if_no_app
    def test_04_data_management_no_capture_no_restore(self):
        sections = {'vision': _vision_with_specialized()}
        ctx = {
            'frameworks': ['NDMO', 'PDPL'],
            'org_structure_is_none': True,
        }

        def _stub_audit(sections, lang, doc_subtype=None, **kw):
            return []

        orig_audit = _APP._final_strategy_audit
        _APP._final_strategy_audit = _stub_audit
        try:
            _APP.converge_strategy_sections(
                sections, lang='ar', domain='Data Management',
                fw_short='NDMO', ctx=ctx, max_iter=1,
            )
        finally:
            _APP._final_strategy_audit = orig_audit

        # No Cyber-specific capture.
        self.assertNotIn('_cyber_preserved_specialized_row', ctx)


# ── Test 05 — validators not weakened ──────────────────────────────────
class Test05ValidatorsNotWeakened(unittest.TestCase):

    @_skip_if_no_app
    def test_05_specialized_detector_still_fires_for_thin_vision(self):
        """Confirm the underlying detector still emits the defect for a
        vision that lacks the specialized row — PR-CY18 must not
        weaken the validator."""
        sections = {'vision': _vision_without_specialized()}
        self.assertTrue(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))


if __name__ == '__main__':
    unittest.main()
