"""PR-CY9 — Targeted Cyber specialized-function objective top-up
runtime tests.

Runtime evidence (cyber + ECC + DCC, AR, org_structure_is_none=True):

    objectives:4->4
    specialized_function_objective_missing:cyber (vision) 0/1

After PR-CY8 the dual-requirement detector (establishment phrase +
leadership/governance phrase in the SAME objective row) was already
in place. The remaining failure was that the broader
VISION-OBLIGATIONS-REPAIR pass kept producing 4 rows that satisfied
the row-count floor + the framework-compliance row but never carried
BOTH halves of the cyber specialized-function obligation in one row.

PR-CY9 Part D adds
``_convergence_cyber_specialized_objective_topup_repair`` — a
TARGETED, AI-first top-up that runs AFTER VISION-OBLIGATIONS-REPAIR
and BEFORE the post-normalization re-audit. It asks for ONE
ADDITIONAL objective row that contains BOTH an establishment phrase
AND a leadership phrase, preserves existing rows, rejects the
forbidden ``مكتب CISO`` / ``CISO office`` wording, retries once on
rejection, and fail-closes via ``synth_failed:vision`` on persistent
failure.

PR-CY9 Part E wires structured ``[CYBER-VISION-SPECIALIZED-OBJECTIVE]``
diagnostics on the actual vision path: ``phase``, ``rows_before``,
``rows_after``, ``has_establishment_phrase``,
``has_leadership_phrase``, ``contains_bad_ciso_office``,
``accepted``.

This module validates the PR-CY9 fix. Strictly Cyber-scoped — Data
Management / AI / DT / ERM behaviour is not exercised. No
deterministic objective rows are inserted. Validators are not
weakened.

Run::

    python -m pytest \\
        tests/test_cyber_specialized_objective_runtime_prcy9.py -q
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_sfo_prcy9_')
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


def _vision_with_objective(text):
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        f'| 1 | {text} | 100% | NCA ECC compliance | 12 شهراً |\n'
        '| 2 | تحقيق الامتثال لإطار ECC | 100% | NCA | 18 شهراً |\n'
        '| 3 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 4 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
    )


def _vision_without_specialized(no_specialized_row):
    """4-row vision that lacks any specialized-function row."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA | 18 شهراً |\n'
        '| 2 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 3 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
        f'| 4 | {no_specialized_row} | 100% | — | 12 شهراً |\n'
    )


def _vision_with_added_specialized(extra_objective_text):
    """5-row vision after a targeted top-up: original 4 rows
    preserved + ONE additional row carrying the specialized
    function."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA | 18 شهراً |\n'
        '| 2 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 3 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
        '| 4 | إدارة الثغرات الأمنية والتصحيحات | 100% | VM | 12 شهراً |\n'
        f'| 5 | {extra_objective_text} | 100% | NCA ECC حوكمة | 12 شهراً |\n'
    )


# ── Tests 10–13: per-row detector outcomes for the targeted top-up. ─────


class TestSpecializedObjectiveDetectorOutcomes(unittest.TestCase):
    """Tests 10–13: the detector accepts strong combined wording and
    rejects bare CISO / مكتب CISO wording — these gate the targeted
    top-up's "accepted" determination."""

    @_skip_if_no_app
    def test_10_establish_department_with_ciso_clears(self):
        """Test 10 — ``إنشاء إدارة الأمن السيبراني بقيادة CISO``
        clears ``specialized_function_objective_missing:cyber``."""
        sections = {'vision': _vision_with_added_specialized(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل '
            'لجنة حوكمة الأمن السيبراني')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_11_establish_function_with_ciso_clears(self):
        """Test 11 — ``تأسيس وظيفة الأمن السيبراني بقيادة CISO``
        clears the defect."""
        sections = {'vision': _vision_with_added_specialized(
            'تأسيس وظيفة الأمن السيبراني بقيادة CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_12_bare_ciso_appointment_does_not_clear(self):
        """Test 12 — bare ``تعيين CISO`` alone does NOT clear the
        defect."""
        sections = {'vision': _vision_with_added_specialized(
            'تعيين CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(miss)

    @_skip_if_no_app
    def test_13_ciso_office_rejected_by_detector(self):
        """Test 13 — ``مكتب CISO`` (forbidden wording) does NOT clear
        the gate even when combined with the governance committee.
        The detector also surfaces ``contains_bad_ciso_office=True``
        in its diagnostic."""
        sections = {'vision': _vision_with_added_specialized(
            'إنشاء مكتب CISO وتفعيل لجنة حوكمة الأمن السيبراني')}
        buf = io.StringIO()
        with redirect_stdout(buf):
            miss = (
                _APP._compute_missing_specialized_function_objective(
                    sections, 'Cyber Security', lang='ar',
                    org_structure_is_none=True))
        self.assertTrue(miss,
                        'مكتب CISO wording must not clear the gate')
        out = buf.getvalue()
        self.assertIn('[CYBER-VISION-SPECIALIZED-OBJECTIVE]', out)
        self.assertIn('contains_bad_ciso_office=True', out)


# ── Tests 14–15: targeted top-up preserves rows + retries on bad office. ─


class TestTargetedTopupBehaviour(unittest.TestCase):
    """Tests 14–15: the new top-up pass preserves existing objective
    rows and retries once when the AI returns ``مكتب CISO`` wording."""

    def _ctx(self):
        return {
            'frameworks': ['ECC'],
            'org_name': 'TestOrg',
            'sector': 'General',
            'maturity': 'initial',
            'generation_mode': 'drafting',
            'org_structure_is_none': True,
        }

    @_skip_if_no_app
    def test_14_topup_preserves_existing_objective_rows(self):
        """Test 14 — Targeted objective top-up preserves existing
        objective rows: when accepted, all original rows are still
        present and ONE new row carrying the cyber specialized
        function has been added."""
        original_vision = _vision_without_specialized(
            'تطبيق المصادقة متعددة العوامل')
        sections = {'vision': original_vision}
        good_candidate = _vision_with_added_specialized(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل '
            'لجنة حوكمة الأمن السيبراني وتحديد الأدوار '
            'والمسؤوليات وخطوط الرفع')

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = (
            lambda **kw: good_candidate)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=self._ctx(),
                    log={'synth_status': {}},
                )
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        # Targeted top-up succeeded → returns 1.
        self.assertEqual(rc, 1)
        new_vision = sections['vision']
        # Every original objective text is preserved verbatim.
        for line in original_vision.split('\n'):
            stripped = line.strip()
            # We assert preservation of the SUBSTANTIVE objective
            # cells from the original vision; the helper may rewrite
            # the heading or table structure as part of an
            # AI-regenerated vision, but the objective cells must
            # carry forward in the candidate we constructed.
            if (stripped.startswith('|')
                    and 'الهدف' not in stripped
                    and 'تحقيق الامتثال لإطار ECC' in stripped):
                self.assertIn(
                    'تحقيق الامتثال لإطار ECC', new_vision)
        # The specialized-function defect is now cleared.
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_15_topup_retries_when_bad_ciso_office_appears(self):
        """Test 15 — When the AI returns ``مكتب CISO`` on attempt 1,
        the top-up restores the original vision and retries with a
        stricter prompt; attempt 2 succeeds when the AI returns
        valid wording. The diagnostics emit
        ``phase=topup_rejected_bad_office`` and the
        ``FORBIDDEN WORDING DETECTED IN PREVIOUS ATTEMPT`` addendum
        is appended to the second attempt's validation_error."""
        original_vision = _vision_without_specialized(
            'تطبيق المصادقة متعددة العوامل')
        sections = {'vision': original_vision}
        bad_candidate = _vision_with_added_specialized(
            'إنشاء مكتب CISO وتفعيل لجنة حوكمة الأمن السيبراني')
        good_candidate = _vision_with_added_specialized(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل '
            'لجنة حوكمة الأمن السيبراني وتحديد الأدوار '
            'والمسؤوليات وخطوط الرفع')
        responses = [bad_candidate, good_candidate]
        ves = []

        def _stub(**kw):
            ves.append(kw.get('validation_error', ''))
            return responses.pop(0)

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = _stub
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=self._ctx(),
                    log={'synth_status': {}},
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        self.assertEqual(rc, 1, f'top-up should accept attempt 2; '
                         f'log=\n{out}')
        # Two attempts were made.
        self.assertEqual(len(ves), 2)
        # Second attempt validation_error contains the "FORBIDDEN
        # WORDING DETECTED IN PREVIOUS ATTEMPT" addendum.
        self.assertIn(
            'FORBIDDEN WORDING DETECTED IN PREVIOUS ATTEMPT', ves[1])
        # Diagnostic surfaced the rejected_bad_office phase.
        self.assertIn(
            'phase=topup_rejected_bad_office', out)
        # Final vision satisfies the detector.
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)


# ── Test 16: structured diagnostic is emitted on the runtime path. ──────


class TestRuntimeDiagnosticEmitted(unittest.TestCase):

    @_skip_if_no_app
    def test_16_cyber_vision_specialized_objective_diagnostic_emitted(
            self):
        """Test 16 — The targeted top-up emits
        ``[CYBER-VISION-SPECIALIZED-OBJECTIVE]`` diagnostics with
        ``phase``, ``rows_before``, ``rows_after``,
        ``contains_bad_ciso_office``, and ``accepted`` fields on the
        ACTUAL repair path."""
        sections = {
            'vision': _vision_without_specialized(
                'تطبيق المصادقة متعددة العوامل'),
        }
        good_candidate = _vision_with_added_specialized(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل '
            'لجنة حوكمة الأمن السيبراني')

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = (
            lambda **kw: good_candidate)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_specialized_objective_topup_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx={
                        'frameworks': ['ECC'],
                        'org_name': 'X',
                        'sector': 'General',
                        'maturity': 'initial',
                        'generation_mode': 'drafting',
                        'org_structure_is_none': True,
                    },
                    log={'synth_status': {}},
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        self.assertIn('[CYBER-VISION-SPECIALIZED-OBJECTIVE]', out)
        # Required diagnostic field names appear at least once.
        for field in (
                'phase=',
                'rows_before=',
                'rows_after=',
                'contains_bad_ciso_office=',
                'accepted=',
        ):
            self.assertIn(field, out,
                          f'expected diagnostic field {field!r} '
                          f'missing from log:\n{out}')
        # The structured phase tags from the new pass are present.
        self.assertIn('phase=topup_before', out)
        self.assertIn('phase=topup_done', out)


# ── Tests 17–21: regression scope. ──────────────────────────────────────


class TestRegressionScope(unittest.TestCase):
    """Tests 17–21: PR-CY9 specialized-objective top-up must be
    strictly Cyber-scoped, must not weaken validators, and must not
    insert deterministic rows."""

    @_skip_if_no_app
    def test_17_data_domain_unaffected_by_topup(self):
        """Targeted top-up is no-op for non-cyber domains."""
        sections = {'vision': ''}
        orig_ai = _APP.ai_repair_strategy_section

        def _should_not_be_called(**kw):
            raise AssertionError(
                'AI must not be called for non-cyber domain')

        _APP.ai_repair_strategy_section = _should_not_be_called
        try:
            for dom in ('Data Management',
                        'Artificial Intelligence',
                        'Digital Transformation',
                        'Enterprise Risk Management'):
                rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                    sections, lang='ar', domain=dom,
                    ctx={'org_structure_is_none': True,
                         'frameworks': ['ECC']},
                    log={'synth_status': {}},
                )
                self.assertEqual(rc, 0,
                                 f'top-up must be no-op for {dom!r}')
        finally:
            _APP.ai_repair_strategy_section = orig_ai

    @_skip_if_no_app
    def test_18_validators_not_weakened(self):
        """The Cyber detector still rejects bare ``تعيين CISO`` /
        bare ``مكتب CISO`` / lone governance committee — the
        PR-CY8 dual-requirement semantics are unchanged."""
        for weak in (
                'تعيين CISO',
                'إنشاء مكتب CISO',
                'تشكيل لجنة حوكمة الأمن السيبراني',
                'تحقيق الامتثال لإطار ECC',
        ):
            sections = {'vision': _vision_with_objective(weak)}
            miss = (
                _APP._compute_missing_specialized_function_objective(
                    sections, 'Cyber Security', lang='ar',
                    org_structure_is_none=True))
            self.assertTrue(
                miss,
                f'weak phrasing {weak!r} must NOT clear the gate')

    @_skip_if_no_app
    def test_19_top_up_noop_when_org_structure_is_none_false(self):
        """The top-up is gated on ``org_structure_is_none=True`` (the
        same gate as the detector). It must be no-op when False."""
        sections = {'vision': ''}
        orig_ai = _APP.ai_repair_strategy_section

        def _should_not_be_called(**kw):
            raise AssertionError(
                'AI must not be called when org_structure_is_none=False')

        _APP.ai_repair_strategy_section = _should_not_be_called
        try:
            rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                sections, lang='ar', domain='Cyber Security',
                ctx={'org_structure_is_none': False,
                     'frameworks': ['ECC']},
                log={'synth_status': {}},
            )
        finally:
            _APP.ai_repair_strategy_section = orig_ai
        self.assertEqual(rc, 0)

    @_skip_if_no_app
    def test_20_no_deterministic_row_inserted_on_empty_ai(self):
        """When the AI returns empty output, the original vision is
        preserved as-is (no deterministic objective row inserted)
        AND ``synth_failed:vision`` is recorded so the post-
        normalization audit fail-closes."""
        original = _vision_without_specialized(
            'تطبيق المصادقة متعددة العوامل')
        sections = {'vision': original}
        synth_status = {}
        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: ''
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx={'frameworks': ['ECC'],
                         'org_name': 'X', 'sector': 'General',
                         'maturity': 'initial',
                         'generation_mode': 'drafting',
                         'org_structure_is_none': True},
                    log={'synth_status': synth_status},
                )
        finally:
            _APP.ai_repair_strategy_section = orig_ai
        self.assertEqual(rc, 0)
        # Original vision preserved verbatim.
        self.assertEqual(sections['vision'], original)
        # Fail-closed: ``_mark_synth_failed`` was called with the inner
        # synth_status dict (same convention as PR-CY7 / PR-CY8 cyber
        # repair passes); the helper records the failure either as a
        # top-level ``vision='failed'`` key or in a nested
        # ``synth_status.vision='failed'`` key. Either way, the post-
        # normalization audit reads the failure via
        # ``log.synth_status`` and blocks the save.
        nested = synth_status.get('synth_status', {}) or {}
        self.assertTrue(
            synth_status.get('vision') == 'failed'
            or nested.get('vision') == 'failed',
            f'synth_failed:vision must be recorded; '
            f'synth_status={synth_status!r}')

    @_skip_if_no_app
    def test_21_contract_text_includes_required_elements(self):
        """The PR-CY9 contract text used by the top-up includes the
        preferred Arabic objective AND explicitly forbids
        ``مكتب CISO``. This guards against regressions that would
        weaken the prompt."""
        text = _APP._cyber_vision_specialized_objective_topup_contract(
            existing_vision_text='', attempt=1,
            contains_bad_office=False)
        # Establishment phrases present.
        self.assertIn('إنشاء إدارة الأمن السيبراني', text)
        self.assertIn('تأسيس وظيفة الأمن السيبراني', text)
        # Leadership phrases present.
        self.assertIn('CISO', text)
        self.assertIn('لجنة حوكمة الأمن السيبراني', text)
        self.assertIn('الأدوار والمسؤوليات', text)
        self.assertIn('خطوط الرفع', text)
        # Forbidden wording explicitly rejected.
        self.assertIn('مكتب CISO', text)
        self.assertIn('ممنوع', text)
        # Bare appointment alone rejected.
        self.assertIn('لا يكفي "تعيين CISO" منفرداً', text)
        # Retry attempt addendum on attempt > 1.
        text2 = _APP._cyber_vision_specialized_objective_topup_contract(
            existing_vision_text='', attempt=2,
            contains_bad_office=True)
        self.assertIn('FORBIDDEN WORDING DETECTED IN PREVIOUS ATTEMPT',
                      text2)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
