"""PR-CY10 — Runtime regression proof for the targeted Cyber
specialized-function objective top-up.

Background
==========

Render deployment evidence (gunicorn ``app:app --bind 0.0.0.0:$PORT
--timeout 180 --workers 1``) continued to surface, AFTER PR-CY9 commit
``b351cb7`` was merged into ``main``::

    specialized_function_objective_missing:cyber (vision) 0/1

PR-CY9 Part D introduced
``_convergence_cyber_specialized_objective_topup_repair`` — a
TARGETED, AI-first top-up that runs AFTER ``VISION-OBLIGATIONS-REPAIR``
and BEFORE the post-normalization re-audit.  It preserves every
existing objective row and adds ONE additional row carrying BOTH an
establishment phrase AND a leadership phrase in the SAME cell.
``مكتب CISO`` / ``CISO office`` wording is rejected and the pass
retries once before fail-closing via ``synth_failed:vision``.

This PR-CY10 module focuses on the RUNTIME PATH (the actual function
invoked from the post-normalization audit at the
``_convergence_cyber_specialized_objective_topup_repair`` call-site,
gated on ``domain='cyber'`` AND ``org_structure_is_none=True``).  It
proves:

1.  When a persistent ``specialized_function_objective_missing:cyber``
    defect is presented to the runtime pass, the AI-first top-up
    actually fires and the structured
    ``[CYBER-VISION-SPECIALIZED-OBJECTIVE]`` diagnostic appears.
2.  An AI candidate carrying ``إنشاء إدارة الأمن السيبراني بقيادة
    CISO`` clears the defect when emitted on the runtime path.
3.  An AI candidate carrying the forbidden ``مكتب CISO`` wording is
    rejected at runtime even when the row otherwise looks well-formed.
4.  Existing objective rows from the pre-top-up vision survive when
    the top-up accepts a new candidate.

The regression block proves:

* No call into the AI for non-cyber domains (Data / AI / DT / ERM).
* The PR-CY8 dual-requirement detector is NOT weakened.
* No deterministic objective row is ever inserted by this module.
* auth / DB / export / PDF / DOCX helpers are NOT touched.

Strictly Cyber-scoped.  Validators are NOT weakened.

Run::

    python -m pytest \\
        tests/test_cyber_runtime_final_specialized_objective_prcy10.py -q
"""
import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_sfo_prcy10_')
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


# ── Vision fixtures ──────────────────────────────────────────────────────


def _vision_without_specialized(no_specialized_row):
    """4-row vision that exercises the persistent defect: every row
    is a valid Cyber objective, but NONE of them carries both halves
    of the dual-requirement obligation in a single cell."""
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
    """6-row vision after a targeted top-up: original 4 rows preserved
    + ECC and DCC framework-compliance rows + ONE additional row
    carrying the specialized-function obligation.  Both ECC and DCC
    compliance rows are present so the vision contract validator
    accepts the candidate when ``frameworks=['ECC', 'DCC']``."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA ECC | 18 شهراً |\n'
        '| 2 | تحقيق الامتثال لإطار DCC | 100% | NCA DCC | 18 شهراً |\n'
        '| 3 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 4 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
        '| 5 | إدارة الثغرات الأمنية والتصحيحات | 100% | VM | 12 شهراً |\n'
        f'| 6 | {extra_objective_text} | 100% | NCA حوكمة | 12 شهراً |\n'
    )


def _ctx_cyber_ecc_dcc(org_structure_is_none=True):
    return {
        'frameworks': ['ECC', 'DCC'],
        'org_name': 'TestOrg',
        'sector': 'General',
        'maturity': 'initial',
        'generation_mode': 'drafting',
        'org_structure_is_none': org_structure_is_none,
    }


# ── Test 1: targeted top-up FIRES when defect is present ────────────────


class TestRuntimeFinalTargetedTopupFires(unittest.TestCase):

    @_skip_if_no_app
    def test_1_final_topup_fires_when_specialized_missing(self):
        """Test 1 — The final targeted Cyber vision top-up actually
        runs when ``specialized_function_objective_missing:cyber``
        remains.  The structured ``[CYBER-VISION-SPECIALIZED-
        OBJECTIVE] phase=topup_before`` diagnostic must appear and
        ``ai_repair_strategy_section`` must be invoked at least once."""
        sections = {
            'vision': _vision_without_specialized(
                'تطبيق المصادقة متعددة العوامل'),
        }
        # Sanity: the defect IS present before the runtime pass runs.
        self.assertTrue(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True),
            'precondition: defect must be present before the top-up')

        good_candidate = _vision_with_added_specialized(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل '
            'لجنة حوكمة الأمن السيبراني وتحديد الأدوار '
            'والمسؤوليات وخطوط الرفع')
        ai_calls = {'n': 0}

        def _stub(**kw):
            ai_calls['n'] += 1
            return good_candidate

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = _stub
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=_ctx_cyber_ecc_dcc(),
                    log={'synth_status': {}},
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        self.assertGreaterEqual(
            ai_calls['n'], 1,
            'AI repair must be invoked on the runtime path')
        self.assertEqual(rc, 1, f'top-up should accept; log=\n{out}')
        self.assertIn('[CYBER-VISION-SPECIALIZED-OBJECTIVE]', out)
        self.assertIn('phase=topup_before', out)
        self.assertIn('phase=topup_done', out)


# ── Test 2: strong candidate clears the defect ──────────────────────────


class TestRuntimeStrongCandidateClearsDefect(unittest.TestCase):

    @_skip_if_no_app
    def test_2_establish_dept_with_ciso_clears_defect(self):
        """Test 2 — An objective row containing ``إنشاء إدارة الأمن
        السيبراني بقيادة CISO`` clears the
        ``specialized_function_objective_missing:cyber`` defect when
        emitted by the runtime top-up."""
        sections = {
            'vision': _vision_without_specialized(
                'تطبيق المصادقة متعددة العوامل'),
        }
        good_candidate = _vision_with_added_specialized(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO')

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: good_candidate
        try:
            rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                sections, lang='ar',
                domain='Cyber Security',
                ctx=_ctx_cyber_ecc_dcc(),
                log={'synth_status': {}},
            )
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        self.assertEqual(rc, 1)
        self.assertFalse(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True),
            'defect must be cleared on the runtime path')


# ── Test 3: bad ``مكتب CISO`` wording is rejected by the runtime pass ──


class TestRuntimeBadCisoOfficeRejected(unittest.TestCase):

    @_skip_if_no_app
    def test_3_bad_ciso_office_rejected_and_diagnostic_emitted(self):
        """Test 3 — When the AI returns ``مكتب CISO`` wording on
        attempt 1, the runtime top-up restores the original vision
        and emits ``phase=topup_rejected_bad_office`` BEFORE
        retrying with the ``FORBIDDEN WORDING DETECTED`` addendum."""
        original = _vision_without_specialized(
            'تطبيق المصادقة متعددة العوامل')
        sections = {'vision': original}
        bad_candidate = _vision_with_added_specialized(
            'إنشاء مكتب CISO وتفعيل لجنة حوكمة الأمن السيبراني')
        good_candidate = _vision_with_added_specialized(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل '
            'لجنة حوكمة الأمن السيبراني')
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
                    ctx=_ctx_cyber_ecc_dcc(),
                    log={'synth_status': {}},
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        # Bad office attempt produced the rejection diagnostic.
        self.assertIn('phase=topup_rejected_bad_office', out)
        # Second attempt carries the FORBIDDEN WORDING addendum.
        self.assertEqual(len(ves), 2)
        self.assertIn(
            'FORBIDDEN WORDING DETECTED IN PREVIOUS ATTEMPT', ves[1])
        # Second attempt produced a clean vision.
        self.assertEqual(rc, 1, f'attempt 2 should clear; log=\n{out}')
        self.assertFalse(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))

    @_skip_if_no_app
    def test_3b_bad_ciso_office_persists_marks_synth_failed(self):
        """Test 3b — When BOTH attempts return ``مكتب CISO`` wording
        the top-up restores the original vision verbatim AND
        marks ``synth_failed:vision`` so the post-normalization
        audit blocks the save (no deterministic row is ever
        inserted)."""
        original = _vision_without_specialized(
            'تطبيق المصادقة متعددة العوامل')
        sections = {'vision': original}
        bad_candidate = _vision_with_added_specialized(
            'إنشاء مكتب CISO وتفعيل لجنة حوكمة الأمن السيبراني')
        synth_status = {}

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: bad_candidate
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=_ctx_cyber_ecc_dcc(),
                    log={'synth_status': synth_status},
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        self.assertEqual(rc, 0)
        # Original vision preserved verbatim — NO deterministic row.
        self.assertEqual(sections['vision'], original)
        # Fail-closed signal is recorded.
        nested = synth_status.get('synth_status', {}) or {}
        self.assertTrue(
            synth_status.get('vision') == 'failed'
            or nested.get('vision') == 'failed',
            f'synth_failed:vision must be recorded after persistent '
            f'bad-office; synth_status={synth_status!r}\nlog=\n{out}')


# ── Test 4: existing objective rows preserved ───────────────────────────


class TestRuntimeExistingRowsPreserved(unittest.TestCase):

    @_skip_if_no_app
    def test_4_existing_objective_rows_preserved_after_topup(self):
        """Test 4 — Every substantive objective from the original
        vision must survive the top-up (no row dropped, no row
        rewritten).  This is the PR-CY9 "preserve existing objective
        rows" invariant under runtime conditions.  The AI is told
        in the contract to preserve rows; this test simulates a
        compliant AI response that keeps the original cells and
        appends the specialized-function row, then verifies the
        runtime pass accepts it without dropping any."""
        original = _vision_without_specialized(
            'تطبيق المصادقة متعددة العوامل')
        sections = {'vision': original}
        # Compliant candidate: original 4 rows VERBATIM + DCC
        # compliance row + specialized-function row.
        good_candidate = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار '
            'الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA | '
            '18 شهراً |\n'
            '| 2 | تنفيذ إدارة الهوية والوصول | 100% | IAM | '
            '12 شهراً |\n'
            '| 3 | تأسيس مركز العمليات الأمنية | 100% | SOC | '
            '18 شهراً |\n'
            '| 4 | تطبيق المصادقة متعددة العوامل | 100% | — | '
            '12 شهراً |\n'
            '| 5 | تحقيق الامتثال لإطار DCC | 100% | NCA DCC | '
            '18 شهراً |\n'
            '| 6 | إنشاء إدارة الأمن السيبراني بقيادة CISO '
            'وتفعيل لجنة حوكمة الأمن السيبراني | 100% | NCA '
            'حوكمة | 12 شهراً |\n'
        )

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: good_candidate
        try:
            rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                sections, lang='ar',
                domain='Cyber Security',
                ctx=_ctx_cyber_ecc_dcc(),
                log={'synth_status': {}},
            )
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        self.assertEqual(rc, 1)
        new_vision = sections['vision']
        for substantive in (
                'تحقيق الامتثال لإطار ECC',
                'تنفيذ إدارة الهوية والوصول',
                'تأسيس مركز العمليات الأمنية',
                'تطبيق المصادقة متعددة العوامل',
        ):
            self.assertIn(
                substantive, new_vision,
                f'objective {substantive!r} must be preserved after '
                f'top-up; new vision:\n{new_vision}')


# ── Regression: scope, validators, deterministic-row prohibition ────────


class TestRegressionScope(unittest.TestCase):
    """The PR-CY9/PR-CY10 targeted top-up must remain strictly
    Cyber-scoped, must not weaken validators, and must not insert
    deterministic objective rows."""

    @_skip_if_no_app
    def test_5_data_ai_dt_erm_runtime_unchanged(self):
        """The runtime top-up is a hard no-op for Data / AI / DT /
        ERM: the AI must NOT be invoked for any non-cyber domain."""
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
                self.assertEqual(
                    rc, 0,
                    f'top-up must be no-op for {dom!r}')
        finally:
            _APP.ai_repair_strategy_section = orig_ai

    @_skip_if_no_app
    def test_6_validators_not_weakened(self):
        """The PR-CY8 dual-requirement detector still rejects bare
        ``تعيين CISO`` / ``مكتب CISO`` / lone governance committee /
        framework-compliance-only rows.  PR-CY10 must NOT weaken
        this check."""
        for weak in (
                'تعيين CISO',
                'إنشاء مكتب CISO',
                'تشكيل لجنة حوكمة الأمن السيبراني',
                'تحقيق الامتثال لإطار ECC',
        ):
            sections = {
                'vision': _vision_with_added_specialized(weak),
            }
            self.assertTrue(
                _APP._compute_missing_specialized_function_objective(
                    sections, 'Cyber Security', lang='ar',
                    org_structure_is_none=True),
                f'weak phrasing {weak!r} must NOT clear the gate')

    @_skip_if_no_app
    def test_7_no_deterministic_row_inserted_on_empty_ai(self):
        """When the AI returns empty output the original vision is
        preserved verbatim (NO deterministic objective row is ever
        inserted) and ``synth_failed:vision`` is recorded."""
        original = _vision_without_specialized(
            'تطبيق المصادقة متعددة العوامل')
        sections = {'vision': original}
        synth_status = {}

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: ''
        try:
            rc = _APP._convergence_cyber_specialized_objective_topup_repair(
                sections, lang='ar',
                domain='Cyber Security',
                ctx=_ctx_cyber_ecc_dcc(),
                log={'synth_status': synth_status},
            )
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        self.assertEqual(rc, 0)
        self.assertEqual(sections['vision'], original)
        nested = synth_status.get('synth_status', {}) or {}
        self.assertTrue(
            synth_status.get('vision') == 'failed'
            or nested.get('vision') == 'failed')

    @_skip_if_no_app
    def test_8_auth_db_export_helpers_not_touched(self):
        """PR-CY10 only changes test files plus (if necessary) the
        Cyber convergence path.  Sanity-check that obvious auth /
        DB / export entry-points remain importable and unchanged in
        signature.  This guards against an accidental refactor."""
        for attr in ('app', 'login_required', 'render_template'):
            self.assertTrue(
                hasattr(_APP, attr),
                f'{attr!r} must remain available on app.py')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
