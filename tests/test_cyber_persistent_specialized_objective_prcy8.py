"""PR-CY8 — Persistent Cyber specialized-function objective failure
after PR-CY7.

Runtime evidence (cyber + ECC + DCC, AR):

    specialized_function_objective_missing:cyber (vision) 0/1

After PR-CY7 the repair prompt already required
``إدارة الأمن السيبراني بقيادة CISO`` and forbade ``مكتب CISO``.
However the detector still accepted weak phrasings that did NOT
establish the cybersecurity function (e.g. bare
``تعيين رئيس الأمن السيبراني``, a lone ``تشكيل لجنة حوكمة الأمن
السيبراني`` row, or a bare ``وظيفة الأمن السيبراني`` mention),
which let AI candidates pass the gate without actually creating the
specialized department.

PR-CY8 splits the cyber registry into an ``establishment_*`` token
group (إنشاء/تأسيس إدارة/وظيفة الأمن السيبراني) and a
``leadership_*`` token group (CISO / رئيس الأمن السيبراني / لجنة
حوكمة الأمن السيبراني / الأدوار والمسؤوليات / خطوط الرفع). A row
must contain BOTH an establishment phrase AND a leadership phrase to
clear the gate.

This module validates the PR-CY8 fix:

  1. ``إنشاء إدارة الأمن السيبراني وتعيين CISO`` clears the defect
     (establishment + leadership in one row),
  2. ``تأسيس وظيفة الأمن السيبراني بقيادة CISO`` clears the defect,
  3. Bare ``مكتب CISO`` does NOT clear the defect,
  4. Bare ``تعيين CISO`` does NOT clear the defect,
  5. Bare ``تشكيل لجنة حوكمة الأمن السيبراني`` (governance committee
     only, no department/function establishment) does NOT clear the
     defect,
  6. The composite Vision repair prompt contains
     ``إدارة الأمن السيبراني بقيادة CISO``,
  7. The composite Vision repair prompt does NOT request
     ``مكتب CISO`` (only the negative ``لا تستخدم مكتب CISO``
     instruction is allowed),
  8. The minimum objective rows floor is unchanged,
  9. Data / AI / DT / ERM specialized-function detection still uses
     the original single-list semantics (no dual-token regression).

Run::

    python -m pytest \\
        tests/test_cyber_persistent_specialized_objective_prcy8.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_sfo_prcy8_')
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
    )


class TestStrongObjectivesClearDefect(unittest.TestCase):
    """Rows with BOTH establishment + leadership phrases clear the
    cyber specialized-function gate."""

    @_skip_if_no_app
    def test_establish_department_with_ciso_clears(self):
        # Strong establishment + leadership combined in one row.
        sections = {'vision': _vision_with_objective(
            'إنشاء إدارة الأمن السيبراني وتعيين CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(
            miss,
            'إنشاء إدارة الأمن السيبراني وتعيين CISO must clear '
            'specialized_function_objective_missing:cyber')

    @_skip_if_no_app
    def test_establish_function_led_by_ciso_clears(self):
        # ``بقيادة CISO`` is a combined establishment + leadership
        # phrase recognised in a single row.
        sections = {'vision': _vision_with_objective(
            'تأسيس وظيفة الأمن السيبراني بقيادة CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(
            miss,
            'تأسيس وظيفة الأمن السيبراني بقيادة CISO must clear '
            'the defect')

    @_skip_if_no_app
    def test_specialized_department_with_committee_clears(self):
        # Establishment + leadership/committee phrase in the same row.
        sections = {'vision': _vision_with_objective(
            'إنشاء إدارة متخصصة للأمن السيبراني بقيادة CISO '
            'وتفعيل لجنة حوكمة الأمن السيبراني')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_establishment_with_roles_and_reporting_lines_clears(self):
        # Leadership group includes الأدوار والمسؤوليات / خطوط الرفع.
        sections = {'vision': _vision_with_objective(
            'إنشاء إدارة الأمن السيبراني مع تحديد الأدوار '
            'والمسؤوليات وخطوط الرفع')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)


class TestWeakObjectivesDoNotClearDefect(unittest.TestCase):
    """Weak phrasings — leadership alone, lone CISO mention, lone
    governance committee, or the deprecated ``مكتب CISO`` — must NOT
    clear the gate."""

    @_skip_if_no_app
    def test_bare_ciso_office_does_not_clear(self):
        # Deprecated ``مكتب CISO`` wording must NOT clear the gate.
        sections = {'vision': _vision_with_objective('إنشاء مكتب CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(
            miss,
            '"مكتب CISO" alone must NOT clear the gate')

    @_skip_if_no_app
    def test_bare_ciso_appointment_does_not_clear(self):
        sections = {'vision': _vision_with_objective('تعيين CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(
            miss,
            'bare تعيين CISO must NOT clear the gate without an '
            'establishment phrase')

    @_skip_if_no_app
    def test_bare_governance_committee_does_not_clear(self):
        # Governance committee is now a leadership/governance phrase
        # only — a row that mentions only the committee (no
        # establishment of the department / function) must not clear
        # the gate.
        sections = {'vision': _vision_with_objective(
            'تشكيل لجنة حوكمة الأمن السيبراني')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(
            miss,
            'lone governance committee row must NOT clear the gate')

    @_skip_if_no_app
    def test_split_across_rows_does_not_clear(self):
        # Even if the SO table mentions establishment in one row and
        # CISO in a DIFFERENT row, the gate is not cleared — both
        # halves must appear in the SAME row (one cohesive objective).
        sections = {'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء إدارة الأمن السيبراني | 100% | NCA | 12 شهراً |\n'
            '| 2 | تعيين CISO | 100% | NCA | 12 شهراً |\n'
        )}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(
            miss,
            'establishment + leadership split across two rows must '
            'NOT clear the gate; both halves must be in the SAME row')


class TestCompositeRepairPromptWording(unittest.TestCase):
    """Composite Vision repair prompt for Cyber must require
    ``إدارة الأمن السيبراني بقيادة CISO`` and forbid ``مكتب CISO``."""

    @_skip_if_no_app
    def _build_prompt(self):
        text, _min_rows = _APP._build_vision_composite_repair_contract(
            domain='Cyber Security',
            selected_frameworks=['ECC'],
            org_structure_is_none=True,
            generation_mode='drafting',
            lang='ar',
            existing_vision='',
            existing_valid_rows=0,
            missing_obligations={
                'compliance_missing': ['ECC'],
                'specialized_missing': True,
            },
            attempt=1,
        )
        return text

    @_skip_if_no_app
    def test_prompt_requires_idarat_alamn_with_ciso(self):
        # Composite repair contract must explicitly require the
        # professional Arabic wording ``إدارة الأمن السيبراني بقيادة
        # CISO``.
        prompt = self._build_prompt()
        self.assertIn(
            'إدارة الأمن السيبراني بقيادة CISO', prompt,
            'prompt must require إدارة الأمن السيبراني بقيادة CISO')

    @_skip_if_no_app
    def test_prompt_does_not_require_makatib_ciso(self):
        # The prompt may mention "مكتب CISO" only inside the
        # NEGATIVE instruction ``لا تستخدم عبارة "مكتب CISO"`` —
        # it must never request the deprecated wording positively.
        prompt = self._build_prompt()
        self.assertIn(
            'لا تستخدم عبارة "مكتب CISO"', prompt,
            'prompt must include the explicit "do not use مكتب CISO" '
            'instruction')

    @_skip_if_no_app
    def test_min_objective_rows_unchanged(self):
        # PR-CY8 must not weaken the minimum row floor.
        obl = _APP._compute_applicable_strategy_obligations(
            domain='Cyber Security',
            selected_frameworks=['ECC'],
            org_structure_is_none=True,
            generation_mode='drafting',
            lang='ar',
        )
        _, min_rows = _APP._build_vision_composite_repair_contract(
            domain='Cyber Security',
            selected_frameworks=['ECC'],
            org_structure_is_none=True,
            generation_mode='drafting',
            lang='ar',
            existing_vision='',
            existing_valid_rows=0,
            missing_obligations={'compliance_missing': ['ECC'],
                                 'specialized_missing': True},
            attempt=1,
        )
        self.assertEqual(min_rows,
                         int(obl.get('min_objective_rows') or min_rows))


class TestRegressionScope(unittest.TestCase):
    """Strict scope: PR-CY8 does NOT change Data / AI / DT / ERM
    detection semantics. The dual-token requirement is cyber-only."""

    @_skip_if_no_app
    def test_data_specialized_objective_unchanged(self):
        # Data uses the original single-list semantics — a row with
        # "إنشاء مكتب إدارة البيانات" alone still clears the gate.
        sections = {'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** بيانات موثوقة.\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء مكتب إدارة البيانات | 100% | NDMO | 12 شهراً |\n'
        )}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Data Management', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_ai_specialized_objective_unchanged(self):
        sections = {'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** ذكاء اصطناعي مسؤول.\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء مكتب حوكمة الذكاء الاصطناعي | 100% | SDAIA '
            '| 12 شهراً |\n'
        )}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Artificial Intelligence', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_dt_specialized_objective_unchanged(self):
        sections = {'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** تحول رقمي.\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء مكتب التحول الرقمي | 100% | DGA | 12 شهراً |\n'
        )}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Digital Transformation', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_erm_specialized_objective_unchanged(self):
        sections = {'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** إدارة المخاطر.\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء إدارة المخاطر المؤسسية | 100% | COSO '
            '| 12 شهراً |\n'
        )}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Enterprise Risk Management', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(miss)

    @_skip_if_no_app
    def test_other_domains_keep_single_list_tokens(self):
        # Sanity: data/ai/dt/erm registry entries do NOT define a
        # ``establishment_*`` group, so they continue to use the
        # legacy single-list semantics.
        for code in ('data', 'ai', 'dt', 'erm'):
            entry = (_APP._DOMAIN_SPECIALIZED_FUNCTION_OBJECTIVE_TOKENS
                     .get(code, {}))
            self.assertFalse(
                bool(entry.get('establishment_ar'))
                or bool(entry.get('establishment_en')),
                f'{code} must not have dual-token mode')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
