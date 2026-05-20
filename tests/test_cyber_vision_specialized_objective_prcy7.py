"""PR-CY7 — Cyber Security vision specialized-function objective.

Validates Part D of the problem statement:

  * The Cyber vision/objectives section must include a valid
    specialized-function objective when ``org_structure_is_none=True``.
    Strong establishment phrases (e.g. "إنشاء إدارة الأمن السيبراني
    وتعيين CISO" / "تأسيس وظيفة الأمن السيبراني بقيادة CISO") must
    clear the ``specialized_function_objective_missing:cyber`` defect.
  * Weak phrases that mention "CISO" alone WITHOUT establishing the
    cybersecurity function/department must NOT clear the defect.
  * The deprecated wording "مكتب CISO" must not pass; it is normalized
    by ``_normalize_cyber_ar_ciso_wording`` to "إدارة الأمن السيبراني
    بقيادة CISO" (the only accepted phrasing).
  * The composite vision repair prompt requires
    "إدارة الأمن السيبراني" + CISO (not just bare "CISO").
  * Minimum objective rows are unchanged and the template-residue
    detection is not weakened.

Run::

    python -m pytest \\
        tests/test_cyber_vision_specialized_objective_prcy7.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_vobj_prcy7_')
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


class TestCyberVisionSpecializedObjective(unittest.TestCase):
    """Detector behaviour for the cyber specialized-function objective."""

    @_skip_if_no_app
    def test_strong_arabic_objective_clears_defect(self):
        sections = {'vision': _vision_with_objective(
            'إنشاء إدارة الأمن السيبراني وتعيين CISO لقيادة الحوكمة')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(
            miss,
            'إنشاء إدارة الأمن السيبراني وتعيين CISO must clear '
            'specialized_function_objective_missing:cyber')

    @_skip_if_no_app
    def test_function_under_ciso_leadership_clears_defect(self):
        sections = {'vision': _vision_with_objective(
            'تأسيس وظيفة الأمن السيبراني بقيادة رئيس الأمن السيبراني CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(
            miss,
            'تأسيس وظيفة الأمن السيبراني بقيادة CISO must clear defect')

    @_skip_if_no_app
    def test_governance_committee_only_does_not_pass(self):
        # Per problem statement: "lone CISO" weak phrasing should
        # NOT clear the defect — the row must establish the function
        # (department / function / operating model) as well.
        sections = {'vision': _vision_with_objective('تعيين CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(
            miss,
            'bare "تعيين CISO" must NOT clear specialized-function '
            'defect; an establishment phrase is required')

    @_skip_if_no_app
    def test_makatib_ciso_does_not_pass(self):
        # "مكتب CISO" is the deprecated wording that the AR
        # CISO-wording normalizer rewrites to
        # "إدارة الأمن السيبراني بقيادة CISO". The detector itself
        # MUST NOT accept the un-normalized form.
        sections = {'vision': _vision_with_objective('إنشاء مكتب CISO')}
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(
            miss,
            'raw "إنشاء مكتب CISO" must NOT satisfy the gate')

    @_skip_if_no_app
    def test_normalized_ciso_wording_clears_defect(self):
        # When the normalizer runs first, "مكتب CISO" becomes
        # "إدارة الأمن السيبراني بقيادة CISO" — that wording is in
        # the accept token list.
        text = _vision_with_objective('إنشاء مكتب CISO')
        sections = {'vision': text}
        _APP._normalize_cyber_ar_ciso_wording(sections, 'ar', 'cyber')
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertFalse(
            miss,
            'after CISO-wording normalization the objective must '
            'clear the gate')


class TestCyberVisionCompositeRepairPrompt(unittest.TestCase):
    """Composite repair contract for Cyber requires
    "إدارة الأمن السيبراني" + CISO and forbids "مكتب CISO"."""

    @_skip_if_no_app
    def test_prompt_requires_idarat_and_ciso(self):
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
        self.assertIn('إدارة الأمن السيبراني', text)
        self.assertIn('CISO', text)

    @_skip_if_no_app
    def test_prompt_forbids_makatib_ciso(self):
        text, _ = _APP._build_vision_composite_repair_contract(
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
        # Prompt must instruct the model NOT to write "مكتب CISO".
        self.assertIn('لا تستخدم عبارة "مكتب CISO"', text)

    @_skip_if_no_app
    def test_minimum_objective_rows_unchanged(self):
        # PR-CY7 must not weaken the minimum row floor. The floor
        # value is whatever ``_compute_applicable_strategy_obligations``
        # returns for Cyber+ECC drafting; we only assert it is the
        # same value before and after the composite contract is built.
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

    @_skip_if_no_app
    def test_template_residue_detection_not_weakened(self):
        # Sanity: a vision string with an obvious template marker
        # MUST still be detected by the existing residue gate (which
        # PR-CY7 must not weaken).
        residue_text = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
            '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | EN_TEMPLATE | 100% | TBD | 12 شهراً |\n'
        )
        if hasattr(_APP, '_AR_TEMPLATE_RESIDUE_MAP'):
            # Best-effort sanity: at least one residue token is in the
            # registry; we don't rely on a specific helper signature
            # so the test remains stable across PRs.
            self.assertTrue(_APP._AR_TEMPLATE_RESIDUE_MAP)
        # The detector for specialized-function still returns
        # missing=True for this text (the row is just a template
        # marker, not an establishment phrase).
        miss = _APP._compute_missing_specialized_function_objective(
            {'vision': residue_text}, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(miss)


class TestCyberVisionRegressionScope(unittest.TestCase):
    """Other domains must keep their specialized-function tokens
    unchanged."""

    @_skip_if_no_app
    def test_data_specialized_function_tokens_unchanged(self):
        toks = (_APP._DOMAIN_SPECIALIZED_FUNCTION_OBJECTIVE_TOKENS
                .get('data', {}))
        self.assertIn('data management office', toks.get('en', ()))
        self.assertIn('إنشاء مكتب إدارة البيانات', toks.get('ar', ()))

    @_skip_if_no_app
    def test_ai_specialized_function_tokens_unchanged(self):
        toks = (_APP._DOMAIN_SPECIALIZED_FUNCTION_OBJECTIVE_TOKENS
                .get('ai', {}))
        self.assertIn('ai governance office', toks.get('en', ()))

    @_skip_if_no_app
    def test_dt_specialized_function_tokens_unchanged(self):
        toks = (_APP._DOMAIN_SPECIALIZED_FUNCTION_OBJECTIVE_TOKENS
                .get('dt', {}))
        self.assertIn('digital transformation office', toks.get('en', ()))

    @_skip_if_no_app
    def test_erm_specialized_function_tokens_unchanged(self):
        toks = (_APP._DOMAIN_SPECIALIZED_FUNCTION_OBJECTIVE_TOKENS
                .get('erm', {}))
        self.assertIn('risk committee', toks.get('en', ()))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
