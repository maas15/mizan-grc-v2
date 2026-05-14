"""PR-5B.9H — Vision composite repair generation hardening.

Validates the new repair-payload builder
(``_build_vision_composite_repair_contract``), the strengthened
``_AI_REPAIR_SECTION_SCHEMA["vision"]`` prompt, and the bounded
retry orchestration inside the PR-5B.9F VISION-OBLIGATIONS-REPAIR
pass.

Run:
    python -m pytest tests/test_vision_composite_repair_generation_pr5b9h.py -q
"""

import importlib.util
import inspect
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_vision_composite_pr5b9h_')
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


# ── Helpers to build deterministic Vision sections used by the tests ──────
def _vision_with_n_rows(n, *, include_compliance=False,
                         include_cyber_dept=False,
                         include_data_dmo=False,
                         include_ai_office=False,
                         lang='ar'):
    rows = []
    idx = 1
    if include_compliance:
        rows.append(
            f'| {idx} | تحقيق الالتزام بضوابط NCA ECC وNCA TCC '
            '| 100% من الضوابط مُطبَّقة | يُغلق فجوة الالتزام التنظيمي '
            '| 12 شهراً |'
        )
        idx += 1
    if include_cyber_dept:
        rows.append(
            f'| {idx} | إنشاء الإدارة المتخصصة للأمن السيبراني '
            '(دائرة/مكتب/لجنة) وتعيين رئيس الأمن السيبراني CISO '
            '| اعتماد الهيكل وتعيين CISO | يُغلق فجوة الوظيفة المتخصصة '
            '| 9 أشهر |'
        )
        idx += 1
    if include_data_dmo:
        rows.append(
            f'| {idx} | إنشاء مكتب إدارة البيانات وتعيين رئيس البيانات CDO '
            '| اعتماد مكتب إدارة البيانات | يُغلق فجوة الوظيفة المتخصصة '
            '| 9 أشهر |'
        )
        idx += 1
    if include_ai_office:
        rows.append(
            f'| {idx} | إنشاء مكتب أو وحدة حوكمة الذكاء الاصطناعي '
            'مع تفعيل مدير مخاطر النماذج '
            '| اعتماد مكتب الحوكمة | يُغلق فجوة الوظيفة المتخصصة '
            '| 9 أشهر |'
        )
        idx += 1
    while idx <= n:
        rows.append(
            f'| {idx} | تطوير القدرة الاستراتيجية رقم {idx} '
            '| 100% | تعزيز القدرة المؤسسية وتحقيق الأهداف '
            f'الاستراتيجية رقم {idx} | 12 شهراً |'
        )
        idx += 1
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** تعزيز القدرات الاستراتيجية للمنظمة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المقياس المستهدف | المبرر '
        '| الإطار الزمني |\n'
        '|---|------------------|------------------|--------'
        '|----------------|\n'
        + '\n'.join(rows) + '\n'
    )


# ──────────────────────────────────────────────────────────────────────────
class CompositeContractBuilderTests(unittest.TestCase):
    """Tests 1–5 — repair-payload builder generates correct prompt."""

    @_skip_if_no_app
    def test_01_cyber_ecc_tcc_orgnone_requires_min_six_rows(self):
        # Cyber + ECC/TCC + org_structure_is_none + consulting → at
        # least 6 rows demanded in the validation_error text.
        existing = _vision_with_n_rows(0)
        ve_msg, min_rows = _APP._build_vision_composite_repair_contract(
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision=existing,
            existing_valid_rows=0,
        )
        self.assertGreaterEqual(min_rows, 6)
        self.assertIn(str(min_rows), ve_msg)
        self.assertIn('at least 6 valid', ve_msg)

    @_skip_if_no_app
    def test_02_cyber_repair_prompt_requires_separate_compliance_objective(
            self):
        existing = _vision_with_n_rows(0)
        ve_msg, _ = _APP._build_vision_composite_repair_contract(
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision=existing,
            existing_valid_rows=0,
        )
        # Both ECC and TCC named verbatim and a SEPARATE compliance row
        # is demanded.
        self.assertIn('ECC', ve_msg)
        self.assertIn('TCC', ve_msg)
        self.assertIn('SEPARATE row', ve_msg)
        self.assertIn('compliance', ve_msg.lower())

    @_skip_if_no_app
    def test_03_cyber_repair_prompt_requires_separate_specialized_function(
            self):
        existing = _vision_with_n_rows(0)
        ve_msg, _ = _APP._build_vision_composite_repair_contract(
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision=existing,
            existing_valid_rows=0,
        )
        self.assertIn('ESTABLISHING', ve_msg)
        self.assertIn('Cybersecurity', ve_msg)
        self.assertIn('CISO', ve_msg)
        self.assertIn('IN ADDITION', ve_msg)
        self.assertIn('MUST NOT replace', ve_msg)

    @_skip_if_no_app
    def test_04_data_repair_prompt_requires_dmo_cdo_objective(self):
        existing = _vision_with_n_rows(0)
        ve_msg, min_rows = _APP._build_vision_composite_repair_contract(
            domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision=existing,
            existing_valid_rows=0,
        )
        self.assertGreaterEqual(min_rows, 6)
        # Compliance row names NDMO / PDPL, specialized-function row
        # demands DMO / CDO / Data Governance Committee.
        self.assertIn('NDMO', ve_msg)
        self.assertIn('PDPL', ve_msg)
        self.assertIn('Data Management Office', ve_msg)
        self.assertIn('Chief Data Officer', ve_msg)

    @_skip_if_no_app
    def test_05_ai_repair_prompt_requires_ai_governance_office_model_risk(
            self):
        existing = _vision_with_n_rows(0)
        ve_msg, _ = _APP._build_vision_composite_repair_contract(
            domain='Artificial Intelligence',
            selected_frameworks=['SDAIA'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision=existing,
            existing_valid_rows=0,
        )
        self.assertIn('SDAIA', ve_msg)
        self.assertIn('AI Governance Office', ve_msg)
        self.assertIn('model risk', ve_msg.lower())


# ──────────────────────────────────────────────────────────────────────────
class CompositeContractValidatorTests(unittest.TestCase):
    """Tests 6–9 — invalid candidates rejected, valid ones accepted."""

    @_skip_if_no_app
    def test_06_four_row_candidate_rejected(self):
        text = _vision_with_n_rows(4, include_compliance=True)
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertEqual(report['rows'], 4)
        self.assertGreaterEqual(report['required_min_rows'], 6)

    @_skip_if_no_app
    def test_07_six_rows_missing_compliance_rejected(self):
        # 6 rows but no ECC/TCC compliance row.
        text = _vision_with_n_rows(6, include_cyber_dept=True)
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertFalse(report['has_compliance'])
        self.assertTrue(any(
            'compliance_objective_missing' in e for e in report['errors']))

    @_skip_if_no_app
    def test_08_six_rows_missing_specialized_function_rejected(self):
        # 6 rows + compliance but NO cyber-dept establishment row.
        text = _vision_with_n_rows(6, include_compliance=True)
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertFalse(report['has_specialized'])
        self.assertTrue(any(
            'specialized_function_objective_missing' in e
            for e in report['errors']))

    @_skip_if_no_app
    def test_09_six_rows_with_both_obligations_passes(self):
        text = _vision_with_n_rows(
            6, include_compliance=True, include_cyber_dept=True)
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertTrue(
            report['ok'],
            'Expected 6-row vision with both obligations to pass; '
            'errors=%r' % (report['errors'],))
        self.assertTrue(report['has_compliance'])
        self.assertTrue(report['has_specialized'])


# ──────────────────────────────────────────────────────────────────────────
class CompositeRepairOrchestrationTests(unittest.TestCase):
    """Tests 10–11 — safe-assign behaviour & row counter alignment."""

    @_skip_if_no_app
    def test_10_existing_valid_vision_not_overwritten_by_invalid_repair(
            self):
        # An existing vision with 6 valid rows + both obligations must
        # NOT be overwritten by a 4-row repair candidate.
        original = _vision_with_n_rows(
            6, include_compliance=True, include_cyber_dept=True)
        sections = {'vision': original}
        candidate_bad = _vision_with_n_rows(
            4, include_compliance=True, include_cyber_dept=True)
        report = _APP._assign_vision_if_valid_or_restore(
            sections, candidate_bad, original,
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
            synth_status={},
        )
        self.assertFalse(report['assign_allowed'])
        # Original preserved verbatim — no deterministic rows added.
        self.assertEqual(sections['vision'], original)
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(sections['vision']), 6)

    @_skip_if_no_app
    def test_11_count_valid_objective_rows_counts_six_arabic_rows(self):
        text = _vision_with_n_rows(
            6, include_compliance=True, include_cyber_dept=True)
        n = _APP.count_valid_objective_rows(text)
        self.assertEqual(
            n, 6,
            f'count_valid_objective_rows must accept 6 Arabic rows; '
            f'got {n}')


# ──────────────────────────────────────────────────────────────────────────
class CallSitesAndStrictScopeTests(unittest.TestCase):
    """Tests 12–15 — strict-scope obligations of the PR."""

    @_skip_if_no_app
    def test_12_no_direct_sections_vision_assignment_bypasses_safe_helper(
            self):
        # Audit the VISION-OBLIGATIONS-REPAIR pass body: every
        # ai_repair_strategy_section('vision', ...) call inside the
        # repair pass MUST be followed by a call to
        # ``_assign_vision_if_valid_or_restore`` rather than a direct
        # ``sections['vision'] = ...`` assignment of the AI candidate.
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as fh:
            src = fh.read()
        # Locate the PR-5B.9F repair block.
        anchor = '[VISION-OBLIGATIONS-REPAIR]'
        first = src.find(anchor)
        self.assertGreater(
            first, -1, 'Could not locate VISION-OBLIGATIONS-REPAIR block')
        # Look at the next ~20k chars (the whole repair pass).
        block = src[first:first + 20000]
        # Inside the block, every AI-repair vision call site uses the
        # safe-assign helper before any direct assignment of the AI
        # candidate.
        self.assertIn('_assign_vision_if_valid_or_restore', block)
        self.assertIn("section_key='vision'", block)
        # The literal pattern ``sections['vision'] = _vo_new`` must
        # NOT appear — that would bypass the contract validator.
        self.assertNotIn("sections['vision'] = _vo_new", block)

    @_skip_if_no_app
    def test_13_no_deterministic_objective_rows_inserted_by_helpers(self):
        # The new builder is read-only; calling it does not mutate
        # anything and never returns deterministic objective rows
        # (it returns a prompt string + an int).
        existing = _vision_with_n_rows(0)
        ve_msg, min_rows = _APP._build_vision_composite_repair_contract(
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision=existing,
            existing_valid_rows=0,
        )
        self.assertIsInstance(ve_msg, str)
        self.assertIsInstance(min_rows, int)
        # It must NOT contain literal markdown table data rows
        # (would mean deterministic objective rows leaking into the
        # prompt as fixed content).
        for marker in (
                '| 1 | تحقيق الالتزام',
                '| 2 | إنشاء الإدارة',
                '| 1 | Achieve compliance',
        ):
            self.assertNotIn(marker, ve_msg)

    @_skip_if_no_app
    def test_14_validators_not_weakened_min_six_for_consulting(self):
        # _validate_vision_contract still demands >= 6 rows for
        # consulting/assurance, irrespective of the new builder.
        report = _APP._validate_vision_contract(
            _vision_with_n_rows(5, include_compliance=True,
                                 include_cyber_dept=True),
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertGreaterEqual(report['required_min_rows'], 6)
        self.assertFalse(report['ok'])
        # And the builder reports the same floor.
        _, min_rows = _APP._build_vision_composite_repair_contract(
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision='',
            existing_valid_rows=0,
        )
        self.assertGreaterEqual(min_rows, 6)

    @_skip_if_no_app
    def test_15_export_pdf_docx_auth_db_untouched(self):
        # The new helper / strengthened schema must not reach into
        # PDF/DOCX/auth/DB modules.
        fn = getattr(_APP, '_build_vision_composite_repair_contract')
        src = inspect.getsource(fn)
        for forbidden in (
                'reportlab', 'docx', 'sqlalchemy', 'login_user',
                'User.query', 'send_file', 'login_required',
        ):
            self.assertNotIn(
                forbidden, src,
                f'_build_vision_composite_repair_contract '
                f'unexpectedly references {forbidden}')
        # Vision schema strengthening also must not reference those.
        schema = _APP._AI_REPAIR_SECTION_SCHEMA.get('vision', {})
        for v in schema.values():
            for forbidden in (
                    'reportlab', 'docx', 'sqlalchemy', 'login_user',
                    'send_file', 'login_required'):
                self.assertNotIn(
                    forbidden, v,
                    f'vision schema unexpectedly references {forbidden}')


# ──────────────────────────────────────────────────────────────────────────
class RetryOrchestrationStructureTests(unittest.TestCase):
    """Confirms the bounded retry orchestration was wired into the
    PR-5B.9F VISION-OBLIGATIONS-REPAIR pass."""

    @_skip_if_no_app
    def test_retry_loop_present_in_repair_pass(self):
        with open(os.path.join(
                os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as fh:
            src = fh.read()
        anchor = '[VISION-OBLIGATIONS-REPAIR]'
        first = src.find(anchor)
        self.assertGreater(first, -1)
        block = src[first:first + 20000]
        # The bounded retry constant and the contract-builder call must
        # both appear inside the repair pass.
        self.assertIn('_VO_MAX_ATTEMPTS', block)
        self.assertIn(
            '_build_vision_composite_repair_contract', block)
        self.assertIn('attempt=', block)


if __name__ == '__main__':
    unittest.main()
