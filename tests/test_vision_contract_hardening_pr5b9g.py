"""PR-5B.9G — Vision repair contract hardening.

Validates the new safe-assign guard (``_assign_vision_if_valid_or_restore``)
and contract validator (``_validate_vision_contract``):

  * Template / placeholder markers in candidate Vision are rejected.
  * Row-count regressions (e.g. 4-row repair on a 6-row vision) are
    rejected.
  * Compliance / specialized-function obligations are enforced.
  * Selected-framework leakage (e.g. SAMA appearing when scope is
    ECC + TCC only) is rejected.
  * On rejection, the original Vision is restored and synth_failed is
    marked so the post-normalization audit fails closed.

Run:
    python -m pytest tests/test_vision_contract_hardening_pr5b9g.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_vision_contract_pr5b9g_')
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


def _vision_with_n_rows(n, *, include_compliance=False,
                         include_cyber_dept=False,
                         include_sama=False,
                         lang='ar'):
    """Build a Vision section with ``n`` valid Strategic Objective rows.

    Optional injected objectives (still counted toward ``n``):
      * ``include_compliance`` — adds ``تحقيق الالتزام بضوابط NCA ECC وNCA TCC``
        as the first row.
      * ``include_cyber_dept`` — adds ``إنشاء الإدارة المتخصصة للأمن السيبراني``.
      * ``include_sama`` — adds an explicit SAMA compliance row (used to
        verify framework-leakage detection).
    """
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
            '(دائرة/مكتب/لجنة) | اعتماد الهيكل التنظيمي وتعيين رئيس '
            'الأمن السيبراني | يُغلق فجوة الوظيفة المتخصصة | 9 أشهر |'
        )
        idx += 1
    if include_sama:
        rows.append(
            f'| {idx} | تحقيق الالتزام بإطار ساما للأمن السيبراني '
            '| 100% من ضوابط ساما مُطبَّقة | يُغلق فجوة الالتزام '
            'بمتطلبات SAMA | 12 شهراً |'
        )
        idx += 1
    while idx <= n:
        rows.append(
            f'| {idx} | تطوير القدرة الاستراتيجية رقم {idx} '
            '| 100% | تعزيز القدرة المؤسسية وتحقيق الأهداف '
            f'الاستراتيجية رقم {idx} | 12 شهراً |'
        )
        idx += 1
    if lang == 'ar':
        return (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            'الرؤية: تعزيز القدرات الاستراتيجية للمنظمة.\n\n'
            '### الأهداف الاستراتيجية:\n\n'
            '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
            '|---|------------------|-------|--------|---------------|\n'
            + '\n'.join(rows) + '\n'
        )
    return (
        '## 1. Vision & Objectives\n\n'
        'Vision: Strengthen strategic capabilities.\n\n'
        '### Strategic Objectives:\n\n'
        '| # | Objective | Target | Justification | Timeframe |\n'
        '|---|-----------|--------|---------------|-----------|\n'
        + '\n'.join(rows) + '\n'
    )


class VisionContractValidatorTests(unittest.TestCase):
    """Tests for ``_validate_vision_contract``."""

    @_skip_if_no_app
    def test_01_arabic_cyber_ecc_tcc_four_rows_rejected(self):
        # Cyber + ECC/TCC + consulting requires >= 6 valid SO rows.
        text = _vision_with_n_rows(4, include_compliance=True)
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertEqual(report['rows'], 4)
        self.assertEqual(report['required_min_rows'], 6)
        self.assertTrue(any(
            e.startswith('vision_so_rows=4') for e in report['errors']))

    @_skip_if_no_app
    def test_02_arabic_cyber_ecc_tcc_zero_rows_rejected(self):
        # Empty objectives table — 0 rows must fail.
        text = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            'الرؤية: تعزيز القدرات.\n\n'
            '### الأهداف الاستراتيجية:\n\n'
            '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
            '|---|------------------|-------|--------|---------------|\n'
        )
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertEqual(report['rows'], 0)
        self.assertTrue(any(
            'vision_so_rows=0' in e for e in report['errors']))

    @_skip_if_no_app
    def test_03_template_marker_rejected(self):
        # English EN_TEMPLATE marker must hard-fail the contract.
        text = _vision_with_n_rows(6, include_compliance=True)
        text = text + '\n\n<<EN_TEMPLATE>> placeholder content here\n'
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertTrue(report['has_template_marker'])
        self.assertTrue(any(
            e.startswith('vision_contains_en_template_marker')
            for e in report['errors']))

    @_skip_if_no_app
    def test_04_placeholder_tokens_rejected(self):
        # Unreplaced {framework} / [organization] tokens must reject.
        text = _vision_with_n_rows(6, include_compliance=True)
        text = text + '\n\nالرؤية: {framework} لـ [organization]\n'
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertTrue(report['has_template_marker'])

    @_skip_if_no_app
    def test_05_valid_six_row_vision_passes(self):
        # 6 rows + ECC/TCC compliance + cyber-dept objective passes the
        # full PR-5B.9G contract for Cyber + ECC/TCC + consulting +
        # org_structure_is_none=True.
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
            'Expected valid 6-row vision to pass; errors=%r'
            % (report['errors'],))
        self.assertEqual(report['rows'], 6)
        self.assertTrue(report['has_compliance'])
        self.assertTrue(report['has_specialized'])
        self.assertEqual(report['leaked_frameworks'], [])

    @_skip_if_no_app
    def test_09_sama_leaked_when_only_ecc_tcc_selected(self):
        # SAMA appears in body but not in selected scope → leakage.
        text = _vision_with_n_rows(
            6, include_compliance=True, include_sama=True)
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertIn('SAMA', report['leaked_frameworks'])
        self.assertTrue(any(
            'unselected_framework' in e for e in report['errors']))

    @_skip_if_no_app
    def test_10_sama_accepted_when_selected(self):
        # When SAMA IS in scope, the SAMA objective is allowed; row
        # count must still be >= 6.
        text = _vision_with_n_rows(
            6, include_compliance=True, include_sama=True)
        report = _APP._validate_vision_contract(
            text, domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC', 'SAMA'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
        )
        # The compliance objective row covers ECC/TCC; the SAMA row
        # covers SAMA. Row count is >= 6, no leakage.
        self.assertEqual(report['leaked_frameworks'], [])
        self.assertGreaterEqual(report['rows'], 6)
        # The SAMA framework should not be flagged as leaked.
        self.assertNotIn(
            'vision_mentions_unselected_framework:SAMA',
            report['errors'])


class VisionContractAssignTests(unittest.TestCase):
    """Tests for ``_assign_vision_if_valid_or_restore``."""

    @_skip_if_no_app
    def test_06_six_row_not_overwritten_by_four_row_repair(self):
        original = _vision_with_n_rows(6, include_compliance=True)
        sections = {'vision': original}
        candidate = _vision_with_n_rows(4, include_compliance=True)
        report = _APP._assign_vision_if_valid_or_restore(
            sections, candidate, original,
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
            synth_status={},
        )
        self.assertFalse(report['assign_allowed'])
        # Original 6-row vision preserved.
        self.assertEqual(sections['vision'], original)
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(sections['vision']), 6)

    @_skip_if_no_app
    def test_07_template_marker_candidate_restores_original(self):
        original = _vision_with_n_rows(6, include_compliance=True)
        sections = {'vision': original}
        candidate = original + '\n\n<<EN_TEMPLATE>> placeholder\n'
        synth_status = {}
        report = _APP._assign_vision_if_valid_or_restore(
            sections, candidate, original,
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
            synth_status=synth_status,
        )
        self.assertFalse(report['assign_allowed'])
        self.assertTrue(report['has_template_marker'])
        # Original vision preserved.
        self.assertEqual(sections['vision'], original)
        # synth_failed marked for the vision section.
        self.assertEqual(
            (synth_status.get('synth_status') or {}).get('vision'),
            'failed',
        )

    @_skip_if_no_app
    def test_12_zero_rows_not_produced_after_successful_repair(self):
        # When the candidate has 0 rows the helper MUST NOT assign.
        original = _vision_with_n_rows(6, include_compliance=True)
        sections = {'vision': original}
        candidate = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            'الرؤية فقط بدون جدول.\n'
        )
        report = _APP._assign_vision_if_valid_or_restore(
            sections, candidate, original,
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
            synth_status={},
        )
        self.assertFalse(report['assign_allowed'])
        self.assertEqual(report['rows'], 0)
        # Original vision preserved (still has its rows).
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(sections['vision']), 6)

    @_skip_if_no_app
    def test_11_specialized_function_repaired_only_if_six_rows(self):
        # When org_structure_is_none=True the candidate must include
        # BOTH the compliance objective AND the cyber-dept objective
        # AND >=6 rows.
        original = _vision_with_n_rows(2)
        sections = {'vision': original}
        candidate_thin = _vision_with_n_rows(
            5, include_compliance=True, include_cyber_dept=True)
        report = _APP._assign_vision_if_valid_or_restore(
            sections, candidate_thin, original,
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
            synth_status={},
        )
        self.assertFalse(report['assign_allowed'])
        # A full 6-row candidate with both obligations should pass.
        candidate_full = _vision_with_n_rows(
            6, include_compliance=True, include_cyber_dept=True)
        sections2 = {'vision': original}
        report2 = _APP._assign_vision_if_valid_or_restore(
            sections2, candidate_full, original,
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
            synth_status={},
        )
        self.assertTrue(
            report2['assign_allowed'],
            'Expected full 6-row candidate to pass; errors=%r'
            % (report2['errors'],))


class VisionRepairCallSitesUseSafeAssignTests(unittest.TestCase):
    """Tests that direct ai_repair_strategy_section('vision') call sites
    in the strategy generation pipeline route through the safe-assign
    helper / contract validator (PR-5B.9G clause B)."""

    @_skip_if_no_app
    def test_08_synthesize_objectives_depth_rejects_template_marker(self):
        # Even when AI returns a 6-row vision, a template-marker leak
        # must be rejected — the contract is enforced before assignment.
        sections = {'vision': _vision_with_n_rows(2)}
        marker_text = (
            _vision_with_n_rows(6) + '\n\n<<EN_TEMPLATE>>\n'
        )
        original = _APP.ai_repair_strategy_section

        def _stub(*a, **kw):
            return marker_text

        _APP.ai_repair_strategy_section = _stub
        try:
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_objectives_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='ECC',
                    generation_mode='consulting',
                )
            err = ctx.exception
            self.assertEqual(getattr(err, 'section', None), 'vision')
            # Original vision preserved (never assigned with marker).
            self.assertEqual(
                _APP.count_valid_objective_rows(sections['vision']),
                2,
            )
        finally:
            _APP.ai_repair_strategy_section = original


class NoDeterministicRowsAndValidatorIntegrityTests(unittest.TestCase):
    """Confirms PR-5B.9G strict-scope obligations:

      * No deterministic objective rows are inserted by the new helpers.
      * Validators are not weakened (min row count remains >= 6 for
        consulting/assurance).
      * Export / PDF / DOCX / auth / DB modules are untouched.
    """

    @_skip_if_no_app
    def test_13_no_deterministic_rows_inserted_by_helpers(self):
        # Calling the validator does not mutate sections.
        sections = {'vision': _vision_with_n_rows(4)}
        before = sections['vision']
        report = _APP._validate_vision_contract(
            sections['vision'], domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertEqual(sections['vision'], before)
        # Calling the safe-assign helper with an INVALID candidate
        # restores the original — it never injects deterministic rows.
        candidate_invalid = _vision_with_n_rows(3)
        _APP._assign_vision_if_valid_or_restore(
            sections, candidate_invalid, before,
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
            synth_status={},
        )
        # Original preserved verbatim — no deterministic rows added.
        self.assertEqual(sections['vision'], before)
        self.assertEqual(
            _APP.count_valid_objective_rows(sections['vision']), 4)

    @_skip_if_no_app
    def test_14_validator_not_weakened_consulting_min_six(self):
        # The required min for consulting/assurance is 6 — even when
        # original_valid_rows is lower than 6, required_min stays at 6.
        report = _APP._validate_vision_contract(
            _vision_with_n_rows(5, include_compliance=True),
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
            original_valid_rows=0,
        )
        self.assertGreaterEqual(report['required_min_rows'], 6)
        # original_valid_rows higher than the global floor wins.
        report2 = _APP._validate_vision_contract(
            _vision_with_n_rows(7, include_compliance=True),
            domain='Cyber Security',
            selected_frameworks=['ECC', 'TCC'],
            org_structure_is_none=False,
            generation_mode='consulting', lang='ar',
            original_valid_rows=8,
        )
        self.assertGreaterEqual(report2['required_min_rows'], 8)

    @_skip_if_no_app
    def test_15_export_pdf_docx_auth_db_untouched(self):
        # Confirm the new helpers live in app.py only and that no PDF/
        # DOCX/auth/DB module names appear in the helper source.
        import inspect
        for fn_name in (
                '_validate_vision_contract',
                '_assign_vision_if_valid_or_restore',
                '_vision_template_marker_hits',
                '_vision_leaked_frameworks',
        ):
            fn = getattr(_APP, fn_name)
            src = inspect.getsource(fn)
            for forbidden in (
                    'reportlab', 'docx', 'sqlalchemy', 'login_user',
                    'User.query', 'send_file', 'login_required',
            ):
                self.assertNotIn(
                    forbidden, src,
                    f'{fn_name} unexpectedly references {forbidden}')


if __name__ == '__main__':
    unittest.main()
