"""PR-5B.9M — Vision template-residue contract hardening.

Production symptom: Data Management Arabic strategy generation failed with
``vision_contains_en_template_residue``. PR-5B.9G's vision contract
(``_validate_vision_contract``) caught template MARKERS but not the EN
template RESIDUE tokens (the ``_AR_TEMPLATE_RESIDUE_MAP`` keys and the
bare scaffold labels ``Objective``, ``Framework``, ``Target``, ``Reason``,
``Timeframe``, ``Strategic Objectives template``) that the final-audit
``*_contains_en_template_residue`` check rejected later in the pipeline,
exhausting the retry budget.

Tests (read-only, no AI provider needed):

  1. Data Management Arabic vision containing ``Objective: <fill>`` is
     rejected by the contract.
  2. Vision containing ``[framework]`` / ``{placeholder}`` is rejected.
  3. Candidate with template residue is NOT assigned to ``sections['vision']``.
  4. Retry validation_error includes the EXACT residue token names.
  5. Valid Arabic 6-row Data vision with NDMO/PDPL compliance + Data
     Management Office objective passes the full contract.
  6. The fix did NOT add deterministic objective rows (the helper returns
     the same row count it was given).
  7. Validators are not weakened — empty / too-few-rows vision still
     rejected.

Run:
    python -m pytest tests/test_vision_template_residue_pr5b9m.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_vision_residue_pr5b9m_')
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


def _data_vision_n_rows(
        n, *, include_compliance=False, include_dmo=False,
        extra_text=''):
    """Build an Arabic Data Management vision with ``n`` SO rows."""
    rows = []
    idx = 1
    if include_compliance:
        # NDMO + PDPL compliance objective row (Data domain).
        rows.append(
            f'| {idx} | تحقيق الالتزام بإطار حوكمة البيانات NDMO '
            'ونظام حماية البيانات الشخصية PDPL | 100% من الضوابط '
            'مُطبَّقة | يُغلق فجوة الالتزام التنظيمي | 12 شهراً |'
        )
        idx += 1
    if include_dmo:
        # Data Management Office establishment objective (Data
        # domain specialized-function obligation).
        rows.append(
            f'| {idx} | إنشاء مكتب إدارة البيانات وتعيين رئيس البيانات '
            '(CDO) وتشكيل لجنة حوكمة البيانات | اعتماد الهيكل '
            'التنظيمي وتعيين CDO | يُغلق فجوة الوظيفة المتخصصة | '
            '9 أشهر |'
        )
        idx += 1
    while idx <= n:
        rows.append(
            f'| {idx} | تطوير قدرة حوكمة البيانات رقم {idx} '
            '| 100% | تعزيز جودة وتكامل البيانات وتحقيق متطلبات '
            f'NDMO رقم {idx} | 12 شهراً |'
        )
        idx += 1
    body = (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'الرؤية: تعزيز حوكمة البيانات وتحقيق متطلبات NDMO و PDPL.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        + '\n'.join(rows) + '\n'
    )
    if extra_text:
        body += '\n\n' + extra_text + '\n'
    return body


class VisionResidueDetectorTests(unittest.TestCase):
    """Direct tests for ``_vision_template_residue_hits``."""

    @_skip_if_no_app
    def test_helper_exists(self):
        self.assertTrue(
            hasattr(_APP, '_vision_template_residue_hits'),
            'PR-5B.9M must expose _vision_template_residue_hits',
        )

    @_skip_if_no_app
    def test_ar_residue_map_keys_detected_for_ar(self):
        # ``System/Tool`` and ``Within `` are AR-only residue tokens.
        hits = _APP._vision_template_residue_hits(
            'cell text with System/Tool and Within 6 months scope',
            lang='ar')
        self.assertIn('System/Tool', hits)
        self.assertIn('Within ', hits)

    @_skip_if_no_app
    def test_ar_residue_map_not_active_for_en(self):
        # The same map applies only to AR strategies — for EN strategies
        # "System/Tool" is a legitimate English heading.
        hits = _APP._vision_template_residue_hits(
            'cell text with System/Tool and Within 6 months',
            lang='en')
        self.assertNotIn('System/Tool', hits)
        self.assertNotIn('Within ', hits)

    @_skip_if_no_app
    def test_objective_placeholder_label_detected(self):
        # Bare scaffold label "Objective: <fill in>".
        hits = _APP._vision_template_residue_hits(
            'Some text Objective: <fill in> end', lang='ar')
        self.assertTrue(
            any('Objective: <' in h for h in hits),
            f'expected "Objective: <" hit, got {hits!r}')

    @_skip_if_no_app
    def test_framework_placeholder_label_detected(self):
        hits = _APP._vision_template_residue_hits(
            'Framework: <name here> ...', lang='ar')
        self.assertTrue(
            any('Framework: <' in h for h in hits),
            f'expected "Framework: <" hit, got {hits!r}')

    @_skip_if_no_app
    def test_target_timeframe_reason_detected(self):
        for lbl in ('Target', 'Timeframe', 'Reason'):
            hits = _APP._vision_template_residue_hits(
                f'{lbl}: <to fill> ...', lang='ar')
            self.assertTrue(
                any(lbl in h for h in hits),
                f'expected "{lbl}:" hit, got {hits!r}')

    @_skip_if_no_app
    def test_clean_arabic_vision_yields_no_hits(self):
        text = _data_vision_n_rows(
            6, include_compliance=True, include_dmo=True)
        hits = _APP._vision_template_residue_hits(text, lang='ar')
        self.assertEqual(
            hits, [],
            f'clean Arabic Data vision must not flag residue, got {hits!r}')


class VisionContractResidueTests(unittest.TestCase):
    """``_validate_vision_contract`` integrates the residue check."""

    @_skip_if_no_app
    def test_objective_residue_rejected_for_data_ar(self):
        # Data + NDMO/PDPL + consulting (>= 6 valid rows) with residue.
        text = _data_vision_n_rows(
            6, include_compliance=True, include_dmo=True,
            extra_text='Note: Objective: <to be filled> later'
        )
        report = _APP._validate_vision_contract(
            text, domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertTrue(report.get('has_template_residue', False),
                        f'has_template_residue must be True; report={report}')
        self.assertTrue(
            any(e.startswith('vision_contains_en_template_residue')
                for e in report['errors']),
            f'expected residue defect, got errors={report["errors"]}')
        # The retry validation_error must name the EXACT residue token.
        residue_err = next(
            e for e in report['errors']
            if e.startswith('vision_contains_en_template_residue'))
        self.assertIn('Objective:', residue_err,
                      f'expected exact token in error, got {residue_err!r}')

    @_skip_if_no_app
    def test_framework_placeholder_rejected_for_data_ar(self):
        text = _data_vision_n_rows(
            6, include_compliance=True, include_dmo=True,
            extra_text='Footer: Framework: <NDMO> details'
        )
        report = _APP._validate_vision_contract(
            text, domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertTrue(report.get('has_template_residue', False))

    @_skip_if_no_app
    def test_system_tool_residue_rejected_for_data_ar(self):
        # The AR residue-map key "System/Tool" is the specific token
        # the production final-audit catches as
        # ``vision_contains_en_template_residue``.
        text = _data_vision_n_rows(
            6, include_compliance=True, include_dmo=True,
            extra_text='Notes: System/Tool placeholder'
        )
        report = _APP._validate_vision_contract(
            text, domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertTrue(report.get('has_template_residue', False))
        residue_err = next(
            e for e in report['errors']
            if e.startswith('vision_contains_en_template_residue'))
        self.assertIn('System/Tool', residue_err)

    @_skip_if_no_app
    def test_valid_data_vision_passes_contract(self):
        # 6 rows + NDMO/PDPL compliance + DMO establishment passes the
        # full PR-5B.9M contract for Data + consulting +
        # org_structure_is_none=True.
        text = _data_vision_n_rows(
            6, include_compliance=True, include_dmo=True)
        report = _APP._validate_vision_contract(
            text, domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertTrue(
            report['ok'],
            f'valid Data vision must pass; errors={report["errors"]}')
        self.assertFalse(report.get('has_template_residue', True))
        self.assertEqual(report['rows'], 6)


class VisionSafeAssignResidueTests(unittest.TestCase):
    """``_assign_vision_if_valid_or_restore`` must NOT assign a
    candidate that fails the residue check, and must restore the
    original Vision instead."""

    @_skip_if_no_app
    def test_residue_candidate_not_assigned(self):
        original_text = _data_vision_n_rows(
            6, include_compliance=True, include_dmo=True)
        residue_candidate = original_text + (
            '\n\nObjective: <to fill> footer\n')
        sections = {'vision': original_text}
        synth_status = {}
        report = _APP._assign_vision_if_valid_or_restore(
            sections, residue_candidate, original_text,
            domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            synth_status=synth_status,
        )
        # Assignment was refused.
        self.assertFalse(report['assign_allowed'])
        self.assertTrue(report.get('has_template_residue', False))
        # Vision restored — NOT the residue-bearing candidate.
        self.assertEqual(sections['vision'], original_text)
        self.assertNotIn('Objective: <', sections['vision'])
        # synth_status flagged 'vision' as failed so the audit fails closed.
        # ``_mark_synth_failed`` writes under a nested 'synth_status' key.
        _nested = synth_status.get('synth_status', synth_status)
        self.assertIn('vision', _nested)

    @_skip_if_no_app
    def test_valid_candidate_assigned(self):
        original_text = _data_vision_n_rows(5)  # 5 rows — below req
        new_text = _data_vision_n_rows(
            6, include_compliance=True, include_dmo=True)
        sections = {'vision': original_text}
        synth_status = {}
        report = _APP._assign_vision_if_valid_or_restore(
            sections, new_text, original_text,
            domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            synth_status=synth_status,
        )
        self.assertTrue(report['assign_allowed'],
                        f'expected assign; errors={report["errors"]}')
        self.assertEqual(sections['vision'], new_text)


class VisionResidueNoWeakeningTests(unittest.TestCase):
    """The residue fix must not weaken existing validators:
    empty / too-few-rows vision still rejected even when residue clean.
    Also: the helper does not insert deterministic objective rows.
    """

    @_skip_if_no_app
    def test_empty_vision_still_rejected(self):
        text = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            'الرؤية: تعزيز حوكمة البيانات.\n\n'
            '### الأهداف الاستراتيجية:\n\n'
            '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
            '|---|------------------|-------|--------|---------------|\n'
        )
        report = _APP._validate_vision_contract(
            text, domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertEqual(report['rows'], 0)

    @_skip_if_no_app
    def test_4_rows_still_rejected_below_min(self):
        text = _data_vision_n_rows(
            4, include_compliance=True, include_dmo=True)
        report = _APP._validate_vision_contract(
            text, domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting', lang='ar',
        )
        self.assertFalse(report['ok'])
        self.assertLess(report['rows'], report['required_min_rows'])

    @_skip_if_no_app
    def test_assign_or_restore_does_not_synthesize_rows(self):
        # The safe-assign helper never adds rows — when rejecting a
        # candidate it restores the ORIGINAL, never injects fabricated
        # objective rows.
        original_text = _data_vision_n_rows(6,
                                            include_compliance=True,
                                            include_dmo=True)
        bad_candidate = _data_vision_n_rows(3)  # too few rows
        sections = {'vision': original_text}
        synth_status = {}
        before_rows = _APP.count_valid_objective_rows(original_text)
        _APP._assign_vision_if_valid_or_restore(
            sections, bad_candidate, original_text,
            domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            synth_status=synth_status,
        )
        after_rows = _APP.count_valid_objective_rows(sections['vision'])
        self.assertEqual(after_rows, before_rows,
                         'safe-assign must not synthesize rows')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
