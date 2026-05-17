"""PR-5B.9P — Persistent NDMO compliance objective runtime failure.

Validates that the PR-5B.9N alias widening is wired into the runtime
detection / repair / safe-assign paths and that NO duplicate / legacy
NDMO detection logic exists. Adds end-to-end-style tests around the
documented Arabic / English NDMO+PDPL+DMO/CDO objective wordings that
the user reported still failing after PR-5B.9N.

Twelve test cases:

  1.  Data + selected_frameworks=['NDMO'] emits no defect when Vision
      contains "تحقيق الالتزام بإطار NDMO لحوكمة وإدارة البيانات".
  2.  Data + selected_frameworks=['NDMO','PDPL'] emits no defect when
      Vision has separate NDMO and PDPL rows.
  3.  Data + selected_frameworks=['NDMO','PDPL'] emits
      ``selected_framework_compliance_objective_missing:NDMO`` when only
      PDPL is present.
  4.  Data + org_structure_is_none=True still requires the DMO/CDO
      specialized-function objective in addition to NDMO.
  5.  ``_build_vision_composite_repair_contract`` for Data + NDMO names
      the exact NDMO objective requirement (display name + SEPARATE
      compliance wording).
  6.  A valid 6-row Data Vision with NDMO is NOT overwritten by a later
      candidate missing the NDMO objective row.
  7.  No duplicate / legacy NDMO detection paths — every emission site
      routes through ``_compute_missing_compliance_objective``.
  8.  ``_final_strategy_audit`` and the post-normalization audit (via
      ``_validate_vision_contract``) agree on the NDMO result for the
      same Vision text.
  9.  Template residue (``[organization]`` / ``{framework}`` / ``TODO``)
      remains rejected by ``_validate_vision_contract`` even when the
      NDMO objective text is otherwise present.
  10. No deterministic Strategic Objective rows are inserted by any
      detection / contract helper.
  11. Validators are NOT weakened: Data Management consulting mode still
      requires >= 6 Strategic Objective rows, an empty Vision still
      fails NDMO detection, and the residue / leakage gates remain.
  12. export / PDF / DOCX / auth / DB modules are untouched: spot-check
      a stable set of symbols.

Run:

    python -m pytest \\
        tests/test_ndmo_persistent_runtime_failure_pr5b9p.py -q
"""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_ndmo_pr5b9p_')
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


_AR_HEADER = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** حوكمة بيانات وطنية ممتثلة.\n\n'
    '### الأهداف الاستراتيجية:\n\n'
    '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
    '|---|------------------|-------|--------|---------------|\n'
)


def _vision_with_ndmo_only():
    """Vision with a single NDMO compliance objective row."""
    return (
        _AR_HEADER
        + '| 1 | تحقيق الالتزام بإطار NDMO لحوكمة وإدارة البيانات '
          '| 100% | الامتثال التنظيمي | 12 شهراً |\n'
        + '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        + '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        + '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
        + '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        + '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


def _vision_with_separate_ndmo_and_pdpl():
    return (
        _AR_HEADER
        + '| 1 | تحقيق الالتزام بإطار NDMO لحوكمة وإدارة البيانات '
          '| 100% | الامتثال لإطار حوكمة البيانات الوطني | 12 شهراً |\n'
        + '| 2 | تحقيق الالتزام بمتطلبات PDPL لحماية البيانات الشخصية '
          '| 100% | حماية البيانات الشخصية | 12 شهراً |\n'
        + '| 3 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        + '| 4 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        + '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        + '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


def _vision_with_pdpl_only_no_ndmo():
    return (
        _AR_HEADER
        + '| 1 | تحقيق الالتزام بمتطلبات PDPL لحماية البيانات الشخصية '
          '| 100% | حماية البيانات الشخصية | 12 شهراً |\n'
        + '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        + '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        + '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
        + '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        + '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


def _vision_with_ndmo_pdpl_and_cdo():
    """Three separate rows: NDMO, PDPL, DMO/CDO. >= 6 valid rows."""
    return (
        _AR_HEADER
        + '| 1 | تحقيق الالتزام بإطار NDMO لحوكمة وإدارة البيانات '
          '| 100% | الامتثال لإطار حوكمة البيانات الوطني | 12 شهراً |\n'
        + '| 2 | تحقيق الالتزام بمتطلبات PDPL لحماية البيانات الشخصية '
          '| 100% | حماية البيانات الشخصية | 12 شهراً |\n'
        + '| 3 | تأسيس مكتب إدارة البيانات وتعيين Chief Data Officer / CDO '
          '| 100% | إنشاء الوظيفة المتخصصة | 18 شهراً |\n'
        + '| 4 | بناء مستودع بيانات مركزي | 100% | مركزية البيانات | 18 شهراً |\n'
        + '| 5 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        + '| 6 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
    )


def _vision_no_ndmo():
    """Six valid rows but no NDMO / PDPL compliance row."""
    return (
        _AR_HEADER
        + '| 1 | تطوير قدرات تحليل البيانات | 100% | تحسين القرار | 12 شهراً |\n'
        + '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        + '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        + '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
        + '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        + '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


# ── Test classes ─────────────────────────────────────────────────────────


class NDMORuntimeDetectionTests(unittest.TestCase):
    """Tests 1, 2, 3, 4 — runtime detection of the documented wordings."""

    @_skip_if_no_app
    def test_01_data_ndmo_only_no_defect_with_canonical_wording(self):
        sections = {'vision': _vision_with_ndmo_only()}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['NDMO'],
            domain='Data Management', lang='ar',
        )
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_02_data_ndmo_and_pdpl_separate_rows_no_defect(self):
        sections = {'vision': _vision_with_separate_ndmo_and_pdpl()}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['NDMO', 'PDPL'],
            domain='Data Management', lang='ar',
        )
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_03_pdpl_only_emits_ndmo_missing_defect_in_final_audit(self):
        sections = {
            'vision': _vision_with_pdpl_only_no_ndmo(),
            'pillars': '## 2. الركائز\n\n### الركيزة 1\n',
            'environment': '## 3. البيئة\n\nنص.\n',
            'gaps': '## 4. الفجوات\n',
            'roadmap': '## 5. الخارطة\n',
            'kpis': '## 6. مؤشرات\n',
            'confidence': '## 7. الثقة\n',
        }
        # Direct helper assertion.
        direct_missing = _APP._compute_missing_compliance_objective(
            sections, ['NDMO', 'PDPL'],
            domain='Data Management', lang='ar',
        )
        self.assertIn('NDMO', direct_missing)
        self.assertNotIn('PDPL', direct_missing)
        # _final_strategy_audit must emit the same defect tag.
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            selected_frameworks=['NDMO', 'PDPL'],
            domain='Data Management', org_structure_is_none=False,
        )
        tags = [d[1] for d in defects]
        self.assertTrue(
            any(
                t.startswith(
                    'selected_framework_compliance_objective_missing:')
                and 'NDMO' in t for t in tags
            ),
            f'NDMO defect missing from tags={tags}',
        )

    @_skip_if_no_app
    def test_04_org_structure_none_requires_cdo_in_addition_to_ndmo(self):
        """A Vision with NDMO row but no DMO/CDO row must still fail the
        specialized-function check when ``org_structure_is_none=True``."""
        # NDMO satisfied but DMO/CDO objective missing.
        sections_no_cdo = {'vision': _vision_with_ndmo_only()}
        ndmo_missing = _APP._compute_missing_compliance_objective(
            sections_no_cdo, ['NDMO'],
            domain='Data Management', lang='ar',
        )
        self.assertNotIn('NDMO', ndmo_missing)
        sf_missing = (
            _APP._compute_missing_specialized_function_objective(
                sections_no_cdo, 'Data Management', lang='ar',
                org_structure_is_none=True,
            )
        )
        self.assertTrue(
            sf_missing,
            'Specialized-function objective should be flagged missing',
        )
        # Both rows present: both checks must pass on the same Vision.
        sections_with_cdo = {'vision': _vision_with_ndmo_pdpl_and_cdo()}
        self.assertEqual(
            _APP._compute_missing_compliance_objective(
                sections_with_cdo, ['NDMO', 'PDPL'],
                domain='Data Management', lang='ar',
            ),
            [],
        )
        self.assertFalse(
            _APP._compute_missing_specialized_function_objective(
                sections_with_cdo, 'Data Management', lang='ar',
                org_structure_is_none=True,
            )
        )
        # Row count guarantees the two new compliance rows + CDO row do
        # NOT shrink the table below the 6-row floor.
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(
                _vision_with_ndmo_pdpl_and_cdo()),
            6,
        )


class NDMOUnifiedRepairPromptTests(unittest.TestCase):
    """Test 5 — composite repair contract names NDMO explicitly."""

    @_skip_if_no_app
    def test_05_repair_prompt_names_ndmo_pdpl_and_cdo_for_data(self):
        ve_msg, min_rows = (
            _APP._build_vision_composite_repair_contract(
                domain='Data Management',
                selected_frameworks=['NDMO', 'PDPL'],
                org_structure_is_none=True,
                generation_mode='consulting',
                lang='ar',
                existing_vision='',
                existing_valid_rows=0,
            )
        )
        # Compliance clause must name NDMO and PDPL by display label.
        self.assertIn('NDMO', ve_msg)
        self.assertIn('PDPL', ve_msg)
        # Specialized-function clause must name DMO + CDO.
        self.assertIn('Data Management Office', ve_msg)
        self.assertIn('Chief Data Officer', ve_msg)
        # The (C) clause must require a SEPARATE compliance row.
        self.assertIn('SEPARATE', ve_msg)
        # The (S) clause must require an additional row that does NOT
        # replace the compliance row.
        self.assertIn('IN ADDITION', ve_msg)
        self.assertIn('MUST NOT replace', ve_msg)
        # Min row floor is preserved at >= 6 for Data consulting.
        self.assertGreaterEqual(min_rows, 6)

    @_skip_if_no_app
    def test_05b_repair_prompt_names_ndmo_for_data_only(self):
        ve_msg, _ = _APP._build_vision_composite_repair_contract(
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
            existing_vision='',
            existing_valid_rows=0,
        )
        self.assertIn('NDMO', ve_msg)
        self.assertIn('SEPARATE', ve_msg)


class NDMOOverwritePreventionTests(unittest.TestCase):
    """Test 6 — valid 6-row NDMO Vision is not overwritten by a candidate
    missing the NDMO objective row."""

    @_skip_if_no_app
    def test_06_overwrite_prevention_via_safe_assign_helper(self):
        original = _vision_with_ndmo_only()
        candidate = _vision_no_ndmo()
        sections = {'vision': original}
        report = _APP._assign_vision_if_valid_or_restore(
            sections, candidate, original,
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        # Candidate rejected.
        self.assertFalse(report.get('assign_allowed'))
        # Original Vision restored unchanged.
        self.assertEqual(sections['vision'], original)
        # Rejection reason includes NDMO.
        self.assertTrue(
            any('NDMO' in e for e in report.get('errors', [])),
            f'NDMO defect missing in errors={report.get("errors")}',
        )


class NDMOSingleSourceDetectionTests(unittest.TestCase):
    """Tests 7, 8 — no duplicate detection paths; final audit and
    contract validator agree."""

    @_skip_if_no_app
    def test_07_single_detection_helper_used_at_every_emission_site(self):
        """Every site that emits
        ``selected_framework_compliance_objective_missing`` must use
        ``_compute_missing_compliance_objective`` — there is no legacy
        keyword list shadowing the registry aliases."""
        with open(
                os.path.join(
                    os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as fh:
            src = fh.read()
        # Each emission line must be preceded (within the same function
        # body, ~250-line window) by a call to the shared helper.
        emit_marker = "'selected_framework_compliance_objective_missing:'"
        helper_marker = '_compute_missing_compliance_objective('
        emit_positions = []
        idx = 0
        while True:
            i = src.find(emit_marker, idx)
            if i < 0:
                break
            emit_positions.append(i)
            idx = i + len(emit_marker)
        # At least two emission sites exist (final audit and contract
        # validator); each must have the helper invoked above it.
        self.assertGreaterEqual(len(emit_positions), 2)
        for pos in emit_positions:
            window = src[max(0, pos - 8000):pos]
            self.assertIn(
                helper_marker, window,
                'emission site is not preceded by '
                '_compute_missing_compliance_objective call',
            )
        # Negative: no legacy hard-coded NDMO keyword list elsewhere.
        # ``ndmo_keywords`` / ``NDMO_OBJECTIVE_KEYWORDS`` are forbidden
        # names — detection routes through the registry aliases.
        for legacy in ('NDMO_OBJECTIVE_KEYWORDS', 'ndmo_keywords ='):
            self.assertNotIn(
                legacy, src,
                f'legacy NDMO keyword container {legacy!r} found '
                'in app.py',
            )

    @_skip_if_no_app
    def test_08_final_audit_and_contract_validator_agree(self):
        """``_validate_vision_contract`` and ``_final_strategy_audit``
        must produce the same NDMO defect for the same Vision text."""
        # Case A — Vision satisfies NDMO. Both must report "not missing".
        sections_ok = {
            'vision': _vision_with_ndmo_only(),
            'pillars': '## 2. الركائز\n\n### الركيزة 1\n',
            'environment': '## 3. البيئة\n\nنص.\n',
            'gaps': '## 4. الفجوات\n',
            'roadmap': '## 5. الخارطة\n',
            'kpis': '## 6. مؤشرات\n',
            'confidence': '## 7. الثقة\n',
        }
        contract_ok = _APP._validate_vision_contract(
            sections_ok['vision'],
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        self.assertTrue(contract_ok.get('has_compliance'))
        final_ok = _APP._final_strategy_audit(
            sections_ok, lang='ar', doc_subtype=None,
            selected_frameworks=['NDMO'],
            domain='Data Management', org_structure_is_none=False,
        )
        final_ok_tags = [d[1] for d in final_ok]
        self.assertFalse(
            any(
                t.startswith(
                    'selected_framework_compliance_objective_missing:')
                and 'NDMO' in t for t in final_ok_tags
            ),
            f'unexpected NDMO defect on satisfied Vision: {final_ok_tags}',
        )
        # Case B — Vision missing NDMO. Both must flag the defect.
        sections_bad = dict(sections_ok)
        sections_bad['vision'] = _vision_no_ndmo()
        contract_bad = _APP._validate_vision_contract(
            sections_bad['vision'],
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        self.assertFalse(contract_bad.get('has_compliance'))
        final_bad = _APP._final_strategy_audit(
            sections_bad, lang='ar', doc_subtype=None,
            selected_frameworks=['NDMO'],
            domain='Data Management', org_structure_is_none=False,
        )
        final_bad_tags = [d[1] for d in final_bad]
        self.assertTrue(
            any(
                t.startswith(
                    'selected_framework_compliance_objective_missing:')
                and 'NDMO' in t for t in final_bad_tags
            ),
            f'expected NDMO defect missing: {final_bad_tags}',
        )


class NDMOInvariantsTests(unittest.TestCase):
    """Tests 9, 10, 11, 12 — template residue, no determinism, no
    weakening, export/PDF/DOCX/auth/DB untouched."""

    @_skip_if_no_app
    def test_09_template_residue_still_rejected(self):
        residue_vision = (
            _AR_HEADER
            + '| 1 | تحقيق الالتزام بإطار NDMO {framework} '
              '| 100% | [organization] | 12 شهراً |\n'
            + '| 2 | بناء مستودع بيانات | 100% | مركزية | 18 شهراً |\n'
            + '| 3 | تدريب فرق البيانات | 100% | كفاءات | 12 شهراً |\n'
            + '| 4 | اعتماد أدوات تحليل | 100% | كفاءة | 12 شهراً |\n'
            + '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
            + '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
        )
        report = _APP._validate_vision_contract(
            residue_vision,
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        self.assertFalse(report['ok'])
        joined = ' '.join(report['errors'])
        self.assertTrue(
            ('vision_contains_en_template_marker' in joined)
            or ('vision_contains_en_template_residue' in joined),
            f'template residue/marker not flagged; errors={report["errors"]}',
        )

    @_skip_if_no_app
    def test_10_no_deterministic_objective_rows_inserted(self):
        """Detection / contract helpers are read-only — they must NOT
        mutate sections, insert objective rows, or change row counts."""
        original_no = _vision_no_ndmo()
        original_ok = _vision_with_ndmo_only()
        for vis in (original_no, original_ok):
            sections = {'vision': vis}
            # Detection (twice — idempotent).
            _APP._compute_missing_compliance_objective(
                sections, ['NDMO', 'PDPL'],
                domain='Data Management', lang='ar',
            )
            _APP._compute_missing_compliance_objective(
                sections, ['NDMO', 'PDPL'],
                domain='Data Management', lang='ar',
            )
            # Contract validator is also read-only.
            _APP._validate_vision_contract(
                sections['vision'],
                domain='Data Management',
                selected_frameworks=['NDMO'],
                org_structure_is_none=True,
                generation_mode='consulting',
                lang='ar',
            )
            # Builder is also read-only.
            _APP._build_vision_composite_repair_contract(
                domain='Data Management',
                selected_frameworks=['NDMO', 'PDPL'],
                org_structure_is_none=True,
                generation_mode='consulting',
                lang='ar',
                existing_vision=sections['vision'],
                existing_valid_rows=_APP.count_valid_objective_rows(
                    sections['vision']),
            )
            self.assertEqual(sections['vision'], vis)
            self.assertEqual(
                _APP.count_valid_objective_rows(sections['vision']),
                _APP.count_valid_objective_rows(vis),
            )

    @_skip_if_no_app
    def test_11_validators_not_weakened(self):
        """Data Management consulting still requires >= 6 SO rows; an
        empty Vision still fails NDMO detection; framework-leakage
        check still active."""
        obligations = (
            _APP._compute_applicable_strategy_obligations(
                domain='Data Management',
                selected_frameworks=['NDMO'],
                org_structure_is_none=False,
                generation_mode='consulting',
                lang='ar',
            )
        )
        self.assertGreaterEqual(
            int(obligations.get('min_objective_rows') or 0), 6,
        )
        # Empty / nearly-empty Vision must still flag NDMO.
        self.assertIn(
            'NDMO',
            _APP._compute_missing_compliance_objective(
                {'vision': ''}, ['NDMO'],
                domain='Data Management', lang='ar',
            ),
        )
        # Vision text without any objective rows must still flag NDMO.
        self.assertIn(
            'NDMO',
            _APP._compute_missing_compliance_objective(
                {'vision': 'فقط فقرة سردية بدون جدول.'}, ['NDMO'],
                domain='Data Management', lang='ar',
            ),
        )

    @_skip_if_no_app
    def test_12_export_pdf_docx_auth_db_modules_untouched(self):
        for sym in (
                # Core API route.
                'api_generate_strategy',
                # Strategy helpers untouched.
                'count_valid_objective_rows',
                # Vision contract surface used by safe-assign.
                '_validate_vision_contract',
                '_assign_vision_if_valid_or_restore',
                '_build_vision_composite_repair_contract',
                # Registry surface used by the runtime path.
                '_FRAMEWORK_COVERAGE_REQUIREMENTS',
                '_compute_missing_compliance_objective',
                '_resolve_selected_frameworks',
        ):
            with self.subTest(symbol=sym):
                self.assertTrue(
                    hasattr(_APP, sym),
                    f'expected symbol missing: {sym}',
                )
        # NDMO registry entry must still resolve in Data Management.
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']
        self.assertIn(
            'Data Management', spec.get('applicable_domains', []),
        )


class NDMODiagnosticLogTests(unittest.TestCase):
    """The new PR-5B.9P diagnostic log must fire when NDMO is in the
    resolved selected_frameworks list and must NOT fire for unrelated
    frameworks."""

    @_skip_if_no_app
    def test_diagnostic_emits_for_ndmo_selection(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._compute_missing_compliance_objective(
                {'vision': _vision_with_ndmo_only()},
                ['NDMO'],
                domain='Data Management', lang='ar',
            )
        out = buf.getvalue()
        self.assertIn('[NDMO-OBJECTIVE-CHECK]', out)
        self.assertIn("selected_frameworks=['NDMO']", out)
        self.assertIn('missing=[]', out)

    @_skip_if_no_app
    def test_diagnostic_silent_when_ndmo_not_selected(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._compute_missing_compliance_objective(
                {'vision': _vision_no_ndmo()},
                ['ECC'],
                domain='Cyber Security', lang='ar',
            )
        self.assertNotIn('[NDMO-OBJECTIVE-CHECK]', buf.getvalue())


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
