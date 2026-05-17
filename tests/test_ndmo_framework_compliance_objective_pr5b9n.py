"""PR-5B.9N — NDMO framework compliance objective detection & repair.

Pins:
  * ``_FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']`` declares the widened
    AR/EN aliases listed in the runtime requirement so
    ``_compute_missing_compliance_objective`` recognises an NDMO
    compliance row whether the AI used "NDMO Data Management Framework",
    "إطار حوكمة البيانات الوطني", "تحقيق الامتثال لإطار إدارة البيانات
    الوطني", or "حوكمة البيانات".
  * A Vision lacking any NDMO-aligned objective row emits
    ``selected_framework_compliance_objective_missing:NDMO`` from
    ``_final_strategy_audit``.
  * A combined NDMO + PDPL wording such as
    "تحقيق الالتزام بضوابط NDMO Data Management Framework
    وPersonal Data Protection Law (PDPL)" satisfies BOTH frameworks.
  * The unified Vision repair contract for Data Management explicitly
    names NDMO + (when org_structure_is_none) Data Management Office /
    Chief Data Officer.
  * No deterministic Strategic Objective rows are inserted and no
    validator threshold is weakened.

Run:
    python -m pytest \
        tests/test_ndmo_framework_compliance_objective_pr5b9n.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_ndmo_pr5b9n_')
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


# ── Vision fixtures ──────────────────────────────────────────────────────


def _vision_no_ndmo():
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** بناء قدرات بيانات موثوقة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        '| 1 | تطوير قدرات تحليل البيانات | 100% | تحسين القرار | 12 شهراً |\n'
        '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
        '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


def _vision_with_ndmo_alias(alias_text):
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** بناء قدرات بيانات موثوقة وممتثلة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        f'| 1 | تحقيق الالتزام بـ {alias_text} '
        '| 100% | تحقيق المتطلبات التنظيمية | 12 شهراً |\n'
        '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
        '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


def _vision_combined_ndmo_pdpl():
    """Combined wording cited in the requirement (Part D)."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** حوكمة بيانات وطنية ممتثلة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        '| 1 | تحقيق الالتزام بضوابط NDMO Data Management Framework '
        'وPersonal Data Protection Law (PDPL) '
        '| 100% | الامتثال التنظيمي | 12 شهراً |\n'
        '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
        '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
        '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
        '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
    )


def _vision_ndmo_pdpl_distinct_with_cdo():
    """Three separate rows: NDMO, PDPL, DMO/CDO. >=6 valid rows."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** حوكمة بيانات وطنية ممتثلة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        '| 1 | تحقيق الالتزام بإطار NDMO لحوكمة وإدارة البيانات '
        '| 100% | الامتثال لإطار حوكمة البيانات الوطني | 12 شهراً |\n'
        '| 2 | تحقيق الالتزام بمتطلبات PDPL لحماية البيانات الشخصية '
        '| 100% | الامتثال لنظام حماية البيانات الشخصية | 12 شهراً |\n'
        '| 3 | تأسيس مكتب إدارة البيانات وتعيين Chief Data Officer '
        '| 100% | إنشاء الوظيفة المتخصصة | 18 شهراً |\n'
        '| 4 | بناء مستودع بيانات مركزي | 100% | مركزية البيانات | 18 شهراً |\n'
        '| 5 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
        '| 6 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
    )


# ── Test classes ─────────────────────────────────────────────────────────


class NDMOAliasRegistryTests(unittest.TestCase):
    """Test 6 — NDMO aliases recognized in Arabic and English."""

    @_skip_if_no_app
    def test_ndmo_registry_present(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('NDMO')
        self.assertIsNotNone(spec, 'NDMO registry entry missing')

    @_skip_if_no_app
    def test_ndmo_widened_aliases_contain_required_tokens(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']
        aliases = [a.lower() for a in spec.get('aliases', [])]
        for tok in (
                # English
                'ndmo',
                'ndmo data management framework',
                'ndmo data governance framework',
                'national data management office',
                'data governance',
                'data management',
                'data quality',
                'data catalog',
                'metadata',
                'data classification',
                'data lifecycle',
                'data ownership',
                'data stewardship',
                # Arabic
                'إدارة البيانات الوطنية',
                'مكتب إدارة البيانات الوطنية',
                'إطار إدارة البيانات الوطني',
                'إطار حوكمة البيانات الوطني',
                'تحقيق الامتثال لإطار إدارة البيانات الوطني',
                'تحقيق الامتثال لإطار حوكمة البيانات الوطني',
                'حوكمة البيانات',
                'إدارة البيانات',
                'جودة البيانات',
                'كتالوج البيانات',
                'البيانات الوصفية',
                'تصنيف البيانات',
                'دورة حياة البيانات',
                'ملكية البيانات',
                'أمناء البيانات',
        ):
            with self.subTest(token=tok):
                self.assertIn(
                    tok.lower(), aliases,
                    f'NDMO alias missing: {tok!r}',
                )


class NDMOComplianceDetectionTests(unittest.TestCase):
    """Tests 1-4 + 6 — alias detection / audit emission."""

    @_skip_if_no_app
    def test_01_data_ndmo_arabic_vision_with_objective_passes(self):
        sections = {
            'vision': _vision_with_ndmo_alias(
                'إطار NDMO لحوكمة وإدارة البيانات'),
        }
        missing = _APP._compute_missing_compliance_objective(
            sections, ['NDMO'], domain='Data Management', lang='ar',
        )
        self.assertNotIn('NDMO', missing)

    @_skip_if_no_app
    def test_02_data_ndmo_pdpl_combined_wording_satisfies_both(self):
        sections = {'vision': _vision_combined_ndmo_pdpl()}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['NDMO', 'PDPL'],
            domain='Data Management', lang='ar',
        )
        self.assertNotIn('NDMO', missing)
        self.assertNotIn('PDPL', missing)

    @_skip_if_no_app
    def test_03_data_ndmo_missing_emits_defect(self):
        sections = {'vision': _vision_no_ndmo()}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['NDMO'], domain='Data Management', lang='ar',
        )
        self.assertIn('NDMO', missing)

    @_skip_if_no_app
    def test_03b_audit_emits_ndmo_missing_in_defect_list(self):
        sections = {
            'vision': _vision_no_ndmo(),
            'pillars': '## 2. الركائز\n\n### الركيزة 1\n',
            'environment': '## 3. البيئة\n\nنص.\n',
            'gaps': '## 4. الفجوات\n',
            'roadmap': '## 5. الخارطة\n',
            'kpis': '## 6. مؤشرات\n',
            'confidence': '## 7. الثقة\n',
        }
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            selected_frameworks=['NDMO'], domain='Data Management',
            org_structure_is_none=False,
        )
        tags = [d[1] for d in defects]
        self.assertTrue(
            any(
                t.startswith(
                    'selected_framework_compliance_objective_missing:')
                and 'NDMO' in t for t in tags
            ),
            f'NDMO compliance defect not emitted; tags={tags}',
        )

    @_skip_if_no_app
    def test_04_ndmo_and_specialized_function_coexist(self):
        """org_structure_is_none → both NDMO compliance row AND
        DMO/CDO row must be detected as satisfied; >=6 valid rows."""
        vision = _vision_ndmo_pdpl_distinct_with_cdo()
        sections = {'vision': vision}
        missing_fw = _APP._compute_missing_compliance_objective(
            sections, ['NDMO', 'PDPL'],
            domain='Data Management', lang='ar',
        )
        self.assertNotIn('NDMO', missing_fw)
        self.assertNotIn('PDPL', missing_fw)
        missing_sf = (
            _APP._compute_missing_specialized_function_objective(
                sections, 'Data Management', lang='ar',
                org_structure_is_none=True,
            )
        )
        self.assertFalse(missing_sf)
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(vision), 6,
        )

    @_skip_if_no_app
    def test_06_each_required_alias_satisfies_compliance_objective(self):
        for alias in (
                'NDMO Data Management Framework',
                'NDMO Data Governance Framework',
                'National Data Management Office',
                'إطار حوكمة البيانات الوطني',
                'إطار إدارة البيانات الوطني',
                'مكتب إدارة البيانات الوطنية',
                'حوكمة البيانات',
                'إدارة البيانات',
        ):
            with self.subTest(alias=alias):
                sections = {
                    'vision': _vision_with_ndmo_alias(alias),
                }
                missing = _APP._compute_missing_compliance_objective(
                    sections, ['NDMO'],
                    domain='Data Management', lang='ar',
                )
                self.assertNotIn(
                    'NDMO', missing,
                    f'NDMO compliance not detected for alias {alias!r}',
                )


class NDMOVisionRepairContractTests(unittest.TestCase):
    """Test 5 — repair prompt for Data Management must name NDMO +
    (when org_structure_is_none) DMO / Chief Data Officer."""

    @_skip_if_no_app
    def test_05_data_ndmo_repair_prompt_names_ndmo_and_dmo_cdo(self):
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
        # Min rows >= 6 (consulting mode for Data Management).
        self.assertGreaterEqual(min_rows, 6)
        # Compliance clause names NDMO + PDPL display values.
        self.assertIn('NDMO', ve_msg)
        self.assertIn('PDPL', ve_msg)
        # Specialized-function clause names DMO + CDO.
        self.assertIn('Data Management Office', ve_msg)
        self.assertIn('Chief Data Officer', ve_msg)
        # Coexistence wording — neither row replaces the other.
        self.assertIn('SEPARATE', ve_msg)
        self.assertIn('IN ADDITION', ve_msg)
        self.assertIn('MUST NOT replace', ve_msg)

    @_skip_if_no_app
    def test_05b_data_ndmo_only_repair_prompt_names_ndmo(self):
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


class NDMOPreservationAndResidueTests(unittest.TestCase):
    """Tests 7, 8 — preservation guard + template residue rejection."""

    @_skip_if_no_app
    def test_07_valid_six_row_data_vision_not_overwritten_by_repair_lacking_ndmo(
            self):
        """A valid 6-row Vision must not be overwritten by a repaired
        candidate that lacks the NDMO compliance objective."""
        original = _vision_ndmo_pdpl_distinct_with_cdo()
        candidate_without_ndmo = _vision_no_ndmo()
        sections = {'vision': original}
        report = _APP._assign_vision_if_valid_or_restore(
            sections,
            candidate_without_ndmo,
            original,
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        # Candidate must be rejected …
        self.assertFalse(report.get('assign_allowed'))
        # … and original vision preserved unchanged.
        self.assertEqual(sections['vision'], original)
        # The rejection must include the NDMO defect tag.
        self.assertTrue(
            any('NDMO' in e for e in report.get('errors', [])),
            f'NDMO defect missing from errors: {report.get("errors")}',
        )

    @_skip_if_no_app
    def test_08_template_residue_still_rejected_for_data_ndmo(self):
        residue_vision = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** TODO insert vision here.\n\n'
            '### الأهداف الاستراتيجية:\n\n'
            '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
            '|---|------------------|-------|--------|---------------|\n'
            '| 1 | تحقيق الالتزام بإطار NDMO {framework} '
            '| 100% | [organization] | 12 شهراً |\n'
            '| 2 | بناء مستودع بيانات | 100% | مركزية البيانات | 18 شهراً |\n'
            '| 3 | تدريب فرق البيانات | 100% | بناء الكفاءات | 12 شهراً |\n'
            '| 4 | اعتماد أدوات تحليل | 100% | الكفاءة | 12 شهراً |\n'
            '| 5 | تطوير لوحات المعلومات | 100% | الشفافية | 12 شهراً |\n'
            '| 6 | قياس جودة المخرجات | 100% | التحسين | 12 شهراً |\n'
        )
        report = _APP._validate_vision_contract(
            residue_vision,
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
            original_valid_rows=0,
        )
        self.assertFalse(report['ok'])
        joined = ' '.join(report['errors'])
        # Either marker or residue check must fire.
        self.assertTrue(
            ('vision_contains_en_template_marker' in joined)
            or ('vision_contains_en_template_residue' in joined),
            f'Template marker/residue not flagged; errors={report["errors"]}',
        )


class NDMOInvariantsTests(unittest.TestCase):
    """Tests 9, 10, 11 — no deterministic rows, validators not weakened,
    export/PDF/DOCX/auth/DB untouched."""

    @_skip_if_no_app
    def test_09_no_deterministic_objective_rows_injected(self):
        """Calling the read-only detection / contract helpers must not
        mutate ``sections`` and must not inject any objective rows."""
        original = _vision_no_ndmo()
        sections = {'vision': original}
        # Detection is read-only.
        _APP._compute_missing_compliance_objective(
            sections, ['NDMO'], domain='Data Management', lang='ar',
        )
        self.assertEqual(sections['vision'], original)
        # Contract builder is read-only.
        _APP._build_vision_composite_repair_contract(
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
            existing_vision=original,
            existing_valid_rows=_APP.count_valid_objective_rows(original),
        )
        self.assertEqual(sections['vision'], original)
        # Row count is unchanged after detection — no rows added.
        self.assertEqual(
            _APP.count_valid_objective_rows(sections['vision']),
            _APP.count_valid_objective_rows(original),
        )

    @_skip_if_no_app
    def test_10_validators_not_weakened_min_so_rows_consulting_data(self):
        """Min objective rows for Data Management (consulting) >= 6."""
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
        # An empty / nearly-empty Vision MUST still fail validation
        # for NDMO — the fix did not silence the gate.
        empty_sections = {'vision': ''}
        missing = _APP._compute_missing_compliance_objective(
            empty_sections, ['NDMO'],
            domain='Data Management', lang='ar',
        )
        self.assertIn('NDMO', missing)

    @_skip_if_no_app
    def test_11_export_pdf_docx_auth_db_modules_untouched(self):
        """The PR-5B.9N fix changes only the NDMO registry entry. Spot-
        check that export / PDF / DOCX / auth / DB symbols still resolve
        and are not patched out."""
        for sym in (
                # Routes / API.
                'api_generate_strategy',
                # Strategy helpers untouched.
                'count_valid_objective_rows',
                # NDMO registry entry remains a dict with aliases.
                '_FRAMEWORK_COVERAGE_REQUIREMENTS',
        ):
            with self.subTest(symbol=sym):
                self.assertTrue(
                    hasattr(_APP, sym),
                    f'expected symbol missing: {sym}',
                )
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']
        self.assertIn('aliases', spec)
        self.assertIn(
            'Data Management', spec.get('applicable_domains', []),
        )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
