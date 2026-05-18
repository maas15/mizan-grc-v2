"""PR-5B.9Y — PDPL save guard ordering and runtime defect parsing.

Regression suite for the persistent runtime failure where PDPL Data
Management strategies still received the generic
``selected_framework_coverage_missing`` 422 even after PR-5B.9X added
the FINAL PDPL DATA SAVE GUARD. PR-5B.9Y moves the PDPL save guard so
it runs BEFORE the generic post-normalization 422 and parses the
actual runtime defect-string shape emitted by the post-normalization
audit (``... (pillars) 0/1`` / ``... (gaps) 0/1`` etc.).

Scope: Data Management + PDPL only. Cyber / AI / Digital
Transformation / ERM / NDMO behaviour is preserved. AI-first only —
no deterministic strategy rows; validators are not weakened.

Run:
    python -m pytest \
        tests/test_pdpl_save_guard_runtime_pr5b9y.py -q
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_pr5b9y_')
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
            self.skipTest('app.py not importable')
        return fn(self, *a, **kw)

    return _wrapped


def _read_app_source():
    with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'),
              encoding='utf-8') as f:
        return f.read()


# ──────────────────────────────────────────────────────────────────────
# Part 1 — Guard ordering: PR-5B.9Y guard runs BEFORE the generic
# selected_framework_coverage_missing 422.
# ──────────────────────────────────────────────────────────────────────


class TestGuardOrdering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = _read_app_source()

    @_skip_if_no_app
    def test_pr5b9y_guard_runs_before_generic_post_norm_422(self):
        idx_guard = self.src.find('PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        # The generic 422 we are racing is the post-normalization
        # blocker construction immediately below the guard.
        idx_generic = self.src.find('post_normalization_blockers')
        self.assertGreater(
            idx_guard, 0, 'PR-5B.9Y guard marker missing')
        self.assertGreater(
            idx_generic, 0, 'post_normalization_blockers anchor missing')
        self.assertLess(
            idx_guard, idx_generic,
            'PR-5B.9Y guard must run BEFORE the generic 422 return')

    @_skip_if_no_app
    def test_pr5b9y_guard_returns_pdpl_save_guard_residual(self):
        anchor = self.src.find('PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        self.assertGreater(anchor, 0)
        block = self.src[anchor:anchor + 30000]
        self.assertIn("'pdpl_save_guard_residual'", block)
        self.assertIn("'pdpl_save_guard_canonical'", block)
        self.assertIn('}), 422', block)

    @_skip_if_no_app
    def test_pr5b9y_guard_scoped_to_data_pdpl_only(self):
        anchor = self.src.find('PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        self.assertGreater(anchor, 0)
        block = self.src[anchor:anchor + 30000]
        self.assertIn('normalize_domain', block)
        self.assertIn("'data'", block)
        self.assertIn("'PDPL' in _pr5b9y_resolved", block)

    @_skip_if_no_app
    def test_pr5b9y_guard_uses_compute_missing_validator(self):
        anchor = self.src.find('PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        block = self.src[anchor:anchor + 30000]
        self.assertIn(
            '_compute_missing_selected_framework_coverage', block)
        self.assertIn('_canonicalize_selected_framework_family', block)

    @_skip_if_no_app
    def test_pr5b9y_diagnostics_present(self):
        anchor = self.src.find('PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        raw = self.src[anchor:anchor + 30000]
        # Collapse Python implicit string concatenation so substring
        # assertions target the *logical* runtime string rather than
        # the source-level wrap fragments.
        block = re.sub(r"'\s*\n\s*'", "", raw)
        self.assertIn('[PDPL-SAVE-GUARD]', block)
        self.assertIn('reached=True', block)
        self.assertIn('remaining_before=', block)
        self.assertIn('parsed_residual=', block)
        self.assertIn('repair_attempted=', block)
        self.assertIn('remaining_after=', block)
        self.assertIn('will_return_422=', block)
        self.assertIn('[DATA-FRAMEWORK-COVERAGE-REPAIR]', block)
        self.assertIn('required_terms=', block)
        self.assertIn('candidate_terms_found=', block)


# ──────────────────────────────────────────────────────────────────────
# Part 2 — Runtime defect string parser: all 5 shapes plus filtering.
# ──────────────────────────────────────────────────────────────────────


class TestRuntimeDefectParser(unittest.TestCase):

    @_skip_if_no_app
    def test_parses_pillars_runtime_shape(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:data_classification_pdpl (pillars) 0/1'
        ])
        self.assertIn(('PDPL', 'data_classification_pdpl', 'pillars'),
                      out)

    @_skip_if_no_app
    def test_parses_gaps_runtime_shape(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:breach_notification (gaps) 0/1'
        ])
        self.assertIn(('PDPL', 'breach_notification', 'gaps'), out)

    @_skip_if_no_app
    def test_parses_roadmap_runtime_shape(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:breach_notification (roadmap) 0/1'
        ])
        self.assertIn(('PDPL', 'breach_notification', 'roadmap'), out)

    @_skip_if_no_app
    def test_parses_kpis_runtime_shape(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:personal_data_classification (kpis) 0/1'
        ])
        self.assertIn(
            ('PDPL', 'personal_data_classification', 'kpis'), out)

    @_skip_if_no_app
    def test_parses_confidence_runtime_shape(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:personal_data_classification (confidence) 0/1'
        ])
        self.assertIn(
            ('PDPL', 'personal_data_classification', 'confidence'), out)

    @_skip_if_no_app
    def test_parses_kpi_alias_to_kpis(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:breach_notification (kpi) 0/1'
        ])
        self.assertIn(('PDPL', 'breach_notification', 'kpis'), out)

    @_skip_if_no_app
    def test_parses_risks_alias_to_confidence(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:breach_notification (risks) 0/1'
        ])
        self.assertIn(
            ('PDPL', 'breach_notification', 'confidence'), out)

    @_skip_if_no_app
    def test_parses_final_strategy_audit_4tuple(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([(
            'pillars',
            'selected_framework_coverage_missing:'
            'PDPL:data_classification_pdpl',
            0, 1,
        )])
        self.assertIn(
            ('PDPL', 'data_classification_pdpl', 'pillars'), out)

    @_skip_if_no_app
    def test_parses_colon_section_tail_shape(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'PDPL:breach_notification:roadmap'
        ])
        self.assertIn(('PDPL', 'breach_notification', 'roadmap'), out)

    @_skip_if_no_app
    def test_parses_compute_missing_3tuple_shape(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([('PDPL', 'breach_notification', 'kpis')])
        self.assertIn(('PDPL', 'breach_notification', 'kpis'), out)

    @_skip_if_no_app
    def test_filters_non_pdpl_frameworks(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            ('PDPL', 'privacy_governance', 'pillars'),
            ('NDMO', 'data_lifecycle', 'pillars'),
            'selected_framework_coverage_missing:ECC:identity_access:gaps',
        ])
        # privacy_governance is PDPL but NOT in the 3 PDPL targets;
        # NDMO and ECC are non-PDPL and must be filtered.
        self.assertEqual(out, [])

    @_skip_if_no_app
    def test_canonicalizes_data_classification_pdpl_to_personal(self):
        c = _APP._canonicalize_selected_framework_family
        self.assertEqual(
            c('PDPL', 'data_classification_pdpl'),
            'personal_data_classification')
        self.assertEqual(
            c('PDPL', 'personal_data_classification'),
            'personal_data_classification')

    @_skip_if_no_app
    def test_parser_dedupes_residuals(self):
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            ('PDPL', 'breach_notification', 'kpis'),
            'selected_framework_coverage_missing:'
            'PDPL:breach_notification (kpis) 0/1',
        ])
        self.assertEqual(out.count(
            ('PDPL', 'breach_notification', 'kpis')), 1)


# ──────────────────────────────────────────────────────────────────────
# Part 3 — Exact-term acceptance gate.
# ──────────────────────────────────────────────────────────────────────


class TestExactTermAcceptance(unittest.TestCase):

    @_skip_if_no_app
    def test_classification_requires_specific_ar_concept(self):
        g = _APP._pdpl_save_guard_candidate_satisfies
        # Generic "حماية البيانات الشخصية" does NOT satisfy.
        self.assertFalse(g(
            'personal_data_classification',
            'حماية البيانات الشخصية والامتثال لـ PDPL مطلوبة'))
        # Exact term satisfies.
        self.assertTrue(g(
            'personal_data_classification',
            'نطبق تصنيف البيانات الشخصية على جميع البيانات الحساسة'))

    @_skip_if_no_app
    def test_classification_requires_specific_en_concept(self):
        g = _APP._pdpl_save_guard_candidate_satisfies
        self.assertFalse(g(
            'data_classification_pdpl',
            'PDPL compliance is required across the organization'))
        self.assertTrue(g(
            'data_classification_pdpl',
            'Adopt a Personal Data Classification scheme aligned to PDPL'))
        self.assertTrue(g(
            'data_classification_pdpl',
            'Implement sensitive personal data classification controls'))

    @_skip_if_no_app
    def test_breach_requires_specific_ar_concept(self):
        g = _APP._pdpl_save_guard_candidate_satisfies
        # Generic personal-data-protection language is NOT enough.
        self.assertFalse(g(
            'breach_notification',
            'حماية البيانات الشخصية والامتثال لـ PDPL'))
        self.assertTrue(g(
            'breach_notification',
            'يجب إخطار الخروقات خلال 72 ساعة من اكتشافها'))
        self.assertTrue(g(
            'breach_notification',
            'الإبلاغ عن الانتهاكات إلى الهيئة المختصة'))

    @_skip_if_no_app
    def test_breach_requires_specific_en_concept(self):
        g = _APP._pdpl_save_guard_candidate_satisfies
        self.assertFalse(g(
            'breach_notification',
            'PDPL compliance and personal data protection program'))
        self.assertTrue(g(
            'breach_notification',
            'Establish a 72-hour Data Breach Notification procedure'))
        self.assertTrue(g(
            'breach_notification',
            'Maintain breach reporting playbooks for the DPO office'))

    @_skip_if_no_app
    def test_required_terms_for_classification_include_problem_set(self):
        ar, en = _APP._pdpl_save_guard_required_terms(
            'personal_data_classification')
        self.assertIn('تصنيف البيانات الشخصية', ar)
        self.assertIn('personal data classification', en)
        ar2, _ = _APP._pdpl_save_guard_required_terms(
            'data_classification_pdpl')
        self.assertIn('تصنيف البيانات الشخصية', ar2)

    @_skip_if_no_app
    def test_required_terms_for_breach_include_problem_set(self):
        ar, en = _APP._pdpl_save_guard_required_terms(
            'breach_notification')
        self.assertIn('إخطار الخروقات', ar)
        self.assertIn('الإبلاغ عن الانتهاكات', ar)
        self.assertIn('breach notification', en)
        self.assertIn('breach reporting', en)

    @_skip_if_no_app
    def test_unknown_family_does_not_satisfy(self):
        g = _APP._pdpl_save_guard_candidate_satisfies
        self.assertFalse(g('privacy_governance', 'anything'))
        self.assertFalse(g('', 'anything'))
        self.assertFalse(g('breach_notification', ''))


# ──────────────────────────────────────────────────────────────────────
# Part 4 — Source-level invariants: no deterministic rows, validators
# not weakened, AI-first repair only, Cyber/AI/DT/ERM/NDMO untouched.
# ──────────────────────────────────────────────────────────────────────


class TestSourceInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = _read_app_source()
        anchor = cls.src.find(
            'PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        assert anchor > 0
        raw = cls.src[anchor:anchor + 30000]
        cls.guard_block = re.sub(r"'\s*\n\s*'", "", raw)

    @_skip_if_no_app
    def test_guard_does_not_insert_deterministic_rows(self):
        for forbidden in ("f'| ", 'f"| ', "'- |' ", '"- |" '):
            self.assertNotIn(forbidden, self.guard_block)

    @_skip_if_no_app
    def test_guard_uses_ai_repair_strategy_section(self):
        # AI-first repair pathway.
        self.assertIn('ai_repair_strategy_section', self.guard_block)

    @_skip_if_no_app
    def test_guard_marks_synth_failed_on_rejection(self):
        self.assertIn('_mark_synth_failed', self.guard_block)
        self.assertIn('pdpl_save_guard_residual:', self.guard_block)

    @_skip_if_no_app
    def test_validator_signature_unchanged(self):
        # PR-5B.9Y must not have weakened the upstream validator.
        f = _APP._compute_missing_selected_framework_coverage
        # Empty selection -> empty.
        self.assertEqual(f({'pillars': '', 'gaps': '', 'roadmap': '',
                             'kpis': '', 'confidence': ''}, []), [])
        # PDPL selected on empty sections -> missing families reported.
        missing = f({'pillars': '', 'gaps': '', 'roadmap': '',
                     'kpis': '', 'confidence': ''}, ['PDPL'],
                    domain='Data Management', lang='ar')
        fams = {fam for _, fam, _ in missing}
        # The three PDPL save-guard targets must still be detectable as
        # missing by the validator.
        self.assertTrue(
            ('personal_data_classification' in fams)
            or ('data_classification_pdpl' in fams),
            f'PDPL classification family must still be detected: {fams}')
        self.assertIn('breach_notification', fams)

    @_skip_if_no_app
    def test_non_pdpl_frameworks_canonicalizer_unchanged(self):
        c = _APP._canonicalize_selected_framework_family
        for fw_key in ('ECC', 'SDAIA', 'COSO_ERM', 'ISO27001',
                       'NIST_AI_RMF', 'DGA', 'ISO22301', 'ISO31000'):
            spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get(fw_key)
            if not spec:
                continue
            for fam_tpl in spec.get('capabilities', []):
                fam = fam_tpl[0]
                self.assertEqual(c(fw_key, fam), fam, (fw_key, fam))

    @_skip_if_no_app
    def test_ndmo_data_lifecycle_canonicalizer_unchanged(self):
        c = _APP._canonicalize_selected_framework_family
        self.assertEqual(
            c('NDMO', 'data_lifecycle'), 'data_lifecycle')

    @_skip_if_no_app
    def test_parser_does_not_emit_non_pdpl(self):
        # Cyber/AI/DT/ERM defects must not be smuggled into the
        # PDPL save guard's residual list.
        p = _APP._pdpl_save_guard_parse_runtime_residuals
        out = p([
            'selected_framework_coverage_missing:'
            'ECC:identity_access (pillars) 0/1',
            'selected_framework_coverage_missing:'
            'SDAIA:ai_risk_assessment (gaps) 0/1',
            'selected_framework_coverage_missing:'
            'COSO_ERM:risk_response (roadmap) 0/1',
            'selected_framework_coverage_missing:'
            'NDMO:data_lifecycle (kpis) 0/1',
        ])
        self.assertEqual(out, [])

    @_skip_if_no_app
    def test_pr5b9x_guard_still_present_after_pr5b9y(self):
        # PR-5B.9X belt-and-suspenders guard must remain after PR-5B.9Y
        # so any path that bypasses PR-5B.9Y is still fail-closed.
        self.assertIn(
            'PR-5B.9X — FINAL PDPL DATA SAVE GUARD', self.src)
        idx_9y = self.src.find(
            'PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        idx_9x = self.src.find(
            'PR-5B.9X — FINAL PDPL DATA SAVE GUARD')
        # 9Y runs before generic 422; 9X is the absolute last check
        # after that — so 9X appears AFTER 9Y in source.
        self.assertGreater(idx_9x, idx_9y)


# ──────────────────────────────────────────────────────────────────────
# Part 5 — auth/DB/export/PDF/DOCX modules unchanged. The PR-5B.9Y
# patch is scoped to the strategy save path; assert no edits to other
# infrastructure layers.
# ──────────────────────────────────────────────────────────────────────


class TestUnrelatedSurfaceUntouched(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = _read_app_source()

    @_skip_if_no_app
    def test_no_new_db_schema_changes_in_guard(self):
        anchor = self.src.find('PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        block = self.src[anchor:anchor + 30000]
        # No CREATE TABLE / ALTER TABLE within the guard block.
        self.assertNotIn('CREATE TABLE', block)
        self.assertNotIn('ALTER TABLE', block)

    @_skip_if_no_app
    def test_no_export_pdf_docx_changes_in_guard(self):
        anchor = self.src.find('PR-5B.9Y — FINAL PDPL DATA SAVE GUARD')
        block = self.src[anchor:anchor + 30000]
        # No PDF/DOCX export wiring inside the guard.
        for forbidden in ('reportlab', 'docx.Document(', 'SimpleDocTemplate'):
            self.assertNotIn(forbidden, block)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
