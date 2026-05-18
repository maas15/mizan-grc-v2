"""PR-5B.9W — Persistent NDMO data_lifecycle + PDPL classification coverage.

Regression suite for the persistent runtime failure where
``selected_framework_coverage_missing`` kept surfacing for:

  * ``NDMO:data_lifecycle``
  * ``PDPL:data_classification_pdpl``
  * ``PDPL:personal_data_classification``

across the environment, pillars, gaps, roadmap, kpis, and confidence
sections of the Data Management strategy, even after PR-5B.9V was
deployed.

Scope: Data Management only. Cyber / AI / Digital Transformation /
ERM behaviour must be preserved.

Run:
    python -m pytest \
        tests/test_data_framework_coverage_persistent_pr5b9w.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9w_')
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


# ──────────────────────────────────────────────────────────────────────
# Part A — Generalised canonicalizer for selected-framework families.
# ──────────────────────────────────────────────────────────────────────

class TestGeneralisedFamilyCanonicalizer(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_exists_and_is_callable(self):
        self.assertTrue(
            hasattr(_APP, '_canonicalize_selected_framework_family'))
        self.assertTrue(callable(
            _APP._canonicalize_selected_framework_family))

    @_skip_if_no_app
    def test_pdpl_classification_aliases_collapse(self):
        c = _APP._canonicalize_selected_framework_family
        self.assertEqual(
            c('PDPL', 'data_classification_pdpl'),
            'personal_data_classification')
        self.assertEqual(
            c('PDPL', 'personal_data_classification'),
            'personal_data_classification')

    @_skip_if_no_app
    def test_ndmo_data_lifecycle_is_canonical(self):
        c = _APP._canonicalize_selected_framework_family
        self.assertEqual(c('NDMO', 'data_lifecycle'), 'data_lifecycle')

    @_skip_if_no_app
    def test_unknown_framework_or_family_passthrough(self):
        c = _APP._canonicalize_selected_framework_family
        self.assertEqual(c('ECC', 'cryptography'), 'cryptography')
        self.assertEqual(c('NDMO', 'data_quality'), 'data_quality')
        self.assertEqual(c('', 'anything'), 'anything')
        self.assertEqual(c('PDPL', ''), '')

    @_skip_if_no_app
    def test_legacy_pdpl_helper_still_works(self):
        # Back-compat: PR-5B.9V's _canonicalize_pdpl_family must keep
        # the same behaviour.
        c = _APP._canonicalize_pdpl_family
        self.assertEqual(
            c('PDPL', 'data_classification_pdpl'),
            'personal_data_classification')
        self.assertEqual(c('NDMO', 'data_lifecycle'), 'data_lifecycle')


# ──────────────────────────────────────────────────────────────────────
# Part B — NDMO:data_lifecycle vocabulary strengthened.
# ──────────────────────────────────────────────────────────────────────

class TestNdmoDataLifecycleVocabulary(unittest.TestCase):

    @_skip_if_no_app
    def test_registry_vocabulary_includes_required_phrases(self):
        ndmo = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']
        ar_kws = en_kws = ()
        for fam, ar, en in ndmo['capabilities']:
            if fam == 'data_lifecycle':
                ar_kws = ar
                en_kws = en
                break
        # Arabic (problem statement Part B)
        for phrase in (
                'دورة حياة البيانات',
                'إدارة دورة حياة البيانات',
                'سياسات الاحتفاظ بالبيانات',
                'الاحتفاظ بالبيانات',
                'أرشفة البيانات',
                'إتلاف البيانات',
                'حذف البيانات',
                'الاحتفاظ والأرشفة والإتلاف'):
            self.assertIn(phrase, ar_kws, phrase)
        # English (problem statement Part B)
        for phrase in (
                'data lifecycle',
                'data lifecycle management',
                'data retention',
                'retention policy',
                'archival',
                'archiving',
                'disposal',
                'data disposal',
                'deletion',
                'data retention and disposal'):
            self.assertIn(phrase, en_kws, phrase)

    @_skip_if_no_app
    def test_idarah_dorat_hayat_albayanat_satisfies_lifecycle(self):
        text = (
            'تتضمن السياسة إدارة دورة حياة البيانات بما يشمل التصنيف '
            'والتخزين والمعالجة.')
        missing = _APP._compute_missing_selected_framework_coverage(
            text, ['NDMO'], domain='Data Management', lang='ar')
        miss_set = {(fw, fam) for fw, fam, _ in missing}
        self.assertNotIn(('NDMO', 'data_lifecycle'), miss_set)

    @_skip_if_no_app
    def test_archival_or_disposal_satisfies_lifecycle(self):
        for phrase in (
                'النص يصف الاحتفاظ والأرشفة والإتلاف للبيانات',
                'حذف البيانات وفق سياسة الاحتفاظ',
                'this section covers retention policy and archival',
                'data lifecycle management with disposal procedures'):
            missing = _APP._compute_missing_selected_framework_coverage(
                phrase, ['NDMO'], domain='Data Management', lang='ar')
            miss_set = {(fw, fam) for fw, fam, _ in missing}
            self.assertNotIn(
                ('NDMO', 'data_lifecycle'), miss_set,
                'phrase failed: ' + phrase)

    @_skip_if_no_app
    def test_dfc_family_tokens_registers_lifecycle_phrases(self):
        # Source-level assertion: the per-family token catalog used by
        # the AI repair prompt must surface the problem-statement
        # Arabic/English vocabulary for NDMO:data_lifecycle.
        import re
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                  encoding='utf-8') as f:
            src = f.read()
        anchor = src.find("('NDMO', 'data_lifecycle')")
        self.assertGreater(anchor, 0)
        block = src[anchor:anchor + 4000]
        # Collapse Python implicit string concat across line breaks
        # so phrases like 'إدارة دورة حياة ' + 'البيانات' match as one.
        block = re.sub(r"'\s*\n\s*'", "", block)
        for phrase in (
                'إدارة دورة حياة البيانات',
                'الاحتفاظ والأرشفة والإتلاف',
                'سياسات الاحتفاظ بالبيانات',
                'أرشفة البيانات',
                'حذف البيانات',
                'data lifecycle management',
                'retention policy',
                'archival',
                'disposal',
                'deletion',
                'data retention and disposal'):
            self.assertIn(phrase, block, phrase)


# ──────────────────────────────────────────────────────────────────────
# Part C — PDPL classification vocabulary strengthened.
# ──────────────────────────────────────────────────────────────────────

class TestPdplClassificationVocabulary(unittest.TestCase):

    @_skip_if_no_app
    def test_registry_vocabulary_includes_required_phrases(self):
        pdpl = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['PDPL']
        caps = {fam: (ar, en) for fam, ar, en in pdpl['capabilities']}
        for fam in ('data_classification_pdpl',
                    'personal_data_classification'):
            ar, en = caps[fam]
            for phrase in (
                    'تصنيف البيانات الشخصية',
                    'تصنيف البيانات الحساسة',
                    'تصنيف ومعالجة البيانات الشخصية',
                    'تصنيف بيانات أصحاب البيانات',
                    'معالجة البيانات الشخصية',
                    'فئات البيانات الشخصية'):
                self.assertIn(phrase, ar, (fam, phrase))
            for phrase in (
                    'personal data classification',
                    'sensitive personal data classification',
                    'personal data handling',
                    'classify personal data',
                    'personal data categories'):
                self.assertIn(phrase, en, (fam, phrase))

    @_skip_if_no_app
    def test_single_phrase_satisfies_both_classification_families(self):
        text = (
            'تنفذ المؤسسة تصنيف البيانات الشخصية ضمن سياسة حماية '
            'البيانات.')
        missing = _APP._compute_missing_selected_framework_coverage(
            text, ['PDPL'], domain='Data Management', lang='ar')
        miss_set = {(fw, fam) for fw, fam, _ in missing}
        self.assertNotIn(
            ('PDPL', 'data_classification_pdpl'), miss_set)
        self.assertNotIn(
            ('PDPL', 'personal_data_classification'), miss_set)

    @_skip_if_no_app
    def test_new_phrases_satisfy_classification_families(self):
        for phrase in (
                'تصنيف بيانات أصحاب البيانات وفق السياسة',
                'فئات البيانات الشخصية وفق PDPL',
                'classify personal data per the data protection law',
                'personal data categories listed in the policy'):
            missing = _APP._compute_missing_selected_framework_coverage(
                phrase, ['PDPL'], domain='Data Management', lang='ar')
            miss_set = {(fw, fam) for fw, fam, _ in missing}
            self.assertNotIn(
                ('PDPL', 'data_classification_pdpl'), miss_set,
                'phrase failed (data_classification_pdpl): ' + phrase)
            self.assertNotIn(
                ('PDPL', 'personal_data_classification'), miss_set,
                'phrase failed (personal_data_classification): ' + phrase)


# ──────────────────────────────────────────────────────────────────────
# Part D — Section-specific repair contract guidance.
# ──────────────────────────────────────────────────────────────────────

class TestSectionSpecificRepairGuidance(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import re
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                  encoding='utf-8') as f:
            cls.src = f.read()
        anchor = cls.src.find('_DFC_SECTION_GUIDANCE = {')
        assert anchor > 0, '_DFC_SECTION_GUIDANCE block missing'
        block = cls.src[anchor:anchor + 12000]
        # Python's implicit string concatenation splits a single
        # logical phrase across multiple ``'...'`` fragments. Collapse
        # the inter-fragment boundary (``' \n    '``) so substring
        # assertions can target the *logical* runtime string rather
        # than the literal source layout.
        cls.block = re.sub(r"'\s*\n\s*'", "", block)

    @_skip_if_no_app
    def test_environment_required_phrases_present(self):
        for phrase in (
                'إدارة دورة حياة البيانات',
                'الاحتفاظ والأرشفة والإتلاف',
                'تصنيف البيانات الشخصية',
                'إخطار الخروقات',
                'حوكمة الخصوصية'):
            self.assertIn(phrase, self.block, 'environment: ' + phrase)

    @_skip_if_no_app
    def test_gaps_explicit_weakness_phrases_present(self):
        for phrase in (
                'ضعف إدارة دورة حياة البيانات',
                'ضعف أو غياب تصنيف البيانات الشخصية',
                'ضعف إخطار الخروقات والإبلاغ عن الانتهاكات'):
            self.assertIn(phrase, self.block, 'gaps: ' + phrase)

    @_skip_if_no_app
    def test_roadmap_implementation_phrases_present(self):
        for phrase in (
                'تطبيق إدارة دورة حياة البيانات',
                'تطبيق تصنيف البيانات الشخصية',
                'تفعيل إخطار الخروقات والإبلاغ عن الانتهاكات'):
            self.assertIn(phrase, self.block, 'roadmap: ' + phrase)

    @_skip_if_no_app
    def test_kpis_lifecycle_compliance_phrase_present(self):
        # The other KPI phrases are inherited from PR-5B.9V; the new
        # PR-5B.9W requirement is the lifecycle-compliance KPI.
        self.assertIn(
            'نسبة الالتزام بسياسات دورة حياة البيانات', self.block)

    @_skip_if_no_app
    def test_confidence_lifecycle_classification_phrases_present(self):
        for phrase in (
                'دورة حياة البيانات',
                'تصنيف البيانات الشخصية',
                'إخطار الخروقات',
                'حوكمة الخصوصية'):
            self.assertIn(phrase, self.block, 'confidence: ' + phrase)


# ──────────────────────────────────────────────────────────────────────
# Part E — Final overwrite guard covers NDMO:data_lifecycle.
# ──────────────────────────────────────────────────────────────────────

class TestFinalOverwriteGuardCoversNdmoLifecycle(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                  encoding='utf-8') as f:
            cls.src = f.read()
        anchor = cls.src.find(
            'PR-5B.9V: [DATA-FRAMEWORK-COVERAGE-FINAL]')
        assert anchor > 0, 'PR-5B.9V final guard marker missing'
        cls.guard_block = cls.src[anchor:anchor + 30000]

    @_skip_if_no_app
    def test_final_targets_registry_includes_ndmo_lifecycle(self):
        # The PR-5B.9W per-framework target registry must list
        # NDMO:data_lifecycle alongside PDPL classification + breach.
        self.assertIn(
            "_DFC_FINAL_TARGETS_BY_FW", self.guard_block)
        self.assertIn("'NDMO'", self.guard_block)
        self.assertIn("'data_lifecycle'", self.guard_block)
        # Existing PDPL targets are preserved.
        self.assertIn("'PDPL'", self.guard_block)
        self.assertIn("'data_classification_pdpl'", self.guard_block)
        self.assertIn("'personal_data_classification'", self.guard_block)
        self.assertIn("'breach_notification'", self.guard_block)

    @_skip_if_no_app
    def test_final_guard_uses_generalised_canonicalizer(self):
        # The guard logs canonical family ids via the new helper so
        # NDMO and PDPL diagnostics share one canonicalization code
        # path.
        self.assertIn(
            '_canonicalize_selected_framework_family',
            self.guard_block)

    @_skip_if_no_app
    def test_final_guard_logs_both_original_and_canonical(self):
        # Per problem-statement Part A: "Do not remove original family
        # names from output logs; include both original and canonical
        # names."
        self.assertIn('family=', self.guard_block)
        self.assertIn('canonical_family=', self.guard_block)

    @_skip_if_no_app
    def test_final_guard_is_ai_first_and_fail_closed(self):
        # No deterministic content; AI repair + fail-closed via
        # _mark_synth_failed.
        self.assertIn('ai_repair_strategy_section(', self.guard_block)
        self.assertIn('_mark_synth_failed', self.guard_block)
        # No hand-rolled markdown rows in the guard scope.
        for forbidden in ("f'| ", 'f"| '):
            self.assertNotIn(forbidden, self.guard_block)


# ──────────────────────────────────────────────────────────────────────
# Negative tests — non-Data behaviour preserved.
# ──────────────────────────────────────────────────────────────────────

class TestOtherDomainsUnchanged(unittest.TestCase):

    @_skip_if_no_app
    def test_cyber_ai_dt_erm_canonicalizer_passthrough(self):
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
    def test_pdpl_registry_capability_set_unchanged(self):
        pdpl = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['PDPL']
        fam_ids = {tpl[0] for tpl in pdpl['capabilities']}
        for required in ('privacy_governance', 'consent_management',
                         'data_subject_rights',
                         'data_classification_pdpl',
                         'personal_data_classification',
                         'breach_notification'):
            self.assertIn(required, fam_ids)

    @_skip_if_no_app
    def test_ndmo_registry_capability_set_unchanged(self):
        ndmo = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']
        fam_ids = {tpl[0] for tpl in ndmo['capabilities']}
        for required in ('data_governance', 'data_quality',
                         'data_catalog', 'data_stewardship',
                         'data_lifecycle'):
            self.assertIn(required, fam_ids)

    @_skip_if_no_app
    def test_validators_not_weakened(self):
        self.assertGreaterEqual(_APP._RICHNESS_MIN_SO_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_PILLARS, 3)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_GAP_ROWS, 2)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_ROADMAP_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_KPI_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_CSF_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_RISK_ROWS, 4)

    @_skip_if_no_app
    def test_auth_db_export_untouched(self):
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                  encoding='utf-8') as f:
            src = f.read()
        for sym in ('login_required', 'ADMIN_PASSWORD',
                    'export_pdf', 'export_docx'):
            self.assertIn(sym, src, sym)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
