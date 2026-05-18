"""PR-5B.9X — Enforce PDPL classification and breach coverage in Data sections.

Regression suite for the persistent runtime failure where
``selected_framework_coverage_missing`` kept surfacing focused on PDPL:

  * ``PDPL:data_classification_pdpl``
  * ``PDPL:personal_data_classification``
  * ``PDPL:breach_notification``

across the Data Management strategy sections (pillars, gaps, roadmap,
kpis, confidence) even after PR-5B.9W was deployed.

Scope: Data Management only. Cyber / AI / Digital Transformation /
ERM behaviour must be preserved. AI-first only — no deterministic
strategy rows; validators are not weakened.

Run:
    python -m pytest \
        tests/test_data_pdpl_classification_breach_sections_pr5b9x.py -q
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9x_')
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
# Part 1 — DATA-FRAMEWORK-COVERAGE-REPAIR runs after all section
# overwrites and repairs pillars/gaps/roadmap/kpis/confidence.
# ──────────────────────────────────────────────────────────────────────


class TestRepairOrderingAndCoveredSections(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _read_app_source()

    @_skip_if_no_app
    def test_repair_pass_runs_after_known_section_overwrites(self):
        """[DATA-FRAMEWORK-COVERAGE-REPAIR] must come AFTER the other
        Data-section overwrite passes the problem statement enumerates
        so any content they removed is restored before the final audit.
        """
        for earlier in (
                '[ROADMAP-BALANCE-REPAIR]',
                '[ENVIRONMENT-FRAMEWORK-REPAIR]',
                '[PILLARS-GOVERNANCE-REPAIR]',
                '[GAPS-STRUCTURAL-GAP-REPAIR]',
                '[ROADMAP-GOVERNANCE-SETUP-REPAIR]'):
            idx_earlier = self.src.find(earlier)
            if idx_earlier < 0:
                continue  # pass may be optional in some flows
            # Look up the [DATA-FRAMEWORK-COVERAGE-REPAIR] tag AFTER
            # this earlier overwrite pass.
            idx_repair = self.src.find(
                '[DATA-FRAMEWORK-COVERAGE-REPAIR]', idx_earlier)
            self.assertGreater(
                idx_repair, idx_earlier,
                f'[DATA-FRAMEWORK-COVERAGE-REPAIR] must run after '
                f'{earlier}')

    @_skip_if_no_app
    def test_repair_targets_include_five_affected_sections(self):
        """The PDPL registry's repair_targets MUST include every section
        the problem statement names as affected."""
        pdpl = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['PDPL']
        for sec in ('pillars', 'gaps', 'roadmap', 'kpis', 'confidence'):
            self.assertIn(sec, pdpl['repair_targets'], sec)
            self.assertIn(sec, pdpl['required_sections'], sec)

    @_skip_if_no_app
    def test_final_overwrite_guard_routes_every_affected_section(self):
        """The PR-5B.9V/9W FINAL overwrite guard whitelist of sections
        must include every section the runtime error names."""
        anchor = self.src.find('PR-5B.9V: [DATA-FRAMEWORK-COVERAGE-FINAL]')
        self.assertGreater(anchor, 0)
        block = self.src[anchor:anchor + 30000]
        # The guard's allow-list literal.
        for sec_literal in (
                "'pillars'", "'gaps'", "'roadmap'", "'kpis'",
                "'confidence'"):
            self.assertIn(sec_literal, block, sec_literal)


# ──────────────────────────────────────────────────────────────────────
# Part 2 — PDPL classification family ids canonicalize to one obligation
# and one phrase satisfies both detections.
# ──────────────────────────────────────────────────────────────────────


class TestPdplClassificationCanonicalization(unittest.TestCase):

    @_skip_if_no_app
    def test_both_ids_canonicalize_to_personal_data_classification(self):
        c = _APP._canonicalize_selected_framework_family
        self.assertEqual(
            c('PDPL', 'data_classification_pdpl'),
            'personal_data_classification')
        self.assertEqual(
            c('PDPL', 'personal_data_classification'),
            'personal_data_classification')

    @_skip_if_no_app
    def test_breach_notification_passthrough(self):
        # breach_notification has no aliases; canonical id is itself.
        c = _APP._canonicalize_selected_framework_family
        self.assertEqual(
            c('PDPL', 'breach_notification'),
            'breach_notification')

    @_skip_if_no_app
    def test_single_arabic_phrase_satisfies_both_classification_families(self):
        text = (
            'تنفذ المؤسسة سياسة تصنيف البيانات الشخصية وفق نظام حماية '
            'البيانات الشخصية.')
        missing = _APP._compute_missing_selected_framework_coverage(
            text, ['PDPL'], domain='Data Management', lang='ar')
        miss_set = {(fw, fam) for fw, fam, _ in missing}
        self.assertNotIn(('PDPL', 'data_classification_pdpl'), miss_set)
        self.assertNotIn(
            ('PDPL', 'personal_data_classification'), miss_set)

    @_skip_if_no_app
    def test_single_english_phrase_satisfies_both_classification_families(self):
        text = (
            'The organisation enforces personal data classification per '
            'the data protection law.')
        missing = _APP._compute_missing_selected_framework_coverage(
            text, ['PDPL'], domain='Data Management', lang='en')
        miss_set = {(fw, fam) for fw, fam, _ in missing}
        self.assertNotIn(('PDPL', 'data_classification_pdpl'), miss_set)
        self.assertNotIn(
            ('PDPL', 'personal_data_classification'), miss_set)


# ──────────────────────────────────────────────────────────────────────
# Part 3 — Breach terms (إخطار الخروقات AND الإبلاغ عن الانتهاكات)
# are recognized by the validator.
# ──────────────────────────────────────────────────────────────────────


class TestBreachVocabulary(unittest.TestCase):

    @_skip_if_no_app
    def test_registry_includes_both_arabic_breach_phrasings(self):
        pdpl = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['PDPL']
        ar = ()
        for fam, _ar, _en in pdpl['capabilities']:
            if fam == 'breach_notification':
                ar = _ar
                break
        # Both phrasings the problem statement explicitly lists.
        self.assertIn('إخطار الخروقات', ar)
        self.assertIn('الإبلاغ عن الانتهاكات', ar)

    @_skip_if_no_app
    def test_ikhtar_alkhuruqaat_satisfies_breach_family(self):
        text = 'تلتزم المؤسسة بإخطار الخروقات خلال 72 ساعة وفق PDPL.'
        missing = _APP._compute_missing_selected_framework_coverage(
            text, ['PDPL'], domain='Data Management', lang='ar')
        miss_set = {(fw, fam) for fw, fam, _ in missing}
        self.assertNotIn(('PDPL', 'breach_notification'), miss_set)

    @_skip_if_no_app
    def test_ablagh_anil_intihakaat_satisfies_breach_family(self):
        text = (
            'يتم الإبلاغ عن الانتهاكات إلى الجهة المختصة فور اكتشافها.')
        missing = _APP._compute_missing_selected_framework_coverage(
            text, ['PDPL'], domain='Data Management', lang='ar')
        miss_set = {(fw, fam) for fw, fam, _ in missing}
        self.assertNotIn(('PDPL', 'breach_notification'), miss_set)


# ──────────────────────────────────────────────────────────────────────
# Part 4 — Section-specific repair prompts EXPLICITLY include both
# required phrases verbatim for every affected section.
# ──────────────────────────────────────────────────────────────────────


class TestSectionPromptsExplicitlyIncludeBothPhrases(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _read_app_source()
        anchor = cls.src.find('_DFC_SECTION_GUIDANCE = {')
        assert anchor > 0, '_DFC_SECTION_GUIDANCE block missing'
        # Cap window large enough to cover all six sections.
        cls.guidance_block = cls.src[anchor:anchor + 15000]
        # Collapse Python implicit string concatenation so substring
        # assertions target the *logical* runtime prompt string rather
        # than the source-level fragments.
        cls.collapsed = re.sub(
            r"'\s*\n\s*'", "", cls.guidance_block)
        # Split per-section so a phrase planted in one section can't
        # falsely satisfy the assertion for another.
        cls.sections = {}
        for sec in ('pillars', 'gaps', 'roadmap', 'kpis', 'confidence'):
            mark = "'{}': (".format(sec)
            i = cls.collapsed.find(mark)
            assert i > 0, 'missing section ' + sec
            j_candidates = [
                cls.collapsed.find("'{}': (".format(other), i + 1)
                for other in ('pillars', 'gaps', 'roadmap', 'kpis',
                              'confidence')
                if other != sec
            ]
            j_candidates = [j for j in j_candidates if j > i]
            end = min(j_candidates) if j_candidates else (i + 4000)
            cls.sections[sec] = cls.collapsed[i:end]

    @_skip_if_no_app
    def test_each_affected_section_includes_classification_phrase(self):
        for sec in ('pillars', 'gaps', 'roadmap', 'kpis', 'confidence'):
            self.assertIn(
                'تصنيف البيانات الشخصية', self.sections[sec],
                'section={} missing classification phrase'.format(sec))

    @_skip_if_no_app
    def test_each_affected_section_includes_both_breach_phrasings(self):
        # Each of the five affected sections must explicitly list both
        # breach phrasings so the AI repair prompt cannot paraphrase
        # past either one.
        for sec in ('pillars', 'gaps', 'roadmap', 'kpis', 'confidence'):
            self.assertIn(
                'إخطار الخروقات', self.sections[sec],
                'section={} missing «إخطار الخروقات»'.format(sec))
            self.assertIn(
                'الإبلاغ عن الانتهاكات', self.sections[sec],
                'section={} missing «الإبلاغ عن الانتهاكات»'.format(sec))

    @_skip_if_no_app
    def test_pr5b9x_explicit_mandate_marker_present(self):
        # The new PR-5B.9X verbatim mandate clause must appear in each
        # of the five affected sections so operators can audit which
        # sections carry the strengthened contract.
        for sec in ('pillars', 'gaps', 'roadmap', 'kpis', 'confidence'):
            self.assertIn(
                'PR-5B.9X MANDATORY', self.sections[sec],
                'section={} missing PR-5B.9X mandate clause'.format(sec))


# ──────────────────────────────────────────────────────────────────────
# Part 5 — Final pre-save guard fails closed on residual PDPL
# classification / breach coverage.
# ──────────────────────────────────────────────────────────────────────


class TestFinalPdplSaveGuard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _read_app_source()
        anchor = cls.src.find('PR-5B.9X — FINAL PDPL DATA SAVE GUARD')
        assert anchor > 0, 'PR-5B.9X save guard marker missing'
        raw = cls.src[anchor:anchor + 14000]
        # Collapse Python implicit string concatenation so substring
        # assertions target the *logical* runtime string rather than
        # the source-level fragments.
        cls.guard_block = re.sub(r"'\s*\n\s*'", "", raw)

    @_skip_if_no_app
    def test_guard_targets_three_pdpl_families(self):
        for fam in (
                'data_classification_pdpl',
                'personal_data_classification',
                'breach_notification'):
            self.assertIn(
                "'{}'".format(fam), self.guard_block, fam)

    @_skip_if_no_app
    def test_guard_covers_five_affected_sections(self):
        for sec in ('pillars', 'gaps', 'roadmap', 'kpis', 'confidence'):
            self.assertIn(
                "'{}'".format(sec), self.guard_block, sec)

    @_skip_if_no_app
    def test_guard_scoped_to_data_pdpl_only(self):
        # Domain gate so Cyber/AI/DT/ERM strategies are untouched.
        self.assertIn("normalize_domain", self.guard_block)
        self.assertIn("'data'", self.guard_block)
        self.assertIn("'PDPL' in _pr5b9x_resolved", self.guard_block)

    @_skip_if_no_app
    def test_guard_uses_compute_missing_validator(self):
        # The guard must re-use the existing validator (no weakened
        # heuristic).
        self.assertIn(
            '_compute_missing_selected_framework_coverage',
            self.guard_block)

    @_skip_if_no_app
    def test_guard_returns_422_with_residual_payload(self):
        self.assertIn("'pdpl_save_guard_residual'", self.guard_block)
        self.assertIn("'pdpl_save_guard_canonical'", self.guard_block)
        self.assertIn('}), 422', self.guard_block)

    @_skip_if_no_app
    def test_guard_logs_canonical_via_helper(self):
        self.assertIn(
            '_canonicalize_selected_framework_family',
            self.guard_block)
        self.assertIn('[DATA-PDPL-SAVE-GUARD]', self.guard_block)
        self.assertIn(
            '[STRATEGY-GATE] save_decision=BLOCKED',
            self.guard_block)

    @_skip_if_no_app
    def test_guard_does_not_insert_deterministic_rows(self):
        # No hand-rolled markdown rows / table cells.
        for forbidden in ("f'| ", 'f"| ', "'- |' ", '"- |" '):
            self.assertNotIn(forbidden, self.guard_block)
        # No call into ai_repair_strategy_section here either (the
        # guard is purely fail-closed; preceding passes own AI repair).
        # This is asserted indirectly via the residual payload above.

    @_skip_if_no_app
    def test_guard_runs_after_post_normalization_audit(self):
        idx_post_norm = self.src.find(
            'POST-NORMALIZATION RE-AUDIT')
        idx_guard = self.src.find(
            'PR-5B.9X — FINAL PDPL DATA SAVE GUARD')
        self.assertGreater(idx_post_norm, 0)
        self.assertGreater(idx_guard, idx_post_norm)


# ──────────────────────────────────────────────────────────────────────
# Part 6 — Non-Data domains unchanged; validators not weakened;
# no deterministic content was introduced.
# ──────────────────────────────────────────────────────────────────────


class TestOtherDomainsAndValidatorsUnchanged(unittest.TestCase):

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
        src = _read_app_source()
        for sym in ('login_required', 'ADMIN_PASSWORD',
                    'export_pdf', 'export_docx'):
            self.assertIn(sym, src, sym)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
