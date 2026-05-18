"""PR-5B.9V — Persistent PDPL classification & breach coverage tests.

Follow-up regression suite to PR-5B.9U. Targets the persistent runtime
failure where ``selected_framework_coverage_missing`` for
PDPL:data_classification_pdpl, PDPL:personal_data_classification, and
PDPL:breach_notification kept surfacing in the pillars / gaps / roadmap
/ kpis / confidence sections even after PR-5B.9U was deployed.

Scope: Data Management / PDPL only. Cyber / AI / DT / ERM behaviour
must be preserved.

Run:
    python -m pytest \
        tests/test_data_pdpl_coverage_persistent_pr5b9v.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pdpl_pr5b9v_')
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


# ──────────────────────────────────────────────────────────────────────
# Tests 1–3 — Parser captures the three persistent PDPL families.
# ──────────────────────────────────────────────────────────────────────

class TestParserCapturesPersistentPdplFamilies(unittest.TestCase):

    @_skip_if_no_app
    def test_parser_captures_pdpl_data_classification_pdpl(self):
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            ('pillars',
             'selected_framework_coverage_missing:PDPL:'
             'data_classification_pdpl', 0, 1),
        ]
        grouped = p(defects, domain='data')
        self.assertIn('pillars', grouped)
        self.assertEqual(
            grouped['pillars']['PDPL'], ['data_classification_pdpl'])

    @_skip_if_no_app
    def test_parser_captures_pdpl_personal_data_classification(self):
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            ('kpis',
             'selected_framework_coverage_missing:PDPL:'
             'personal_data_classification', 0, 1),
        ]
        grouped = p(defects, domain='data')
        self.assertEqual(
            grouped['kpis']['PDPL'],
            ['personal_data_classification'])

    @_skip_if_no_app
    def test_parser_captures_pdpl_breach_notification(self):
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            ('roadmap',
             'selected_framework_coverage_missing:PDPL:'
             'breach_notification', 0, 1),
            'selected_framework_coverage_missing:PDPL:'
            'breach_notification:gaps',
        ]
        grouped = p(defects, domain='data')
        self.assertEqual(
            grouped['roadmap']['PDPL'], ['breach_notification'])
        self.assertEqual(
            grouped['gaps']['PDPL'], ['breach_notification'])


# ──────────────────────────────────────────────────────────────────────
# Test 4 — Canonicalization: both family ids map to one obligation.
# Test 5 — A strong AR phrase satisfies BOTH family detections.
# Test 6 — "إخطار الخروقات" satisfies breach_notification.
# ──────────────────────────────────────────────────────────────────────

class TestPdplClassificationCanonicalization(unittest.TestCase):

    @_skip_if_no_app
    def test_canonical_helper_collapses_classification_aliases(self):
        c = _APP._canonicalize_pdpl_family
        self.assertEqual(
            c('PDPL', 'data_classification_pdpl'),
            'personal_data_classification')
        self.assertEqual(
            c('PDPL', 'personal_data_classification'),
            'personal_data_classification')
        # Non-PDPL families and other PDPL families pass through.
        self.assertEqual(
            c('PDPL', 'privacy_governance'), 'privacy_governance')
        self.assertEqual(
            c('NDMO', 'data_classification_pdpl'),
            'data_classification_pdpl')

    @_skip_if_no_app
    def test_strong_personal_data_classification_phrase_satisfies_both(self):
        """A single AR phrase such as ``تصنيف البيانات الشخصية`` must
        satisfy BOTH ``data_classification_pdpl`` and
        ``personal_data_classification`` family detections — the two
        family ids represent the SAME conceptual obligation."""
        f = _APP._compute_missing_selected_framework_coverage
        for ar_phrase in (
                'تصنيف البيانات الشخصية',
                'تصنيف البيانات الحساسة',
                'تصنيف ومعالجة البيانات الشخصية'):
            sections = {
                'pillars': '',
                'gaps': (
                    'حوكمة الخصوصية وإدارة الموافقات وحقوق صاحب '
                    'البيانات وإخطار الخروقات. ' + ar_phrase),
                'roadmap': '', 'kpis': '', 'confidence': '',
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='ar')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'data_classification_pdpl', pdpl,
                f'phrase {ar_phrase!r} should satisfy '
                'data_classification_pdpl')
            self.assertNotIn(
                'personal_data_classification', pdpl,
                f'phrase {ar_phrase!r} should satisfy '
                'personal_data_classification')

        for en_phrase in (
                'personal data classification',
                'sensitive personal data classification',
                'personal data handling'):
            sections = {
                'pillars': '',
                'gaps': (
                    'privacy governance and consent management and '
                    'data subject rights and breach notification. '
                    + en_phrase),
                'roadmap': '', 'kpis': '', 'confidence': '',
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='en')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'data_classification_pdpl', pdpl,
                f'phrase {en_phrase!r} should satisfy '
                'data_classification_pdpl')
            self.assertNotIn(
                'personal_data_classification', pdpl,
                f'phrase {en_phrase!r} should satisfy '
                'personal_data_classification')

    @_skip_if_no_app
    def test_ikhttaar_alkhuruq_satisfies_breach_notification(self):
        """The literal AR token ``إخطار الخروقات`` must satisfy the
        PDPL breach_notification family wherever it appears."""
        f = _APP._compute_missing_selected_framework_coverage
        sections = {
            'pillars': (
                'حوكمة الخصوصية وإدارة الموافقات وحقوق صاحب البيانات '
                'وتصنيف البيانات الشخصية. إخطار الخروقات.'),
            'gaps': '', 'roadmap': '', 'kpis': '', 'confidence': '',
        }
        missing = f(sections, ['PDPL'],
                    domain='Data Management', lang='ar')
        pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
        self.assertNotIn('breach_notification', pdpl)


# ──────────────────────────────────────────────────────────────────────
# Test 7 — Repair-pass prompt strings cover every targeted section.
# Test 8 — First failed repair triggers second bounded attempt.
# Test 9 — Candidate still missing after second attempt rejected &
#          original restored.
# ──────────────────────────────────────────────────────────────────────

class TestRepairPassStructure(unittest.TestCase):
    """Source-level audits of the [DATA-FRAMEWORK-COVERAGE-REPAIR] block
    (AI delegations can't be exercised without API keys in CI)."""

    @classmethod
    def setUpClass(cls):
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            cls.src = f.read()
        anchor = cls.src.find(
            'PR-5B.9T: Data framework coverage repair')
        assert anchor > 0
        cls.block = cls.src[anchor:anchor + 120000]

    @_skip_if_no_app
    def test_repair_prompt_covers_all_pdpl_sections_and_terms(self):
        # Every targeted section has explicit guidance.
        for sec_key in ('pillars', 'gaps', 'roadmap', 'kpis',
                        'confidence'):
            self.assertIn(f"'{sec_key}': (", self.block,
                          f'guidance missing for section {sec_key}')
        # Explicit PDPL classification + breach terms in the prompt.
        for term in (
                'حوكمة الخصوصية',
                'إدارة الموافقات',
                'حقوق صاحب البيانات',
                'تصنيف البيانات الشخصية',
                'إخطار الخروقات',
                'الإبلاغ عن الانتهاكات'):
            self.assertIn(term, self.block,
                          f'PDPL term {term!r} missing from prompt')
        # KPI-specific measurable indicators — strings may be split
        # across adjacent string literals in source, so we check
        # contiguous substrings that ARE present in single literals.
        for kpi_phrase in (
                'نسبة تصنيف ',
                'نسبة الموافقات المدارة',
                'إخطار الخروقات',
                'الاستجابة لطلبات حقوق ',
                'الإبلاغ عن الخروقات في '):
            self.assertIn(kpi_phrase, self.block,
                          f'KPI phrase {kpi_phrase!r} missing')

    @_skip_if_no_app
    def test_second_bounded_attempt_runs_when_first_candidate_undercovered(self):
        # Iteration bound = 2; second-pass directive present.
        self.assertIn('_dfc_attempt = 0', self.block)
        self.assertIn('while _dfc_attempt < 2', self.block)
        self.assertIn('SECOND-PASS', self.block)
        # Re-runs the coverage helper inside the loop to recompute
        # ``_dfc_still_missing`` per attempt.
        self.assertGreaterEqual(
            self.block.count(
                '_compute_missing_selected_framework_coverage('), 2,
            'coverage helper must be invoked per attempt inside the '
            'iterative repair loop')

    @_skip_if_no_app
    def test_rejected_second_attempt_restores_original_and_fail_closes(self):
        # Rejected candidate rollback happens via sections[_sk] =
        # _dfc_before, then fail-close via _mark_synth_failed.
        self.assertIn('sections[_sk] = _dfc_before', self.block)
        self.assertIn('if not _dfc_accepted', self.block)
        self.assertIn('_mark_synth_failed', self.block)
        # Per-attempt structured log carries the required fields.
        self.assertIn('missing_before=', self.block)
        self.assertIn('missing_after=', self.block)
        self.assertIn('accepted=', self.block)
        self.assertIn('restored=', self.block)


# ──────────────────────────────────────────────────────────────────────
# Test 10 — Final audit cannot pass if PDPL selected_framework_coverage_
#           missing remains.
# Test 11 — Later overwrite removing PDPL classification is caught
#           before final save (final overwrite guard logs + audits).
# ──────────────────────────────────────────────────────────────────────

class TestFinalAuditAndOverwriteGuard(unittest.TestCase):

    @_skip_if_no_app
    def test_final_audit_blocks_when_pdpl_classification_missing(self):
        # Sections explicitly missing PDPL classification & breach.
        sections = {
            'vision': '',
            'environment': '',
            'pillars': 'حوكمة الخصوصية وإدارة الموافقات.',
            'gaps': 'حوكمة الخصوصية وإدارة الموافقات.',
            'roadmap': 'حوكمة الخصوصية وإدارة الموافقات.',
            'kpis': 'حوكمة الخصوصية وإدارة الموافقات.',
            'confidence': 'حوكمة الخصوصية وإدارة الموافقات.',
        }
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype='technical',
            selected_frameworks=['PDPL'], domain='Data Management',
        )
        # Some defect must mention selected_framework_coverage_missing
        # for PDPL classification or breach notification.
        tags = [d[1] for d in defects]
        flat = ';'.join(tags)
        self.assertIn(
            'selected_framework_coverage_missing:PDPL', flat,
            f'final audit must emit PDPL coverage defects when '
            f'classification/breach missing; got tags={tags}')
        # Specifically each missing family is enumerated.
        self.assertTrue(
            any('PDPL:data_classification_pdpl' in t for t in tags)
            or any('PDPL:personal_data_classification' in t
                   for t in tags),
            'classification family must surface as a defect')
        self.assertTrue(
            any('PDPL:breach_notification' in t for t in tags),
            'breach_notification family must surface as a defect')

    @_skip_if_no_app
    def test_final_overwrite_guard_exists_and_logs(self):
        """Source-level audit of the [DATA-FRAMEWORK-COVERAGE-FINAL]
        overwrite guard."""
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        # Guard tag present.
        self.assertIn('[DATA-FRAMEWORK-COVERAGE-FINAL]', src)
        # Targets the persistent PDPL families.
        self.assertIn("'data_classification_pdpl'", src)
        self.assertIn("'personal_data_classification'", src)
        self.assertIn("'breach_notification'", src)
        # Routes back to ai_repair_strategy_section with a strict
        # validation_error and re-runs the audit + coverage helper.
        guard_anchor = src.find('PR-5B.9V: [DATA-FRAMEWORK-COVERAGE-FINAL]')
        self.assertGreater(
            guard_anchor, 0,
            'PR-5B.9V final overwrite guard marker missing')
        guard_block = src[guard_anchor:guard_anchor + 20000]
        self.assertIn('ai_repair_strategy_section(', guard_block)
        self.assertIn('_compute_missing_selected_framework_coverage(',
                      guard_block)
        self.assertIn('_final_strategy_audit(', guard_block)
        self.assertIn('will_fail=', guard_block)
        # Fail-closed path present (does NOT inject deterministic
        # content): restores original section and marks synth_failed.
        self.assertIn('_mark_synth_failed', guard_block)


# ──────────────────────────────────────────────────────────────────────
# Test 12 — NDMO unchanged.
# Test 13 — Cyber/AI/DT/ERM unchanged.
# ──────────────────────────────────────────────────────────────────────

class TestNonPdplBehaviourPreserved(unittest.TestCase):

    @_skip_if_no_app
    def test_ndmo_capabilities_unchanged(self):
        reqs = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['NDMO']
        fams = {tpl[0] for tpl in reqs['capabilities']}
        # PR-5B.9Q widened NDMO to 5 families.
        for required in ('data_governance', 'data_quality',
                         'data_catalog', 'data_stewardship',
                         'data_lifecycle'):
            self.assertIn(required, fams)
        # The canonical helper must NOT collapse NDMO families.
        c = _APP._canonicalize_pdpl_family
        for fam in fams:
            self.assertEqual(c('NDMO', fam), fam)

    @_skip_if_no_app
    def test_cyber_ai_dt_erm_registries_unchanged(self):
        # Cyber (ECC), AI (SDAIA), Risk (COSO_ERM) and any DT-relevant
        # frameworks remain registered with their canonical
        # capability families intact.
        reqs = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS
        for fw in ('ECC', 'SDAIA', 'COSO_ERM'):
            self.assertIn(fw, reqs)
            self.assertTrue(reqs[fw].get('capabilities'))
        # Sanity: PDPL/NDMO additions did not leak into other
        # frameworks' applicable_domains.
        for fw in ('ECC', 'SDAIA'):
            self.assertNotIn(
                'Data Management',
                reqs[fw].get('applicable_domains', []))


# ──────────────────────────────────────────────────────────────────────
# Test 14 — No deterministic rows inserted by the repair pass.
# Test 15 — Validators not weakened.
# Test 16 — auth/DB/export untouched.
# ──────────────────────────────────────────────────────────────────────

class TestNoDeterministicNoValidatorWeakeningNoSideEffects(
        unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            cls.src = f.read()

    @_skip_if_no_app
    def test_repair_block_has_no_deterministic_row_insertion(self):
        # Both the in-pass repair block and the final overwrite guard
        # MUST delegate to ai_repair_strategy_section. No literal "|"
        # markdown rows are constructed inside the repair scope.
        for anchor_label, window in (
                ('PR-5B.9T: Data framework coverage repair', 60000),
                ('PR-5B.9V: [DATA-FRAMEWORK-COVERAGE-FINAL]', 25000)):
            anchor = self.src.find(anchor_label)
            self.assertGreater(
                anchor, 0,
                f'anchor {anchor_label!r} missing')
            block = self.src[anchor:anchor + window]
            # The repair block must invoke ai_repair_strategy_section.
            self.assertGreaterEqual(
                block.count('ai_repair_strategy_section('), 1,
                f'{anchor_label} must delegate to AI')
            # The repair block must NOT contain hand-rolled markdown
            # table rows (i.e. no literal '| ... |' lines built as
            # f-strings within the repair scope).
            for forbidden in (
                    "f'| ", 'f"| ', "+ '| ", '+ "| '):
                self.assertNotIn(
                    forbidden, block,
                    f'deterministic row marker {forbidden!r} found '
                    f'in repair block {anchor_label}')

    @_skip_if_no_app
    def test_validators_not_weakened(self):
        # Minimum-row thresholds PR-5B.9V must preserve (recorded
        # baseline from app.py at PR-5B.9V time).
        self.assertGreaterEqual(_APP._RICHNESS_MIN_SO_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_PILLARS, 3)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_GAP_ROWS, 2)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_ROADMAP_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_KPI_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_CSF_ROWS, 4)
        self.assertGreaterEqual(_APP._RICHNESS_MIN_RISK_ROWS, 4)
        # PDPL detection sensitivity preserved — adding the canonical
        # alias did NOT collapse the registry capability list.
        pdpl = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['PDPL']
        fam_ids = {tpl[0] for tpl in pdpl['capabilities']}
        for required in ('privacy_governance', 'consent_management',
                         'data_subject_rights',
                         'data_classification_pdpl',
                         'personal_data_classification',
                         'breach_notification'):
            self.assertIn(required, fam_ids)

    @_skip_if_no_app
    def test_auth_db_export_untouched(self):
        """No imports/symbols added or removed for auth/db/export
        layers in this PR. Smoke-check that the surface still exists."""
        # Auth surface — login_required decorator and admin password
        # check remain present.
        for sym in ('login_required', 'ADMIN_PASSWORD',
                    'export_pdf', 'export_docx'):
            self.assertIn(sym, self.src,
                          f'expected surface symbol {sym!r} not found '
                          'in app.py — auth/db/export may have been '
                          'touched')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
