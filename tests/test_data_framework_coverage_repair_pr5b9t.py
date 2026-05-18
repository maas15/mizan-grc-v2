"""PR-5B.9T — Data Management selected-framework coverage repair.

Validates the new ``[DATA-FRAMEWORK-COVERAGE-REPAIR]`` pass that runs
after ``[ROADMAP-BALANCE-REPAIR]`` and ``[ENVIRONMENT-FRAMEWORK-REPAIR]``
and before the post-normalization re-audit. The pass repairs
``selected_framework_coverage_missing:NDMO|PDPL:<family>`` defects
section-by-section using ``ai_repair_strategy_section`` with an
explicit AR/EN concept vocabulary per family.

Scope is **Data Management only** — Cyber / AI / Digital
Transformation / ERM behaviour must be preserved.

Run:
    python -m pytest \
        tests/test_data_framework_coverage_repair_pr5b9t.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_fwcov_pr5b9t_')
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


class TestDataFrameworkCoverageRepairExists(unittest.TestCase):
    """Part A — Source-level audit: the new pass must be present in
    ``api_generate_strategy`` and must run AFTER
    ``[ENVIRONMENT-FRAMEWORK-REPAIR]`` (and therefore after
    ``[ROADMAP-BALANCE-REPAIR]``) and BEFORE the
    ``POST-NORMALIZATION RE-AUDIT`` block."""

    def test_block_anchor_exists(self):
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        self.assertIn(
            '[DATA-FRAMEWORK-COVERAGE-REPAIR]', src,
            'Expected DATA-FRAMEWORK-COVERAGE-REPAIR block in app.py')

    def test_block_runs_after_env_and_before_post_norm_audit(self):
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        # Locate marker positions. The last occurrence of each tag is
        # what runs in production; pick the orchestration block, not
        # the comment header above the registry.
        env_marker = src.rfind('[ENVIRONMENT-FRAMEWORK-REPAIR]')
        dfc_marker = src.find('[DATA-FRAMEWORK-COVERAGE-REPAIR]')
        post_marker = src.find('POST-NORMALIZATION RE-AUDIT')
        self.assertGreater(env_marker, 0)
        self.assertGreater(dfc_marker, 0)
        self.assertGreater(post_marker, 0)
        self.assertLess(
            env_marker, dfc_marker,
            '[DATA-FRAMEWORK-COVERAGE-REPAIR] must run AFTER '
            '[ENVIRONMENT-FRAMEWORK-REPAIR]')
        self.assertLess(
            dfc_marker, post_marker,
            '[DATA-FRAMEWORK-COVERAGE-REPAIR] must run BEFORE '
            'POST-NORMALIZATION RE-AUDIT')

    def test_block_is_data_only(self):
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        anchor = src.find('PR-5B.9T: Data framework coverage repair')
        self.assertGreater(anchor, 0)
        # The full repair block is ~40KB; take a generous window.
        block = src[anchor:anchor + 60000]
        self.assertIn("normalize_domain", block)
        self.assertIn("'data'", block)
        self.assertIn("'NDMO'", block)
        self.assertIn("'PDPL'", block)
        # Must delegate to ai_repair_strategy_section (AI-first).
        self.assertIn('ai_repair_strategy_section(', block)
        # Must re-validate via the coverage helper.
        self.assertIn(
            '_compute_missing_selected_framework_coverage', block)
        # Must fail-closed via _mark_synth_failed on persistent miss.
        self.assertIn('_mark_synth_failed', block)

    def test_block_carries_full_family_vocabulary(self):
        """Part B — the repair prompt must enumerate explicit AR/EN
        concept vocabulary for every NDMO/PDPL family named in the
        problem statement."""
        import re
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        anchor = src.find('PR-5B.9T: Data framework coverage repair')
        self.assertGreater(anchor, 0)
        block = src[anchor:anchor + 60000]
        # Strip whitespace so multi-line tuple literals match.
        compact = re.sub(r'\s+', '', block)
        # NDMO families
        for fam in ('data_governance', 'data_quality', 'data_catalog',
                    'data_stewardship', 'data_lifecycle'):
            self.assertIn(
                f"('NDMO','{fam}')", compact,
                f'NDMO family missing from token map: {fam}')
        # PDPL families
        for fam in ('privacy_governance', 'consent_management',
                    'data_subject_rights', 'breach_notification',
                    'personal_data_classification',
                    'data_classification_pdpl'):
            self.assertIn(
                f"('PDPL','{fam}')", compact,
                f'PDPL family missing from token map: {fam}')
        # Spot-check exact AR/EN concept tokens from the problem
        # statement (sample one per family) so the prompt actually
        # names them as substrings that the validator can match.
        for tok in ('دورة حياة البيانات', 'data lifecycle management',
                    'كتالوج البيانات', 'metadata',
                    'حوكمة الخصوصية', 'privacy governance',
                    'إدارة الموافقات', 'consent management',
                    'حقوق صاحب البيانات', 'data subject rights',
                    'تصنيف البيانات الشخصية',
                    'personal data classification',
                    'الإبلاغ عن الانتهاكات', 'breach notification'):
            self.assertIn(
                tok, block,
                f'Repair vocabulary missing literal token: {tok!r}')

    def test_block_targets_all_required_sections(self):
        """Part C — the per-section guidance map must name every
        affected section (environment / pillars / gaps / roadmap /
        kpis / confidence)."""
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        anchor = src.find('PR-5B.9T: Data framework coverage repair')
        self.assertGreater(anchor, 0)
        block = src[anchor:anchor + 60000]
        guidance_anchor = block.find('_DFC_SECTION_GUIDANCE')
        self.assertGreater(guidance_anchor, 0)
        # The map must contain a key for every required section.
        for sk in ('environment', 'pillars', 'gaps', 'roadmap',
                   'kpis', 'confidence'):
            self.assertIn(
                f"'{sk}':",
                block[guidance_anchor:guidance_anchor + 20000],
                f'Section guidance missing for: {sk}')


class TestPdplFamilyDetection(unittest.TestCase):
    """The coverage helper must detect each PDPL family from natural
    AR/EN phrasing so the new repair pass triggers correctly when the
    AI body omits a family."""

    @_skip_if_no_app
    def test_pdpl_families_detected_individually(self):
        f = _APP._compute_missing_selected_framework_coverage
        # Section text covering NDMO globally but missing every PDPL
        # family except privacy_governance.
        sections = {
            'pillars': (
                '## 2. الركائز\n\n'
                '### الركيزة 1\n'
                'حوكمة البيانات وجودة البيانات وكتالوج البيانات '
                'وأمناء البيانات ودورة حياة البيانات.\n'
                'حوكمة الخصوصية لحماية البيانات الشخصية.\n'),
            'environment': '', 'gaps': '', 'roadmap': '',
            'kpis': '', 'confidence': '',
        }
        missing = f(sections, ['NDMO', 'PDPL'],
                    domain='Data Management', lang='ar')
        # NDMO should be globally satisfied.
        ndmo_missing = [(fw, fam) for fw, fam, _ in missing
                        if fw == 'NDMO']
        self.assertEqual(ndmo_missing, [])
        # PDPL: privacy_governance is present; the other four PDPL
        # families must be reported missing on every repair_target.
        pdpl_fams = {fam for fw, fam, _ in missing if fw == 'PDPL'}
        self.assertNotIn('privacy_governance', pdpl_fams)
        for required in ('consent_management', 'data_subject_rights',
                         'data_classification_pdpl',
                         'breach_notification'):
            self.assertIn(
                required, pdpl_fams,
                f'Expected PDPL:{required} missing for AR sections '
                'that do not name it')

    @_skip_if_no_app
    def test_validator_uses_cross_section_presence(self):
        """Part D — verify the validator is NOT per-section-overreach:
        a family that appears in only ONE required section satisfies
        the coverage requirement globally (not all-families-in-all-
        sections)."""
        f = _APP._compute_missing_selected_framework_coverage
        sections = {
            'pillars': '',
            'environment': '',
            'gaps': '',
            'roadmap': (
                '## 5. خارطة الطريق\n\n'
                'حوكمة البيانات وجودة البيانات وكتالوج البيانات '
                'وأمناء البيانات ودورة حياة البيانات.\n'
                'حوكمة الخصوصية وإدارة الموافقات وحقوق صاحب البيانات '
                'وتصنيف البيانات الشخصية والإبلاغ عن الانتهاكات.\n'),
            'kpis': '', 'confidence': '',
        }
        missing = f(sections, ['NDMO', 'PDPL'],
                    domain='Data Management', lang='ar')
        # Every family is named once (in roadmap) — coverage globally
        # satisfied; no defects.
        self.assertEqual(
            missing, [],
            'Validator must use cross-section presence; mentioning a '
            'family in one required section should clear the '
            'coverage obligation. Got: ' + repr(missing))


class TestCrossDomainUntouched(unittest.TestCase):
    """The new pass must NOT trigger for Cyber / AI / DT / ERM
    strategies even when the selected frameworks list happens to
    overlap (defensive — e.g. user mistakenly selects NDMO on a
    Cyber strategy). Verified by source-level inspection: the
    trigger requires both normalize_domain(domain)=='data' AND
    NDMO/PDPL in the resolved framework list."""

    def test_trigger_requires_data_domain(self):
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        anchor = src.find('PR-5B.9T: Data framework coverage repair')
        self.assertGreater(anchor, 0)
        block = src[anchor:anchor + 60000]
        # The trigger composes domain check AND framework resolution.
        self.assertIn("_dfc_dcode.strip().lower() == 'data'", block)
        self.assertIn("'NDMO' in _dfc_resolved_fw", block)
        self.assertIn("'PDPL' in _dfc_resolved_fw", block)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
