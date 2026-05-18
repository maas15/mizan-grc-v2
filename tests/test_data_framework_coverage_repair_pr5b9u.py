"""PR-5B.9U — PDPL selected-framework coverage iterative repair.

Follow-up regression suite to PR-5B.9T. Validates:

  Part A. The new ``_parse_selected_framework_coverage_defects`` helper
          groups defects per (section, framework, family) regardless of
          whether they arrive as 4-tuples (final-audit shape) or plain
          colon-delimited strings (``selected_framework_coverage_
          missing:PDPL:privacy_governance[:gaps]``).

  Part B. ``_normalize_audit_section_key`` maps free-form section
          labels (``kpi`` / ``indicators`` / ``risks`` / ``gap`` ...)
          onto the canonical sections-dict keys
          (``kpis`` / ``confidence`` / ``gaps`` ...).

  Part C. The expanded PDPL aliases in
          ``_FRAMEWORK_COVERAGE_REQUIREMENTS['PDPL']`` accept the
          broader vocabulary the [DATA-FRAMEWORK-COVERAGE-REPAIR]
          prompt asks the AI to use (privacy policy / حماية البيانات
          الشخصية / إخطار تسرب البيانات / data breach notification /
          حق الوصول / data subject access request ...) so AI-generated
          content does not produce false-negative coverage misses.

  Part D. Source-level audit that the [DATA-FRAMEWORK-COVERAGE-REPAIR]
          block now performs a bounded iterative second-pass repair
          (attempt counter up to 2) and only fail-closes after both
          attempts have left the targeted families unmet.

Scope: Data Management / PDPL only. Cyber / AI / DT / ERM behaviour
must be preserved.

Run:
    python -m pytest \
        tests/test_data_framework_coverage_repair_pr5b9u.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_fwcov_pr5b9u_')
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


class TestNormalizeAuditSectionKey(unittest.TestCase):
    """Part B — section-key aliasing helper."""

    @_skip_if_no_app
    def test_canonical_keys_pass_through(self):
        n = _APP._normalize_audit_section_key
        for sk in ('kpis', 'confidence', 'roadmap', 'gaps',
                   'pillars', 'environment', 'vision'):
            self.assertEqual(n(sk), sk)

    @_skip_if_no_app
    def test_common_aliases(self):
        n = _APP._normalize_audit_section_key
        self.assertEqual(n('kpi'), 'kpis')
        self.assertEqual(n('indicators'), 'kpis')
        self.assertEqual(n('KRI'), 'kpis')
        self.assertEqual(n('risks'), 'confidence')
        self.assertEqual(n('risk'), 'confidence')
        self.assertEqual(n('Gap'), 'gaps')
        self.assertEqual(n('pillar'), 'pillars')
        self.assertEqual(n('env'), 'environment')
        self.assertEqual(n('Regulatory_Context'), 'environment')
        self.assertEqual(n('objectives'), 'vision')

    @_skip_if_no_app
    def test_empty_and_unknown(self):
        n = _APP._normalize_audit_section_key
        self.assertEqual(n(''), '')
        self.assertEqual(n(None), '')
        # Unknown labels pass through lowercased, never silently
        # dropped — so the repair pass can still log them.
        self.assertEqual(n('FooBar'), 'foobar')


class TestParseSelectedFrameworkCoverageDefects(unittest.TestCase):
    """Part A — defect parser groups by section/framework/family."""

    @_skip_if_no_app
    def test_parses_final_audit_tuple_shape(self):
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            ('gaps',
             'selected_framework_coverage_missing:PDPL:privacy_governance',
             0, 1),
            ('kpis',
             'selected_framework_coverage_missing:PDPL:'
             'data_classification_pdpl', 0, 1),
            ('confidence',
             'selected_framework_coverage_missing:PDPL:'
             'personal_data_classification', 0, 1),
            ('roadmap',
             'selected_framework_coverage_missing:PDPL:breach_notification',
             0, 1),
        ]
        grouped = p(defects, domain='data')
        self.assertEqual(
            grouped['gaps']['PDPL'], ['privacy_governance'])
        self.assertEqual(
            grouped['kpis']['PDPL'], ['data_classification_pdpl'])
        self.assertEqual(
            grouped['confidence']['PDPL'],
            ['personal_data_classification'])
        self.assertEqual(
            grouped['roadmap']['PDPL'], ['breach_notification'])

    @_skip_if_no_app
    def test_parses_colon_delimited_string_with_section_suffix(self):
        """The problem-statement defect shape includes a trailing
        ``:<section>`` token. The parser must honour it as the section
        even if the outer 4-tuple section says otherwise (the trailing
        token is more specific)."""
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            'selected_framework_coverage_missing:PDPL:privacy_governance:gaps',
            ('roadmap',
             'selected_framework_coverage_missing:PDPL:'
             'breach_notification:roadmap', 0, 1),
        ]
        grouped = p(defects, domain='data')
        self.assertIn('gaps', grouped)
        self.assertEqual(grouped['gaps']['PDPL'], ['privacy_governance'])
        self.assertEqual(
            grouped['roadmap']['PDPL'], ['breach_notification'])

    @_skip_if_no_app
    def test_parses_alias_section_labels(self):
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            ('kpi',
             'selected_framework_coverage_missing:PDPL:'
             'consent_management', 0, 1),
            ('risks',
             'selected_framework_coverage_missing:PDPL:'
             'data_subject_rights', 0, 1),
        ]
        grouped = p(defects, domain='data')
        # ``kpi`` → ``kpis``; ``risks`` → ``confidence``.
        self.assertIn('kpis', grouped)
        self.assertIn('confidence', grouped)
        self.assertEqual(
            grouped['kpis']['PDPL'], ['consent_management'])
        self.assertEqual(
            grouped['confidence']['PDPL'], ['data_subject_rights'])

    @_skip_if_no_app
    def test_ignores_unrelated_flags(self):
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            ('roadmap', 'data_roadmap_balance_missing:'
                        'personal_data_classification', 0, 1),
            ('gaps', 'gap_guidance_missing', 0, 1),
            ('vision', 'selected_framework_compliance_objective_'
                       'missing:PDPL', 0, 1),
        ]
        grouped = p(defects, domain='data')
        self.assertEqual(grouped, {})

    @_skip_if_no_app
    def test_empty_input(self):
        p = _APP._parse_selected_framework_coverage_defects
        self.assertEqual(p(None), {})
        self.assertEqual(p([]), {})

    @_skip_if_no_app
    def test_dedupes_families_per_section(self):
        p = _APP._parse_selected_framework_coverage_defects
        defects = [
            ('gaps',
             'selected_framework_coverage_missing:PDPL:privacy_governance',
             0, 1),
            ('gaps',
             'selected_framework_coverage_missing:PDPL:privacy_governance',
             0, 1),
            ('gaps',
             'selected_framework_coverage_missing:PDPL:breach_notification',
             0, 1),
        ]
        grouped = p(defects, domain='data')
        # No duplicate of ``privacy_governance``.
        self.assertEqual(
            grouped['gaps']['PDPL'],
            ['privacy_governance', 'breach_notification'])


class TestPdplAliasesAcceptRepairVocabulary(unittest.TestCase):
    """Part C — the validator must accept the AR/EN vocabulary the
    [DATA-FRAMEWORK-COVERAGE-REPAIR] prompt instructs the AI to use.
    Otherwise the model writes valid content but the validator still
    flags the family as missing → root-cause F in the problem
    statement."""

    @_skip_if_no_app
    def test_privacy_governance_accepts_repair_tokens(self):
        f = _APP._compute_missing_selected_framework_coverage
        for ar_phrase in ('سياسات الخصوصية',
                          'حماية البيانات الشخصية'):
            sections = {
                'pillars': '', 'gaps': '', 'roadmap': '',
                'kpis': '',
                # Other PDPL families covered so we isolate the
                # privacy_governance check.
                'confidence': (
                    'إدارة الموافقات وحقوق صاحب البيانات '
                    'وتصنيف البيانات الشخصية وإخطار الخروقات. '
                    + ar_phrase),
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='ar')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'privacy_governance', pdpl,
                f'privacy_governance should be satisfied by AR token '
                f'{ar_phrase!r} but validator still flagged it')

        for en_phrase in ('privacy policy',
                          'personal data protection'):
            sections = {
                'pillars': '', 'gaps': '', 'roadmap': '',
                'kpis': '',
                'confidence': (
                    'consent management and data subject rights and '
                    'personal data classification and breach '
                    'notification. ' + en_phrase),
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='en')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'privacy_governance', pdpl,
                f'privacy_governance should be satisfied by EN token '
                f'{en_phrase!r} but validator still flagged it')

    @_skip_if_no_app
    def test_data_subject_rights_accepts_rights_specific_tokens(self):
        f = _APP._compute_missing_selected_framework_coverage
        for ar_phrase in ('حق الوصول', 'حق التصحيح', 'حق الحذف'):
            sections = {
                'pillars': '', 'gaps': '',
                'roadmap': (
                    'حوكمة الخصوصية وإدارة الموافقات وتصنيف '
                    'البيانات الشخصية وإخطار الخروقات. '
                    + ar_phrase),
                'kpis': '', 'confidence': '',
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='ar')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'data_subject_rights', pdpl,
                f'data_subject_rights should be satisfied by AR token '
                f'{ar_phrase!r}')

        for en_phrase in ('access request', 'rectification', 'erasure'):
            sections = {
                'pillars': '', 'gaps': '',
                'roadmap': (
                    'privacy governance and consent management and '
                    'personal data classification and breach '
                    'notification. ' + en_phrase),
                'kpis': '', 'confidence': '',
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='en')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'data_subject_rights', pdpl,
                f'data_subject_rights should be satisfied by EN token '
                f'{en_phrase!r}')

    @_skip_if_no_app
    def test_breach_notification_accepts_broader_tokens(self):
        f = _APP._compute_missing_selected_framework_coverage
        for ar_phrase in ('إخطار تسرب البيانات',
                          'الإبلاغ عن خرق البيانات'):
            sections = {
                'pillars': '',
                'gaps': (
                    'حوكمة الخصوصية وإدارة الموافقات وحقوق صاحب '
                    'البيانات وتصنيف البيانات الشخصية. ' + ar_phrase),
                'roadmap': '', 'kpis': '', 'confidence': '',
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='ar')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'breach_notification', pdpl,
                f'breach_notification should be satisfied by AR token '
                f'{ar_phrase!r}')

        for en_phrase in ('data breach notification',
                          'personal data breach notification'):
            sections = {
                'pillars': '',
                'gaps': (
                    'privacy governance and consent management and '
                    'data subject rights and personal data '
                    'classification. ' + en_phrase),
                'roadmap': '', 'kpis': '', 'confidence': '',
            }
            missing = f(sections, ['PDPL'],
                        domain='Data Management', lang='en')
            pdpl = {fam for fw, fam, _ in missing if fw == 'PDPL'}
            self.assertNotIn(
                'breach_notification', pdpl,
                f'breach_notification should be satisfied by EN token '
                f'{en_phrase!r}')

    @_skip_if_no_app
    def test_personal_data_classification_is_a_registry_capability(self):
        """The PDPL registry now exposes ``personal_data_classification``
        as a sibling capability of ``data_classification_pdpl`` so the
        two naming conventions emit a consistent defect signal."""
        reqs = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['PDPL']
        fams = {tpl[0] for tpl in reqs['capabilities']}
        self.assertIn('data_classification_pdpl', fams)
        self.assertIn('personal_data_classification', fams)


class TestIterativeRepairBlock(unittest.TestCase):
    """Part D — the [DATA-FRAMEWORK-COVERAGE-REPAIR] block must perform
    a bounded iterative second-pass repair (max 2 attempts) before
    fail-closing."""

    def test_block_uses_attempt_loop(self):
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        anchor = src.find('PR-5B.9T: Data framework coverage repair')
        self.assertGreater(anchor, 0)
        block = src[anchor:anchor + 80000]
        # Bounded iteration marker.
        self.assertIn('_dfc_attempt', block)
        self.assertIn('while _dfc_attempt < 2', block)
        # Stricter second-pass directive marker (broken across two
        # adjacent string literals in source; check for the first half).
        self.assertIn('SECOND-PASS', block)
        # Fail-close happens only AFTER the loop (i.e. after both
        # attempts) — guarded by ``if not _dfc_accepted``.
        self.assertIn('if not _dfc_accepted', block)

    def test_block_preserves_aiifirst_contract(self):
        """The iterative attempts must STILL delegate to
        ai_repair_strategy_section (AI-first) and fail-close via
        _mark_synth_failed with the original section restored. No
        deterministic content insertion."""
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        anchor = src.find('PR-5B.9T: Data framework coverage repair')
        block = src[anchor:anchor + 80000]
        # Each attempt MUST invoke ai_repair_strategy_section.
        self.assertGreaterEqual(
            block.count('ai_repair_strategy_section('), 1,
            'iterative attempts must delegate to '
            'ai_repair_strategy_section (AI-first)')
        # Restore-then-fail-close path exists.
        self.assertIn('sections[_sk] = _dfc_before', block)
        self.assertIn('_mark_synth_failed', block)

    def test_pdpl_section_guidance_includes_explicit_terms(self):
        """Part C contract — the per-section guidance must name the
        explicit PDPL terms the problem statement enumerates so the
        AI repair prompt is unambiguous."""
        with open(
                os.path.join(os.path.dirname(__file__), '..', 'app.py'),
                encoding='utf-8') as f:
            src = f.read()
        anchor = src.find('PR-5B.9T: Data framework coverage repair')
        block = src[anchor:anchor + 80000]
        # gaps
        self.assertIn('إدارة الموافقات', block)
        # roadmap (string is split across multiple adjacent literals
        # in source — check sub-strings that ARE contiguous).
        self.assertIn('تنفيذ ضوابط حماية ', block)
        self.assertIn('البيانات الشخصية وفق PDPL', block)
        # KPI section — strings split across adjacent literals; verify
        # contiguous substrings that ARE present in single literals.
        self.assertIn('الامتثال لحوكمة الخصوصية', block)
        self.assertIn('نسبة الموافقات المدارة', block)
        self.assertIn('الاستجابة لطلبات حقوق ', block)
        self.assertIn('إخطار الخروقات', block)
        # confidence — already implied by the PDPL section terms.
        self.assertIn('حوكمة الخصوصية', block)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
